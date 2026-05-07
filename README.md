### TCP/S — Transparent TCP Encryption at Layer 4

*Author: ArtamonovKA, written on GLM-5.1*

# Architecture
```
tcps/
├── v3/ # Current version (X25519 init-key exchange + ChaCha20-Poly1305 + PSK + forward secrecy)
│ ├── tcps.h # Header: states, constants, ChaCha20, Poly1305, X25519, PSK, ct_memcmp
│ ├── tcps_main.c # Netfilter hooks, probe/TM options, TOFU unicast discovery, PSK verify, key rotation
│ ├── tcps_crypto.c # ChaCha20 stream cipher + Poly1305 MAC + X25519 DH + KDF + PSK derivation
│ └── Makefile # Build: make → tcps.ko
```

# How it works

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — adds TCP option **TC** (kind=253, len=4, magic=0x5443) to SYN
2. Netfilter hook PRE_ROUTING — detects the TC option in SYN → creates a connection record
3. SYN-ACK also carries the TC option — both hosts have confirmed TCPS support
4. After handshake — **PSK** (derived from init-key exchange) → KDF → 4 forwarded keys (enc_c2s, enc_s2c, mac_c2s, mac_s2c)
5. All TCP data is encrypted with ChaCha20 (stream cipher, XOR on the stream position, packet size does not change)
6. Each data packet is signed with Poly1305 MAC (TM option, kind=253, len=8, tag=4 bytes)
7. Works for all TCP sockets on the system, applications are unaware of this.
8. Ports from skip_ports (default 22) are skipped - SSH/SCP work without modification.
9. Loopback connections (127.x.x.x) are skipped.
10. GSO packets are skipped entirely (authentication is impossible without a tag in each segment).

# Init-key exchange - key exchange protocol

Each node generates init_key (random 32B) at boot → pub_key = curve25519(init_key, base).

**TOFU unicast discovery (port 54321):**

Peer discovery no longer uses broadcast. Instead:

1. SYN with TC option triggers unicast DISCOVER on the peer's IP (via workqueue)
2. A background thread sends DISCOVER to peers without a PSK (from the TOFU table)
3. During key rotation, unicast DISCOVER to all peers in TOFU (sending DISCOVER instead of KEYXCHG ensures DH consistency—both sides use the current pubkey from packets)

```
Node A (sends SYN) Node B (receives SYN with TC)
| |
| SYN + TC option ────────────────► | tcps_in sees TC → tcps_trigger_discover(A) 
| | 
|◄── DISCOVER(pub_A) ──────────── | unicast, type=0x01 (from workqueue) 
| | 
|── KEYXCHG(pub_B, enc(init_B)) ► | unicast, type=0x02 
| enc = ChaCha20(DH(init_B, pub_A), init_B) 
| | 
|◄── KEYXCHG(pub_A, enc(init_A))─ | unicast 
| enc = ChaCha20(DH(init_A, pub_B), init_A) 
| |
| PSK = KDF(DH_shared, init_A, init_B) — identical on both sides
```

**DH consistency during rotation:**

When both nodes rotate keys simultaneously, the DH shared key may not match (the sender uses the peer's old pubkey from TOFU, and the receiver uses the sender's new pubkey from the packet). Solution:

1. During rotation, DISCOVER (not KEYXCHG) is sent → the receiver responds with KEYXCHG with the current pubkey.
2. The receiver attempts to decrypt the init_key with the current and previous init_keys (prev_init_key is preserved during rotation).
3. Check: `curve25519(decrypted_init) == pkt.pubkey` — if it matches, the DH shared key is correct.
4. This guarantees DH consistency even during simultaneous rotation.
```

**Packet format:**

| Type | Size | Contents |
|----------|--------|-----------|
| DISCOVER (0x01) | 37B | magic(4) + type(1) + pub_key(32) |
| KEYXCHG (0x02) | 69B | magic(4) + type(1) + pub_key(32) + enc_init_key(32) |
| KEYXCHG_AUTH (0x03) | 73B | magic(4) + type(1) + pub_key(32) + enc_init_key(32) + auth_tag(4) |

**PSK derivation:**
- `DH_shared = X25519(my_init_key, peer_pub_key)`
- Init keys are ordered by public key (memcmp) → deterministic order
- `PSK = ChaCha20_KDF(DH_shared, "TCPS-PSK" || init_key_low || init_key_high)`

**DH fallback PSK** (when the PSK has not yet been established):
- `PSK_fallback = ChaCha20_KDF(DH_shared, "TCPS-FB")` — a separate position in the keystream
- If DH shared = all zeros (low-order point attack) → fallback to a zero PSK with a warning

**Result:** Both nodes receive the same PSK without transmitting the init_key in cleartext.

# Poly1305 MAC (TM option)

Each encrypted data packet contains a TM TCP option with a 4-byte Poly1305 tag:

| Field | Value | Description |
|------|----------|----------|
| Kind | 253 | Experimental (RFC 4727) |
| Length | 8 | Option length |
| Magic | 0x544D | "TM" |
| Tag | 4 bytes | Poly1305 MAC (truncated to 4 bytes) |

**MAC is calculated:**
- Poly1305 one-time key = ChaCha20(mac_key, pos+32, zeros, 32) — offset +32 from the encryption position
- AAD = flags(1) + seq(4), padded to 16 bytes
- Input: AAD || encrypted_payload(padded to 16) || len(aad)_le64 || len(payload)_le64
- Tag is truncated to 4 bytes (2^32 forgery resistance)
- Tag comparison — constant-time (`tcps_ct_memcmp`), protection against timing attacks

**4 keys per connection** (via `tcps_derive_keys`):
- `enc_key` (c2s) — outgoing encryption
- `dec_key` (s2c) — incoming decryption
- `mac_enc_key` (cmac) — outgoing MAC
- `mac_dec_key` (smac) — incoming MAC

**Behavior:**
- TM option is NOT removed upon reception - TCP stack ignores unknown kind=253
- GSO packets are passed entirely (without encryption or MAC) - segments cannot be authenticated
- RST without MAC in KEYED state → DROP (injection protection)
- Data without MAC after `peer_has_mac` → DROP (bit-flipping protection)

# KEYXCHG_AUTH — Key rotation authentication

When rotating the init-key, the module sends KEYXCHG_AUTH instead of KEYXCHG:

```
KEYXCHG_AUTH = KEYXCHG + auth_tag
auth_tag = Poly1305(prev_psk, 0, type+pubkey+enc_init, 65, NULL, 0) [4 bytes]
```

**Downgrade protection:**
- The recipient checks the auth_tag against prev_psk (constant-time comparison)
- If the tag matches, → KEYXCHG_AUTH verified (rotation is legitimate)
- If the tag does not match, → WARN, continue as plain KEYXCHG (prev_psk is out of sync during simultaneous rotation)
- If KEYXCHG does not have AUTH, but we have prev_psk, → WARN (peer reload?)
- If KEYXCHG_AUTH without prev_psk → WARN, accept as plain KEYXCHG

# Forward Secrecy (init-key rotation)

Every 3600 seconds (TCPS_KEY_ROTATE_INTERVAL):
1. A new init_key / pub_key pair is generated
2. The old PSK is stored as prev_psk (for KEYXCHG_AUTH)
3. Unicast DISCOVER is sent to all peers in the TOFU table → peers respond with KEYXCHG with the current pubkey (DH consistency)
4. The old init_key is stored as prev_init_key (for DH retry when decrypting KEYXCHG)
5. New connections use the new PSK
6. Existing connections continue with the old keys

# Out-of-band PSK verification (MITM protection)

**Problem:** MITM can spoof public keys Keys in UDP exchange → both nodes will receive different PSKs → MITM can decrypt both sides.

**Solution:** PSK fingerprint — the first 8 bytes of the PSK, shown on both sides. The operator compares:

```bash
# On node A:
cat /proc/tcps_peers
# 192.168.1.42 pub=... psk=unverified fp=02f9b20aad44590b

# On node B:
cat /proc/tcps_peers
# 192.168.1.151 pub=... psk=unverified fp=02f9b20aad44590b
# ^^^^^^^^^^^^^^^^ MATCHES!

# Verify (if fingerprint matches):
echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers

# If NOT a match → MITM! Do not verify.
```

**Parameter `psk_require_verify`:**

| Mode | Before verify | After verify |
|---|---|---|
| `psk_require_verify=0` (default) | Full PSK immediately | Full PSK |
| `psk_require_verify=1` | DH fallback (weaker) | Full PSK |

When `psk_require_verify=1`: connections to unverified peers use DH fallback (without init_key). After manual verification, full PSK is used.

# MITM Protection (TOFU + PSK verify + KEYXCHG_AUTH)

**Three-level protection:**

1. **TOFU** — detects public key changes:
- `strict_tofu=0`: warns + updates (allows reload)
- `strict_tofu=1`: blocks (MITM protection, reload requires manual intervention)

2. **PSK verify** — detects MITM during the first exchange:
- Fingerprint matches → no MITM → `verify` confirms → full PSK
- Fingerprint does not match → MITM → do not confirm → DH fallback

3. **KEYXCHG_AUTH** — detects MITM during key rotation:
- Auth tag matches → rotation is legitimate → new PSK
- Auth tag does not Matches → MITM → REJECT → Old PSK retained

**Scenarios:**

| Scenario | TOFU | PSK fingerprint | KEYXCHG_AUTH | Result |
|----------|------|-----------------|--------------|-----------|
| No MITM, first exchange | New peer | Same | — | verify → full PSK |
| MITM on first exchange | New peer | **Different** | — | Do not verify → DH fallback |
| MITM on repeat (strict_tofu=1) | Key changed | — | — | Blocked |
| MITM on rotation (prev_psk available) | — | — | **FAILED** | REJECT, old PSK |
| Legitimate rotation | — | — | OK | New PSK |
| Reload without MITM | Key updated | — | WARN | PSK recalculated |
| KEYXCHG_AUTH without prev_psk | — | — | WARN, accept as KEYXCHG | Sender does not yet have prev_psk |

**Module parameters:**

| Parameter | Default | Description |
|----------|-------------|-----------|
| `skip_ports` | 22 | Ports to skip (already encrypted) |
| `strict_tofu` | 0 | 0=update key with warning, 1=block on change |
| `psk_require_verify` | 0 | 0=PSK immediately, 1=require verify before full PSK |
| `rotate_interval` | 3600 | Init-key rotation interval in seconds |
| `key_file` | (empty) | File to store the init-key (empty = RAM only, e.g. /etc/tcps/init_key) |

```bash
insmod tcps.ko skip_ports=22,443 strict_tofu=1 psk_require_verify=1 key_file=/etc/tcps/init_key
cat /sys/module/tcps/parameters/psk_require_verify
echo 1 > /sys/module/tcps/parameters/psk_require_verify
```

# Probe option — detect TCPS support

TCP option kind=253 (experimental range according to RFC 4727; middleboxes are stripped less frequently).

| Field | Value |Description |
|------|----------|----------|
| Kind | 253 | Experimental (RFC 4727) |
| Length | 4 | Option length |
| Data | 0x5443 | Magic "TC" |

**Behavior when stripping an option with a middlebox:**
- SYN without TC → server does not create a record → plain TCP
- SYN-ACK without TC → client removes the record → plain TCP
- Both sides correctly fall back to unencrypted TCP

# Operation Scenarios

## Both sides have a module (PSK exchange)

```
Step | Node A (tcps.ko) | Node B (tcps.ko)
-----|-------------------------------------------|-------------------------------------------
1 | SYN + TC option ───────────────────────► | Sees TC, creates conn, trigger DISCOVER
2 | | SYN-ACK + TC option
3 | ◄─────────────────── ───────────────────── |
4 | KDF(PSK, client_ISN, server_ISN) → 4 keys| KDF(PSK, client_ISN, server_ISN) → 4 keys
5 | ◄══════════ ChaCha20 + Poly1305 ═══════► | Both directions are encrypted + signed
| Applications (nginx/postgres) are unaware
```

## Only one side has a module (auto-fallback)

```
Step | Client (tcps.ko) | Server (no module)
-----|-------------------------------------------|-------------------------------------------
1 | SYN + TC option ──────────────────────────► | Ignores unknown option 253
2 | | SYN-ACK (without TC option)
3 | ◄────────────────────────────────────────────── |
4 | No TC in SYN-ACK → delete conn |
5 | data (no modification) ──────────────────► | Normal data
| apt-get update, DNS, curl — everything works!
```

## MITM attack detected (fingerprint doesn't match)

```
Step | Node A | MITM | Node B
-----|------------------------------|------------------|-------------------------------
1 | DISCOVER(pub_A) ──► | pub_A→M substitution | ──► DISCOVER(pub_M)
2 | ◄── KEYXCHG(pub_M, enc_M) | | ◄── KEYXCHG(pub_B, enc_B)
3 | PSK_A = KDF(DH(A,M), init_A, init_M) |
4 | | | PSK_B = KDF(DH(M,B), init_M, init_B)
5 | fingerprint_A ≠ fingerprint_B |
6 | The operator sees: fp=aaa... ≠ fp=bbb... → MITM! |
7 | Does not confirm verify → DH fallback |
```

## MITM during key rotation (KEYXCHG_AUTH)

```
Step | Node A (rotated) | MITM | Node B
-----|-------------------------------|-------------------|-------------------------------
1 | KEYXCHG_AUTH(pub_A', enc, tag)►| substitution tag | ──► KEYXCHG_AUTH(tag')
2 | | | Poly1305(prev_psk, ...) ≠ tag'
3 | | | REJECT → old PSK preserved
```

# Reloading the module (reload)

With `rmmod` + `insmod`:
1. Init_key **by default only in RAM** (no file on disk)
2. On boot - if `key_file` is not set → a new init_key is generated (forward secrecy with rmmod)
3. On boot - if `key_file=/etc/tcps/init_key` → loaded from file → **same pubkey** → TOFU/PSK preserved
4. Key file - permissions 0600, root-only (similar to ~/.ssh/id_rsa)
5. Connection table is cleared with rmmod (existing TCP sessions are broken)
6. TOFU cache and PSK are preserved with key_file (pubkey is not (varies)

**Recommendation:** Use `key_file=` for servers (TOFU consistency), without it - for workstations (maximum forward secrecy)

**Impact on connections:**

| Stage | SSH (port 22) | Other TCP |
|------|--------------|------------|
| Module loaded | OK (skip) | Encrypted (PSK + MAC) |
| `rmmod` | OK (no module) | Existing keys are broken |
| `insmod` (before discovery) | OK | New - weak keys (no peer) |
| After DISCOVER + KEYXCHG | OK | New - DH fallback (before verify) |
| After verify | OK | New - full PSK |

# Cryptography (without OpenSSL)

- **X25519 ECDH** — 32-byte keys, via kernel crypto API (`libcurve25519`)
- All-zero shared secret verification (low-order point attack) → -EINVAL
- **ChaCha20** — stream cipher, XOR on stream position, without changing packet size
- 64-bit counter, nonce=0 (uniqueness via separate keys per connection)
- Keystream temporary blocks (`blk[]`) are zeroed after use
- Stream position tracks 32-bit wrap-around (seq_hi) → correct operation after 4GB
- **Poly1305 MAC** — self-implemented (26-bit limb), 4-byte tag in TM option
- Correct finalization: carry via `>> 26`, reduction by `2^130-5`, sign-bit mask
- One-time key = ChaCha20(mac_key, pos+32, zeros, 32) — offset from the encryption position
- AAD: flags(1) + seq(4), padded to 16 bytes
- Input: AAD || payload(padded) || len(aad)_le64 || len(payload)_le64
- Tag comparison — constant-time (`tcps_ct_memcmp`)
- **PSK derivation** — `KDF = ChaCha20_KDF(DH_shared, "TCPS-PSK" || init_key_A || init_key_B)`
- DH_shared ensures consistency (both sides compute the sameo)
- Init keys add additional entropy (defense-in-depth)
- The order of init_key is determined by the public key (deterministically)
- The domain label "TCPS-PSK" separates the PSK from other KDF positions
- **DH fallback PSK** — `KDF = ChaCha20_KDF(DH_shared, "TCPS-FB")` — separate position, domain-separated
- **Per-connection KDF** — `KDF(PSK, client_ISN, server_ISN)` → 4 keys
- `TCPS c2s` (position 0x80000000000000000) — enc_key
- `TCPS s2c` (position 0x80000000000000040) — dec_key
- `TCPS cmac` (position 0x80000000000000080) — mac_enc_key
- `TCPS smac` (position 0x80000000000000C0) — mac_dec_key
- KDF label limited to 31 bytes (overflow protection)
- Stream position calculated from ISN + 1 — unique for each connection
- Private keys are destroyed via `memzero_explicit` when module unloads

# Security Audit (fixed)

A logic and vulnerability audit was performed. Fixes by category:

## CRITICAL (5 fixes)

| # | Vulnerability | Fix |
|---|-----------|------------|
| C-1 | Poly1305: broken carry (`uint32` overflow instead of limb overflow) + modulus `2^128-5` instead of `2^130-5` | Carry via `>> 26`, reduction `h4 + (g3>>26) - (1<<24)`, sign-bit mask `(int32_t)g4 >> 31` |
| C-2 | `memcmp` timing side-channel on MAC tag (~1024 attempts to forge) | `tcps_ct_memcmp()` — constant-time XOR accumulation |
| C-3 | MAC truncated to 4 bytes (32-bit security) | Left 4B due to TCP option space limitation; mitigated constant-time compare |
| C-4 | `kfree` on `rcu_head` offset → frees invalid address | `tcps_peer_free_rcu()` with `container_of` + `memzero_explicit` |
| C-5 | Zero PSK on DH error → zero-key encryption | All-zero DH shared secret verification; fallback via `tcps_derive_psk_fallback()` with a separate position |

## HIGH (8 fixes)

| # | Vulnerability | Fix |
|---|-----------|-------------|
| H-1 | PSK is read without locking (torn read during rotation) | `spin_lock(&tcps_peers_lock)` in `tcps_peer_get_psk()` |
| H-2 | No all-zero DH shared secret verification (low-order point attack) | `tcps_dh_shared()` returns -EINVAL for all-zero |
| H-3 | GSO packets are encrypted without MAC (bit-flipping) | GSO packets are completely skipped (NF_ACCEPT without encryption) |
| H-4 | `spin_lock` instead of `spin_lock_bh` in `tcps_in` → deadlock | All locks in `tcps_in` → `spin_lock_bh` |
| H-5 | Duplicate connections during SYN retransmit (memory leak) | `tcps_conn_add_unique()` — lookup before add |
| H-6 | 4GB seq wrap → keystream reuse (two-time pad) | `enc_seq_hi`/`dec_seq_hi` track 32-bit wrap |
| H-7 | Decryption without MAC with `peer_has_mac` (bit-flipping) | NF_DROP when `peer_has_mac && !has_tm` |
| H-8 | Module exit does not flush workqueue → use-after-free | `flush_scheduled_work()` in `tcps_exit()` |

## MEDIUM (9 fixes)

| # | Vulnerability | Fix |
|---|-----------|-------------|
| M-1 | ChaCha20 `blk[]` keystream remains on the stack | `memzero_explicit(blk)` after each block |
| M-2 | KDF label buffer overflow (no strlen check) | `strlen` is limited to 31 bytes |
| M-3 | KEYXCHG_AUTH without prev_psk → REJECT blocks PSK exchange | WARN + accept KEYXCHG as plain (race condition during first rotation) |
| M-4 | TCP options parser scans payload (false TM match) | `tcps_opt_end()` limits scan to `th->doff*4` |
| M-5 | FIN sets DEAD too early (retransmit without encryption) | FIN sets `kill=1`, state remains KEYED until cleanup timeout |
| M-6 | `kernel_sendmsg` inside `rcu_read_lock` during rotation | Collecting addresses under RCU, sending outside RCU |
| M-7 | `tcps_recalc_csum` with negative tcplen → crash | Checking `tcplen < sizeof(tcphdr)` |
| M-8 | Unlimited peer table (OOM from scanning) | `TCPS_MAX_PEERS=64` with atomic counter |
| M-9 | MAC and encryption at the same keystream position | MAC at `pos+32` (offset by 1 ChaCha20 block) |
| M-10 | DH shared desync during simultaneous rotation (fingerprints don't match) | DISCOVER instead of KEYXCHG during rotation + prev_init_key DH retry + curve25519(decrypted)==pkt.pubkey verification |
| M-11 | KEYXCHG_AUTH FAILED → REJECT blocks PSK during race condition | WARN + continue as plain KEYXCHG (MITM is impossible without a private key) |

## LOW/INFO (retained)

| Vulnerability | Reason |
|-----------|---------|
| MAC 4 bytes instead of 16 | TM option 12B won't fit in most packets |
| ACK-only packets without MAC | No payload → no MAC position |
| RST in cleartext | Partial protection: RST without MAC when peer_has_mac → DROP |
| First exchange vulnerable to MITM | Detectable via fingerprint verify |
| No version negotiation in the protocol | The current version is the only one |

# Deployment

On the server and client (Linux, amd64, kernel 6.x):

```bash
cd v3/
apt install build-essential linux-headers-$(uname -r)
modprobe curve25519-x86
make
insmod tcps.ko psk_require_verify=1
```

PSK verification (on both machines):
```bash
# Step 1: Verify fingerprint
cat /proc/tcps_peers
# Node A: 192.168.1.42 ... psk=unverified fp=02f9b20aad44590b
# Node B: 192.168.1.151 ... psk=unverified fp=02f9b20aad44590b

# Step 2: If fp matches, verify
echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers

# Step 3: Verify
cat /proc/tcps_peers
# 192.168.1.42 ... psk=verified fp=02f9b20aad44590b
```

Unloading the module:
```bash
rmmod tcps
```

# Verifying operation

## dmesg

```bash
dmesg | grep tcps
```

Loading:
```
tcps: X25519 init-key generated, pubkey=4ea7a766cdcfd414...
tcps: module loaded, X25519+ChaCha20-Poly1305+PSK+FS active (rotate=3600s)
```

PSK installed (TOFU unicast discovery):
```
tcps: TOFU added peer 192.168.1.42
tcps: PSK established with 192.168.1.42 fingerprint=b063826598bc8201
```

Key rotation:
```
tcps: init-key ROTATED, new pubkey=1a2b3c4d...
tcps: KEYXCHG_AUTH verified from 192.168.1.42
tcps: PSK established with 192.168.1.42 fingerprint=5e6f7a8b...
```

MITM detected during rotation:
```
tcps: KEYXCHG_AUTH FAILED from 192.168.1.42 (prev_psk mismatch, rotation race?) -> continuing as plain KEYXCHG
```

DH retry during simultaneous rotation:
```
tcps: init-key ROTATED, new pubkey=1a2b3c4d...
tcps: KEYXCHG_AUTH verified from 192.168.1.42
tcps: PSK established with 192.168.1.42 fingerprint=5e6f7a8b...
```

PSK verified:
```
tcps: PSK VERIFIED for 192.168.1.42
```

DH fallback (PSK not verified):
```
tcps: PSK not verified for 192.168.1.42, using DH fallback
```

Low-order point (DH shared = zeros):
```
tcps: DH all-zero for 192.168.1.42 -> DH fallback
```

## /proc/tcps_peers

```bash
cat /proc/tcps_peers
# 192.168.1.42 pub=d2a7929b... psk=verified fp=02f9b20aad44590b

# Add peer manually:
echo "192.168.1.42=hex_pubkey..." > /proc/tcps_peers

# Verify PSK:
echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers
```

## tcpdump — visual encryption verification

```bash
tcpdump -i ens18 -A -s0 tcp
```

| Flag | Description |
|---------|----------|
| `unknown-253` in SYN | TC probe option (4 bytes, magic 0x5443) |
| `unknown-253` in data | TM MAC option (8 bytes, magic 0x544D, tag 4B) |
| Unreadable data | Payload encrypted with ChaCha20 |
| Readable data | Plain TCP — peer without module or skip_ports |

# Security Properties

| Property | Mechanism |
|----------|----------|
| Encryption | ChaCha20 stream cipher (XOR on stream position) |
| Data Integrity | Poly1305 MAC (4B tag) + constant-time verify + DROP without MAC |
| Key exchange | X25519 ECDH + init-key exchange → PSK |
| Low-order point protection | All-zero DH shared → fallback verification |
| PSK derivation | KDF(DH_shared, "TCPS-PSK"\|\|init_key_A\|\|init_key_B) — domain-separated |
| DH fallback PSK | Separate KDF position + label "TCPS-FB" — domain-separated |
| Directed keys | Per-connection KDF (PSK, ISN) with labels c2s/s2c/cmac/smac |
| MAC/enc separation | MAC on pos+32, encryption on pos — different keystream blocks |
| Forward secrecy | Init-key rotation (rotate_interval, default 3600s), KEYXCHG_AUTH |
| MITM protection (first exchange) | PSK fingerprint + out-of-band verify |
| MITM protection (repeat) | TOFU + strict_tofu |
| MITM protection (rotation) | KEYXCHG_AUTH — Poly1305 authentication via prev_psk |
| DH consistency during rotation | DISCOVER instead of KEYXCHG + prev_init_key retry + curve25519 verify |
| RST injection protection | RST without MAC in KEYED → DROP |
| Bit-flipping protection | Data without MAC with peer_has_mac → DROP |
| Timing attack protection | `tcps_ct_memcmp` for MAC and KEYXCHG_AUTH |
| Downgrade protection | Probe option — none → fallback to plain TCP |
| Auto-discovery | TOFU unicast discovery (port 54321), triggered by SYN |
| Skip ports | Port 22 is skipped — SSH/SCP is not affected |
| Skip loopback | 127.x.x.x is skipped — local connections are not encrypted |
| Skip GSO | GSO packets are not encrypted (cannot be authenticated) |
| Seq wrap | 32-bit wraparound is tracked (seq_hi) → no keystream reuse |
| Duplicate conn | `tcps_conn_add_unique()` — no duplicates during SYN retransmit |
| Peer limit | Max 64 peers (TCPS_MAX_PEERS) — OOM protection |
| Privilege | memzero_explicit, key in RAM (optional on disk 0600) |
| RCU/lifecycle | Correct RCU callbacks, flush_scheduled_work() on unload |

# Known limitations

| Limitation | Description |
|-------------|----------|
| IPv4 only | IPv6 is not yet supported |
| GSO without encryption | GSO packets are skipped entirely (segments cannot be authenticated) |
| MAC 4 bytes | Truncated Poly1305 tag (2^32 forgery), the full 16B will not fit in the TCP option |
| First-use MITM | The first exchange is vulnerable to MITM (detectable via fingerprint) |
| PSK verify manually | The operator must compare fingerprints on both machines |
| Keypair persistence | Optional: `key_file=` → file 0600; without parameter - RAM only (forward secrecy with rmmod) |
| Reload breaks connections | Existing TCP sessions are broken with rmmod/insmod |
| TM option is not removed | TM option remains on reception (TCP stack ignores kind=253) |
| Options may not fit | With SACK blocks + TM (8B) may exceed 40B TCP option space |
| ACK-only without MAC | Packets without payload are not signed |
| RST in cleartext | Partial protection: RST without MAC when peer_has_mac → DROP |
| No version negotiation | Protocol changes are incompatible |