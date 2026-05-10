### TCP/S — Transparent TCP Encryption at Layer 4

*Author: ArtamonovKA, written on GLM-5.1*

# Architecture
```
tcps/
├── v3/ # Current version (X25519 + ChaCha20-Poly1305 + PSK + forward secrecy)
│ ├── tcps.h # Header: states, constants, ChaCha20, Poly1305, X25519, PSK, ct_memcmp
│ ├── tcps_main.c # Netfilter hooks, probe option, TOFU unicast discovery, PSK verify, key rotation, GSO, rate-limit
│ ├── tcps_crypto.c # ChaCha20 + Poly1305 + X25519 (self-contained, __int128) + KDF + PSK derivation
│ └── Makefile # Build: make → tcps.ko
```

# How it works

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — adds TCP option **TC** (kind=253, len=4, magic=0x5443) to SYN
2. Netfilter hook PRE_ROUTING — detects TC option in SYN → creates Connection record
3. SYN-ACK also carries a TC option — both hosts have confirmed TCPS support.
4. After handshake — **PSK** (from init-key exchange) → KDF → 4 directional keys (enc_c2s, enc_s2c, mac_c2s, mac_s2c)
5. All TCP data is encrypted with **ChaCha20** (stream cipher, XOR on the stream position, payload size does not change)
6. Each data packet is signed with **Poly1305 MAC** — **16-byte full tag** is added as a payload suffix.
7. On reception: the tag is extracted from the end of the payload, verified, then skb_trim + iph->tot_len adjustment.
8. MSS is reduced by 16 bytes in SYN/SYN-ACK (so that the resulting packet does not exceed the MTU).
9. Works for all TCP sockets on the system; applications are unaware of any information.
10. Ports from `skip_ports` (default 22) are skipped - SSH/SCP work without modification.
11. Loopback connections (127.x.x.x) are skipped.
12. GSO packets are processed: GSO is disabled on the socket (`sk_gso_type=0`), with a race window - software segmentation + encryption of each segment.
13. Socket memory accounting: `skb->truesize` and `sk_rmem_alloc` are adjusted for compatibility with TCP flow control.

# Init-key exchange - key exchange protocol

Each node generates **init_key** (random 32B) → **pub_key** = curve25519(init_key, base) at boot.

**TOFU unicast discovery (port 54321):**

Peer discovery does not use broadcast:

1. SYN with the TC option triggers unicast DISCOVER on the peer's IP (via workqueue)
2. A background thread sends DISCOVER to peers without a PSK (from the TOFU table)
3. During key rotation, unicast DISCOVER to all peers in the TOFU

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

1. During rotation, DISCOVER (not KEYXCHG) is sent → the recipient responds with KEYXCHG with the current pubkey
2. The recipient attempts to decrypt the init_key with the current and previous init_key (prev_init_key)
3. Check: `curve25519(decrypted_init) == pkt.pubkey`

**Rate-limit on discovery (port 54321):**

| Limit | Value | Description |
|-------|----------|----------|
| Per-IP | 1 packet / 2 sec | No more than one DISCOVER/KEYXCHG from one IP per 2 seconds |
| Global | 10 packets/sec | No more than 10 KEYXCHG operations per second total |
| Slots | 16 | Number of monitored IP addresses |

Protects against CPU DoS (curve25520 ~2-4 operations per KEYXCHG) and TOFU table overflows.

**Packet format:**

| Type | Size | Contents |
|-----|---------|-----------|
| DISCOVER (0x01) | 37B | magic(4) + type(1) + pub_key(32) |
| KEYXCHG (0x02) | 69B | magic(4) + type(1) + pub_key(32) + enc_init_key(32) |
| KEYXCHG_AUTH (0x03) | 85B | magic(4) + type(1) + pub_key(32) + enc_init_key(32) + auth_tag(16) |

**PSK derivation:**
- `DH_shared = X25519(my_init_key, peer_pub_key)`
- Init keys are ordered by public key (memcmp) → deterministic order
- `PSK = ChaCha20_KDF(DH_shared, "TCPS-PSK" || init_key_low || init_key_high)`

**DH fallback PSK** (when PSK has not yet been established):
- `PSK_fallback = ChaCha20_KDF(DH_shared, "TCPS-FB")`
- If DH shared = all zeros (low-order point attack) → fallback to a zero PSK with a warning

# Poly1305 MAC — 16-byte payload suffix

Each encrypted packet contains a **full 16-byte Poly1305 tag** at the end Payload:

```
| IP header | TCP header | encrypted payload | MAC tag (16B) |
```

**MAC is calculated:**
- One-time key Poly1305 = ChaCha20(mac_key, pos+32,zeros, 32)
- AAD = flags(1) + seq(4), padded to 16 bytes
- Login: AAD || encrypted_payload(padded to 16) || len(aad)_le64 || len(payload)_le64
- Full 16-byte tag (2^128 forgery resistance)
- Tag comparison — constant-time (`tcps_ct_memcmp`)

**When sending (tcps_out):**
1. ChaCha20 encryption at the stream position
2. Poly1305 tag calculation
3. Adding the tag via `skb_put(skb, 16)`
4. `skb->truesize += 16` (socket memory accounting)
5. `iph->tot_len += 16`
6. Recalculating checksums

**When receiving (tcps_in):**
1. Extract the last 16 bytes of the payload as a tag
2. Verify the Poly1305 MAC
3. `skb_trim(skb, skb->len - 16)` — removing the tag
4. `atomic_sub(16, &skb->sk->sk_rmem_alloc)` + `skb->truesize -= 16` (socket accounting)
5. `iph->tot_len -= 16`
6. ChaCha20 decryption
7. Checksum recalculation

**MSS adjustment:** SYN and SYN-ACK contain a reduced MSS (by 16 bytes) to ensure the resulting MAC packet does not exceed the MTU.

**4 keys per connection** (via `tcps_derive_keys`):
- `enc_key` (c2s) — outgoing encryption
- `dec_key` (s2c) — incoming decryption
- `mac_enc_key` (cmac) — outgoing MAC
- `mac_dec_key` (smac) — incoming MAC

**Behavior:**
- RST without MAC in KEYED state → DROP
- Data without MAC after `peer_has_mac` → DROP
- GSO packets: segmentation + MAC per segment + reinjection

# KEYXCHG_AUTH — key rotation authentication

When rotating the init-key, the module sends KEYXCHG_AUTH:

```
KEYXCHG_AUTH = KEYXCHG + auth_tag
auth_tag = Poly1305(prev_psk, 0, type+pubkey+enc_init, 65, NULL, 0) [16 bytes]
```

**Downgrade protection:**
- If tag matches → KEYXCHG_AUTH verified
- If tag does not match → WARN, continue as plain KEYXCHG
- If KEYXCHG without AUTH, but we have prev_psk → WARN (peer reload?)

# Forward secrecy (init-key rotation)

Every 3600 seconds (TCPS_KEY_ROTATE_INTERVAL):
1. A new init_key / pub_key pair is generated
2. The old PSK is stored as prev_psk (for KEYXCHG_AUTH)
3. Unicast DISCOVER is sent to all peers in the TOFU table
4. The old init_key is stored as prev_init_key (for DH retry)
5. New connections use the new PSK
6. Existing connections continue using the old keys

# Out-of-band PSK verification (MITM protection)

**Problem:** MITM can substitute public keys in UDP exchanges → both nodes will receive different PSKs.

**Solution:** PSK fingerprint — the first 8 bytes of the PSK:

```bash
# On node A:
cat /proc/tcps_peers
# 192.168.1.42 pub=... psk=unverified fp=02f9b20aad44590b

# On node B:
cat /proc/tcps_peers
# 192.168.1.151 pub=... psk=unverified fp=02f9b20aad44590b

# Verify:
echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers
```

**Parameter `psk_require_verify`:**

| Mode | Before verify | After verify |
|---|---|---|
| `psk_require_verify=0` (default) | Full PSK immediately | Full PSK |
| `psk_require_verify=1` | DH fallback (weaker) | Full PSK |

# MITM Protection (TOFU + PSK verify + KEYXCHG_AUTH)

**Three-level protection:**

1. **TOFU** — detects public key changes:
- `strict_tofu=0`: warns + updates
- `strict_tofu=1`: blocks

2. **PSK verify** — detects MITM during the first exchange:
- Fingerprint matches → no MITM → verify → full PSK
- Fingerprint does not match → MITM → do not verify → DH fallback

3. **KEYXCHG_AUTH** — detects MITM during key rotation:
- Auth tag matches → rotation is legitimate
- Auth tag does not match → old PSK is retained

# Cryptography (without external dependencies)

All cryptography — **self-contained**, does not depend on the kernel crypto API or OpenSSL. Portable to FreeBSD and other Unix systems.

- **X25519 ECDH** — self-contained donna-style implementation with `__int128` for fe_mul
- 64-bit limb representation (5 × 64-bit)
- donna-style overlapping loads/stores for fe_load/fe_store
- crecip exponent chain for fe_inv
- All-zero shared secret verification (low-order point attack) → -EINVAL

- **ChaCha20** — stream cipher, XOR on stream position
- 64-bit counter, nonce=0 (uniqueness via separate keys per connection)
- Keystream temporary blocks (`blk[]`) are zeroed out after use
- Stream position is tracked by 32-bit wrap-around (seq_hi)

- **Poly1305 MAC** — self-implemented (26-bit limb), full 16-byte tag
- Correct finalization: carry via `>> 26`, reduction by `2^130-5`, sign-bit mask
- One-time key = ChaCha20(mac_key, pos+32, zeros, 32)
- AAD: flags(1) + seq(4), padded to 16 bytes
- Tag comparison — constant-time (`tcps_ct_memcmp`)

- **PSK derivation** — `KDF = ChaCha20_KDF(DH_shared, "TCPS-PSK" || init_key_A || init_key_B)`
- Init keys are ordered by public key (deterministically)
- Domain label "TCPS-PSK" separates PSK from other KDF positions

- **Per-connection KDF** — `KDF(PSK, client_ISN, server_ISN)` → 4 keys
- `TCPS c2s` (position 0x8000000000000000) - enc_key 
- `TCPS s2c` (position 0x8000000000000040) - dec_key 
- `TCPS cmac` (position 0x8000000000000080) — mac_enc_key 
- `TCPS smac` (position 0x80000000000000C0) - mac_dec_key

- Private keys are destroyed via `memzero_explicit` when unloading the module

# Socket memory accounting

When adding or removing a MAC tag (16B), socket memory accounting must be adjusted, otherwise TCP flow control limits throughput to ~1.68 Mbps.

**Sending (tcps_out):**
- `skb->truesize += TCPS_MAC_SIZE` — the added tag increases the actual buffer size
- Without this adjustment: `sk_wmem_alloc` gets out of sync → TCP stack throttles when sending

**Receiving (tcps_in):**
- `atomic_sub(TCPS_MAC_SIZE, &skb->sk->sk_rmem_alloc)` — return the accrued 16 bytes
- `skb->truesize -= TCPS_MAC_SIZE` — decrease the actual buffer size
- Without this adjustment: `sk_rmem_alloc` accumulates 16 extra bytes per packet → TCP window shrinks → 1.68 Mbps

# GSO (Generic Segmentation Offload) processing

**Problem:** GSO allows TCP to create large segments (up to 64KB), which are segmented by the NIC or kernel AFTER the netfilter hook.

**Solution — a combined approach:**

1. **Primary mechanism:** On the first KEYED packet, `sk->sk_gso_type = 0` is set — TCP stops creating GSO segments.

2. **Fallback (race window):** If a GSO packet was created before `sk_gso_type=0` was set:
- `skb_gso_segment(skb, 0)` — software segmentation
- Each segment: linearization → ChaCha20 encryption → Poly1305 MAC (16B suffix)
- Segments are reinjected via `ip_local_out()` with `skb->mark = TCPS_SKB_MARK`

**Performance:**
- iperf3: ~128 Mbps (from GSO to NIC)
- curl/nginx: ~93 Mbps
- Baseline without module: ~2.76 Gbps
- Overhead: per-packet ChaCha20 + Poly1305, GSO segmentation, `skb_linearize`

# Probe option — detect TCPS support

TCP option kind=253 (experimental range RFC 4727):

| Field | Value | Description |
|------|----------|----------|
| Kind | 253 | Experimental (RFC 4727) |
| Length | 4 | Option length |
| Data | 0x5443 | Magic "TC" |

**Middlebox fallback:**
- SYN without TC → server doesn't create a record → plain TCP
- SYN-ACK without TC → client deletes the record → plain TCP

# Operation Scenarios

## Both sides have a module (PSK exchange)

```
Step | Node A (tcps.ko) | Node B (tcps.ko)
-----|-------------------------------------------|-------------------------------------------
1 | SYN + TC option ──────────────────────────► | Sees TC, creates a conn, trigger DISCOVER
2 | | SYN-ACK + TC option
3 | ◄─────────────────── ───────────────────── |
4 | KDF(PSK, client_ISN, server_ISN) → 4 keys| KDF(PSK, client_ISN, server_ISN) → 4 keys
5 | ◄══════════ ChaCha20 + Poly1305 ═══════► | Each direction: encryption + 16B MAC suffix
```

## Only one side has a modulus (auto-fallback)

```
Step | Client (tcps.ko) | Server (no modulus)
-----|-------------------------------------------|-------------------------------------------
1 | SYN + TC option ──────────────────────────► | Ignores unknown option 253
2 | | SYN-ACK (without TC option)
3 | ◄───────────────────────────────────────────── |
4 | No TC in SYN-ACK → remove conn |
5 | data (no modification) ─────────────────────► | Normal data
```

# Reloading the module (reload)

With `rmmod` + `insmod`:
1. Init_key **by default only in RAM** (no file on disk)
2. On boot - if `key_file` is not set → a new init_key is generated (forward secrecy with rmmod)
3. On boot - if `key_file=/etc/tcps/init_key` → loaded from file → **same pubkey** → TOFU/PSK are preserved
4. Key file - permissions 0600, root-only
5. The connection table is cleared during rmmod (existing TCP sessions are broken)

**Module parameters:**

| Parameter | Default | Description |
|----------|-------------|-----------|
| `skip_ports` | 22 | Ports to skip (already encrypted) |
| `strict_tofu` | 0 | 0=update key with warning, 1=block on change |
| `psk_require_verify` | 0 | 0=PSK immediately, 1=require verify before full PSK |
| `rotate_interval` | 3600 | Init-key rotation interval in seconds |
| `key_file` | (empty) | File to save the init-key (e.g., /etc/tcps/init_key) |

```bash
insmod tcps.ko skip_ports=22,443 strict_tofu=1 psk_require_verify=1 key_file=/etc/tcps/init_key
```

# Security Audit

## CRITICAL (5 fixes)

| # | Vulnerability | Fix |
|---|-----------|-------------|
| C-1 | Poly1305: broken carry + modulus `2^128-5` instead of `2^130-5` | Carry via `>> 26`, `2^130-5` reduction, sign-bit mask |
| C-2 | `memcmp` timing side-channel on MAC tag | `tcps_ct_memcmp()` — constant-time XOR accumulation |
| C-3 | MAC truncated to 4 bytes (32-bit security) | Full 16-byte Poly1305 tag as payload suffix |
| C-4 | `kfree` at `rcu_head` offset → frees invalid address | `tcps_peer_free_rcu()` with `container_of` + `memzero_explicit` |
| C-5 | Zero PSK on DH error → zero-key encryption | All-zero DH shared check; `tcps_derive_psk_fallback()` |

## HIGH (9 fixes)

| # | Vulnerability | Fix |
|---|-----------|------------|
|H-1 | PSK is read without locking (torn read during rotation) | `spin_lock(&tcps_peers_lock)` in `tcps_peer_get_psk()` |
| H-2 | No all-zero DH shared secret check | `tcps_dh_shared()` returns -EINVAL for all-zero |
| H-3 | GSO packets are encrypted without MAC | GSO is disabled + fallback segmentation + MAC per segment |
| H-4 | `spin_lock` instead of `spin_lock_bh` → deadlock | All locks in the hook → `spin_lock_bh` |
| H-5 | Duplicate connections during SYN retransmit | `tcps_conn_add_unique()` — lookup before add |
| H-6 | seq wrap on 4GB → keystream reuse | `enc_seq_hi`/`dec_seq_hi` track 32-bit wrap |
| H-7 | Decryption without MAC with `peer_has_mac` | NF_DROP when `peer_has_mac && no_tag` |
| H-8 | Module exit does not flush workqueue → use-after-free | `flush_scheduled_work()` in `tcps_exit()` |
| H-9 | UDP 54321 without rate-limit → CPU DoS | Per-IP (1/2 sec) + global (10/sec) rate limiting |

## MEDIUM (9 fixes)

| # | Vulnerability | Fix |
|---|-----------|------------|
| M-1 | ChaCha20 `blk[]` keystream remains on the stack | `memzero_explicit(blk)` after each block |
| M-2 | KDF label buffer overflow | `strlen` limited to 31 bytes |
| M-3 | KEYXCHG_AUTH without prev_psk → REJECT blocks | WARN + accept as plain KEYXCHG |
| M-4 | TCP option parser scans in payload | `tcps_opt_end()` limits scan to `th->doff*4` |
| M-5 | FIN sets DEAD too early | FIN sets `kill=1`, state remains KEYED |
| M-6 | `kernel_sendmsg` inside `rcu_read_lock` | Collect addresses under RCU, send outside RCU |
| M-7 | `tcps_recalc_csum` with negative tcplen | Check `tcplen < sizeof(tcphdr)` |
| M-8 | Unlimited peer table | `TCPS_MAX_PEERS=64` with atomic counter |
| M-9 | MAC and encryption at one keystream position | MAC at `pos+32` (offset by 1 ChaCha20 block) |

## LOW/INFO (retained)

| Vulnerability | Cause |
|-----------|---------|
| ACK-only packets without MAC | No payload → no tag |
| RST in cleartext | Partial protection: RST without MAC when peer_has_mac → DROP |
| First exchange vulnerable to MITM | Detectable via fingerprint verify |
| No version negotiation | The current version is the only one |

# Deployment

On the server and client (Linux, amd64, kernel 6.x):

```bash
cd v3/
apt install build-essential linux-headers-$(uname -r)
make
insmod tcps.ko psk_require_verify=1
```

PSK verification (on both machines):
```bash
cat /proc/tcps_peers
# Peer A: 192.168.1.42 ... psk=unverified fp=02f9b20aad44590b
# Peer B: 192.168.1.151 ... psk=unverified fp=02f9b20aad44590b

echo "verify 192.168.1.42" 02f9b20aad44590b" > /proc/tcps_peers
```

Dump:
```bash
rmmod tcps
```

# Check operation

## dmesg

```bash
dmesg | grep tcps
```

Loading:
```
tcps: X25519 init-key generated, pubkey=4ea7a766cdcfd414...
tcps: module loaded, X25519+ChaCha20-Poly1305+PSK+FS active (rotate=3600s)
```

PSK installed:
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

## /proc/tcps_peers

```bash
cat /proc/tcps_peers
# 192.168.1.42 pub=d2a7929b... psk=verified fp=02f9b20aad44590b

echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers
```

## tcpdump — visual encryption verification

```bash
tcpdump -i ens18 -A -s0 tcp
```

| Sign | Description |
|---------|----------|
| `unknown-253` in SYN | TC probe option (4 bytes, magic 0x5443) |
| Unreadable data | Payload encrypted with ChaCha20 |
| Readable data | Plain TCP - peer without module or skip_ports |
| Payload is 16B larger than expected | Poly1305 tag suffix |

# Performance

| Metric | With module | Without module (baseline) |
|---------|-----------|----------------------|
| iperf3 (10s) | 128 Mbps | 2.76 Gbps |
| curl (100MB) | 93 Mbps | ~1 Gbps |
| MAC failures | 0 | — |
| Retries | 14 (initial only) | 0 |

Overhead: per-packet ChaCha20 + Poly1305, GSO segmentation, `skb_linearize`.

# Security Properties

| Property | Mechanism |
|----------|----------|
| Encryption | ChaCha20 stream cipher (XOR on stream position) |
| Data Integrity | Poly1305 MAC (16B full tag) + constant-time verify + DROP without MAC |
| Key Exchange | X25519 ECDH (self-contained) + init-key exchange → PSK |
| Low-order point protection | All-zero DH shared verification → fallback |
| PSK derivation | KDF(DH_shared, "TCPS-PSK"\|\|init_key_A\|\|init_key_B) — domain-separated |
| Directed keys | Per-connection KDF(PSK, ISN) with c2s/s2c/cmac/smac labels |
| MAC/enc separation | MAC on pos+32, encryption on pos — different keystream blocks |
| Forward secrecy | Init-key rotation (3600 sec), KEYXCHG_AUTH |
| MITM protection (first exchange) | PSK fingerprint + out-of-band verify |
| MITM protection (repeat) | TOFU + strict_tofu |
| MITM protection (rotation) | KEYXCHG_AUTH — Poly1305 via prev_psk |
| DH consistency during rotation | DISCOVER + prev_init_key retry + curve25519 verify |
| Discovery DoS protection | Rate-limit: per-IP (1/2 sec) + global (10/sec) |
| RST injection protection | RST without MAC in KEYED → DROP |
| Bit-flipping protection | Data without MAC when peer_has_mac → DROP |
| Timing attack protection | `tcps_ct_memcmp` for MAC and KEYXCHG_AUTH |
| Downgrade protection | Probe option — none → fallback to plain TCP |
| Socket accounting | `skb->truesize` + `sk_rmem_alloc` adjustments |
| Peer limit | Max 64 peers (TCPS_MAX_PEERS) |
| RCU/lifecycle | Correct RCU callbacks, flush_scheduled_work() on unload |

# Known limitations

| Limitation | Description |
|-------------|----------|
| IPv4 only | IPv6 not yet supported |
| First-use MITM | The first exchange is vulnerable to MITM (detected via fingerprint) |
| PSK verify manually | The operator must compare fingerprints on both machines |
| Keypair persistence | Optional: `key_file=` → file 0600; without - RAM only |
| Reload breaks connections | Existing TCP sessions are broken by rmmod/insmod |
| ACK-only without MAC | Packets without payload are not signed |
| RST in cleartext | Partial protection: RST without MAC when peer_has_mac → DROP |
| No version negotiation | Protocol changes are incompatible |
| Throughput overhead | ~5% of baseline due to per-packet crypto + GSO segmentation |