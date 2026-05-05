### TCP/S — Transparent TCP Encryption at Layer 4

# Architecture
```
tcps/
├── kernel/ # Linux kernel module (LKM)
│ ├── tcps.h # Header: states, AEAD constants, TOFU, embedded TI, probe, epoch
│ ├── tcps_main.c # Netfilter hooks, options, MAC, TOFU + forward secrecy + epoch rotation + auto-discovery + in-band probe
│ ├── tcps_crypto.c # X25519 + ChaCha20 + Poly1305 + mac_prefix for the kernel
│ ├── Makefile # Build: make → tcps.ko
│ └── INSTRUCTION.md # Installation and Testing Instructions
```

# How it works

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — adds TCP option TC (kind=253, 40 bytes) to SYN, with **ephemeral** X25519 pubkey + **epoch** (4 bytes)
2. Netfilter hook PRE_ROUTING — detects TC option in SYN, stores peer ephemeral pubkey + peer epoch
3. SYN-ACK also carries TC option with the server's ephemeral pubkey and epoch — both hosts receive the other host's pubkey and epoch
4. After handshake — ECDH (X25519) shared secret → HKDF-Expand (ChaCha20 PRF) → 4 keys
5. All TCP data is encrypted with ChaCha20 (stream cipher, size unchanged).
6. Each data or FIN packet contains a Poly1305 MAC (16 bytes) in TCP option TM (kind=253, 20 bytes).
7. The Poly1305 key is unique for each packet (derived from position). The AAD includes TCP flags.
8. Packets without a MAC or with an invalid MAC are discarded (NF_DROP). FIN without MAC is also a drop
9. **TI delivery** — only **embedded TI** (49 bytes in the payload of the first data packet)
- TI option (52 bytes) does not fit in the TCP options (maximum 40 bytes) — path removed
10. Embedded TI is verified via TOFU + auth_tag → TCPS_AUTHENTICATED state
11. Embedded TI is sent in the ENCRYPTED **or** AUTHENTICATED state (if `ti_sent == 0`)
- This is necessary for request-response protocols (HTTP, SQL, Redis), where the server receives the client's TI before sending the data itself
12. Works for all TCP sockets on the system; applications are unaware of this.

# TCPS Peer Autodiscovery

The TOFU cache doubles as an **automatic TCPS peer list** — no manual configuration required.

**How ​​it works:**
- The module always adds the TC option to the outgoing SYN (try TCPS)
- If SYN+ACK arrived with the TC option → the peer has the module → TCPS session → the IP is added to TOFU
- If SYN+ACK arrived without the TC option → we check TOFU:
- Peer is in TOFU → downgrade attack! → NF_DROP
- Peer is not in TOFU → plain TCP (the peer doesn't have the module)

**Result:** `apt-get update`, DNS, HTTP to external servers – everything works.
As soon as both sides have the module and have connected at least once, downgrade is automatically blocked.

| Scenario | Peer in TOFU? | Result |
|----------|------------|------------|
| SYN without TC (server) | Yes | NF_DROP — downgrade |
| SYN without TC (server) | No + enforce=0 | NF_ACCEPT — plain TCP |
| SYN without TC (server) | No + enforce=1 | NF_DROP — strict mode |
| SYN+ACK without TC (client) | Yes | NF_DROP — downgrade |
| SYN+ACK without TC (client) | No | PLAIN_PROBE → plain TCP |

If `enforce=1` on the server, even unknown clients must have the module.
If `enforce=0` (default), unknown clients can connect via plain TCP.

# In-band probe — downgrade detection (server side)

Problem: When first connecting to a new peer, a MITM attack can strip the TC option from SYN+ACK.
The client thinks the module isn't present and falls back to plain TCP. This is a classic SSH first-use vector.

**Solution:** The server side in-band probe is retained for compatibility with clients
using an older version of the module (which sends a probe in the payload). The server accepts the probe request, sends a probe response → the client detects a downgrade.

**The current version** doesn't insert a probe into the client's payload (this broke HTTP and other protocols —
36 extra bytes + TCP sequence number desynchronization). Instead:

- If SYN+ACK without TC from an unknown peer → plain TCP (data is not modified)
- If the server receives data without MAC in ENCRYPTED → NF_DROP (MITM is blocked)

**Probe protocol (for compatibility with older clients):**

```
Probe request (client → server):
[0x02]['T']['P']['R'][static_pub(32)] = 36 bytes at the beginning of the first data packet

Probe response (server → client):
[0x03]['T']['P']['S'][static_pub(32)] = 36 bytes at the beginning of the first response
```

**Stream with MITM (strip TC option) — old client + current server:**

1. SYN+ACK without TC → conn enters state `TCPS_PLAIN_PROBE`
2. Old client: first data packet → prepend probe request → `probe_sent=1`
3. Server: sees marker `0x02+'TPR'` in payload → strip probe → creates conn (PLAIN_PROBE) →
adds client to TOFU → logs warning
4. Server: first data response → prepend probe response → `probe_sent=1`
5. Client: sees marker `0x03+'TPS'` → **DOWNGRADE DETECTED** → `kill=1` → NF_DROP all packets →
adds server to TOFU

**Stream during MITM (strip TC option) — current client + current server:**

1. SYN+ACK without TC → `TCPS_PLAIN_PROBE`
2. Client: sends data as plain TCP (probe is not inserted)
3. Server (in ENCRYPTED): receives data without MAC → NF_DROP
4. Connection fails — MITM blocked
5. Server logs: "data without MAC while ENCRYPTED — possible MITM"

**Flow when no module is present on peer:**

1. SYN+ACK without TC → `TCPS_PLAIN_PROBE`
2. Client: sends data as plain TCP
3. Server (without module): receives normal data
4. 30 sec timeout → GC deletes conn → connection continues as plain TCP

**After downgrade detection (old client):**
- Connection is killed (kill=1 → NF_DROP)
- Peer is added to TOFU → next SYN+ACK without TC → NF_DROP (downgrade by TOFU cache)
- MITM cannot be bypassed: even If it stops stripping, TOFU already protects.

# Cryptography (without OpenSSL)

- X25519 ECDH — 32-byte keys, via kernel crypto API (libcurve25519)
- ChaCha20 — stream cipher, XOR on stream position, without changing packet size
- Poly1305 — AEAD MAC, custom implementation on 26-bit limbs
- **Per-packet Poly1305 key** — unique key for each packet (ChaCha20(mac_key, pos + seq))
- **MAC AAD covers TCP flags** — prevents undetected FIN/flags substitution
- KDF — HKDF-Expand pattern: each key is output separately with a unique label
- `TCPS enc_c2s` (position 0x8000000000000000)
- `TCPS enc_s2c` (position 0x80000000000000040)
- `TCPS mac_c2s` (position 0x8000000000000080)
- `TCPS mac_s2c` (position 0x800000000000000C0)
- Timing attack protection — MAC comparison via crypto_memneq (constant-time)
- **Forward secrecy** — ephemeral DH keys (dh_priv) are destroyed (memzero_explicit) after derivation.
Ephemeral pubkeys (dh_pub, dh_peer_pub) are preserved for auth_tag transcript binding.

# MITM protection (TOFU + auth_tag + epoch)

The static X25519 identity key is generated when the module is loaded. The private key is stored
only in kernel RAM; it is never transmitted over the network or written to disk.

**Two-phase protocol:**

Phase 1 — SYN/SYN-ACK: ephemeral DH keys + epoch → encryption (forward secrecy)
Phase 2 — first data packet after encryption: embedded TI with a static key → authentication

**Embedded TI (49 bytes, payload):** marker(1) + static_pubkey(32) + auth_tag(16)
- auth_tag = Poly1305(DH(my_static_priv, peer_static_pub), client_dh || server_dh || ISN_client || ISN_server || is_client)
- auth_tag is bound to ISN + ephemeral DH keys — MITM cannot relay between sessions
- auth_tag = 0 (zero) on the first connection (the sender does not know the key) peer)

**TI option (52 bytes):** kind(1) + len(1) + 'T'(1) + 'I'(1) + static_pub(32) + auth_tag(16)
- **Not used for sending** — 52 bytes exceed the TCP options limit (40 bytes)
- The reception code is preserved for compatibility with future protocol versions.

**TOFU (Trust On First Use):**
- First connection: the peer's static pubkey + epoch are stored in the TOFU cache (IP → pubkey + epoch)
- auth_tag = 0: registration without verification (TOFU trust, like SSH)
- auth_tag ≠ 0: verification via DH(static_priv, peer_pub) — the sender knows our key
- Subsequent connections: the pubkey is checked against the cache, the auth_tag is verified (zero auth_tag for (known peer = downgrade)
- Mismatch of pubkey or auth_tag → MITM detected → NF_DROP
- If TOFU fails: `kill=1` + `TCPS_DEAD` — all subsequent packets are dropped, encrypted data is not leaked to the application
- The TOFU cache is automatically used for downgrade protection (see Autodiscovery + Probe)

**Epoch — Reboot/Key Rotation Detection:**

A random 32-bit `epoch` is generated each time the module is loaded. It is passed in the TC option
and stored in the TOFU cache next to the pubkey. If the pubkey mismatches:

| Condition | auth_tag | Response |
|---------|----------|---------|
| pubkey matches | ≠ 0 | Auth_tag verification |
| pubkey matches | = 0 | **Downgrade** — drop (sender doesn't know our key) |
| pubkey ≠, epoch ≠ | any | **Key rotation** — accept with warning (encrypted channel protects TI) |
| pubkey ≠, epoch same | — | **MITM** — drop connection |

Key rotation (new epoch + new pubkey) is automatically accepted when `auto_rotate=1` (default).
When `auto_rotate=0` — any key change = MITM, requiring a manual restart of the module on both sides.

During rotation, the auth_tag may not match (the sender calculated it using our old key).
This is acceptable: the TI is transmitted within an encrypted channel, and MITM cannot replace it.

**auth_tag prevents forwarding someone else's pubkey:**
MITM attacks can't forge an auth_tag—this requires a static private key,
which only the legitimate peer has. ISN+DH binding prevents relay attacks
(an attempt to forward someone else's auth_tag between two different sessions).

**Limitation:** the first connection is trusted without verification (like SSH);
the server-side in-band probe closes this window for clients running an older version of the module.

**Module Parameters:**

| Parameter | Default | Description |
|----------|------------|-----------|
| `tofu_enforce` | 1 | 0=log only, 1=drop if TOFU doesn't match |
| `enforce` | 0 | 0=allow plain TCP
For unknown peers, 1=drop all non-TCPS |
| `auto_rotate` | 1 | 0=reject key rotation, 1=auto-accept on epoch change |

```bash
insmod tcps.ko tofu_enforce=0 enforce=1 auto_rotate=0
cat /sys/module/tcps/parameters/tofu_enforce
cat /sys/module/tcps/parameters/enforce
cat /sys/module/tcps/parameters/auto_rotate

# Runtime switching
echo 0 > /sys/module/tcps/parameters/tofu_enforce
echo 1 > /sys/module/tcps/parameters/enforce
echo 0 > /sys/module/tcps/parameters/auto_rotate
```

# Downgrade and RST injection protection

**Downgrade attack** (strip TCPS options):
- SYN+ACK without TCPS option from a peer that is **already in TOFU** → NF_DROP (downgrade!)
- SYN+ACK without TCPS option from a **new** peer → plain TCP (peer has no module)
- SYN without TCPS option from a client that is **already in TOFU** → NF_DROP (downgrade!)
- TM option not added → NF_DROP
- `enforce=1` additionally drops SYN from any clients without a TCPS option on the server

**MITM strips SYN+ACK (server in ENCRYPTED, client in PLAIN_PROBE):**
- Client sends data without MAC (PLAIN_PROBE)
- Server receives data without MAC → NF_DROP
- Connection fails — MITM blocked
- Server logs: "data without MAC while ENCRYPTED — possible MITM"

**In-band probe (server part)** — for compatibility with older clients:
- Old client sends probe request in payload → The server detects a token
- The server strips the probe, deactivates the conn in PLAIN_PROBE, and sends a probe response
- The client detects DOWNGRADE DETECTED → kill the connection

**RST injection**: Inbound RST packets in the encrypted state (ENCRYPTED/AUTHENTICATED)
are dropped without changing state. A spoofed RST cannot terminate an encrypted session.
Outbound RST (the application closes the connection) is allowed by setting `kill=1` + `TCPS_DEAD`.
The connection is closed only via FIN or GC timeout.

**TI timeout**: If a TI is not received within 30 seconds (TCPS_TI_TIMEOUT), the GC kills the connection.
Prevents an eternal hang in ENCRYPTED without authentication. If both sides send only a pure ACK (no data), the TI cannot be sent,
the connection will remain in ENCRYPTED mode until the timeout.

**Probe timeout**: If a probe response is not received within 30 seconds (TCPS_PROBE_TIMEOUT),
the GC deletes the connection—the peer truly has no module, and plain TCP continues.

# Embedded TI—sending identity in the payload

TI (Trust Identity) is embedded at the beginning of the payload of the first data packet. A pure ACK without data
cannot carry a TI (TI option 52 bytes exceeds the TCP options limit of 40 bytes).

**Embedding condition:** `!ti_sent && payload_len > 0 && (state == ENCRYPTED || state == AUTHENTICATED)`

This is critical for request-response protocols (HTTP, SQL, Redis, Kafka):
the server receives the client's TI first → switches to AUTHENTICATED → sends a response.
Without the AUTHENTICATED condition, the server would never send its TI, and the client would not know
the server's static pubkey → repeated connections would fail with "zero auth_tag for known peer".

**Encrypt-then-MAC Protocol:**

```
Sender:
1. Generates a TI prefix: [0x01][static_pub(32)][auth_tag(16)] = 49 bytes
2. Prepends the TI prefix to the payload: [TI prefix][app_data]
3. Encrypts the ENTIRE payload including the TI prefix: ChaCha20(key, pos, data)
4. Calculates the MAC: Poly1305(mac_key, pos, flags, encrypted_payload)
5. Adds the TM option (20 bytes)

Packet: [TCP hdr+opts][encrypted TI prefix(49)][encrypted app_data][TM option(20)]
```

```
Receiver:
1. Checks the MAC (TM option) → if not matched, Drop
2. Decrypts payload: ChaCha20(key, pos, data)
3. Verifies first byte == 0x01 → embedded TI
4. Extracts static_pub + auth_tag from the decrypted payload
5. TOFU + auth_tag verification
6. Strip 49 bytes of TI prefix, adjust IP length + TCP checksum
```

Embedded TI detection: first byte of decrypted payload == 0x01. Receiver subtracts 49 bytes,
adjusts IP length and TCP checksum. TCP stack sees only application data.

**Limitation:** If both sides exchange only pure ACKs (no data in either direction),
TI cannot be sent. The connection will remain ENCRYPTED until TCPS_TI_TIMEOUT (30 seconds).

# Operation Scenarios

## Both sides have a module (autodiscovery)

```
Step | Client (tcps.ko) | Server (tcps.ko)
----|------------------------------------------------|--------------------------------------------
1 | SYN + TC option (ephemeral pubkey + epoch) ──► | Sees TC, stores ephemeral pubkey + epoch
2 | | SYN-ACK + TC option (ephemeral pubkey + epoch)
3 | ◄──────────────────────────────────────────────────── | Both hosts know the other's ephemeral pubkey + epoch
4 | X25519(eph_priv, peer_eph_pub) → shared | X25519(eph_priv, peer_eph_pub) → shared
5 | HKDF-Expand(shared, label, ISN) → 4 keys | HKDF-Expand(shared, label, ISN) → 4 keys
6 | ◄══════ ChaCha20 + Poly1305 (forward secret) ═► | Encrypted + integrity (MAC 16B)
7 | data: embedded TI (static pub + auth_tag) ───► | TOFU + auth_tag verification, strip 49B
8 | | TCPS_AUTHENTICATED
9 | ◄ embedded TI (static pub + auth_tag) | Server sends TI in AUTHENTICATED (ti_sent=0)
10 | TOFU + auth_tag verification, strip 49B |
11 | TCPS_AUTHENTICATED on both sides |
| Applications (nginx/postgres/ssh) are unaware
```

## Only one side has a module (auto-fallback)

```
Step | Client (tcps.ko) | Server (no module)
-----|------------------------------------------------|--------------------------------------------
1 | SYN + TC option (ephemeral pubkey + epoch) ──► | Ignores unknown option 253
2 | | SYN-ACK (without TC option)
3 | ◄─ ... data (unmodified) ────────────────────────► | Normal data, HTTP request intact
6 | Probe timeout 30 sec → GC cleaning conn | Normal TCP connection
| apt-get update, DNS, HTTP — everything works!
```

Reconnecting to the same server — PLAIN_PROBE again (peer not in TOFU, no module).
If the server later installs the module, the next connection will automatically become TCPS.

## Downgrade attack blocked (peer already in TOFU)

```
Step | Client (tcps.ko) | MITM → Server (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1 | SYN + TC option ──► | MITM strips TC option
2 | | SYN (no TC) ──► Server: client in TOFU → NF_DROP!
| Or:
1 | SYN + TC option ──► Server (tcps.ko) | SYN-ACK + TC option
2 | ◄── MITM strips TC from SYN-ACK | SYN-ACK (no TC)
3 | Peer in TOFU → NF_DROP! (downgrade detected) |
```

## MITM strips SYN+ACK on first connection

**Server in ENCRYPTED, client in PLAIN_PROBE:**

```
Step | Client (tcps.ko) | MITM → Server (tcps.ko)
----|------------------------------------------------|--------------------------------------------
1 | SYN + TC option ──► MITM passes SYN ──────► | Server: sees TC → ENCRYPTED
2 | | SYN+ACK + TC option ──►
3 | ◄── MITM strips TC from SYN+ACK |
4 | No peer in TOFU → PLAIN_PROBE → plain TCP | Server: ENCRYPTED, expecting MAC
5 | data (no MAC) ──► | Server: no MAC → NF_DROP
6 | | Connection fails — MITM blocked
```

**Old client sends probe (backward compatibility):**

```
Step | Client (old tcps.ko) | MITM → Server (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1-3 | (same sequence) |
4 | No peer in TOFU → PLAIN_PROBE |
5 | [probe request + data] ──► (no MAC) |
6 | | Server: no MAC → probe marker found
7 | | → Deactivates in PLAIN_PROBE, strip probe
8 | | Server: [probe response + data] ──►
9 | ◄── probe response received |
10 | DOWNGRADE DETECTED! → kill=1 → NF_DROP |
| Peer added to TOFU → next attempts → NF_DROP
```

## Restarting module (key rotation)

```
Step | Client (tcps.ko) | Server (tcps.ko — restarted)
-----|------------------------------------------------|--------------------------------------------
1 | SYN + TC option (epoch_A) ────────────────────► | Sees TC, SYN_RECV
2 | | SYN-ACK + TC option (epoch_B — new!)
3 | ◄────────────────────────────────────────────────────────────────────────────────── |
4 | Sees new epoch → TCPS_ENCRYPTED | TCPS_ENCRYPTED
5 | data: embedded TI (auth_tag with OLD server key) ► | tcps_tofu_verify: epoch differs
6 | | → key rotation: auth_tag may not match
7 | | → accept (encrypted channel protects TI)
8 | | → TCPS_AUTHENTICATED
9 | ◄ embedded TI (auth_tag = 0, no client key) | Server has no client in TOFU (cache cleared)
10 | tcps_tofu_verify: new peer, auth_tag=0 |
| → TOFU trust, registration | → TCPS_AUTHENTICATED on both sides
```

# Deployment

On the server and client (Linux, arm64/amd64):

```bash
cd kernel/
apt install build-essential linux-headers-$(uname -r)
modprobe libcurve25519
make
insmod tcps.ko
```

Any TCP connection between these machines is automatically encrypted.
PoStgreSQL, HTTP, SSH—whatever you like. Connections to machines without a module are plain TCP (apt-get works).

Unloading the module:
```bash
rmmod tcps
```

When the module is reloaded, a new static identity key and a new epoch are generated.
The TOFU cache is cleared. If `auto_rotate=1` on the other side, rotation is accepted automatically (the auth_tag may not match, but the encrypted channel is protected by TI).
If `auto_rotate=0`, both sides need to reload the module.

# Verifying operation

## dmesg — sessions and errors

```bash
dmesg | grep tcps
```

Loading module:
```
tcps: module loaded, ECDH (X25519) + ChaCha20-Poly1305 + TOFU active
tcps: identity fingerprint: a1b2c3d4e5f6a7b8 epoch: 1234567890
```

Successful connection (first - TOFU remembers):
```
tcps: encrypted session 192.168.1.69:41548 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: TI embedded in data 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: TOFU: new peer 192.168.1.127 fingerprint 9a8b7c6d5e4f3a2b epoch: 1234567890 (auth_tag present — see above for verification result)
tcps: session authenticated (embedded TI) 192.168.1.69:41548 <-> 192.168.1.127:80
```

Successful connection (repeated - TOFU + auth_tag verification):
```
tcps: encrypted session 192.168.1.69:41550 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: session authenticated (embedded TI) 192.168.1.69:41550 <-> 192.168.1.127:80
```

Plain TCP (peer without module):
```
tcps: peer 93.184.216.34 has no TCPS module, plain TCP
tcps: probe timeout for 192.168.1.69:41548 <-> 93.184.216.34:80, peer has no module
```

In-band probe — MITM detected (old client):
```
tcps: peer 192.168.1.127 has no TCPS module, probing
tcps: probe sent 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: DOWNGRADE DETECTED! Peer 192.168.1.127 has TCPS module but option was stripped
```

Probe from ENCRYPTED (MITM strips only SYN+ACK):
```
tcps: probe from 192.168.1.69 while ENCRYPTED — SYN+ACK was stripped, demoting to PLAIN_PROBE
tcps: probe response sent 192.168.1.127:80 <-> 192.168.1.69:41548
tcps: DOWNGRADE DETECTED! Peer 192.168.1.127 has a TCPS module, but the option was stripped.
```

MITM — data without MAC to the ENCRYPTED server:
```
tcps: data without MAC from 192.168.1.69 while ENCRYPTED — possible MITM
```

Key rotation (module restart on one side, auto_rotate=1):
```
tcps: key rotation detected for peer 192.168.1.127 (epoch 1234567890 -> 987654321)
tcps: old fingerprint 9a8b7c6d5e4f3a2b, new fingerprint deadbeef12345678
tcps: rotation auth_tag mismatch for 192.168.1.127 — sender has old key, accepting (encrypted channel) protects TI)
tcps: session authenticated 192.168.1.69:41552 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

Rotation without auth_tag (peer rebooted, lost TOFU):
```
tcps: key rotation detected for peer 192.168.1.127 (epoch 1234567890 -> 987654321)
tcps: rotation without auth_tag for 192.168.1.127 — sender has no key for us, accepting (encrypted channel protects TI)
```

New peer with auth_tag mismatch (reboot on our side, peer has our old key):
```
tcps: TOFU: new peer 192.168.1.127 auth_tag mismatch — sender has our old key or different key, accepting (encrypted channel protects TI)
tcps: TOFU: new peer 192.168.1.127 fingerprint deadbeef12345678 epoch: 987654321 (auth_tag present — see above for verification result)
```

Downgrade detected (MITM strips TCPS option from known peer):
```
tcps: downgrade detected! SYN+ACK without TCPS from known peers 192.168.1.127
tcps: downgrade detected! SYN without TCPS from known peer 192.168.1.127
```

Zero auth_tag for known peer (downgrade):
```
tcps: zero auth_tag for known peer 192.168.1.127 — possible downgrade
```

MITM attack (key mismatch, same epoch):
```
tcps: MITM detected! Static key mismatch for peer 192.168.1.127 (same epoch 1234567890)
tcps: expected 9a8b7c6d5e4f3a2b, got deadbeef12345678
```

MITM attack (auth_tag mismatch — forwarding someone else's key):
```
tcps: MITM detected! auth_tag mismatch for peer 192.168.1.127
```

MAC error (packet forged or corrupted):
```
tcps: MAC verification failed, dropping
```

Rotation rejected (auto_rotate=0):
```
tcps: key rotation rejected for peer 192.168.1.127 (auto_rotate=0, epoch 1234567890 -> 987654321)
```

## tcpdump — visual encryption verification

```bash
tcpdump -i ens18 -A -s0 tcp
```

Module activity indicators:

| Indicator | Description |
|---------|---------|
| `unknown-253` in SYN | TC option with ephemeral X25519 pubkey + epoch (40 bytes, magic 'T','C') |
| `unknown-253` in data | TM option with Poly1305 tag (20 bytes, magic 'T','M') |
| Unreadable data | Payload encrypted with ChaCha20 |
| Readable data | Plain TCP - peer without modulus (not in TOFU) |

Note: MSS is not included in SYN (TC option occupies all 40 option bytes).
TCP uses the default MSS (536) before Path MTU Discovery.

```

# Security Properties

| Property | Mechanism |
|----------|----------|
| Encryption | ChaCha20 stream cipher |
| Integrity | Poly1305 MAC (16 bytes, per-packet key, AAD covers TCP flags) |
| FIN injection | FIN packets require MAC, spoofed FIN is discarded |
| Forward secrecy | Ephemeral X25519 DH keys (dh_priv is destroyed after derivation) |
| MITM protection | TOFU + auth_tag (Poly1305 MAC 16B, DH pubkeys + ISN in transcript) |
| MITM relay | auth_tag is bound to ISN + ephemeral DH keys - forwarding is impossible |
| Key rotation | Epoch - reboot detection, auto-rotate when epoch changes, encrypted channel protects TI |
| Downgrade protection | TOFU as a peer list + NF_DROP when stripping from known peers |
| Downgrade SYN+ACK strip | Server drops data without MAC → connection not established → MITM blocked |
| Downgrade first-use (old client) | In-band probe via payload — auto-detect MITM on first connection |
| Auto-discovery | TOFU cache automatically detects TCPS/Plain for each IP |
| RST injection | Inbound RST is dropped without changing state; outbound RST sets kill=1 |
| Timing attacks | crypto_memneq for MAC and auth_tag |
| Key separation | HKDF-Expand with unique labels for each key |
| Key privacy | memzero_explicit, RAM only, not written to disk |
| TI delivery | Embedded TI in payload (Encrypt-then-MAC) — authentication with the first data packet |
| TOFU failure | kill=1 on TOFU failure — encrypted data is not leaked to the application |

# Known limitations

| Limitation | Description |
|-------------|----------|
| IPv4 only | IPv6 not yet supported |
| No connection limit | Limit is 4096 (tcps_conn_count). If exceeded, SYN is dropped |
| TOFU kzalloc fail | Connection is rejected instead of trusted (return -1) |
| RST delay | Legitimate RST from peer is dropped, closing via FIN/timeout |
| Pure ACK is not authenticated | ACKs without FIN and without payload do not contain a MAC (overhead). FIN is protected |
| Pure ACK without TI | If both sides send only ACKs without data, TI is not sent → TCPS_TI_TIMEOUT (30 sec) |
| TOFU cache in-memory | Lost during rmmod, keys are not saved to disk |
| Epoch — heuristic | Not a cryptographic proof: an active MITM can replace epoch+key with auto_rotate=1 |
| MSS in SYN | TC option (40B) takes up the entire option space — MSS is not enabled. Default 536, PMTU Discovery compensates |
| Embedded TI marker | Byte 0x01 at the beginning of the payload — a collision with app data can cause a DoS (packet drop) |
| Probe payload-mod MITM | MITM with payload modification capability can strip the probe (much more complex than strip options) |
| First-use trust | The first connection to a new peer without MITM detection is trusted (like SSH). MITM detection only occurs when receiving data without a MAC address to an ENCRYPTED server |
| Key rotation auth_tag | During rotation, the auth_tag may not match (the sender calculated it with our old key). Protection: encrypted channel |
| New peer auth_tag | For new peers, auth_tag does not block registration (the encrypted channel protects TI) |