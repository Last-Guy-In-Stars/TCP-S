### TCP/S — Transparent TCP Encryption at Layer 4

# Architecture
```
tcps/
├── kernel/ # Linux kernel module (LKM)
│ ├── tcps.h # Header: states, constants AEAD, TOFU, TI option, epoch, embedded TI, probe
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
8. Packets without a MAC or with an invalid MAC are discarded (NF_DROP). FIN without MAC is also a drop.
9. **TI delivery** — two mechanisms:
- **TI option** (kind=253, 40 bytes) — on pure ACK (no payload, no FIN)
- **Embedded TI** (37 bytes in payload) — on the first data packet, if a pure ACK has not yet been sent.
10. TI option/embedded TI is verified via TOFU + auth_tag → TCPS_AUTHENTICATED state.
11. Works for all TCP sockets on the system; applications are unaware of this.

# TCPS Peer Autodiscovery

The TOFU cache doubles as an automatic TCPS peer list — no manual configuration required.

**How ​​it works:**
- The module always adds the TC option to the outgoing SYN (try TCPS)
- If SYN+ACK arrived with the TC option → the peer has the module → TCPS session → the IP is added to TOFU
- If SYN+ACK arrived without the TC option → we check TOFU:
- Peer is in TOFU → downgrade attack! → NF_DROP
- Peer is not in TOFU → enable in-band probe (see below)

**Result:** `apt-get update`, DNS, HTTP to external servers – everything works.
As soon as both sides have the module and have connected at least once, downgrade is automatically blocked.

| Scenario | Peer in TOFU? | Result |
|----------|------------|------------|
| SYN without TC (server) | Yes | NF_DROP — downgrade |
| SYN without TC (server) | No + enforce=0 | NF_ACCEPT — plain TCP |
| SYN without TC (server) | No + enforce=1 | NF_DROP — strict mode |
| SYN+ACK without TC (client) | Yes | NF_DROP — downgrade |
| SYN+ACK without TC (client) | No | PLAIN_PROBE → in-band probe |

If `enforce=1` on the server, even unknown clients must have the module.
If `enforce=0` (default), unknown clients can connect via plain TCP.

# In-band probe — automatic downgrade detection on first connection

Problem: When connecting to a new peer for the first time, a MITM can strip the TCP option from SYN+ACK.
The client thinks the module isn't present and falls back to plain TCP. This is a classic SSH first-use vector.

**Solution: in-band probe via payload.** A MITM can easily strip TCP options (header),
but modifying the payload is much more difficult—you need to monitor the TCP stream and adjust the seq/length/checksum.
Most MITM tools (arpspoof, ettercap) don't modify the payload.

**Protocol:**

```
Probe request (client → server):
[0x02]['T']['P']['R'][static_pub(32)] = 36 bytes at the beginning of the first data packet

Probe response (server → client):
[0x03]['T']['P']['S'][static_pub(32)] = 36 bytes at the beginning of the first response
```

**Flow during MITM (strip TC option):**

1. SYN+ACK without TC → conn enters `TCPS_PLAIN_PROBE` state (instead of DEAD)
2. Client: first data packet → prepend probe request → `probe_sent=1`
3. Server: sees `0x02+'TPR'` marker in the payload → strip probe → creates conn (PLAIN_PROBE) →
adds client to TOFU → logs warning
4. Server: first data response → prepend probe response → `probe_sent=1`
5. Client: sees marker `0x03+'TPS'` → **DOWNGRADE DETECTED** → `kill=1` → NF_DROP all packets →
adds server to TOFU

**Flow when no module is present on peer:**

1. SYN+ACK without TC → `TCPS_PLAIN_PROBE`
2. Client: sends probe request in data
3. Server (without module): probe is regular bytes in the payload, the kernel passes it to the application as is
4. The application can ignore it or return an error (36 extra bytes)
5. 30 sec timeout → GC removes conn → the connection continues as plain TCP

**After downgrade detection:**
- The connection is killed (kill=1 → NF_DROP)
- The peer is added to TOFU → next SYN+ACK without TC → NF_DROP (downgrade via TOFU cache)
- MITM cannot be bypassed: even if it stops stripping, TOFU already protects

**Probe limitations:**
- Probe is sent only in the first data packet (if the client does not send data)
(The probe won't escape.)
- Probe response is sent only in the server's first data response.
- 30-second timeout: if there is no response within this time, the probe is canceled.
- The application sees 36 extra bytes if the server doesn't have the module (can be tolerated).
- MITM with payload-modification capability can strip the probe (but this is significantly more difficult than stripping TCP options).

# Cryptography (without OpenSSL)

- X25519 ECDH — 32-byte keys, via kernel crypto API (libcurve25519).
- ChaCha20 — stream cipher, XOR on the stream position, without changing the packet size.
- Poly1305 — AEAD MAC, proprietary implementation on 26-bit limbs.
- **Per-packet Poly1305 key** — a unique key for each packet (ChaCha20(mac_key, pos + seq))
- **MAC AAD covers TCP flags** — prevents FIN/flags substitution without detection
- KDF — HKDF-Expand pattern: each key is output separately with a unique label
- `TCPS enc_c2s` (position 0x8000000000000000)
- `TCPS enc_s2c` (position 0x8000000000000040)
- `TCPS mac_c2s` (position 0x8000000000000080)
- `TCPS mac_s2c` (position 0x800000000000000C0)
- Timing attack protection — MAC comparison via crypto_memneq (constant-time)
- **Forward secrecy** — ephemeral DH keys are destroyed (memzero_explicit) after derivation

# MITM protection (TOFU + auth_tag + epoch)

The static X25519 identity key is generated when the module loads. The private key is stored
only in kernel RAM; it is never transmitted over the network or written to disk.

**Two-phase protocol:**

Phase 1 — SYN/SYN-ACK: ephemeral DH keys + epoch → encryption (forward secrecy)
Phase 2 — ACK/data after encryption: TI (optional or embedded) with a static key → authentication

**TI option (40 bytes, pure ACK):** static_pubkey(32) + auth_tag(4)
**Embedded TI (37 bytes, payload):** marker(1) + static_pubkey(32) + auth_tag(4)
- auth_tag = ChaCha20-PRF(DH(my_static_priv, peer_static_pub), ISN_client || ISN_server || "TAUT")[:4]
- auth_tag = 0 on first connection (no peer key in TOFU cache)
- **auth_tag is linked to ISN** — MITM cannot relay someone else's TI between different sessions

**TOFU (Trust On First Use):**
- First connection: the peer's static pubkey + epoch are stored in the TOFU cache (IP → pubkey + epoch)
- Subsequent connections: the pubkey is checked against the cache, the auth_tag is verified **always** (including zero)
- Mismatch of pubkey or auth_tag → MITM detected → NF_DROP
- The TOFU cache is automatically used to protect against downgrades (see Autodiscovery + Probe)

**Epoch — Reboot/Key Rotation Detection:**

A random 32-bit epoch is generated each time the module is loaded. It is passed to the TC option
and stored in the TOFU cache next to the pubkey. If the pubkey does not match:

| Condition | Response |
|---------|--------|
| pubkey matches | Standard auth_tag verification |
| pubkey ≠, epoch ≠ | **Key rotation** (likely a reboot) — auto-accept + warning |
| pubkey ≠, same epoch | **MITM** — drop connection |

Key rotation (new epoch + new pubkey) is automatically accepted when `auto_rotate=1` (default).
When `auto_rotate=0` — any key change = MITM, requiring a manual module reboot on both sides.

**auth_tag prevents forwarding someone else's pubkey:**
MITM cannot forge the auth_tag—this requires a static private key,
which only the legitimate peer has. ISN binding prevents relay attacks
(an attempt to forward someone else's auth_tag between two different sessions).

**Limitation:** The first connection is trusted without verification (like SSH),
but an in-band probe closes this window for most MITM tools.

**Module Parameters:**

| Parameter | Default | Description |
|----------|------------|-----------|
| `tofu_enforce` | 1 | 0 = log only, 1 = drop if TOFU does not match |
| `enforce` | 0 | 0=allow plain TCP for unknown peers, 1=drop all non-TCPS |
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
- SYN+ACK without TCPS option from a **new** peer → in-band probe → MITM autodetect
- SYN without TCPS option from a client that is **already in TOFU** → NF_DROP (downgrade!)
- TI option not added → NF_DROP (the connection is blocked, not falling back to plaintext)
- TM option not added → NF_DROP
- `enforce=1` additionally drops SYN from any clients without a TCPS option on the server

**In-band probe** — closes the first-use window:
- If MITM strips the TC option on the first connection → probe detects that the module is present → DOWNGRADE DETECTED
- MITM can bypass probe only by modifying the TCP payload (much more complex than stripping)
p options)
- After detection: kill the connection + add to TOFU → all future connections are protected.

**RST injection**: Inbound RST packets in the encrypted state (ENCRYPTED/AUTHENTICATED)
are dropped. A spoofed RST cannot terminate an encrypted session. The connection is closed
only via FIN or GC timeout.

**TI timeout**: If a TI is not received within 30 seconds (TCPS_TI_TIMEOUT), the GC kills the connection.
Prevents an eternal hang in ENCRYPTED mode without authentication.

**Probe timeout**: If a probe response is not received within 30 seconds (TCPS_PROBE_TIMEOUT), the GC deletes the conn — the peer truly has no module, plain TCP continues.

# Embedded TI — sending identity in payload

Problem: The TI option (40 bytes) and TM option (20 bytes) don't fit together in the 60-byte TCP header. If the first packet after encryption contains data, the TI is deferred until pure ACK — the connection remains ENCRYPTED without authentication.

**Solution**: If ti_sent==0 and a payload is present, the TI is embedded at the beginning of the payload:

```
Sender:
[TCP hdr+opts][TI prefix(37, plaintext)][encrypted_app_data][TM option(20)]

TI prefix = [0x01][static_pub(32)][auth_tag(4)]
```

- TI prefix **is not encrypted** ChaCha20 — avoid position overlap
- MAC (Poly1305) covers **both parts**: prefix + encrypted_data
- Receiver: check MAC, decrypt, extract TI, TOFU-verify, strip 37 bytes

Detection of embedded TI: first byte of payload == 0x01. Receiver subtracts 37 bytes,
adjusts IP length and TCP checksum. The TCP stack only sees application data.

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
7a | pure ACK: TI option (static pub + auth_tag) ──► | TOFU + auth_tag verification
7b | data: embedded TI (static pub + auth_tag) ───► | TOFU + auth_tag verification, strip 37B
8 | ◄ TI option or embedded TI | TCPS_AUTHENTICATED on both sides
| Applications (nginx/postgres/ssh) don't know anything
```

## Only one side has the module (auto-fallback)

```
Step | Client (tcps.ko) | Server (no module)
-----|------------------------------------------------|--------------------------------------------
1 | SYN + TC option (ephemeral pubkey + epoch) ──► | Ignores unknown option 253
2 | | SYN-ACK (without TC option)
3 | ◄─────────────────────────────────────────────────── |
4 | Peer not in TOFU → PLAIN_PROBE → probe sent |
5 | [0x02][TPR][static_pub] + data ───────────────────► | Probe is just plain bytes, the kernel passes it to app.
6 | Probe timeout 30 seconds → GC cleans conn | Regular TCP connection
| apt-get update, DNS, HTTP — everything works!
```

Reconnecting to the same server — PLAIN_PROBE again (the peer is not in TOFU, there is no module).
If the server later installs the module, the next connection will automatically become TCPS.

## Downgrade attack blocked (the peer is already in TOFU)

```
Step | Client (tcps.ko) | MITM → Server (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1 | SYN + TC option ──► | MITM strips TC option
2 | | SYN (without TC) ──► Server: client in TOFU → NF_DROP!
| Or:
1 | SYN + TC option ──► Server (tcps.ko) | SYN-ACK + TC option
2 | ◄── MITM strips TC from SYN-ACK | SYN-ACK (without TC)
3 | Peer in TOFU → NF_DROP! (downgrade detected) |
```

## Downgrade on first connection - probe blocked

```
Step | Client (tcps.ko) | MITM → Server (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1 | SYN + TC option ──► | MITM strips TC option
2 | | SYN (no TC) ──► Server: client not in TOFU → plain
3 | | SYN-ACK (no TC) ◄── Server
4 | ◄── MITM passes SYN-ACK unchanged |
5 | Peer not in TOFU → PLAIN_PROBE |
6 | [probe request + data] ──► | MITM not modified
Payload is updated → probe arrives!
7 | | Server: sees probe marker → creates conn, strip probe
8 | | Server: [probe response + data] ──►
9 | ◄── MITM does not modify payload → probe response arrives!
10 | DOWNGRADE DETECTED! → kill=1 → NF_DROP |
| Peer added to TOFU → next attempts → NF_DROP
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
PostgreSQL, HTTP, SSH—anything. Connections to machines without a module are plain TCP (apt-get works).

Unloading the module:
```bash
rmmod tcps
```

When the module is reloaded, a new static identity key and a new epoch are generated.
The TOFU cache is cleared. If `auto_rotate=1` on the other side, rotation is accepted automatically. If `auto_rotate=0`, both sides need to restart the module.

# Checking operation

## dmesg — sessions and errors

```bash
dmesg | grep tcps
```

Loading module:
```
tcps: module loaded, ECDH + ChaCha20-Poly1305 + TOFU active
tcps: identity fingerprint: a1b2c3d4e5f6a7b8 epoch: 1234567890
```

Successful connection (first - TOFU remembers):
```
tcps: encrypted session 192.168.1.69:41548 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: TI option sent 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: TOFU: new peer 192.168.1.127 fingerprint 9a8b7c6d5e4f3a2b epoch: 1234567890
tcps: session authenticated 192.168.1.69:41548 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

Successful connection (retry - TOFU + auth_tag verification):
```
tcps: encrypted session 192.168.1.69:41550 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: session authenticated 192.168.1.69:41550 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

Embedded TI (first data packet) instead of pure ACK):
```
tcps: TI embedded in data 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: session authenticated (embedded TI) 192.168.1.69:41548 <-> 192.168.1.127:80
```

Plain TCP probe (peer without module):
```
tcps: peer 93.184.216.34 has no TCPS module, probing
tcps: probe sent 192.168.1.69:41548 <-> 93.184.216.34:80
tcps: probe timeout for 192.168.1.69:41548 <-> 93.184.216.34:80, peer has no module
```

In-band probe — MITM detected on first connection:
```
tcps: peer 192.168.1.127 has no TCPS module, probing
tcps: probe sent 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: DOWNGRADE DETECTED! Peer 192.168.1.127 has a TCPS module, but the option was stripped.
```

Server: probe received — MITM stripping options:
```
tcps: probe received from 192.168.1.69:41548 — TCPS option was stripped, possible MITM
tcps: probe response sent 192.168.1.127:80 <-> 192.168.1.69:41548
```

Key rotation (module reboot on one side, auto_rotate=1):
```
tcps: key rotation detected for peer 192.168.1.127 (epoch 1234567890 -> 987654321)
tcps: old fingerprint 9a8b7c6d5e4f3a2b, new fingerprint deadbeef12345678
tcps: session authenticated 192.168.1.69:41552 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

Downgrade detected (MITM stripping TCPS option from known peer):
```
tcps: downgrade detected! SYN+ACK without TCPS from known peer 192.168.1.127
tcps: downgrade detected! SYN without TCPS from known peer 192.168.1.127
```

MITM attack (key mismatch, epoch same):
```
tcps: MITM detected! Static key mismatch for peer 192.168.1.127 (same epoch 1234567890)
tcps: expected 9a8b7c6d5e4f3a2b, got deadbeef12345678
```

MITM attack (auth_tag mismatch - sending someone else's key):
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
| `unknown-253` in SYN | TC option with ephemeral X25519 pubkey + epoch (40 bytes, magic 'T', 'C') |
| `unknown-253` in ACK | TI option with static pubkey + auth_tag (40 bytes, magic 'T', 'I') |
| `unknown-253` in data | TM option with Poly1305 tag (20 bytes, magic 'T', 'M') |
| Unreadable data | Payload encrypted with ChaCha20 |
| Readable data | Plain TCP — peer without module (not in TOFU) |

Note: MSS is not included in SYN (TC option occupies all 40 option bytes).
TCP uses the default MSS (536) before Path MTU Discovery.

```bash
# On the attacker: ARP spoofing (strip TC options, but NOT payload)
sysctl -w net.ipv4.ip_forward=1
arpspoof -i eth0 -t <CLIENT_IP> <SERVER_IP> &
arpspoof -i eth0 -t <SERVER_IP> <CLIENT_IP> &
# iptables: strip TCP option 253 from SYN/SYN+ACK
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 536
# (or simply don't modify the payload—like arpspoof by default)

# On the client: FIRST connection (TOFU yet)
empty)
insmod tcps.ko
echo "test" | nc <SERVER_IP> 9000
dmesg | grep tcps
# → "peer <SERVER_IP> has no TCPS module, probing"
# → "probe sent ..."
# → "DOWNGRADE DETECTED! Peer <SERVER_IP> has a TCPS module but the option was stripped"
# Connection killed! Data did NOT reach the MITM.

# On the server:
dmesg | grep tcps
# → "probe received from <CLIENT_IP> — TCPS option was stripped, possible MITM"
# → "probe response sent ..."

# Reconnecting — TOFU protects:
echo "test2" | nc <SERVER_IP> 9000
# → "downgrade detected! SYN+ACK without TCPS from known peer <SERVER_IP>" → NF_DROP
```

# Security Properties

| Property | Mechanism |
|----------|----------|
| Encryption | ChaCha20 stream cipher |
| Integrity | Poly1305 MAC (16 bytes, per-packet key, AAD covers TCP flags) |
| FIN injection | FIN packets require a MAC, spoofed FIN is discarded |
| Forward secrecy | Ephemeral X25519 DH keys, destroyed after derivation |
| MITM protection | TOFU + auth_tag (static identity key) + ISN binding |
| MITM relay | auth_tag is bound to ISN — forwarding between sessions is not possible |
| Key rotation | Epoch — reboot detection, auto-rotate when epoch changes |
| Downgrade protection | TOFU as a peer list + NF_DROP when stripping known peers |
| Downgrade first-use | In-band probe via payload — MITM auto-detect on first connection |
| Auto-discovery | TOFU cache automatically detects TCPS/Plain for each IP |
| RST injection | Inbound RST is dropped in encrypted state |
| Timing attacks | crypto_memneq for MAC and auth_tag |
| Key separation | HKDF-Expand with unique labels for each key |
| Key privacy | memzero_explicit, RAM only, not written to disk |
| TI delivery | Embedded TI in payload — authentication with the first data packet |

# Known Limitations

| Limitation | Description |
|------------|----------|
| IPv4 only | IPv6 not yet supported |
| auth_tag 4 bytes | 32-bit security for identity verification. Increasing this value requires reconsidering the TI option (40B is the maximum TCP options) |
| No connection limit | Limit 4096 (tcps_conn_count). If exceeded, SYN is dropped |
| TOFU kzalloc fail | Connection is rejected instead of trusted (return -1) |
| RST delay | Legitimate RST from peer is dropped, closing via FIN/timeout |
| Pure ACK is not authenticated | ACKs without FIN and without payload do not contain a MAC (overhead). FIN is protected |
| TOFU in-memory cache | Lost during rmmod, keys are not saved to disk |
| Epoch — heuristic | Not a cryptographic proof: an active MITM can replace the epoch+key with auto_rotate=1 |
| MSS in SYN | TC option (40B) takes up the entire option space — MSS is not enabled. Default is 536, PMTU Discovery compensates |
| Embedded TI marker | Byte 0x01 at the beginning of the payload — a collision with app data may result in DoS (packet drop) |
| Probe without data | Probe is sent only in the data packet. If the client does not send data, the probe will not send |
| Probe without response | If the server does not send data, the probe response will not be sent, timeout is 30 seconds |
| Probe payload-mod MITM | A MITM with payload modification capabilities can strip the probe (much more complex than strip options) |
| Probe + plain server | A server without a module receives 36 extra bytes in the probe's payload. The application may return an error |