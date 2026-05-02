### TCP/S — Transparent TCP Encryption at Layer 4

# Architecture
```
tcps/
├── kernel/ # Linux kernel module (LKM)
│ ├── tcps.h # Header: states, AEAD, TOFU, TI option constants
│ ├── tcps_main.c # Netfilter hooks, options, MAC, TOFU + forward secrecy
│ ├── tcps_crypto.c # X25519 + ChaCha20 + Poly1305 for the kernel
│ ├── Makefile # Build: make → tcps.ko
│ └── INSTRUCTION.md # Installation and configuration instructions Testing
```

# How it works

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — adds TCP option TC (kind=253, 36 bytes) to SYN, with an **ephemeral** X25519 pubkey
2. Netfilter hook PRE_ROUTING — detects the TC option in SYN, saves the peer's ephemeral pubkey
3. SYN-ACK also carries the TC option with the server's ephemeral pubkey — both hosts receive the peer's pubkey
4. After handshake — ECDH (X25519) shared secret → HKDF-Expand (ChaCha20 PRF) → 4 keys
5. All TCP data is encrypted with ChaCha20 (stream cipher, size does not change)
6. Each data or FIN packet contains a Poly1305 MAC (16 bytes) in TCP option TM (kind=253, 20 bytes)
7. The Poly1305 key is unique for each packet (derived from position). AAD includes TCP flags.
8. Packets without a MAC or with an invalid MAC are discarded (NF_DROP). FIN without MAC is also a drop
9. **After encryption**: TI option is sent only on pure ACK (no payload, no FIN)
10. TI option is verified via TOFU + auth_tag → TCPS_AUTHENTICATED state
11. Works for all TCP sockets on the system, applications are unaware of this

# Cryptography (without OpenSSL)

- X25519 ECDH — 32-byte keys, via kernel crypto API (libcurve25519)
- ChaCha20 — stream cipher, XOR on stream position, without changing packet size
- Poly1305 — AEAD MAC, custom implementation on 26-bit limbs
- **Per-packet Poly1305 key** — unique key for each packet (ChaCha20(mac_key, pos + seq))
- **MAC AAD covers TCP flags** — prevents spoofing FIN/flags without detection
- KDF — HKDF-Expand pattern: each key is output separately with a unique label
- `TCPS enc_c2s` (position 0x8000000000000000)
- `TCPS enc_s2c` (position 0x8000000000000040)
- `TCPS mac_c2s` (position 0x8000000000000080)
- `TCPS mac_s2c` (position 0x800000000000000C0)
- Timing attack protection — MAC comparison via crypto_memneq (constant-time)
- **Forward secrecy** — ephemeral DH keys are destroyed (memzero_explicit) after derivation

# MITM protection (TOFU + auth_tag)

The static X25519 identity key is generated when the module loads. The private key is stored
only in kernel RAM; it is never transmitted over the network or written to disk.

**Two-phase protocol:**

Phase 1 — SYN/SYN-ACK: ephemeral DH keys → encryption (forward secrecy)
Phase 2 — ACK/data after encryption: TI option with a static key → authentication

**TI option (40 bytes):** static_pubkey(32) + auth_tag(4)
- auth_tag = ChaCha20-PRF(DH(my_static_priv, peer_static_pub), ISN_client || ISN_server || "TAUT")[:4]
- auth_tag = 0 on first connection (no peer key in TOFU cache)

**TOFU (Trust On First Use):**
- First connection: the peer's static pubkey is stored in the TOFU cache (IP → pubkey)
- Subsequent connections: the pubkey is verified with Cache, auth_tag is always verified (including null)
- Mismatch of pubkey or auth_tag → MITM detected → NF_DROP

**auth_tag prevents forwarding someone else's pubkey:**
MITM cannot forge auth_tag—this requires a static private key,
which only the legitimate peer has.

**Limitation:** The first connection is trusted without verification (like SSH).
For critical scenarios, check the fingerprint in dmesg on both machines.

**Module Parameters:**

| Parameter | Default | Description |
|----------|------------|----------|
| `tofu_enforce` | 1 | 0=log only, 1=drop if TOFU mismatch |
| `enforce` | 0 | 0=allow plaintext fallback, 1=drop non-TCPS connections |

```bash
insmod tcps.ko tofu_enforce=0 enforce=1
cat /sys/module/tcps/parameters/tofu_enforce
cat /sys/module/tcps/parameters/enforce

# Runtime switching
echo 0 > /sys/module/tcps/parameters/tofu_enforce
echo 1 > /sys/module/tcps/parameters/enforce
```

# Downgrade and RST injection protection

**Downgrade attack** (strip TCPS options): with `enforce=1`:
- Client: SYN+ACK without TCPS option is dropped
- Server: SYN without TCPS option is dropped
Without `enforce` — fallback to regular TCP.

**RST injection**: Inbound RST packets in encrypted state (ENCRYPTED/AUTHENTICATED)
are dropped. A spoofed RST cannot terminate an encrypted session. The connection is closed
only via a FIN or GC timeout.

# The module must be loaded on both sides – the client and the server.

```
Step | Client (tcps.ko) | Server (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1 | SYN + TC option (ephemeral pubkey) ───────────► | Sees TC, saves ephemeral pubkey
2 | | SYN-ACK + TC option (ephemeral pubkey)
3 | ◄─ ... HKDF-Expand(shared, label, ISN) → 4 keys
6 | ◄══════ ChaCha20 + Poly1305 (forward secret) ═► | Encrypted + integrity (MAC 16B)
7 | ACK + TI option (static pubkey + auth_tag) ──► | TOFU + auth_tag verification
8 | ◄ TI option (static pubkey + auth_tag) | TCPS_AUTHENTICATED on both sides
| Applications (nginx/postgres/ssh) are unaware of anything
```

If only one side has the module, the TCP option TC will not be in the response,
and the module will fallback to regular TCP (without encryption). To disable fallback, set `enforce=1`.

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
PostgreSQL, HTTP, SSH—whatever.

Unloading the module:
```bash
rmmod tcps
```

When the module is reloaded, a new static identity key is generated,
the TOFU cache is cleared. Both sides need to reload the module.

# Verifying operation

## dmesg — sessions and errors

```bash
dmesg | grep tcps
```

Loading module:
```
tcps: module loaded, ECDH + ChaCha20-Poly1305 + TOFU active
tcps: identity fingerprint: a1b2c3d4e5f6a7b8
```

Successful connection (first - TOFU remembers):
```
tcps: encrypted session 192.168.1.69:41548 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: TI option sent 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: TOFU: new peer 192.168.1.127 fingerprint 9a8b7c6d5e4f3a2b
tcps: session authenticated 192.168.1.69:41548 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

Successful connection (retry — TOFU + auth_tag verification):
```
tcps: encrypted session 192.168.1.69:41550 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: session authenticated 192.168.1.69:41550 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

MITM attack detected (key does not match TOFU cache):
```
tcps: MITM detected! Static key mismatch for peer 192.168.1.127
tcps: expected 9a8b7c6d5e4f3a2b, got deadbeef12345678
```

MITM attack detected (auth_tag mismatch — sending someone else's key):
```
tcps: MITM detected! auth_tag mismatch for peer 192.168.1.127
```

MAC error (packet forged or corrupted):
```
tcps: MAC verification failed, dropping
```

## tcpdump — visual encryption verification

```bash
tcpdump -i ens18 -A -s0 tcp
```

Module activity indicators:

| Indicator | Description |
|---------|----------|
| `mss 1440` | MSS decreased by 20 bytes (room for MAC option 20B) |
| `unknown-253` in SYN | TC option with ephemeral X25519 pubkey (36 bytes, magic 'T','C') |
| `unknown-253` in ACK | TI option with static pubkey + auth_tag (40 bytes, magic 'T','I') |
| `unknown-253` in data | TM option with Poly1305 tag (20 bytes, magic 'T','M') |
| Unreadable data | Payload encrypted with ChaCha20 |

```

# Security Properties

| Property | Mechanism |
|----------|----------|
| Encryption | ChaCha20 stream cipher |
| Integrity | Poly1305 MAC (16 bytes, per-packet key, AAD covers TCP flags) |
| FIN injection | FIN packets require a MAC, spoofed FIN is discarded |
| Forward secrecy | Ephemeral X25519 DH keys, destroyed after derivation |
| MITM protection | TOFU + auth_tag (static identity key) |
| Downgrade protection | The `enforce=1` parameter drops non-TCPS connections (client + server side) |
| RST injection | Inbound RST is dropped in encrypted state |
| Timing attacks | crypto_memneq for MAC and auth_tag |
| Key separation | HKDF-Expand with unique labels for each key |
| Key privacy | memzero_explicit, RAM only, not written to disk |

# Known limitations

| Limitation | Description |
|------------|----------|
| TOFU first-use | The first connection is not authenticated (like SSH). Check fingerprint |
| IPv4 only | IPv6 is not yet supported |
| auth_tag 4 bytes | 32-bit security for identity verification. Increasing this requires reconsidering the TI option (40B is the maximum TCP options) |
| No connection limit | Limit 4096 (tcps_conn_count). If exceeded, SYN is dropped |
| TOFU kzalloc fail | The connection is rejected instead of trusted (return -1) |
| TI is retransmitted | TI is sent with every pure ACK until TI is received from the peer (ti_recv) |
| RST delay | Legitimate RST from the peer is dropped, closed via FIN/timeout |
| Pure ACK is not authenticated | ACKs without FIN and without payload do not contain a MAC (overhead). FIN is protected |
| TOFU cache in-memory | Lost during rmmod, keys are not saved to disk |

```

---

License: MIT. Use, fork, modify, and experiment.