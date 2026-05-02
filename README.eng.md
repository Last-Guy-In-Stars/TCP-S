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
2. Netfilter hook PRE_ROUTING — detects TC option in SYN, saves the peer's ephemeral pubkey
3. SYN-ACK also carries TC option with the server's ephemeral pubkey — both hosts receive the peer's pubkey
4. After handshake — ECDH (X25519) shared secret → KDF → 4 keys: enc_c2s, enc_s2c, mac_c2s, mac_s2c
5. All TCP data is encrypted with ChaCha20 (stream cipher, size does not change)
6. Each data packet contains Poly1305 MAC (8 bytes) in TCP option TM (kind=253, 12 bytes)
7. Packets without a MAC or with an invalid MAC are discarded (NF_DROP)
8. **After encryption**: Both hosts exchange a TI option (kind=253, 40 bytes) — static pubkey + auth_tag
9. The TI option is verified via TOFU + auth_tag → TCPS_AUTHENTICATED state
10. Works for all TCP sockets on the system, applications are unaware of this.

# Cryptography (without OpenSSL)

- X25519 ECDH — 32-byte keys, via kernel crypto API (libcurve25519)
- ChaCha20 — stream cipher, XOR on the stream position, without changing the packet size
- Poly1305 — AEAD MAC, custom implementation on 26-bit limbs
- KDF — ChaCha20 as a PRF for deriving 4 keys (128 bytes) from a shared secret + ISN
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
- Subsequent connections: the pubkey is verified with Cache, auth_tag is verified
- Mismatch between pubkey and auth_tag → MITM detected → NF_DROP

**auth_tag prevents forwarding someone else's pubkey:**
MITM cannot forge an auth_tag—this requires a static private key,
which only the legitimate peer has.

**Limitation:** The first connection is trusted without verification (like SSH).
For critical scenarios, check the fingerprint in dmesg on both machines.

**Module parameter `tofu_enforce`:**
- `1` (default) — drop the connection if there is a mismatch
- `0` — only log a warning

```bash
insmod tcps.ko tofu_enforce=0
cat /sys/module/tcps/parameters/tofu_enforce
```

# The module must be loaded on both the client and the server.

```
Step | Client (tcps.ko) | Server (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1 | SYN + TC option (ephemeral pubkey) ───────────► | Sees TC, saves ephemeral pubkey
2 | | SYN-ACK + TC option (ephemeral pubkey)
3 | ◄────────────────────── ──────────────────────── | Both hosts know someone else's ephemeral pubkey
4 | X25519(eph_priv, peer_eph_pub) → shared | X25519(eph_priv, peer_eph_pub) → shared
5 | KDF(shared, ISN) → 4 keys | KDF(shared, ISN) → 4 keys
6 | ◄══════ ChaCha20 + Poly1305 (forward secret) ═► | Encrypted + integrity
7 | ACK + TI option (static pubkey + auth_tag) ──► | TOFU + auth_tag verification
8 | ◄ TI option (static pubkey + auth_tag) | TCPS_AUTHENTICATED on both sides
| Applications (nginx/postgres/ssh) are unaware
```

If only one side has the module, the TCP option TC will not be in the response,
and the module will fall back to regular TCP (without encryption). The connection works as usual.

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

# Verifying work

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
| `mss 1448` | MSS decreased by 12 bytes (space for MAC option) |
| `unknown-253` in SYN | TC option with ephemeral X25519 pubkey (36 bytes, magic 'T','C') |
| `unknown-253` in ACK | TI option with static pubkey + auth_tag (40 bytes, magic 'T','I') |
| `unknown-253` in data | TM option with Poly1305 tag (12 bytes, magic 'T','M') |
| Unreadable data | Payload encrypted with ChaCha20 |

```

# Security Properties

| Property | Mechanism |
|----------|----------|
| Encryption | ChaCha20 stream cipher |
| Integrity | Poly1305 MAC (8 bytes per packet) |
| Forward secrecy | Ephemeral X25519 DH keys, destroyed after derivation |
| MITM protection | TOFU + auth_tag (static identity key) |
| Timing attacks | crypto_memneq for MAC and auth_tag |
| Key privacy | memzero_explicit, RAM only, not written to disk |