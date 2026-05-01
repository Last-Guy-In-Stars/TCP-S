### TCP/S — Transparent TCP Encryption at Layer 4

# Architecture
```
tcps/
├── kernel/ # Linux kernel module (LKM)
│ ├── tcps.h # Header: states, connection structures, AEAD constants
│ ├── tcps_main.c # Netfilter hooks (LOCAL_OUT + PRE_ROUTING), options, MAC
│ ├── tcps_crypto.c # X25519 + ChaCha20 + Poly1305 for the kernel
│ ├── Makefile # Build: make → tcps.ko
│ └── INSTRUCTION.md # Installation and configuration instructions Testing
```

# How it works

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — adds TCP option TC (kind=253, 36 bytes) to SYN, with Curve25519 pubkey
2. Netfilter hook PRE_ROUTING — detects TC option in SYN, saves peer pubkey
3. SYN-ACK also carries TC option from the pubkey server — both hosts receive the peer's pubkey
4. After handshake — ECDH (X25519) shared secret → KDF → 4 keys: enc_c2s, enc_s2c, mac_c2s, mac_s2c
5. All TCP data is encrypted with ChaCha20 (stream cipher, size does not change)
6. Each data packet contains a Poly1305 MAC (8 bytes) in TCP option TM (kind=253, 12 bytes)
7. Packets without a MAC or with an invalid MAC are dropped (NF_DROP)
8. Works for all TCP sockets on the system, applications are unaware of this.

# Cryptography (without OpenSSL)

- X25519 ECDH — 32-byte keys, via the kernel crypto API (libcurve25519)
- ChaCha20 — stream cipher, XOR on the stream position, without changing the packet size
- Poly1305 — AEAD MAC, custom implementation on 26-bit limbs
- KDF — ChaCha20 as a PRF for deriving 4 keys (128 bytes) from a shared secret + ISN
- Protection against timing attacks — MAC comparison via crypto_memneq (constant-time)
- Forward secrecy — DH keys are destroyed (memzero_explicit) after deriving session keys Keys

# The module must be loaded on both sides—the client and the server.

```
Step | Client (tcps.ko) | Server (tcps.ko)
-----|--------------------------------------|--------------------------------------
1 | SYN + TC option (X25519 pubkey) ───► | Sees TC, saves the client's pubkey
2 | | SYN-ACK + TC option (X25519 pubkey)
3 | ◄─────────────────────────────────────── | Both hosts know the other's pubkey
4 | X25519(priv, peer_pub) → shared | X25519(priv, peer_pub) → shared
5 | KDF(shared, ISN) → 4 keys | KDF(shared, ISN) → 4 keys
6 | ◄════════ ChaCha20 + Poly1305 ══════► | Encrypted + Integrity
| Applications (nginx/postgres/ssh) are unaware
```

If only one side has the module, the TCP option TC will not be in the response,
and the module will fall back to regular TCP (without encryption). The connection works as usual.

# Deployment

On the server and client (Linux, arm64/amd64):

```bash
cd kernel/
apt install build-essential linux-headers-$(uname -r)
modprobe libcurve25519 # kernel dependency for X25519
make # compile tcps.ko
insmod tcps.ko # load the module into the kernel
```

Any TCP connection between these machines is automatically encrypted.
PostgreSQL, HTTP, SSH—whatever.
The module resides in netfilter (L4), not on the port. It sees every TCP packet passing through the kernel.

Unloading the module:
```bash
rmmod tcps
```

# Verifying operation

## dmesg — sessions and errors

```bash
dmesg | grep tcps
```

Successful connection:
```
tcps: module loaded, ECDH (X25519) + ChaCha20-Poly1305 active
tcps: SYN out 192.168.1.69:41548->192.168.1.127:80 isn=2400457015
tcps: encrypted session 192.168.1.69:41548 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: SYN+ACK in 192.168.1.127:80->192.168.1.69:41548 derived
```

If only one side has the module, the connection works, but without encryption:
```
tcps: SYN+ACK in without TCPS option ← no TC option in response
```

MAC error (packet forged or corrupted):
```
tcps: MAC verification failed, dropping
```

## tcpdump — visual encryption verification

```bash
tcpdump -i ens18 -A -s0 tcp
```

Module activity indicators in capture:

| Indicator | Description |
|---------|----------|
| `mss 1448` | MSS decreased by 12 bytes (space for MAC option) |
| `unknown-253` in SYN | TC option with X25519 pubkey (36 bytes, magic 'T','C') |
| `unknown-253` in data | TM option with Poly1305 tag (12 bytes, magic 'T', 'M') |
| Unreadable data | Payload encrypted with ChaCha20, no ASCII text |

Example HTTP request via TCPS:
```
> SYN: options [mss 1448, unknown-253 0x5443...] ← TC option + pubkey
< SYN-ACK: options [mss 1448, unknown-253 0x5443...] ← TC option + pubkey
> ACK: (clear ACK, without MAC option)
> PSH,ACK: options [unknown-253 0x544d...], length 77 ← TM option + encrypted HTTP
< ACK: (clear ACK)
< PSH,ACK: options [unknown-253 0x544d...], length 156 ← encrypted HTTP response
```

Without the module, the same HTTP request would show readable text: `GET / HTTP/1.1`, headers, HTML.
The module produces only binary garbage. Applications (curl, nginx) work as usual.

--

License: MIT. Use it, fork it, bypass censorship responsibly.