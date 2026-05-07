### TCP/S — Transparent TCP Encryption at Layer 4

*Author: ArtamonovKA, written on GLM-5.1*

# Architecture
```
tcps/
├── kernel/ # Current version
│ ├── tcps.h # Header: states, constants, ChaCha20, X25519, TOFU
│ ├── tcps_main.c # Netfilter hooks, probe option, UDP discovery, TOFU, skip_ports
│ ├── tcps_crypto.c # ChaCha20 stream cipher + X25519 DH + KDF
│ └── Makefile # Build: make → tcps.ko
```
# Old v1 (broken on GSO, not used)

# How it works

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — adds TCP option **TC** (kind=253, len=4, magic=0x5443) to SYN
2. Netfilter hook PRE_ROUTING — detects the TC option in SYN → creates a connection record
3. SYN-ACK also carries the TC option — both hosts have confirmed TCPS support
4. After handshake — **X25519 ECDH** shared secret → KDF → 2 forwarded keys (c2s, s2c)
5. All TCP data is encrypted with **ChaCha20** (stream cipher, XOR on the stream position, packet size does not change)
6. Works for all TCP sockets on the system, applications are unaware of this
7. Ports from `skip_ports` (default 22) are skipped — SSH/SCP works without modification.

# Peer Autodiscovery (UDP Discovery)

Each host with the module broadcasts its X25519 public key via UDP broadcast (port 54321) every 3 seconds.

**Packet format:** magic(4B, 0x54435053) + X25519_pubkey(32B) = 36 bytes

**Result:**
- Peers automatically discover each other on the same L2 network
- Public keys are stored in the TOFU cache (IP → pubkey)
- Manual configuration is not required
- You can add peers manually: `echo "192.168.1.42=hex_pubkey" > /proc/tcps_peers`

# Cryptography (without OpenSSL)

- **X25519 ECDH** — 32-byte keys, via kernel crypto API (`libcurve25519`)
- **ChaCha20** — stream cipher, XOR on the stream position, without changing the packet size
- **KDF** — HKDF-Expand pattern: `KDF(X25519(my_priv, peer_pub), client_ISN, server_ISN)`
- `TCPS c2s` (position 0x8000000000000000) — client→server key
- `TCPS s2c` (position 0x80000000000000040) — server→client key
- Stream position is calculated from ISN + 1 — unique for each connection
- Private keys are destroyed via `memzero_explicit` when the module is unloaded

# MITM Protection (TOFU)

**TOFU (Trust On First Use)** — like SSH `StrictHostKeyChecking=accept-new`:

- **First connection**: the peer's public key is stored in the TOFU cache (IP → pubkey)
- Vulnerable to MITM on first exchange — like SSH on first connection
- **Subsequent**: key verified against TOFU cache
- `strict_tofu=0` (default): warning + update when key changes (allows module reload)
- `strict_tofu=1`: block when key changes (protects against MITM attacks, but module reloads break connections until manual intervention)

**Module Parameters:**

| Parameter | Default | Description |
|----------|------------|-----------|
| `skip_ports` | 22 | Ports to skip (already encrypted, e.g. 22443) |
| `strict_tofu` | 0 | 0=update key with warning, 1=block when key changes |

```bash
insmod tcps.ko skip_ports=22,443 strict_tofu=1
cat /sys/module/tcps/parameters/strict_tofu
echo 1 > /sys/module/tcps/parameters/strict_tofu
```

# Probe option — detect TCPS support

TCP option kind=253 (experimental range according to RFC 4727; middleboxes are stripped less frequently).

| Field | Value | Description |
|------|----------|----------|
| Kind | 253 | Experimental (RFC 4727) |
| Length | 4 | Option length |
| Data | 0x5443 | Magic "TC" |

**Behavior when stripping the option with a middlebox:**
- SYN without TC → server does not create a record → plain TCP
- SYN-ACK without TC → client removes the record → plain TCP
- Both sides correctly fall back to unencrypted TCP

# Operation Scenarios

## Both sides have a module (autodiscovery)

```
Step | Client (tcps.ko) | Server (tcps.ko)
-----|-------------------------------------------|-------------------------------------------
1 | SYN + TC option ─────────────────────────► | Sees TC, creates conn (PROBE_SYNACK)
2 | | SYN-ACK + TC option
3 | ◄────────────────────────────────────────────────────── |
4 | Sees TC → SYN-ACK → client_isn+server_isn → KDF
5 | | KDF(X25519(my_priv, peer_pub), ISN) → keys
6 | ◄══════════ ChaCha20 encrypted ════════► | Both directions encrypted
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

## Downgrade attack (strip TC option)

If a MITM strips the TC option from a SYN or SYN-ACK, both sides fall back to plain TCP.

**Limitation:** if the middlebox strips asymmetrically (only in one direction), one side encrypts, the other doesn't → data corruption. This is unsolvable without end-to-end verification within the encrypted channel.

# Module reload

With `rmmod` + `insmod`:
1. A **new** X25519 keypair is generated
2. The connection table is cleared
3. The TOFU cache is cleared
4. UDP discovery updates keys on other hosts

**Impact on connections:**

| Stage | SSH (port 22) | Other TCP |
|------|---------------|------------|
| Module loaded | OK (skip) | Encrypted |
| `rmmod` | OK (without module) | Existing keys are broken - the other side tries to decrypt clear traffic |
| `insmod` (before discovery) | OK | New keys are weak (no peer), old keys are broken |
| After discovery | OK | New keys are full DH, working correctly |

**`strict_tofu=0` (default):** On reload, the key on the other side is updated automatically with the warning `TOFU key change for <ip> (updating)`.

**`strict_tofu=1`:** On reload, the key is not updated → new connections use mismatched DH → data corruption. Manually writing to `/proc/tcps_peers` or restarting the module on both sides is required.

# Deployment

On the server and client (Linux, amd64, kernel 6.x):

```bash
cd v2/
apt install build-essential linux-headers-$(uname -r)
modprobe curve25519-x86
make
insmod tcps.ko
```

Any TCP connection between these machines is automatically encrypted.
PostgreSQL, HTTP, Redis—anything. Connections to machines without the module are plain TCP.

Unloading the module:
```bash
rmmod tcps
```

# Verifying operation

## dmesg

```bash
dmesg | grep tcps
```

Loading module:
```
tcps: X25519 identity generated, pubkey=4ea7a766cdcfd414...
tcps: module loaded, X25519 + ChaCha20 + TOFU active
```

Peer discovery:
```
tcps: TOFU added peer 192.168.1.42
```

Key change (updating module on other end):
```
tcps: TOFU key change for 192.168.1.42 (updating)
```

Strict TOFU blocking:
```
tcps: STRICT TOFU: key change BLOCKED for 192.168.1.42
```

## /proc/tcps_peers

```bash
cat /proc/tcps_peers
# 192.168.1.42=a4db7a69021ad4f18efdd4d5982b89e97a57e4cf044281f88b684d8a7cb1c03f

# Add peer manually:
echo "192.168.1.42=a4db7a69021ad4f1...hex_pubkey" > /proc/tcps_peers
```

## tcpdump — visual encryption check

```bash
tcpdump -i ens18 -A -s0 tcp
```

| Sign | Description |
|---------|---------|
| `unknown-253` in SYN | TC probe option (4 bytes, magic 0x5443) |
| Unreadable data | Payload encrypted with ChaCha20 |
| Readable data | Plain TCP — peer without module or skip_ports |

# Security Properties

| Property | Mechanism |
|----------|---------|
| Encryption | ChaCha20 stream cipher (XOR on stream position) |
| Key exchange | X25519 ECDH via kernel crypto API |
| Directed keys | KDF with unique c2s/s2c labels |
| MITM protection | TOFU + strict_tofu (blocking when changing keys) |
| Downgrade protection | Probe option — none → fallback to plain TCP |
| Auto-discovery | UDP broadcast (port 54321) — no manual configuration required |
| Skip ports | Port 22 is skipped — SSH/SCP is not affected |
| Key privacy | memzero_explicit, RAM only, not written to disk |

# Known limitations

| Limitation | Description |
|-------------|----------|
| IPv4 only | IPv6 not yet supported |
| No AEAD/MAC | ChaCha20 without Poly1305 — integrity not checked, data spoofing is possible |
| First-use trust | The first connection to a new peer is vulnerable to MITM (like SSH) |
| TOFU in-memory | Lost during rmmod, keys are not saved to disk |
| Reload breaks connections | Existing TCP sessions are broken during rmmod/insmod (the connection table is cleared) |
| Asymmetric strip | If the middlebox cuts the TC option in only one direction, data corruption occurs |
| No forward secrecy | One X25519 keypair per module, no intra-session rotation |
| UDP discovery spoof | An attacker in the L2 network can replace the public key in a UDP broadcast |
| Unknown peer = weak keys | If the peer is not detected, DH secret = zeros (encryption is formally present, but no protection) |