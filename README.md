### TCP/S — прозрачное шифрование TCP на 4 уровне

# Архитектура
```
tcps/
├── kernel/                    # Linux kernel module (LKM)
│   ├── tcps.h                 # Заголовок: состояния, константы AEAD, TOFU, TI option
│   ├── tcps_main.c            # Netfilter hooks, опции, MAC, TOFU + forward secrecy
│   ├── tcps_crypto.c          # X25519 + ChaCha20 + Poly1305 для ядра
│   ├── Makefile               # Сборка: make → tcps.ko
│   └── INSTRUCTION.md         # Инструкция по установке и тестированию
```

# Как работает

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — добавляет TCP option TC (kind=253, 36 байт) в SYN, с **эфемерным** X25519 pubkey
2. Netfilter hook PRE_ROUTING — обнаруживает TC option в SYN, сохраняет peer ephemeral pubkey
3. SYN-ACK тоже несёт TC option с эфемерным pubkey сервера — оба хоста получают чужой pubkey
4. После handshake — ECDH (X25519) shared secret → HKDF-Expand (ChaCha20 PRF) → 4 ключа
5. Все TCP-данные шифруются ChaCha20 (stream cipher, размер не меняется)
6. Каждый пакет с данными или FIN содержит Poly1305 MAC (16 байт) в TCP option TM (kind=253, 20 байт)
7. Poly1305 key уникален для каждого пакета (derived from position). AAD включает TCP flags
8. Пакеты без MAC или с неверным MAC отбрасываются (NF_DROP). FIN без MAC — тоже дроп
9. **После шифрования**: TI option отправляется только на pure ACK (no payload, no FIN)
10. TI option верифицируется через TOFU + auth_tag → состояние TCPS_AUTHENTICATED
11. Работает для всех TCP-сокетов на системе, приложения ничего не знают

# Криптография (без OpenSSL)

- X25519 ECDH — 32-байтные ключи, через kernel crypto API (libcurve25519)
- ChaCha20 — stream cipher, XOR на позиции потока, без изменения размера пакетов
- Poly1305 — AEAD MAC, собственная реализация на 26-битных лимбах
- **Per-packet Poly1305 key** — уникальный ключ для каждого пакета (ChaCha20(mac_key, pos + seq))
- **MAC AAD covers TCP flags** — предотвращает подмену FIN/flags без обнаружения
- KDF — HKDF-Expand паттерн: каждый ключ выводится отдельно с уникальным лейблом
  - `TCPS enc_c2s` (position 0x8000000000000000)
  - `TCPS enc_s2c` (position 0x8000000000000040)
  - `TCPS mac_c2s` (position 0x8000000000000080)
  - `TCPS mac_s2c` (position 0x80000000000000C0)
- Защита от timing-атак — сравнение MAC через crypto_memneq (constant-time)
- **Forward secrecy** — эфемерные DH-ключи уничтожаются (memzero_explicit) после деривации

# Защита от MITM (TOFU + auth_tag)

Статический identity-ключ X25519 генерируется при загрузке модуля. Приватный ключ хранится
только в RAM ядра, никогда не передаётся по сети, на диск не записывается.

**Двухфазный протокол:**

Фаза 1 — SYN/SYN-ACK: эфемерные DH-ключи → шифрование (forward secrecy)
Фаза 2 — ACK/data после шифрования: TI option со статическим ключом → аутентификация

**TI option (40 байт):** static_pubkey(32) + auth_tag(4)
- auth_tag = ChaCha20-PRF(DH(my_static_priv, peer_static_pub), ISN_client || ISN_server || "TAUT")[:4]
- auth_tag = 0 при первом соединении (нет ключа пира в TOFU-кеше)

**TOFU (Trust On First Use):**
- Первое соединение: статический pubkey пира запоминается в TOFU-кеше (IP → pubkey)
- Последующие: pubkey сверяется с кешем, auth_tag верифицируется **всегда** (включая нулевой)
- Несовпадение pubkey или auth_tag → MITM обнаружен → NF_DROP

**auth_tag предотвращает пересылку чужого pubkey:**
MITM не может подделать auth_tag — для этого нужен статический приватный ключ,
который есть только у легитимного пира.

**Ограничение:** первое соединение доверяется без верификации (как SSH).
Для критичных сценариев — сверьте fingerprint в dmesg на обеих машинах.

**Параметры модуля:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `tofu_enforce` | 1 | 0=только логировать, 1=дропать при несовпадении TOFU |
| `enforce` | 0 | 0=допускать plaintext fallback, 1=дропать non-TCPS соединения |

```bash
insmod tcps.ko tofu_enforce=0 enforce=1
cat /sys/module/tcps/parameters/tofu_enforce
cat /sys/module/tcps/parameters/enforce

# Runtime переключение
echo 0 > /sys/module/tcps/parameters/tofu_enforce
echo 1 > /sys/module/tcps/parameters/enforce
```

# Защита от downgrade и RST injection

**Downgrade-атака** (strip TCPS options): при `enforce=1`:
- Клиент: SYN+ACK без TCPS option дропается
- Сервер: SYN без TCPS option дропается
Без `enforce` — fallback к обычному TCP.

**RST injection**: inbound RST пакеты в зашифрованном состоянии (ENCRYPTED/AUTHENTICATED)
дропаются. Spoofed RST не может разорвать зашифрованную сессию. Соединение закрывается
только через FIN или GC timeout.

# Модуль нужно загрузить на обе стороны — и на клиент, и на сервер.

```
Шаг | Клиент (tcps.ko)                              | Сервер (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1    | SYN + TC option (ephemeral pubkey) ──────────► | Видит TC, сохраняет ephemeral pubkey
2    |                                                | SYN-ACK + TC option (ephemeral pubkey)
3    | ◄────────────────────────────────────────────── | Оба хоста знают чужой ephemeral pubkey
4    | X25519(eph_priv, peer_eph_pub) → shared        | X25519(eph_priv, peer_eph_pub) → shared
5    | HKDF-Expand(shared, label, ISN) → 4 ключа     | HKDF-Expand(shared, label, ISN) → 4 ключа
6    | ◄══════ ChaCha20 + Poly1305 (forward secret) ═► | Зашифровано + целостность (MAC 16B)
7    | ACK + TI option (static pubkey + auth_tag) ──► | TOFU + auth_tag верификация
8    | ◄ TI option (static pubkey + auth_tag)         | TCPS_AUTHENTICATED на обеих сторонах
     | Приложения (nginx/postgres/ssh) ничего не знают
```

Если только одна сторона имеет модуль — TCP option TC не будет в ответе,
и модуль откатится к обычному TCP (без шифрования). Для запрета fallback — `enforce=1`.

# Развёртывание

На сервере и на клиенте (Linux, arm64/amd64):

```bash
cd kernel/
apt install build-essential linux-headers-$(uname -r)
modprobe libcurve25519
make
insmod tcps.ko
```

Любое TCP-подключение между этими машинами автоматически шифруется.
PostgreSQL, HTTP, SSH — что угодно.

Выгрузка модуля:
```bash
rmmod tcps
```

При перезагрузке модуля генерируется новый статический identity-ключ,
TOFU-кеш очищается. Обеим сторонам нужно перезагрузить модуль.

# Проверка работы

## dmesg — сессии и ошибки

```bash
dmesg | grep tcps
```

Загрузка модуля:
```
tcps: module loaded, ECDH + ChaCha20-Poly1305 + TOFU active
tcps: identity fingerprint: a1b2c3d4e5f6a7b8
```

Успешное соединение (первое — TOFU запоминает):
```
tcps: encrypted session 192.168.1.69:41548 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: TI option sent 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: TOFU: new peer 192.168.1.127 fingerprint 9a8b7c6d5e4f3a2b
tcps: session authenticated 192.168.1.69:41548 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

Успешное соединение (повторное — TOFU + auth_tag верификация):
```
tcps: encrypted session 192.168.1.69:41550 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: session authenticated 192.168.1.69:41550 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

MITM-атака обнаружена (ключ не совпадает с TOFU-кешем):
```
tcps: MITM detected! Static key mismatch for peer 192.168.1.127
tcps: expected 9a8b7c6d5e4f3a2b, got deadbeef12345678
```

MITM-атака обнаружена (auth_tag не совпадает — пересылка чужого ключа):
```
tcps: MITM detected! auth_tag mismatch for peer 192.168.1.127
```

Ошибка MAC (пакет подделан или повреждён):
```
tcps: MAC verification failed, dropping
```

## tcpdump — визуальная проверка шифрования

```bash
tcpdump -i ens18 -A -s0 tcp
```

Признаки работы модуля:

| Признак | Описание |
|---------|----------|
| `mss 1440` | MSS уменьшен на 20 байт (место для MAC option 20B) |
| `unknown-253` в SYN | TC option с ephemeral X25519 pubkey (36 байт, magic 'T','C') |
| `unknown-253` в ACK | TI option со static pubkey + auth_tag (40 байт, magic 'T','I') |
| `unknown-253` в данных | TM option с Poly1305 тегом (20 байт, magic 'T','M') |
| Нечитаемые данные | Payload зашифрован ChaCha20 |

```

# Свойства безопасности

| Свойство | Механизм |
|----------|----------|
| Шифрование | ChaCha20 stream cipher |
| Целостность | Poly1305 MAC (16 байт, per-packet key, AAD covers TCP flags) |
| FIN injection | FIN пакеты требуют MAC, spoofed FIN отбрасывается |
| Forward secrecy | Эфемерные X25519 DH-ключи, уничтожаются после деривации |
| MITM-защита | TOFU + auth_tag (статический identity ключ) |
| Downgrade-защита | Параметр `enforce=1` — дропать non-TCPS соединения (client + server side) |
| RST injection | Inbound RST дропается в зашифрованном состоянии |
| Timing-атаки | crypto_memneq для MAC и auth_tag |
| Key separation | HKDF-Expand с уникальными лейблами для каждого ключа |
| Приватность ключей | memzero_explicit, только в RAM, на диск не пишутся |

# Известные ограничения

| Ограничение | Описание |
|-------------|----------|
| TOFU first-use | Первое соединение не аутентифицировано (как SSH). Сверяйте fingerprint |
| IPv4 only | IPv6 пока не поддерживается |
| auth_tag 4 байта | 32-bit security для identity verification. Увеличение требует пересмотра TI option (40B — максимум TCP options) |
| Нет лимита соединений | Лимит 4096 (tcps_conn_count). При превышении — SYN дропается |
| TOFU kzalloc fail | Соединение отклоняется вместо доверия (return -1) |
| TI ретранслируется | TI отправляется на каждом pure ACK пока не получен TI от пира (ti_recv) |
| RST delay | Легитимный RST от пира дропается, закрытие через FIN/timeout |
| Pure ACK не аутентифицирован | ACK без FIN и без payload не содержат MAC (overhead). FIN защищён |
| TOFU cache in-memory | Теряется при rmmod, ключи на диск не сохраняются |
---
Лицензия — MIT. Используйте, создавайте форки, меняйте, эксперементируйте.