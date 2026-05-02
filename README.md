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
4. После handshake — ECDH (X25519) shared secret → KDF → 4 ключа: enc_c2s, enc_s2c, mac_c2s, mac_s2c
5. Все TCP-данные шифруются ChaCha20 (stream cipher, размер не меняется)
6. Каждый пакет с данными содержит Poly1305 MAC (8 байт) в TCP option TM (kind=253, 12 байт)
7. Пакеты без MAC или с неверным MAC отбрасываются (NF_DROP)
8. **После шифрования**: оба хоста обмениваются TI option (kind=253, 40 байт) — статический pubkey + auth_tag
9. TI option верифицируется через TOFU + auth_tag → состояние TCPS_AUTHENTICATED
10. Работает для всех TCP-сокетов на системе, приложения ничего не знают

# Криптография (без OpenSSL)

- X25519 ECDH — 32-байтные ключи, через kernel crypto API (libcurve25519)
- ChaCha20 — stream cipher, XOR на позиции потока, без изменения размера пакетов
- Poly1305 — AEAD MAC, собственная реализация на 26-битных лимбах
- KDF — ChaCha20 как PRF для деривации 4 ключей (128 байт) из shared secret + ISN
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
- Последующие: pubkey сверяется с кешем, auth_tag верифицируется
- Несовпадение pubkey или auth_tag → MITM обнаружен → NF_DROP

**auth_tag предотвращает пересылку чужого pubkey:**
MITM не может подделать auth_tag — для этого нужен статический приватный ключ,
который есть только у легитимного пира.

**Ограничение:** первое соединение доверяется без верификации (как SSH).
Для критичных сценариев — сверьте fingerprint в dmesg на обеих машинах.

**Параметр модуля `tofu_enforce`:**
- `1` (по умолчанию) — дропать соединение при несовпадении
- `0` — только логировать предупреждение

```bash
insmod tcps.ko tofu_enforce=0
cat /sys/module/tcps/parameters/tofu_enforce
```

# Модуль нужно загрузить на обе стороны — и на клиент, и на сервер.

```
Шаг | Клиент (tcps.ko)                              | Сервер (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1    | SYN + TC option (ephemeral pubkey) ──────────► | Видит TC, сохраняет ephemeral pubkey
2    |                                                | SYN-ACK + TC option (ephemeral pubkey)
3    | ◄────────────────────────────────────────────── | Оба хоста знают чужой ephemeral pubkey
4    | X25519(eph_priv, peer_eph_pub) → shared        | X25519(eph_priv, peer_eph_pub) → shared
5    | KDF(shared, ISN) → 4 ключа                    | KDF(shared, ISN) → 4 ключа
6    | ◄══════ ChaCha20 + Poly1305 (forward secret) ═► | Зашифровано + целостность
7    | ACK + TI option (static pubkey + auth_tag) ──► | TOFU + auth_tag верификация
8    | ◄ TI option (static pubkey + auth_tag)         | TCPS_AUTHENTICATED на обеих сторонах
     | Приложения (nginx/postgres/ssh) ничего не знают
```

Если только одна сторона имеет модуль — TCP option TC не будет в ответе,
и модуль откатится к обычному TCP (без шифрования). Соединение работает как обычно.

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
| `mss 1448` | MSS уменьшен на 12 байт (место для MAC option) |
| `unknown-253` в SYN | TC option с ephemeral X25519 pubkey (36 байт, magic 'T','C') |
| `unknown-253` в ACK | TI option со static pubkey + auth_tag (40 байт, magic 'T','I') |
| `unknown-253` в данных | TM option с Poly1305 тегом (12 байт, magic 'T','M') |
| Нечитаемые данные | Payload зашифрован ChaCha20 |

```

# Свойства безопасности

| Свойство | Механизм |
|----------|----------|
| Шифрование | ChaCha20 stream cipher |
| Целостность | Poly1305 MAC (8 байт на пакет) |
| Forward secrecy | Эфемерные X25519 DH-ключи, уничтожаются после деривации |
| MITM-защита | TOFU + auth_tag (статический identity ключ) |
| Timing-атаки | crypto_memneq для MAC и auth_tag |
| Приватность ключей | memzero_explicit, только в RAM, на диск не пишутся |
