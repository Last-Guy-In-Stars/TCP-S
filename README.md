### TCP/S — прозрачное шифрование TCP на 4 уровне

# Архитектура
```
tcps/
├── kernel/                    # Linux kernel module (LKM)
│   ├── tcps.h                 # Заголовок: состояния, структуры коннектов, константы AEAD
│   ├── tcps_main.c            # Netfilter hooks (LOCAL_OUT + PRE_ROUTING), опции, MAC
│   ├── tcps_crypto.c          # X25519 + ChaCha20 + Poly1305 для ядра
│   ├── Makefile               # Сборка: make → tcps.ko
│   └── INSTRUCTION.md         # Инструкция по установке и тестированию
```

# Как работает

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — добавляет TCP option TC (kind=253, 36 байт) в SYN, с Curve25519 pubkey
2. Netfilter hook PRE_ROUTING — обнаруживает TC option в SYN, сохраняет peer pubkey
3. SYN-ACK тоже несёт TC option с pubkey сервера — оба хоста получают чужой pubkey
4. После handshake — ECDH (X25519) shared secret → KDF → 4 ключа: enc_c2s, enc_s2c, mac_c2s, mac_s2c
5. Все TCP-данные шифруются ChaCha20 (stream cipher, размер не меняется)
6. Каждый пакет с данными содержит Poly1305 MAC (8 байт) в TCP option TM (kind=253, 12 байт)
7. Пакеты без MAC или с неверным MAC отбрасываются (NF_DROP)
8. Работает для всех TCP-сокетов на системе, приложения ничего не знают

# Криптография (без OpenSSL)

- X25519 ECDH — 32-байтные ключи, через kernel crypto API (libcurve25519)
- ChaCha20 — stream cipher, XOR на позиции потока, без изменения размера пакетов
- Poly1305 — AEAD MAC, собственная реализация на 26-битных лимбах
- KDF — ChaCha20 как PRF для деривации 4 ключей (128 байт) из shared secret + ISN
- Защита от timing-атак — сравнение MAC через crypto_memneq (constant-time)
- Forward secrecy — DH-ключи уничтожаются (memzero_explicit) после деривации сессионных ключей

# Модуль нужно загрузить на обе стороны — и на клиент, и на сервер.

```
Шаг | Клиент (tcps.ko)                    | Сервер (tcps.ko)
-----|--------------------------------------|--------------------------------------
1    | SYN + TC option (X25519 pubkey) ───► | Видит TC, сохраняет pubkey клиента
2    |                                      | SYN-ACK + TC option (X25519 pubkey)
3    | ◄──────────────────────────────────── | Оба хоста знают чужой pubkey
4    | X25519(priv, peer_pub) → shared      | X25519(priv, peer_pub) → shared
5    | KDF(shared, ISN) → 4 ключа           | KDF(shared, ISN) → 4 ключа
6    | ◄════════ ChaCha20 + Poly1305 ══════► | Зашифровано + целостность
     | Приложения (nginx/postgres/ssh) ничего не знают
```

Если только одна сторона имеет модуль — TCP option TC не будет в ответе,
и модуль откатится к обычному TCP (без шифрования). Соединение работает как обычно.

# Развёртывание

На сервере и на клиенте (Linux, arm64/amd64):

```bash
cd kernel/
apt install build-essential linux-headers-$(uname -r)
modprobe libcurve25519     # зависимость ядра для X25519
make                       # компилируем tcps.ko
insmod tcps.ko             # загружаем модуль в ядро
```

Любое TCP-подключение между этими машинами автоматически шифруется.
PostgreSQL, HTTP, SSH — что угодно.
Модуль сидит в netfilter (L4), а не на порту. Он видит каждый TCP-пакет, проходящий через ядро.

Выгрузка модуля:
```bash
rmmod tcps
```

# Проверка работы

## dmesg — сессии и ошибки

```bash
dmesg | grep tcps
```

Успешное соединение:
```
tcps: module loaded, ECDH (X25519) + ChaCha20-Poly1305 active
tcps: SYN out 192.168.1.69:41548->192.168.1.127:80 isn=2400457015
tcps: encrypted session 192.168.1.69:41548 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: SYN+ACK in 192.168.1.127:80->192.168.1.69:41548 derived
```

Если только одна сторона имеет модуль — соединение работает, но без шифрования:
```
tcps: SYN+ACK in without TCPS option    ← нет TC option в ответе
```

Ошибка MAC (пакет подделан или повреждён):
```
tcps: MAC verification failed, dropping
```

## tcpdump — визуальная проверка шифрования

```bash
tcpdump -i ens18 -A -s0 tcp
```

Признаки работы модуля в capture:

| Признак | Описание |
|---------|----------|
| `mss 1448` | MSS уменьшен на 12 байт (место для MAC option) |
| `unknown-253` в SYN | TC option с X25519 pubkey (36 байт, magic 'T','C') |
| `unknown-253` в данных | TM option с Poly1305 тегом (12 байт, magic 'T','M') |
| Нечитаемые данные | Payload зашифрован ChaCha20, нет ASCII-текста |

Пример HTTP-запроса через tcps:
```
> SYN:      options [mss 1448, unknown-253 0x5443...]     ← TC option + pubkey
< SYN-ACK:  options [mss 1448, unknown-253 0x5443...]     ← TC option + pubkey
> ACK:      (чистый ACK, без MAC option)
> PSH,ACK:  options [unknown-253 0x544d...], length 77     ← TM option + зашифрованный HTTP
< ACK:      (чистый ACK)
< PSH,ACK:  options [unknown-253 0x544d...], length 156    ← зашифрованный HTTP-ответ
```

Без модуля тот же HTTP-запрос показал бы читаемый текст: `GET / HTTP/1.1`, заголовки, HTML.
С модулем — только бинарный мусор. Приложения (curl, nginx) работают как обычно.

---

License — MIT. Use it, fork it, bypass censorship responsibly.