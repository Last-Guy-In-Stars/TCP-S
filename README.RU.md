### TCP/S — прозрачное шифрование TCP на 4 уровне

*Autor: ArtamonovKA, writed on GLM-5.1*

# Архитектура
```
tcps/
├── kernel/                        # Текущая версия
│   ├── tcps.h                 # Заголовок: состояния, константы, ChaCha20, X25519, TOFU
│   ├── tcps_main.c            # Netfilter hooks, probe option, UDP discovery, TOFU, skip_ports
│   ├── tcps_crypto.c          # ChaCha20 stream cipher + X25519 DH + KDF
│   └── Makefile               # Сборка: make → tcps.ko
```
# Старая v1 (сломана на GSO, не используется)

# Как работает

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — добавляет TCP option **TC** (kind=253, len=4, magic=0x5443) в SYN
2. Netfilter hook PRE_ROUTING — обнаруживает TC option в SYN → создаёт запись соединения
3. SYN-ACK тоже несёт TC option — оба хоста подтвердили поддержку TCPS
4. После handshake — **X25519 ECDH** shared secret → KDF → 2 направленных ключа (c2s, s2c)
5. Все TCP-данные шифруются **ChaCha20** (stream cipher, XOR на позиции потока, размер пакета не меняется)
6. Работает для всех TCP-сокетов на системе, приложения ничего не знают
7. Порты из `skip_ports` (по умолчанию 22) пропускаются — SSH/SCP работают без модификации

# Автообнаружение пиров (UDP discovery)

Каждый хост с модулем вещает свой X25519 публичный ключ по UDP broadcast (порт 54321) каждые 3 секунды.

**Формат пакета:** magic(4B, 0x54435053) + X25519_pubkey(32B) = 36 байт

**Результат:**
- Пиры автоматически обнаруживают друг друга в одной L2-сети
- Публичные ключи сохраняются в TOFU-кеше (IP → pubkey)
- Ручная конфигурация не нужна
- Можно добавить пира вручную: `echo "192.168.1.42=hex_pubkey" > /proc/tcps_peers`

# Криптография (без OpenSSL)

- **X25519 ECDH** — 32-байтные ключи, через kernel crypto API (`libcurve25519`)
- **ChaCha20** — stream cipher, XOR на позиции потока, без изменения размера пакетов
- **KDF** — HKDF-Expand паттерн: `KDF(X25519(my_priv, peer_pub), client_ISN, server_ISN)`
  - `TCPS c2s` (position 0x8000000000000000) — ключ клиент→сервер
  - `TCPS s2c` (position 0x8000000000000040) — ключ сервер→клиент
- Позиция потока вычисляется от ISN + 1 — уникальна для каждого соединения
- Приватные ключи уничтожаются через `memzero_explicit` при выгрузке модуля

# Защита от MITM (TOFU)

**TOFU (Trust On First Use)** — как SSH `StrictHostKeyChecking=accept-new`:

- **Первое соединение**: публичный ключ пира запоминается в TOFU-кеше (IP → pubkey)
  - Уязвимо к MITM при первом обмене — как SSH при первом подключении
- **Последующие**: ключ сверен с TOFU-кешем
  - `strict_tofu=0` (по умолчанию): при смене ключа — предупреждение + обновление (разрешает reload модуля)
  - `strict_tofu=1`: при смене ключа — **блокировка** (защита от MITM, но reload модуля ломает соединения до ручного вмешательства)

**Параметры модуля:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `skip_ports` | 22 | Порты для пропуска (уже зашифрованные, напр. 22 443) |
| `strict_tofu` | 0 | 0=обновлять ключ с warning, 1=блокировать при смене ключа |

```bash
insmod tcps.ko skip_ports=22,443 strict_tofu=1
cat /sys/module/tcps/parameters/strict_tofu
echo 1 > /sys/module/tcps/parameters/strict_tofu
```

# Probe option — обнаружение поддержки TCPS

TCP option kind=253 (экспериментальный диапазон RFC 4727, middleboxes реже стрипают).

| Поле | Значение | Описание |
|------|----------|----------|
| Kind | 253 | Экспериментальный (RFC 4727) |
| Length | 4 | Длина опции |
| Data | 0x5443 | Magic "TC" |

**Поведение при strip опции middlebox'ом:**
- SYN без TC → сервер не создаёт запись → plain TCP
- SYN-ACK без TC → клиент удаляет запись → plain TCP
- Обе стороны корректно откатываются на незашифрованное TCP

# Сценарии работы

## Обе стороны имеют модуль (автообнаружение)

```
Шаг | Клиент (tcps.ko)                         | Сервер (tcps.ko)
-----|-------------------------------------------|-------------------------------------------
1    | SYN + TC option ──────────────────────►   | Видит TC, создаёт conn (PROBE_SYNACK)
2    |                                           | SYN-ACK + TC option
3    | ◄──────────────────────────────────────── |
4    | Видит TC → SYN-ACK → client_isn+server_isn → KDF
5    |                                           | KDF(X25519(my_priv, peer_pub), ISN) → ключи
6    | ◄══════════ ChaCha20 зашифровано ════════► | Оба направления зашифрованы
     | Приложения (nginx/postgres) ничего не знают
```

## Только одна сторона имеет модуль (авто-fallback)

```
Шаг | Клиент (tcps.ko)                         | Сервер (без модуля)
-----|-------------------------------------------|-------------------------------------------
1    | SYN + TC option ──────────────────────►   | Игнорирует unknown option 253
2    |                                           | SYN-ACK (без TC option)
3    | ◄──────────────────────────────────────── |
4    | Нет TC в SYN-ACK → удалить conn           |
5    | data (без модификации) ────────────────►  | Обычные данные
     | apt-get update, DNS, curl — всё работает!
```

## Downgrade-атака (strip TC option)

Если MITM стрипает TC option из SYN или SYN-ACK — обе стороны откатываются на plain TCP.

**Ограничение:** если middlebox стрипает асимметрично (только в одном направлении) — одна сторона шифрует, другая нет → порча данных. Это нерешаемо без end-to-end верификации внутри зашифрованного канала.

# Перезагрузка модуля (reload)

При `rmmod` + `insmod`:
1. Генерируется **новый** X25519 keypair
2. Таблица соединений очищается
3. TOFU-кеш очищается
4. UDP discovery обновляет ключи на других хостах

**Влияние на соединения:**

| Этап | SSH (port 22) | Другие TCP |
|------|---------------|------------|
| Модуль загружен | OK (skip) | Зашифрованы |
| `rmmod` | OK (без модуля) | Существующие ломаются — другая сторона пытается расшифровать чистый трафик |
| `insmod` (до discovery) | OK | Новые — слабые ключи (нет пира), старые — сломаны |
| После discovery | OK | Новые — полный DH, работают корректно |

**`strict_tofu=0` (по умолчанию):** при reload ключ на другой стороне обновляется автоматически с предупреждением `TOFU key change for <ip> (updating)`.

**`strict_tofu=1`:** при reload ключ не обновляется → новые соединения используют несовпадающий DH → порча данных. Требуется ручная запись в `/proc/tcps_peers` или перезагрузка модуля на обеих сторонах.

# Развёртывание

На сервере и на клиенте (Linux, amd64, kernel 6.x):

```bash
cd v2/
apt install build-essential linux-headers-$(uname -r)
modprobe curve25519-x86
make
insmod tcps.ko
```

Любое TCP-подключение между этими машинами автоматически шифруется.
PostgreSQL, HTTP, Redis — что угодно. Соединения к машинам без модуля — plain TCP.

Выгрузка модуля:
```bash
rmmod tcps
```

# Проверка работы

## dmesg

```bash
dmesg | grep tcps
```

Загрузка модуля:
```
tcps: X25519 identity generated, pubkey=4ea7a766cdcfd414...
tcps: module loaded, X25519 + ChaCha20 + TOFU active
```

Обнаружение пира:
```
tcps: TOFU added peer 192.168.1.42
```

Смена ключа (при reload модуля на другой стороне):
```
tcps: TOFU key change for 192.168.1.42 (updating)
```

Strict TOFU блокировка:
```
tcps: STRICT TOFU: key change BLOCKED for 192.168.1.42
```

## /proc/tcps_peers

```bash
cat /proc/tcps_peers
# 192.168.1.42=a4db7a69021ad4f18efdd4d5982b89e97a57e4cf044281f88b684d8a7cb1c03f

# Добавить пира вручную:
echo "192.168.1.42=a4db7a69021ad4f1...hex_pubkey" > /proc/tcps_peers
```

## tcpdump — визуальная проверка шифрования

```bash
tcpdump -i ens18 -A -s0 tcp
```

| Признак | Описание |
|---------|----------|
| `unknown-253` в SYN | TC probe option (4 байта, magic 0x5443) |
| Нечитаемые данные | Payload зашифрован ChaCha20 |
| Читаемые данные | Plain TCP — пир без модуля или skip_ports |

# Свойства безопасности

| Свойство | Механизм |
|----------|----------|
| Шифрование | ChaCha20 stream cipher (XOR на позиции потока) |
| Обмен ключами | X25519 ECDH через kernel crypto API |
| Направленные ключи | KDF с уникальными лейблами c2s/s2c |
| MITM-защита | TOFU + strict_tofu (блокировка при смене ключа) |
| Downgrade-защита | Probe option — отсутствие → fallback на plain TCP |
| Auto-discovery | UDP broadcast (порт 54321) — ручная конфигурация не нужна |
| Skip ports | Порт 22 пропускается — SSH/SCP не затрагиваются |
| Приватность ключей | memzero_explicit, только в RAM, на диск не пишутся |

# Известные ограничения

| Ограничение | Описание |
|-------------|----------|
| IPv4 only | IPv6 пока не поддерживается |
| Нет AEAD/MAC | ChaCha20 без Poly1305 — целостность не проверяется, подмена данных возможна |
| First-use trust | Первое соединение к новому пиру уязвимо к MITM (как SSH) |
| TOFU in-memory | Теряется при rmmod, ключи на диск не сохраняются |
| Reload ломает соединения | Существующие TCP-сессии ломаются при rmmod/insmod (таблица соединений очищается) |
| Асимметричный strip | Если middlebox режет TC option только в одном направлении — порча данных |
| Нет forward secrecy | X25519 keypair один на модуль, ротации внутри сессии нет |
| UDP discovery spoof | Атакующий в L2-сети может подменить публичный ключ в UDP broadcast |
| Unknown peer = weak keys | Если пир не обнаружен, DH secret = нули (шифрование формально есть, но без защиты) |
