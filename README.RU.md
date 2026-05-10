### TCP/S — прозрачное шифрование TCP на 4 уровне

*Autor: ArtamonovKA, writed on GLM-5.1*

# Архитектура
```
tcps/
├── v3/                        # Текущая версия (X25519 + ChaCha20-Poly1305 + PSK + forward secrecy)
│   ├── tcps.h                 # Заголовок: состояния, константы, ChaCha20, Poly1305, X25519, PSK, ct_memcmp
│   ├── tcps_main.c            # Netfilter hooks, probe option, TOFU unicast discovery, PSK verify, key rotation, GSO, rate-limit
│   ├── tcps_crypto.c          # ChaCha20 + Poly1305 + X25519 (self-contained, __int128) + KDF + PSK derivation
│   └── Makefile               # Сборка: make → tcps.ko
├── v2/                        # X25519 DH + ChaCha20 + TOFU (без init-key exchange)
├── kernel/                    # Старая v1 (сломана на GSO, не используется)
└── README.md
```

# Как работает

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — добавляет TCP option **TC** (kind=253, len=4, magic=0x5443) в SYN
2. Netfilter hook PRE_ROUTING — обнаруживает TC option в SYN → создаёт запись соединения
3. SYN-ACK тоже несёт TC option — оба хоста подтвердили поддержку TCPS
4. После handshake — **PSK** (из init-key exchange) → KDF → 4 направленных ключа (enc_c2s, enc_s2c, mac_c2s, mac_s2c)
5. Все TCP-данные шифруются **ChaCha20** (stream cipher, XOR на позиции потока, размер payload не меняется)
6. Каждый пакет с данными подписывается **Poly1305 MAC** — **16-байтовый полный тег** добавляется как payload suffix
7. При приёме: тег извлекается из конца payload, верифицируется, затем `skb_trim` + корректировка `iph->tot_len`
8. MSS уменьшается на 16 байт в SYN/SYN-ACK (чтобы итоговый пакет не превысил MTU)
9. Работает для всех TCP-сокетов на системе, приложения ничего не знают
10. Порты из `skip_ports` (по умолчанию 22) пропускаются — SSH/SCP работают без модификации
11. Loopback-соединения (127.x.x.x) пропускаются
12. GSO-пакеты обрабатываются: GSO отключается на сокете (`sk_gso_type=0`), при race window — программная сегментация + шифрование каждого сегмента
13. Socket memory accounting: `skb->truesize` и `sk_rmem_alloc` корректируются для совместимости с TCP flow control

# Init-key exchange — протокол обмена ключами

Каждый узел при загрузке генерирует **init_key** (random 32B) → **pub_key** = curve25519(init_key, base).

**TOFU unicast discovery (порт 54321):**

Обнаружение пиров не использует broadcast:

1. SYN с TC option триггерит unicast DISCOVER на IP пира (через workqueue)
2. Фоновый поток отправляет DISCOVER пирам без PSK (из TOFU таблицы)
3. При ротации ключей — unicast DISCOVER всем пирам из TOFU

```
Узел A (отправляет SYN)           Узел B (получает SYN с TC)
  |                                  |
  | SYN + TC option ──────────────►  |  tcps_in видит TC → tcps_trigger_discover(A)
  |                                  |
  |◄── DISCOVER(pub_A) ──────────── |  unicast, type=0x01 (из workqueue)
  |                                  |
  |── KEYXCHG(pub_B, enc(init_B)) ► |  unicast, type=0x02
  |    enc = ChaCha20(DH(init_B, pub_A), init_B)
  |                                  |
  |◄── KEYXCHG(pub_A, enc(init_A))─ |  unicast
  |    enc = ChaCha20(DH(init_A, pub_B), init_A)
  |                                  |
  |  PSK = KDF(DH_shared, init_A, init_B)  — одинаков на обеих сторонах
```

**DH consistency при ротации:**

1. При ротации отправляется DISCOVER (не KEYXCHG) → получатель отвечает KEYXCHG с текущим pubkey
2. Получатель пытается расшифровать init_key с текущим и предыдущим init_key (prev_init_key)
3. Проверка: `curve25519(decrypted_init) == pkt.pubkey`

**Rate-limit на discovery (порт 54321):**

| Лимит | Значение | Описание |
|-------|----------|----------|
| Per-IP | 1 пакет / 2 сек | Не более одного DISCOVER/KEYXCHG от одного IP за 2 секунды |
| Global | 10 пакетов / сек | Не более 10 KEYXCHG операций в секунду всего |
| Slots | 16 | Количество отслеживаемых IP-адресов |

Защищает от CPU-DoS (curve25520 ~2-4 операции на KEYXCHG) и от переполнения TOFU-таблицы.

**Формат пакетов:**

| Тип | Размер | Содержание |
|-----|--------|-----------|
| DISCOVER (0x01) | 37B | magic(4) + type(1) + pub_key(32) |
| KEYXCHG (0x02) | 69B | magic(4) + type(1) + pub_key(32) + enc_init_key(32) |
| KEYXCHG_AUTH (0x03) | 85B | magic(4) + type(1) + pub_key(32) + enc_init_key(32) + auth_tag(16) |

**PSK derivation:**
- `DH_shared = X25519(my_init_key, peer_pub_key)`
- Init keys упорядочены по публичному ключу (memcmp) → детерминированный порядок
- `PSK = ChaCha20_KDF(DH_shared, "TCPS-PSK" || init_key_low || init_key_high)`

**DH fallback PSK** (когда PSK ещё не установлен):
- `PSK_fallback = ChaCha20_KDF(DH_shared, "TCPS-FB")`
- Если DH shared = все нули (low-order point attack) → fallback к нулевому PSK с предупреждением

# Poly1305 MAC — 16-байтовый payload suffix

Каждый зашифрованный пакет содержит **полный 16-байтовый Poly1305 тег** в конце payload:

```
| IP header | TCP header | encrypted payload | MAC tag (16B) |
```

**MAC вычисляется:**
- Одноразовый ключ Poly1305 = ChaCha20(mac_key, pos+32, zeros, 32)
- AAD = flags(1) + seq(4), padded до 16 байт
- Вход: AAD || encrypted_payload(padded до 16) || len(aad)_le64 || len(payload)_le64
- Полный 16-байтовый тег (2^128 forgery resistance)
- Сравнение тега — constant-time (`tcps_ct_memcmp`)

**При отправке (tcps_out):**
1. Шифрование ChaCha20 на позиции потока
2. Вычисление Poly1305 тега
3. Добавление тега через `skb_put(skb, 16)`
4. `skb->truesize += 16` (socket memory accounting)
5. `iph->tot_len += 16`
6. Пересчёт чексумм

**При приёме (tcps_in):**
1. Извлечение последних 16 байт payload как тега
2. Верификация Poly1305 MAC
3. `skb_trim(skb, skb->len - 16)` — удаление тега
4. `atomic_sub(16, &skb->sk->sk_rmem_alloc)` + `skb->truesize -= 16` (socket accounting)
5. `iph->tot_len -= 16`
6. Расшифровка ChaCha20
7. Пересчёт чексумм

**MSS adjustment:** SYN и SYN-ACK содержат уменьшенный MSS (на 16 байт), чтобы итоговый пакет с MAC не превысил MTU.

**4 ключа на соединение** (через `tcps_derive_keys`):
- `enc_key` (c2s) — шифрование исходящих
- `dec_key` (s2c) — расшифровка входящих
- `mac_enc_key` (cmac) — MAC исходящих
- `mac_dec_key` (smac) — MAC входящих

**Поведение:**
- RST без MAC в KEYED-состоянии → DROP
- Данные без MAC после `peer_has_mac` → DROP
- GSO-пакеты: сегментация + MAC на каждый сегмент + реинжекция

# KEYXCHG_AUTH — аутентификация ротации ключей

При ротации init-key модуль отправляет KEYXCHG_AUTH:

```
KEYXCHG_AUTH = KEYXCHG + auth_tag
auth_tag = Poly1305(prev_psk, 0, type+pubkey+enc_init, 65, NULL, 0)  [16 байт]
```

**Защита от downgrade:**
- Если тег совпадает → KEYXCHG_AUTH verified
- Если тег не совпадает → WARN, продолжить как plain KEYXCHG
- Если KEYXCHG без AUTH, но у нас есть prev_psk → WARN (peer reload?)

# Forward secrecy (ротация init-key)

Каждые 3600 секунд (TCPS_KEY_ROTATE_INTERVAL):
1. Генерируется новая пара init_key / pub_key
2. Старый PSK сохраняется как prev_psk (для KEYXCHG_AUTH)
3. Unicast DISCOVER отправляется всем пирам из TOFU таблицы
4. Старый init_key сохраняется как prev_init_key (для DH retry)
5. Новые соединения используют новый PSK
6. Существующие соединения продолжают на старых ключах

# Out-of-band верификация PSK (MITM-защита)

**Проблема:** MITM может подменить публичные ключи в UDP обмене → оба узла получат разные PSK.

**Решение:** PSK fingerprint — первые 8 байт PSK:

```bash
# На узле A:
cat /proc/tcps_peers
# 192.168.1.42 pub=... psk=unverified fp=02f9b20aad44590b

# На узле B:
cat /proc/tcps_peers
# 192.168.1.151 pub=... psk=unverified fp=02f9b20aad44590b

# Подтвердить:
echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers
```

**Параметр `psk_require_verify`:**

| Режим | До verify | После verify |
|---|---|---|
| `psk_require_verify=0` (по умолчанию) | Полный PSK сразу | Полный PSK |
| `psk_require_verify=1` | DH fallback (слабее) | Полный PSK |

# Защита от MITM (TOFU + PSK verify + KEYXCHG_AUTH)

**Трёхуровневая защита:**

1. **TOFU** — детектирует смену публичного ключа:
   - `strict_tofu=0`: предупреждает + обновляет
   - `strict_tofu=1`: блокирует

2. **PSK verify** — детектирует MITM при первом обмене:
   - Fingerprint совпадает → нет MITM → verify → полный PSK
   - Fingerprint не совпадает → MITM → не подтверждать → DH fallback

3. **KEYXCHG_AUTH** — детектирует MITM при ротации ключей:
   - Auth tag совпадает → ротация легитимна
   - Auth tag не совпадает → старый PSK сохраняется

# Криптография (без внешних зависимостей)

Вся криптография — **self-contained**, не зависит от kernel crypto API или OpenSSL. Портабельна на FreeBSD/другие Unix.

- **X25519 ECDH** — self-contained donna-style реализация с `__int128` для fe_mul
  - 64-bit limb representation (5 × 64-bit)
  - donna-style overlapping loads/stores для fe_load/fe_store
  - crecip exponent chain для fe_inv
  - Проверка all-zero shared secret (low-order point attack) → -EINVAL

- **ChaCha20** — stream cipher, XOR на позиции потока
  - 64-bit counter, nonce=0 (уникальность через отдельные ключи на соединение)
  - Временные блоки keystream (`blk[]`) обнуляются после использования
  - Позиция потока отслеживает 32-битные wrap-around (seq_hi)

- **Poly1305 MAC** — self-implemented (26-bit limb), полный 16-байтовый тег
  - Корректная финализация: carry через `>> 26`, редукция по `2^130-5`, sign-bit mask
  - Одноразовый ключ = ChaCha20(mac_key, pos+32, zeros, 32)
  - AAD: flags(1) + seq(4), padded до 16 байт
  - Сравнение тега — constant-time (`tcps_ct_memcmp`)

- **PSK derivation** — `KDF = ChaCha20_KDF(DH_shared, "TCPS-PSK" || init_key_A || init_key_B)`
  - Init keys упорядочены по публичному ключу (детерминировано)
  - Domain label "TCPS-PSK" разделяет PSK от других KDF позиций

- **Per-connection KDF** — `KDF(PSK, client_ISN, server_ISN)` → 4 ключа
  - `TCPS c2s` (position 0x8000000000000000) — enc_key
  - `TCPS s2c` (position 0x8000000000000040) — dec_key
  - `TCPS cmac` (position 0x8000000000000080) — mac_enc_key
  - `TCPS smac` (position 0x80000000000000C0) — mac_dec_key

- Приватные ключи уничтожаются через `memzero_explicit` при выгрузке модуля

# Socket memory accounting

При добавлении/удалении MAC тега (16B) необходимо корректировать socket memory accounting, иначе TCP flow control ограничивает throughput до ~1.68 Mbps.

**Отправка (tcps_out):**
- `skb->truesize += TCPS_MAC_SIZE` — добавленный тег увеличивает реальный размер буфера
- Без этой корректировки: `sk_wmem_alloc` рассинхронизируется → TCP stack throttles sending

**Приём (tcps_in):**
- `atomic_sub(TCPS_MAC_SIZE, &skb->sk->sk_rmem_alloc)` — вернуть начисленные 16 байт
- `skb->truesize -= TCPS_MAC_SIZE` — уменьшить реальный размер буфера
- Без этой корректировки: `sk_rmem_alloc` накапливает 16 лишних байт на пакет → TCP окно сжимается → 1.68 Mbps

# GSO-обработка (Generic Segmentation Offload)

**Проблема:** GSO позволяет TCP создавать большие сегменты (до 64KB), которые сегментируются NIC или ядром ПОСЛЕ netfilter hook.

**Решение — комбинированный подход:**

1. **Первичный механизм:** При первом KEYED-пакете устанавливается `sk->sk_gso_type = 0` — TCP перестаёт создавать GSO-сегменты

2. **Fallback (race window):** Если GSO-пакет успел создаться до установки `sk_gso_type=0`:
   - `skb_gso_segment(skb, 0)` — программная сегментация
   - Каждый сегмент: линеаризация → шифрование ChaCha20 → Poly1305 MAC (16B suffix)
   - Сегменты реинжектируются через `ip_local_out()` с `skb->mark = TCPS_SKB_MARK`

**Производительность:**
- iperf3: ~128 Mbps (с GSO на NIC)
- curl/nginx: ~93 Mbps
- Baseline без модуля: ~2.76 Gbps
- Накладные расходы: per-packet ChaCha20 + Poly1305, GSO сегментация, `skb_linearize`

# Probe option — обнаружение поддержки TCPS

TCP option kind=253 (экспериментальный диапазон RFC 4727):

| Поле | Значение | Описание |
|------|----------|----------|
| Kind | 253 | Экспериментальный (RFC 4727) |
| Length | 4 | Длина опции |
| Data | 0x5443 | Magic "TC" |

**Middlebox fallback:**
- SYN без TC → сервер не создаёт запись → plain TCP
- SYN-ACK без TC → клиент удаляет запись → plain TCP

# Сценарии работы

## Обе стороны имеют модуль (PSK exchange)

```
Шаг | Узел A (tcps.ko)                         | Узел B (tcps.ko)
-----|-------------------------------------------|-------------------------------------------
1    | SYN + TC option ──────────────────────►   | Видит TC, создаёт conn, trigger DISCOVER
2    |                                           | SYN-ACK + TC option
3    | ◄──────────────────────────────────────── |
4    | KDF(PSK, client_ISN, server_ISN) → 4 ключа| KDF(PSK, client_ISN, server_ISN) → 4 ключа
5    | ◄══════════ ChaCha20 + Poly1305 ═══════►  | Каждое направление: шифрование + 16B MAC suffix
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
```

# Перезагрузка модуля (reload)

При `rmmod` + `insmod`:
1. Init_key **по умолчанию только в RAM** (нет файла на диске)
2. При загрузке — если `key_file` не задан → генерируется новый init_key (forward secrecy при rmmod)
3. При загрузке — если `key_file=/etc/tcps/init_key` → загружается из файла → **тот же pubkey** → TOFU/PSK сохраняются
4. Файл ключа — права 0600, root-only
5. Таблица соединений очищается при rmmod (существующие TCP-сессии ломаются)

**Параметры модуля:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `skip_ports` | 22 | Порты для пропуска (уже зашифрованные) |
| `strict_tofu` | 0 | 0=обновлять ключ с warning, 1=блокировать при смене |
| `psk_require_verify` | 0 | 0=PSK сразу, 1=требовать verify перед полным PSK |
| `rotate_interval` | 3600 | Интервал ротации init-key в секундах |
| `key_file` | (пустой) | Файл для сохранения init-key (напр. /etc/tcps/init_key) |

```bash
insmod tcps.ko skip_ports=22,443 strict_tofu=1 psk_require_verify=1 key_file=/etc/tcps/init_key
```

# Аудит безопасности

## CRITICAL (5 исправлений)

| # | Уязвимость | Исправление |
|---|-----------|-------------|
| C-1 | Poly1305: сломанный carry + модуль `2^128-5` вместо `2^130-5` | Carry через `>> 26`, редукция `2^130-5`, sign-bit mask |
| C-2 | `memcmp` timing side-channel на MAC теге | `tcps_ct_memcmp()` — constant-time XOR-аккумуляция |
| C-3 | MAC усечён до 4 байт (32-bit security) | Полный 16-байтовый Poly1305 тег как payload suffix |
| C-4 | `kfree` на `rcu_head` offset → освобождает неправильный адрес | `tcps_peer_free_rcu()` с `container_of` + `memzero_explicit` |
| C-5 | Zero PSK при ошибке DH → шифрование нулевым ключом | Проверка all-zero DH shared; `tcps_derive_psk_fallback()` |

## HIGH (9 исправлений)

| # | Уязвимость | Исправление |
|---|-----------|-------------|
| H-1 | PSK читается без блокировки (torn read при ротации) | `spin_lock(&tcps_peers_lock)` в `tcps_peer_get_psk()` |
| H-2 | Нет проверки all-zero DH shared secret | `tcps_dh_shared()` возвращает -EINVAL для all-zero |
| H-3 | GSO пакеты шифруются без MAC | GSO отключается + fallback сегментация + MAC на каждый сегмент |
| H-4 | `spin_lock` вместо `spin_lock_bh` → deadlock | Все блокировки в hook → `spin_lock_bh` |
| H-5 | Дублирование соединений при SYN retransmit | `tcps_conn_add_unique()` — lookup перед add |
| H-6 | seq wrap на 4GB → keystream reuse | `enc_seq_hi`/`dec_seq_hi` отслеживают 32-битный wrap |
| H-7 | Дешифровка без MAC при `peer_has_mac` | NF_DROP когда `peer_has_mac && no_tag` |
| H-8 | Module exit не flush workqueue → use-after-free | `flush_scheduled_work()` в `tcps_exit()` |
| H-9 | UDP 54321 без rate-limit → CPU DoS | Per-IP (1/2с) + global (10/с) rate limiting |

## MEDIUM (9 исправлений)

| # | Уязвимость | Исправление |
|---|-----------|-------------|
| M-1 | ChaCha20 `blk[]` keystream остаётся на стеке | `memzero_explicit(blk)` после каждого блока |
| M-2 | KDF label buffer overflow | `strlen` ограничен 31 байтом |
| M-3 | KEYXCHG_AUTH без prev_psk → REJECT блокирует | WARN + принять как plain KEYXCHG |
| M-4 | Парсер TCP опций сканирует в payload | `tcps_opt_end()` ограничивает scan до `th->doff*4` |
| M-5 | FIN устанавливает DEAD слишком рано | FIN ставит `kill=1`, state остаётся KEYED |
| M-6 | `kernel_sendmsg` внутри `rcu_read_lock` | Сбор адресов под RCU, отправка вне RCU |
| M-7 | `tcps_recalc_csum` с отрицательным tcplen | Проверка `tcplen < sizeof(tcphdr)` |
| M-8 | Неограниченная таблица пиров | `TCPS_MAX_PEERS=64` с атомарным счётчиком |
| M-9 | MAC и шифрование на одной позиции keystream | MAC на `pos+32` (offset на 1 блок ChaCha20) |

## LOW/INFO (оставлено)

| Уязвимость | Причина |
|-----------|---------|
| ACK-only пакеты без MAC | Нет payload → нет тега |
| RST в открытом виде | Частичная защита: RST без MAC при peer_has_mac → DROP |
| Первый обмен уязвим к MITM | Обнаруживается через fingerprint verify |
| Нет version negotiation | Текущая версия — единственная |

# Развёртывание

На сервере и на клиенте (Linux, amd64, kernel 6.x):

```bash
cd v3/
apt install build-essential linux-headers-$(uname -r)
make
insmod tcps.ko psk_require_verify=1
```

Верификация PSK (на обеих машинах):
```bash
cat /proc/tcps_peers
# Узел A: 192.168.1.42 ... psk=unverified fp=02f9b20aad44590b
# Узел B: 192.168.1.151 ... psk=unverified fp=02f9b20aad44590b

echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers
```

Выгрузка:
```bash
rmmod tcps
```

# Проверка работы

## dmesg

```bash
dmesg | grep tcps
```

Загрузка:
```
tcps: X25519 init-key generated, pubkey=4ea7a766cdcfd414...
tcps: module loaded, X25519+ChaCha20-Poly1305+PSK+FS active (rotate=3600s)
```

PSK установлен:
```
tcps: TOFU added peer 192.168.1.42
tcps: PSK established with 192.168.1.42 fingerprint=b063826598bc8201
```

Ротация ключей:
```
tcps: init-key ROTATED, new pubkey=1a2b3c4d...
tcps: KEYXCHG_AUTH verified from 192.168.1.42
tcps: PSK established with 192.168.1.42 fingerprint=5e6f7a8b...
```

## /proc/tcps_peers

```bash
cat /proc/tcps_peers
# 192.168.1.42 pub=d2a7929b... psk=verified fp=02f9b20aad44590b

echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers
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
| Payload на 16B больше ожидаемого | Poly1305 tag suffix |

# Производительность

| Метрика | С модулем | Без модуля (baseline) |
|---------|-----------|----------------------|
| iperf3 (10s) | 128 Mbps | 2.76 Gbps |
| curl (100MB) | 93 Mbps | ~1 Gbps |
| MAC failures | 0 | — |
| Retries | 14 (только initial) | 0 |

Накладные расходы: per-packet ChaCha20 + Poly1305, GSO сегментация, `skb_linearize`.

# Свойства безопасности

| Свойство | Механизм |
|----------|----------|
| Шифрование | ChaCha20 stream cipher (XOR на позиции потока) |
| Целостность данных | Poly1305 MAC (16B полный тег) + constant-time verify + DROP без MAC |
| Обмен ключами | X25519 ECDH (self-contained) + init-key exchange → PSK |
| Low-order point защита | Проверка all-zero DH shared → fallback |
| PSK derivation | KDF(DH_shared, "TCPS-PSK"\|\|init_key_A\|\|init_key_B) — domain-separated |
| Направленные ключи | Per-connection KDF(PSK, ISN) с лейблами c2s/s2c/cmac/smac |
| MAC/enc разделение | MAC на pos+32, encryption на pos — разные блоки keystream |
| Forward secrecy | Ротация init-key (3600с), KEYXCHG_AUTH |
| MITM-защита (первый обмен) | PSK fingerprint + out-of-band verify |
| MITM-защита (повторный) | TOFU + strict_tofu |
| MITM-защита (ротация) | KEYXCHG_AUTH — Poly1305 через prev_psk |
| DH consistency при ротации | DISCOVER + prev_init_key retry + curve25519 verify |
| Discovery DoS защита | Rate-limit: per-IP (1/2с) + global (10/с) |
| RST injection защита | RST без MAC в KEYED → DROP |
| Bit-flipping защита | Данные без MAC при peer_has_mac → DROP |
| Timing attack защита | `tcps_ct_memcmp` для MAC и KEYXCHG_AUTH |
| Downgrade-защита | Probe option — отсутствие → fallback на plain TCP |
| Socket accounting | `skb->truesize` + `sk_rmem_alloc` корректировки |
| Peer limit | Max 64 пира (TCPS_MAX_PEERS) |
| RCU/lifecycle | Правильные RCU callbacks, flush_scheduled_work() при unload |

# Известные ограничения

| Ограничение | Описание |
|-------------|----------|
| IPv4 only | IPv6 пока не поддерживается |
| First-use MITM | Первый обмен уязвим к MITM (обнаруживается через fingerprint) |
| PSK verify ручной | Оператор должен сравнить fingerprint на обеих машинах |
| Keypair persistence | Опционально: `key_file=` → файл 0600; без — только RAM |
| Reload ломает соединения | Существующие TCP-сессии ломаются при rmmod/insmod |
| ACK-only без MAC | Пакеты без payload не подписываются |
| RST в открытом виде | Частичная защита: RST без MAC при peer_has_mac → DROP |
| Нет version negotiation | Изменения протокола несовместимы |
| Throughput overhead | ~5% от baseline из-за per-packet crypto + GSO segmentation |
