### TCP/S — прозрачное шифрование TCP на 4 уровне

*Autor: ArtamonovKA, writed on GLM-5.1*

# Архитектура
```
tcps/
├── v3/                        # Текущая версия (X25519 init-key exchange + ChaCha20-Poly1305 + PSK + forward secrecy)
│   ├── tcps.h                 # Заголовок: состояния, константы, ChaCha20, Poly1305, X25519, PSK, ct_memcmp
│   ├── tcps_main.c            # Netfilter hooks, probe/TM options, TOFU unicast discovery, PSK verify, key rotation
│   ├── tcps_crypto.c          # ChaCha20 stream cipher + Poly1305 MAC + X25519 DH + KDF + PSK derivation
│   └── Makefile               # Сборка: make → tcps.ko
```

# Как работает

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — добавляет TCP option **TC** (kind=253, len=4, magic=0x5443) в SYN
2. Netfilter hook PRE_ROUTING — обнаруживает TC option в SYN → создаёт запись соединения
3. SYN-ACK тоже несёт TC option — оба хоста подтвердили поддержку TCPS
4. После handshake — **PSK** (выведенный из init-key exchange) → KDF → 4 направленных ключа (enc_c2s, enc_s2c, mac_c2s, mac_s2c)
5. Все TCP-данные шифруются **ChaCha20** (stream cipher, XOR на позиции потока, размер пакета не меняется)
6. Каждый пакет с данными подписывается **Poly1305 MAC** (TM option, kind=253, len=8, tag=4 байта)
7. Работает для всех TCP-сокетов на системе, приложения ничего не знают
8. Порты из `skip_ports` (по умолчанию 22) пропускаются — SSH/SCP работают без модификации
9. Loopback-соединения (127.x.x.x) пропускаются
10. GSO-пакеты пропускаются целиком (невозможно аутентифицировать без тега в каждом сегменте)

# Init-key exchange — протокол обмена ключами

Каждый узел при загрузке генерирует **init_key** (random 32B) → **pub_key** = curve25519(init_key, base).

**TOFU unicast discovery (порт 54321):**

Обнаружение пиров больше не использует broadcast. Вместо этого:

1. SYN с TC option триггерит unicast DISCOVER на IP пира (через workqueue)
2. Фоновый поток отправляет DISCOVER пирам без PSK (из TOFU таблицы)
3. При ротации ключей — unicast DISCOVER всем пирам из TOFU (отправка DISCOVER вместо KEYXCHG обеспечивает DH consistency — обе стороны используют текущие pubkey из пакетов)

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

Когда оба узла ротируют ключи одновременно, DH shared может не совпасть (отправитель использует старый pubkey пира из TOFU, а получатель — новый pubkey отправителя из пакета). Решение:

1. При ротации отправляется DISCOVER (не KEYXCHG) → получатель отвечает KEYXCHG с текущим pubkey
2. Получатель пытается расшифровать init_key с текущим и предыдущим init_key (prev_init_key сохраняется при ротации)
3. Проверка: `curve25519(decrypted_init) == pkt.pubkey` — если совпадает, DH shared корректный
4. Это гарантирует DH consistency даже при одновременной ротации
```

**Формат пакетов:**

| Тип | Размер | Содержание |
|-----|--------|-----------|
| DISCOVER (0x01) | 37B | magic(4) + type(1) + pub_key(32) |
| KEYXCHG (0x02) | 69B | magic(4) + type(1) + pub_key(32) + enc_init_key(32) |
| KEYXCHG_AUTH (0x03) | 73B | magic(4) + type(1) + pub_key(32) + enc_init_key(32) + auth_tag(4) |

**PSK derivation:**
- `DH_shared = X25519(my_init_key, peer_pub_key)`
- Init keys упорядочены по публичному ключу (memcmp) → детерминированный порядок
- `PSK = ChaCha20_KDF(DH_shared, "TCPS-PSK" || init_key_low || init_key_high)`

**DH fallback PSK** (когда PSK ещё не установлен):
- `PSK_fallback = ChaCha20_KDF(DH_shared, "TCPS-FB")` — отдельная позиция в keystream
- Если DH shared = все нули (low-order point attack) → fallback к нулевому PSK с предупреждением

**Результат:** оба узла получают одинаковый PSK без передачи init_key в открытом виде.

# Poly1305 MAC (TM option)

Каждый пакет с зашифрованными данными содержит TM TCP option с 4-байтовым тегом Poly1305:

| Поле | Значение | Описание |
|------|----------|----------|
| Kind | 253 | Экспериментальный (RFC 4727) |
| Length | 8 | Длина опции |
| Magic | 0x544D | "TM" |
| Tag | 4 байта | Poly1305 MAC (усечённый до 4 байт) |

**MAC вычисляется:**
- Одноразовый ключ Poly1305 = ChaCha20(mac_key, pos+32, zeros, 32) — offset +32 от позиции шифрования
- AAD = flags(1) + seq(4), padded до 16 байт
- Вход: AAD || encrypted_payload(padded до 16) || len(aad)_le64 || len(payload)_le64
- Tag усекается до 4 байт (2^32 forgery resistance)
- Сравнение тега — constant-time (`tcps_ct_memcmp`), защита от timing-атаки

**4 ключа на соединение** (через `tcps_derive_keys`):
- `enc_key` (c2s) — шифрование исходящих
- `dec_key` (s2c) — расшифровка входящих
- `mac_enc_key` (cmac) — MAC исходящих
- `mac_dec_key` (smac) — MAC входящих

**Поведение:**
- TM option НЕ удаляется при приёме — TCP stack игнорирует неизвестный kind=253
- GSO-пакеты пропускаются целиком (без шифрования и MAC) — нельзя аутентифицировать сегменты
- RST без MAC в KEYED-состоянии → DROP (защита от инъекции)
- Данные без MAC после `peer_has_mac` → DROP (защита от bit-flipping)

# KEYXCHG_AUTH — аутентификация ротации ключей

При ротации init-key модуль отправляет KEYXCHG_AUTH вместо KEYXCHG:

```
KEYXCHG_AUTH = KEYXCHG + auth_tag
auth_tag = Poly1305(prev_psk, 0, type+pubkey+enc_init, 65, NULL, 0)  [4 байта]
```

**Защита от downgrade:**
- Получатель проверяет auth_tag с prev_psk (constant-time сравнение)
- Если тег совпадает → KEYXCHG_AUTH verified (ротация легитимна)
- Если тег не совпадает → WARN, продолжить как plain KEYXCHG (prev_psk рассинхронизирован при одновременной ротации)
- Если KEYXCHG без AUTH, но у нас есть prev_psk → WARN (peer reload?)
- Если KEYXCHG_AUTH без prev_psk → WARN, принять как plain KEYXCHG

# Forward secrecy (ротация init-key)

Каждые 3600 секунд (TCPS_KEY_ROTATE_INTERVAL):
1. Генерируется новая пара init_key / pub_key
2. Старый PSK сохраняется как prev_psk (для KEYXCHG_AUTH)
3. Unicast DISCOVER отправляется всем пирам из TOFU таблицы → пиры отвечают KEYXCHG с текущими pubkey (DH consistency)
4. Старый init_key сохраняется как prev_init_key (для DH retry при расшифровке KEYXCHG)
5. Новые соединения используют новый PSK
6. Существующие соединения продолжают на старых ключах

# Out-of-band верификация PSK (MITM-защита)

**Проблема:** MITM может подменить публичные ключи в UDP обмене → оба узла получат разные PSK → MITM может расшифровывать обе стороны.

**Решение:** PSK fingerprint — первые 8 байт PSK, показываемые на обеих сторонах. Оператор сравнивает:

```bash
# На узле A:
cat /proc/tcps_peers
# 192.168.1.42 pub=... psk=unverified fp=02f9b20aad44590b

# На узле B:
cat /proc/tcps_peers
# 192.168.1.151 pub=... psk=unverified fp=02f9b20aad44590b
#                                              ^^^^^^^^^^^^^^^^ СОВПАДАЕТ!

# Подтвердить (если fingerprint совпадает):
echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers

# Если НЕ совпадает → MITM! Не подтверждать.
```

**Параметр `psk_require_verify`:**

| Режим | До verify | После verify |
|---|---|---|
| `psk_require_verify=0` (по умолчанию) | Полный PSK сразу | Полный PSK |
| `psk_require_verify=1` | DH fallback (слабее) | Полный PSK |

При `psk_require_verify=1`: соединения к неверифицированным пирам используют DH fallback (без init_key). После ручной верификации — полный PSK.

# Защита от MITM (TOFU + PSK verify + KEYXCHG_AUTH)

**Трёхуровневая защита:**

1. **TOFU** — детектирует смену публичного ключа:
   - `strict_tofu=0`: предупреждает + обновляет (разрешает reload)
   - `strict_tofu=1`: блокирует (защита от MITM, reload требует ручного вмешательства)

2. **PSK verify** — детектирует MITM при первом обмене:
   - Fingerprint совпадает → нет MITM → `verify` подтверждает → полный PSK
   - Fingerprint не совпадает → MITM → не подтверждать → DH fallback

3. **KEYXCHG_AUTH** — детектирует MITM при ротации ключей:
   - Auth tag совпадает → ротация легитимна → новый PSK
   - Auth tag не совпадает → MITM → REJECT → старый PSK сохраняется

**Сценарии:**

| Сценарий | TOFU | PSK fingerprint | KEYXCHG_AUTH | Результат |
|----------|------|-----------------|--------------|-----------|
| Нет MITM, первый обмен | Новый пир | Одинаковый | — | verify → полный PSK |
| MITM при первом обмене | Новый пир | **Разный** | — | Не verify → DH fallback |
| MITM при повторном (strict_tofu=1) | Ключ изменён | — | — | Блокировка |
| MITM при ротации (есть prev_psk) | — | — | **FAILED** | REJECT, старый PSK |
| Легитимная ротация | — | — | OK | Новый PSK |
| Reload без MITM | Ключ обновлён | — | WARN | PSK пересчитан |
| KEYXCHG_AUTH без prev_psk | — | — | WARN, принять как KEYXCHG | Отправитель ещё не имел prev_psk |

**Параметры модуля:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `skip_ports` | 22 | Порты для пропуска (уже зашифрованные) |
| `strict_tofu` | 0 | 0=обновлять ключ с warning, 1=блокировать при смене |
| `psk_require_verify` | 0 | 0=PSK сразу, 1=требовать verify перед полным PSK |
| `rotate_interval` | 3600 | Интервал ротации init-key в секундах |

```bash
insmod tcps.ko skip_ports=22,443 strict_tofu=1 psk_require_verify=1
cat /sys/module/tcps/parameters/psk_require_verify
echo 1 > /sys/module/tcps/parameters/psk_require_verify
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

## Обе стороны имеют модуль (PSK exchange)

```
Шаг | Узел A (tcps.ko)                         | Узел B (tcps.ko)
-----|-------------------------------------------|-------------------------------------------
1    | SYN + TC option ──────────────────────►   | Видит TC, создаёт conn, trigger DISCOVER
2    |                                           | SYN-ACK + TC option
3    | ◄──────────────────────────────────────── |
4    | KDF(PSK, client_ISN, server_ISN) → 4 ключа| KDF(PSK, client_ISN, server_ISN) → 4 ключа
5    | ◄══════════ ChaCha20 + Poly1305 ═══════►  | Оба направления зашифрованы + подписаны
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

## MITM-атака обнаружена (fingerprint не совпадает)

```
Шаг | Узел A                        | MITM              | Узел B
-----|-------------------------------|-------------------|-------------------------------
1    | DISCOVER(pub_A) ──►          | подмена pub_A→M   | ──► DISCOVER(pub_M)
2    | ◄── KEYXCHG(pub_M, enc_M)    |                   | ◄── KEYXCHG(pub_B, enc_B)
3    | PSK_A = KDF(DH(A,M), init_A, init_M)               |
4    |                               |                   | PSK_B = KDF(DH(M,B), init_M, init_B)
5    | fingerprint_A ≠ fingerprint_B                     |
6    | Оператор видит: fp=aaa... ≠ fp=bbb... → MITM!     |
7    | Не подтверждает verify → DH fallback               |
```

## MITM при ротации ключей (KEYXCHG_AUTH)

```
Шаг | Узел A (rotated)              | MITM              | Узел B
-----|-------------------------------|-------------------|-------------------------------
1    | KEYXCHG_AUTH(pub_A', enc, tag)►| подмена tag      | ──► KEYXCHG_AUTH(tag')
2    |                               |                   | Poly1305(prev_psk, ...) ≠ tag'
3    |                               |                   | REJECT → старый PSK сохранён
```

# Перезагрузка модуля (reload)

При `rmmod` + `insmod`:
1. Генерируется **новый** init_key + pub_key
2. Таблица соединений очищается
3. TOFU-кеш очищается, PSK теряется
4. Новый SYN триггерит unicast DISCOVER → PSK пересчитывается
5. PSK нужно верифицировать заново (при `psk_require_verify=1`)

**Влияние на соединения:**

| Этап | SSH (port 22) | Другие TCP |
|------|---------------|------------|
| Модуль загружен | OK (skip) | Зашифрованы (PSK + MAC) |
| `rmmod` | OK (без модуля) | Существующие ломаются |
| `insmod` (до discovery) | OK | Новые — слабые ключи (нет пира) |
| После DISCOVER + KEYXCHG | OK | Новые — DH fallback (до verify) |
| После verify | OK | Новые — полный PSK |

# Криптография (без OpenSSL)

- **X25519 ECDH** — 32-байтные ключи, через kernel crypto API (`libcurve25519`)
  - Проверка all-zero shared secret (low-order point attack) → -EINVAL
- **ChaCha20** — stream cipher, XOR на позиции потока, без изменения размера пакетов
  - 64-bit counter, nonce=0 (уникальность через отдельные ключи на соединение)
  - Временные блоки keystream (`blk[]`) обнуляются после использования
  - Позиция потока отслеживает 32-битные wrap-around (seq_hi) → корректная работа после 4GB
- **Poly1305 MAC** — self-implemented (26-bit limb), 4-байтовый тег в TM option
  - Корректная финализация: carry через `>> 26`, редукция по `2^130-5`, sign-bit mask
  - Одноразовый ключ = ChaCha20(mac_key, pos+32, zeros, 32) — offset от позиции шифрования
  - AAD: flags(1) + seq(4), padded до 16 байт
  - Вход: AAD || payload(padded) || len(aad)_le64 || len(payload)_le64
  - Сравнение тега — constant-time (`tcps_ct_memcmp`)
- **PSK derivation** — `KDF = ChaCha20_KDF(DH_shared, "TCPS-PSK" || init_key_A || init_key_B)`
  - DH_shared обеспечивает согласованность (обе стороны вычисляют одинаково)
  - Init keys добавляют дополнительную энтропию (defense-in-depth)
  - Порядок init_key определяется по публичному ключу (детерминировано)
  - Domain label "TCPS-PSK" разделяет PSK от других KDF позиций
- **DH fallback PSK** — `KDF = ChaCha20_KDF(DH_shared, "TCPS-FB")` — отдельная позиция, domain-separated
- **Per-connection KDF** — `KDF(PSK, client_ISN, server_ISN)` → 4 ключа
  - `TCPS c2s` (position 0x8000000000000000) — enc_key
  - `TCPS s2c` (position 0x8000000000000040) — dec_key
  - `TCPS cmac` (position 0x8000000000000080) — mac_enc_key
  - `TCPS smac` (position 0x80000000000000C0) — mac_dec_key
  - KDF label ограничен 31 байтом (защита от переполнения)
- Позиция потока вычисляется от ISN + 1 — уникальна для каждого соединения
- Приватные ключи уничтожаются через `memzero_explicit` при выгрузке модуля

# Аудит безопасности (исправлено)

Проведён аудит логики и уязвимостей. Исправления по категориям:

## CRITICAL (5 исправлений)

| # | Уязвимость | Исправление |
|---|-----------|-------------|
| C-1 | Poly1305: сломанный carry (`uint32` overflow вместо limb overflow) + модуль `2^128-5` вместо `2^130-5` | Carry через `>> 26`, редукция `h4 + (g3>>26) - (1<<24)`, sign-bit mask `(int32_t)g4 >> 31` |
| C-2 | `memcmp` timing side-channel на MAC теге (~1024 попыток для подделки) | `tcps_ct_memcmp()` — constant-time XOR-аккумуляция |
| C-3 | MAC усечён до 4 байт (32-bit security) | Оставлено 4B из-за ограничения TCP option space; mitigated constant-time compare |
| C-4 | `kfree` на `rcu_head` offset → освобождает неправильный адрес | `tcps_peer_free_rcu()` с `container_of` + `memzero_explicit` |
| C-5 | Zero PSK при ошибке DH → шифрование нулевым ключом | Проверка all-zero DH shared; fallback через `tcps_derive_psk_fallback()` с отдельной позицией |

## HIGH (8 исправлений)

| # | Уязвимость | Исправление |
|---|-----------|-------------|
| H-1 | PSK читается без блокировки (torn read при ротации) | `spin_lock(&tcps_peers_lock)` в `tcps_peer_get_psk()` |
| H-2 | Нет проверки all-zero DH shared secret (low-order point attack) | `tcps_dh_shared()` возвращает -EINVAL для all-zero |
| H-3 | GSO пакеты шифруются без MAC (bit-flipping) | GSO пакеты полностью пропускаются (NF_ACCEPT без шифрования) |
| H-4 | `spin_lock` вместо `spin_lock_bh` в `tcps_in` → deadlock | Все блокировки в `tcps_in` → `spin_lock_bh` |
| H-5 | Дублирование соединений при SYN retransmit (memory leak) | `tcps_conn_add_unique()` — lookup перед add |
| H-6 | seq wrap на 4GB → keystream reuse (two-time pad) | `enc_seq_hi`/`dec_seq_hi` отслеживают 32-битный wrap |
| H-7 | Дешифровка без MAC при `peer_has_mac` (bit-flipping) | NF_DROP когда `peer_has_mac && !has_tm` |
| H-8 | Module exit не flush workqueue → use-after-free | `flush_scheduled_work()` в `tcps_exit()` |

## MEDIUM (9 исправлений)

| # | Уязвимость | Исправление |
|---|-----------|-------------|
| M-1 | ChaCha20 `blk[]` keystream остаётся на стеке | `memzero_explicit(blk)` после каждого блока |
| M-2 | KDF label buffer overflow (нет проверки strlen) | `strlen` ограничен 31 байтом |
| M-3 | KEYXCHG_AUTH без prev_psk → REJECT блокирует PSK exchange | WARN + принять как plain KEYXCHG (race condition при первой ротации) |
| M-4 | Парсер TCP опций сканирует в payload (false TM match) | `tcps_opt_end()` ограничивает scan до `th->doff*4` |
| M-5 | FIN устанавливает DEAD слишком рано (retransmit без шифрования) | FIN ставит `kill=1`, state остаётся KEYED до cleanup timeout |
| M-6 | `kernel_sendmsg` внутри `rcu_read_lock` при ротации | Сбор адресов под RCU, отправка вне RCU |
| M-7 | `tcps_recalc_csum` с отрицательным tcplen → crash | Проверка `tcplen < sizeof(tcphdr)` |
| M-8 | Неограниченная таблица пиров (OOM от сканирования) | `TCPS_MAX_PEERS=64` с атомарным счётчиком |
| M-9 | MAC и шифрование на одной позиции keystream | MAC на `pos+32` (offset на 1 блок ChaCha20) |
| M-10 | DH shared рассинхрон при одновременной ротации (fingerprints не совпадают) | DISCOVER вместо KEYXCHG при ротации + prev_init_key DH retry + curve25519(decrypted)==pkt.pubkey verification |
| M-11 | KEYXCHG_AUTH FAILED → REJECT блокирует PSK при race condition | WARN + продолжить как plain KEYXCHG (MITM невозможен без приватного ключа) |

## LOW/INFO (оставлено)

| Уязвимость | Причина |
|-----------|---------|
| MAC 4 байта вместо 16 | TM option 12B не влезет в большинство пакетов |
| ACK-only пакеты без MAC | Нет payload → нет позиции для MAC |
| RST в открытом виде | Частичная защита: RST без MAC при peer_has_mac → DROP |
| Первый обмен уязвим к MITM | Обнаруживается через fingerprint verify |
| Нет version negotiation в протоколе | Текущая версия — единственная |

# Развёртывание

На сервере и на клиенте (Linux, amd64, kernel 6.x):

```bash
cd v3/
apt install build-essential linux-headers-$(uname -r)
modprobe curve25519-x86
make
insmod tcps.ko psk_require_verify=1
```

Верификация PSK (на обеих машинах):
```bash
# Шаг 1: проверить fingerprint
cat /proc/tcps_peers
# Узел A: 192.168.1.42 ... psk=unverified fp=02f9b20aad44590b
# Узел B: 192.168.1.151 ... psk=unverified fp=02f9b20aad44590b

# Шаг 2: если fp совпадает — подтвердить
echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers

# Шаг 3: проверить
cat /proc/tcps_peers
# 192.168.1.42 ... psk=verified fp=02f9b20aad44590b
```

Выгрузка модуля:
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

PSK установлен (TOFU unicast discovery):
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

MITM обнаружен при ротации:
```
tcps: KEYXCHG_AUTH FAILED from 192.168.1.42 (prev_psk mismatch, rotation race?) -> continuing as plain KEYXCHG
```

DH retry при одновременной ротации:
```
tcps: init-key ROTATED, new pubkey=1a2b3c4d...
tcps: KEYXCHG_AUTH verified from 192.168.1.42
tcps: PSK established with 192.168.1.42 fingerprint=5e6f7a8b...
```

PSK верифицирован:
```
tcps: PSK VERIFIED for 192.168.1.42
```

DH fallback (PSK не верифицирован):
```
tcps: PSK not verified for 192.168.1.42, using DH fallback
```

Low-order point (DH shared = нули):
```
tcps: DH all-zero for 192.168.1.42 -> DH fallback
```

## /proc/tcps_peers

```bash
cat /proc/tcps_peers
# 192.168.1.42 pub=d2a7929b... psk=verified fp=02f9b20aad44590b

# Добавить пира вручную:
echo "192.168.1.42=hex_pubkey..." > /proc/tcps_peers

# Верифицировать PSK:
echo "verify 192.168.1.42 02f9b20aad44590b" > /proc/tcps_peers
```

## tcpdump — визуальная проверка шифрования

```bash
tcpdump -i ens18 -A -s0 tcp
```

| Признак | Описание |
|---------|----------|
| `unknown-253` в SYN | TC probe option (4 байта, magic 0x5443) |
| `unknown-253` в data | TM MAC option (8 байт, magic 0x544D, tag 4B) |
| Нечитаемые данные | Payload зашифрован ChaCha20 |
| Читаемые данные | Plain TCP — пир без модуля или skip_ports |

# Свойства безопасности

| Свойство | Механизм |
|----------|----------|
| Шифрование | ChaCha20 stream cipher (XOR на позиции потока) |
| Целостность данных | Poly1305 MAC (4B tag) + constant-time verify + DROP без MAC |
| Обмен ключами | X25519 ECDH + init-key exchange → PSK |
| Low-order point защита | Проверка all-zero DH shared → fallback |
| PSK derivation | KDF(DH_shared, "TCPS-PSK"\|\|init_key_A\|\|init_key_B) — domain-separated |
| DH fallback PSK | Отдельная позиция KDF + label "TCPS-FB" — domain-separated |
| Направленные ключи | Per-connection KDF(PSK, ISN) с лейблами c2s/s2c/cmac/smac |
| MAC/enc разделение | MAC на pos+32, encryption на pos — разные блоки keystream |
| Forward secrecy | Ротация init-key (rotate_interval, по умолчанию 3600с), KEYXCHG_AUTH |
| MITM-защита (первый обмен) | PSK fingerprint + out-of-band verify |
| MITM-защита (повторный) | TOFU + strict_tofu |
| MITM-защита (ротация) | KEYXCHG_AUTH — Poly1305 аутентификация через prev_psk |
| DH consistency при ротации | DISCOVER вместо KEYXCHG + prev_init_key retry + curve25519 verify |
| RST injection защита | RST без MAC в KEYED → DROP |
| Bit-flipping защита | Данные без MAC при peer_has_mac → DROP |
| Timing attack защита | `tcps_ct_memcmp` для MAC и KEYXCHG_AUTH |
| Downgrade-защита | Probe option — отсутствие → fallback на plain TCP |
| Auto-discovery | TOFU unicast discovery (порт 54321), триггер от SYN |
| Skip ports | Порт 22 пропускается — SSH/SCP не затрагиваются |
| Skip loopback | 127.x.x.x пропускается — локальные соединения не шифруются |
| Skip GSO | GSO-пакеты не шифруются (нельзя аутентифицировать) |
| Seq wrap | 32-bit wraparound отслеживается (seq_hi) → нет keystream reuse |
| Duplicate conn | `tcps_conn_add_unique()` — нет дубликатов при SYN retransmit |
| Peer limit | Max 64 пира (TCPS_MAX_PEERS) — защита от OOM |
| Privilege | memzero_explicit, только в RAM, на диск не пишутся |
| RCU/lifecycle | Правильные RCU callbacks, flush_scheduled_work() при unload |

# Известные ограничения

| Ограничение | Описание |
|-------------|----------|
| IPv4 only | IPv6 пока не поддерживается |
| GSO без шифрования | GSO-пакеты пропускаются целиком (нельзя аутентифицировать сегменты) |
| MAC 4 байта | Усечённый Poly1305 тег (2^32 forgery), полный 16B не влезет в TCP option |
| First-use MITM | Первый обмен уязвим к MITM (обнаруживается через fingerprint) |
| PSK verify ручной | Оператор должен сравнить fingerprint на обеих машинах |
| TOFU + PSK in-memory | Теряется при rmmod, ключи на диск не сохраняются |
| Reload ломает соединения | Существующие TCP-сессии ломаются при rmmod/insmod |
| TM option не удаляется | На приёме TM option остаётся (TCP stack игнорирует kind=253) |
| Опции могут не влезть | При SACK blocks + TM (8B) может превысить 40B TCP option space |
| ACK-only без MAC | Пакеты без payload не подписываются |
| RST в открытом виде | Частичная защита: RST без MAC при peer_has_mac → DROP |
| Нет version negotiation | Изменения протокола несовместимы |
