### TCP/S — прозрачное шифрование TCP на 4 уровне

# Архитектура
```
tcps/
├── kernel/                    # Linux kernel module (LKM)
│   ├── tcps.h                 # Заголовок: состояния, константы AEAD, TOFU, embedded TI, probe, epoch
│   ├── tcps_main.c            # Netfilter hooks, опции, MAC, TOFU + forward secrecy + epoch rotation + auto-discovery + in-band probe
│   ├── tcps_crypto.c          # X25519 + ChaCha20 + Poly1305 + mac_prefix для ядра
│   ├── Makefile               # Сборка: make → tcps.ko
│   └── INSTRUCTION.md         # Инструкция по установке и тестированию
```

# Как работает

## Kernel module (tcps.ko)

1. Netfilter hook LOCAL_OUT — добавляет TCP option TC (kind=253, 40 байт) в SYN, с **эфемерным** X25519 pubkey + **epoch** (4 байта)
2. Netfilter hook PRE_ROUTING — обнаруживает TC option в SYN, сохраняет peer ephemeral pubkey + peer epoch
3. SYN-ACK тоже несёт TC option с эфемерным pubkey сервера и epoch — оба хоста получают чужой pubkey и epoch
4. После handshake — ECDH (X25519) shared secret → HKDF-Expand (ChaCha20 PRF) → 4 ключа
5. Все TCP-данные шифруются ChaCha20 (stream cipher, размер не меняется)
6. Каждый пакет с данными или FIN содержит Poly1305 MAC (16 байт) в TCP option TM (kind=253, 20 байт)
7. Poly1305 key уникален для каждого пакета (derived from position). AAD включает TCP flags
8. Пакеты без MAC или с неверным MAC отбрасываются (NF_DROP). FIN без MAC — тоже дроп
9. **TI delivery** — только **embedded TI** (49 байт в payload первого data-пакета)
   - TI option (52 байта) не помещается в TCP options (максимум 40 байт) — путь удалён
10. Embedded TI верифицируется через TOFU + auth_tag → состояние TCPS_AUTHENTICATED
11. Embedded TI отправляется в состоянии ENCRYPTED **или** AUTHENTICATED (если `ti_sent == 0`)
    - Это необходимо для request-response протоколов (HTTP, SQL, Redis), где сервер получает TI клиента раньше, чем сам отправляет данные
12. Работает для всех TCP-сокетов на системе, приложения ничего не знают

# Автообнаружение TCPS-пиров

TOFU-кеш удваивается как **автоматический список TCPS-пиров** — ручная конфигурация не нужна.

**Как это работает:**
- Модуль всегда добавляет TC option в исходящий SYN (пробует TCPS)
- Если SYN+ACK пришёл **с** TC option → пир имеет модуль → TCPS-сессия → IP добавляется в TOFU
- Если SYN+ACK пришёл **без** TC option → проверяем TOFU:
  - Пир **в TOFU** → downgrade-атака! → NF_DROP
  - Пира **нет в TOFU** → plain TCP (пир не имеет модуля)

**Результат:** `apt-get update`, DNS, HTTP к внешним серверам — всё работает.
Как только обе стороны имеют модуль и хотя бы раз соединились — downgrade блокируется автоматически.

| Сценарий | Пир в TOFU? | Результат |
|----------|------------|-----------|
| SYN без TC (сервер) | Да | NF_DROP — downgrade |
| SYN без TC (сервер) | Нет + enforce=0 | NF_ACCEPT — plain TCP |
| SYN без TC (сервер) | Нет + enforce=1 | NF_DROP — строгий режим |
| SYN+ACK без TC (клиент) | Да | NF_DROP — downgrade |
| SYN+ACK без TC (клиент) | Нет | PLAIN_PROBE → plain TCP |

При `enforce=1` на сервере — даже неизвестные клиенты обязаны иметь модуль.
При `enforce=0` (по умолчанию) — неизвестные клиенты могут подключаться по plain TCP.

# In-band probe — детект downgrade (серверная часть)

Проблема: при первом соединении к новому пиру MITM может стрипнуть TC option из SYN+ACK.
Клиент думает, что модуля нет, и fallback'ает к plain TCP. Классический SSH first-use вектор.

**Решение:** серверная часть in-band probe сохранена для совместимости с клиентами,
использующими старую версию модуля (которая отправляет probe в payload). Сервер принимает
probe request, отправляет probe response → клиент детектит DOWNGRADE.

**Текущая версия** не вставляет probe в payload клиента (это ломало HTTP и другие протоколы —
36 лишних байт + рассинхрон TCP sequence numbers). Вместо этого:

- Если SYN+ACK без TC от неизвестного пира → plain TCP (данные не модифицируются)
- Если сервер в ENCRYPTED получает данные без MAC → NF_DROP (MITM заблокирован)

**Протокол probe (для совместимости со старыми клиентами):**

```
Probe request (клиент → сервер):
[0x02]['T']['P']['R'][static_pub(32)] = 36 байт в начале первого data-пакета

Probe response (сервер → клиент):
[0x03]['T']['P']['S'][static_pub(32)] = 36 байт в начале первого ответа
```

**Поток при MITM (strip TC option) — старый клиент + текущий сервер:**

1. SYN+ACK без TC → conn переходит в состояние `TCPS_PLAIN_PROBE`
2. Старый клиент: первый data-пакет → prepend probe request → `probe_sent=1`
3. Сервер: видит маркер `0x02+'TPR'` в payload → strip probe → создаёт conn (PLAIN_PROBE) →
   добавляет клиента в TOFU → логирует warning
4. Сервер: первый data-ответ → prepend probe response → `probe_sent=1`
5. Клиент: видит маркер `0x03+'TPS'` → **DOWNGRADE DETECTED** → `kill=1` → NF_DROP всех пакетов →
   добавляет сервер в TOFU

**Поток при MITM (strip TC option) — текущий клиент + текущий сервер:**

1. SYN+ACK без TC → `TCPS_PLAIN_PROBE`
2. Клиент: отправляет данные как plain TCP (probe не вставляется)
3. Сервер (в ENCRYPTED): получает данные без MAC → NF_DROP
4. Соединение не устанавливается — MITM заблокирован
5. Сервер логирует: "data without MAC while ENCRYPTED — possible MITM"

**Поток при отсутствии модуля на пира:**

1. SYN+ACK без TC → `TCPS_PLAIN_PROBE`
2. Клиент: отправляет данные как plain TCP
3. Сервер (без модуля): получает нормальные данные
4. Таймаут 30 сек → GC удаляет conn → соединение продолжается как plain TCP

**После детекта downgrade (старый клиент):**
- Соединение убивается (kill=1 → NF_DROP)
- Пир добавляется в TOFU → следующий SYN+ACK без TC → NF_DROP (downgrade по TOFU-кешу)
- MITM не может обойти: даже если перестанет стрипать, TOFU уже защищает

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
- **Forward secrecy** — эфемерные DH-ключи (dh_priv) уничтожаются (memzero_explicit) после деривации.
  Ephemeral pubkeys (dh_pub, dh_peer_pub) сохраняются для auth_tag transcript binding

# Защита от MITM (TOFU + auth_tag + epoch)

Статический identity-ключ X25519 генерируется при загрузке модуля. Приватный ключ хранится
только в RAM ядра, никогда не передаётся по сети, на диск не записывается.

**Двухфазный протокол:**

Фаза 1 — SYN/SYN-ACK: эфемерные DH-ключи + epoch → шифрование (forward secrecy)
Фаза 2 — первый data-пакет после шифрования: embedded TI со статическим ключом → аутентификация

**Embedded TI (49 байт, payload):** marker(1) + static_pubkey(32) + auth_tag(16)
- auth_tag = Poly1305(DH(my_static_priv, peer_static_pub), client_dh || server_dh || ISN_client || ISN_server || is_client)
- auth_tag привязан к ISN + эфемерным DH-ключам — MITM не может ретранслировать между сессиями
- auth_tag = 0 (нулевой) при первом соединении (отправитель не знает ключ пира)

**TI option (52 байта):** kind(1) + len(1) + 'T'(1) + 'I'(1) + static_pub(32) + auth_tag(16)
- **Не используется для отправки** — 52 байта превышают лимит TCP options (40 байт)
- Код приёма сохранён для совместимости с будущими версиями протокола

**TOFU (Trust On First Use):**
- Первое соединение: статический pubkey + epoch пира запоминаются в TOFU-кеше (IP → pubkey + epoch)
  - auth_tag = 0: регистрация без верификации (TOFU trust, как SSH)
  - auth_tag ≠ 0: верификация через DH(static_priv, peer_pub) — отправитель знает наш ключ
- Последующие: pubkey сверяется с кешем, auth_tag верифицируется (нулевой auth_tag для известного пира = downgrade)
- Несовпадение pubkey или auth_tag → MITM обнаружен → NF_DROP
- При провале TOFU: `kill=1` + `TCPS_DEAD` — все последующие пакеты дропаются, зашифрованные данные не утекают в приложение
- TOFU-кеш автоматически используется для защиты от downgrade (см. Автообнаружение + Probe)

**Epoch — детекция перезагрузки/ротации ключей:**

При каждой загрузке модуля генерируется случайный 32-битный `epoch`. Он передаётся в TC option
и хранится в TOFU-кеше рядом с pubkey. При несовпадении pubkey:

| Условие | auth_tag | Реакция |
|---------|----------|---------|
| pubkey совпадает | ≠ 0 | Верификация auth_tag |
| pubkey совпадает | = 0 | **Downgrade** — дроп (отправитель не знает наш ключ) |
| pubkey ≠, epoch ≠ | любой | **Ротация ключа** — accept с warning (encrypted channel защищает TI) |
| pubkey ≠, epoch тот же | — | **MITM** — дропать соединение |

Ротация ключей (новый epoch + новый pubkey) автопринимается при `auto_rotate=1` (по умолчанию).
При `auto_rotate=0` — любая смена ключа = MITM, требуется ручная перезагрузка модуля на обеих сторонах.

При ротации auth_tag может не совпадать (отправитель вычислил его с нашим старым ключом).
Это допустимо: TI передаётся внутри зашифрованного канала, и MITM не может его подменить.

**auth_tag предотвращает пересылку чужого pubkey:**
MITM не может подделать auth_tag — для этого нужен статический приватный ключ,
который есть только у легитимного пира. ISN+DH-binding предотвращает relay-атаку
(попытку переслать чужой auth_tag между двумя разными сессиями).

**Ограничение:** первое соединение доверяется без верификации (как SSH),
серверная часть in-band probe закрывает это окно для клиентов со старой версией модуля.

**Параметры модуля:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `tofu_enforce` | 1 | 0=только логировать, 1=дропать при несовпадении TOFU |
| `enforce` | 0 | 0=допускать plain TCP для неизвестных пиров, 1=дропать все non-TCPS |
| `auto_rotate` | 1 | 0=отклонять ротацию ключей, 1=автопринимать при смене epoch |

```bash
insmod tcps.ko tofu_enforce=0 enforce=1 auto_rotate=0
cat /sys/module/tcps/parameters/tofu_enforce
cat /sys/module/tcps/parameters/enforce
cat /sys/module/tcps/parameters/auto_rotate

# Runtime переключение
echo 0 > /sys/module/tcps/parameters/tofu_enforce
echo 1 > /sys/module/tcps/parameters/enforce
echo 0 > /sys/module/tcps/parameters/auto_rotate
```

# Защита от downgrade и RST injection

**Downgrade-атака** (strip TCPS options):
- SYN+ACK без TCPS option от пира, который **уже в TOFU** → NF_DROP (downgrade!)
- SYN+ACK без TCPS option от **нового** пира → plain TCP (peer не имеет модуля)
- SYN без TCPS option от клиента, который **уже в TOFU** → NF_DROP (downgrade!)
- TM option не добавилась → NF_DROP
- `enforce=1` дополнительно дропает SYN от любых клиентов без TCPS option на сервере

**MITM стрипает SYN+ACK (сервер в ENCRYPTED, клиент в PLAIN_PROBE):**
- Клиент отправляет данные без MAC (PLAIN_PROBE)
- Сервер получает данные без MAC → NF_DROP
- Соединение не устанавливается — MITM заблокирован
- Сервер логирует: "data without MAC while ENCRYPTED — possible MITM"

**In-band probe (серверная часть)** — для совместимости со старыми клиентами:
- Старый клиент отправляет probe request в payload → сервер обнаруживает маркер
- Сервер strip probe, демотирует conn в PLAIN_PROBE, отправляет probe response
- Клиент детектит DOWNGRADE DETECTED → kill соединения

**RST injection**: inbound RST пакеты в зашифрованном состоянии (ENCRYPTED/AUTHENTICATED)
дропаются **без смены состояния**. Spoofed RST не может разорвать зашифрованную сессию.
Outbound RST (приложение закрывает соединение) пропускается с установкой `kill=1` + `TCPS_DEAD`.
Соединение закрывается только через FIN или GC timeout.

**TI timeout**: если TI не получен за 30 секунд (TCPS_TI_TIMEOUT), GC убивает соединение.
Предотвращает вечное зависание в ENCRYPTED без аутентификации.
Если обе стороны шлют только pure ACK (без данных) — TI не может быть отправлен,
соединение зависнет в ENCRYPTED до timeout.

**Probe timeout**: если probe response не получен за 30 секунд (TCPS_PROBE_TIMEOUT),
GC удаляет conn — пир действительно не имеет модуля, plain TCP продолжается.

# Embedded TI — отправка identity в payload

TI (Trust Identity) встраивается в начало payload первого data-пакета. Pure ACK без данных
не может нести TI (TI option 52 байта превышает лимит TCP options 40 байт).

**Условие embedding:** `!ti_sent && payload_len > 0 && (state == ENCRYPTED || state == AUTHENTICATED)`

Это критично для request-response протоколов (HTTP, SQL, Redis, Kafka):
сервер получает TI клиента первым → переходит в AUTHENTICATED → отправляет ответ.
Без условия AUTHENTICATED сервер никогда не отправил бы свой TI, и клиент не узнал бы
static pubkey сервера → повторные соединения падали бы с "zero auth_tag for known peer".

**Протокол Encrypt-then-MAC:**

```
Отправитель:
1. Формирует TI prefix: [0x01][static_pub(32)][auth_tag(16)] = 49 байт
2. Prepends TI prefix к payload: [TI prefix][app_data]
3. Шифрует ВЕСЬ payload включая TI prefix: ChaCha20(key, pos, data)
4. Вычисляет MAC: Poly1305(mac_key, pos, flags, encrypted_payload)
5. Добавляет TM option (20 байт)

Пакет: [TCP hdr+opts][encrypted TI prefix(49)][encrypted app_data][TM option(20)]
```

```
Приёмник:
1. Проверяет MAC (TM option) → если не совпадает, дроп
2. Расшифровывает payload: ChaCha20(key, pos, data)
3. Проверяет первый байт == 0x01 → embedded TI
4. Извлекает static_pub + auth_tag из расшифрованного payload
5. TOFU + auth_tag верификация
6. Strip 49 байт TI prefix, корректирует IP length + TCP checksum
```

Детекция embedded TI: первый байт расшифрованного payload == 0x01. Приёмник вычитает 49 байт,
корректирует IP length и TCP checksum. TCP stack видит только application data.

**Ограничение:** если обе стороны обмениваются только pure ACK (нет данных ни в одном направлении),
TI не может быть отправлен. Соединение останется в ENCRYPTED до TCPS_TI_TIMEOUT (30 сек).

# Сценарии работы

## Обе стороны имеют модуль (автообнаружение)

```
Шаг | Клиент (tcps.ko)                              | Сервер (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1    | SYN + TC option (ephemeral pubkey + epoch) ──► | Видит TC, сохраняет ephemeral pubkey + epoch
2    |                                                | SYN-ACK + TC option (ephemeral pubkey + epoch)
3    | ◄────────────────────────────────────────────── | Оба хоста знают чужой ephemeral pubkey + epoch
4    | X25519(eph_priv, peer_eph_pub) → shared        | X25519(eph_priv, peer_eph_pub) → shared
5    | HKDF-Expand(shared, label, ISN) → 4 ключа     | HKDF-Expand(shared, label, ISN) → 4 ключа
6    | ◄══════ ChaCha20 + Poly1305 (forward secret) ═► | Зашифровано + целостность (MAC 16B)
7    | data: embedded TI (static pub + auth_tag) ───► | TOFU + auth_tag верификация, strip 49B
8    |                                                | TCPS_AUTHENTICATED
9    | ◄ embedded TI (static pub + auth_tag)          | Сервер шлёт TI в AUTHENTICATED (ti_sent=0)
10   | TOFU + auth_tag верификация, strip 49B         |
11   | TCPS_AUTHENTICATED на обеих сторонах           |
     | Приложения (nginx/postgres/ssh) ничего не знают
```

## Только одна сторона имеет модуль (авто-fallback)

```
Шаг | Клиент (tcps.ko)                              | Сервер (без модуля)
-----|------------------------------------------------|--------------------------------------------
1    | SYN + TC option (ephemeral pubkey + epoch) ──► | Игнорирует неизвестный option 253
2    |                                                | SYN-ACK (без TC option)
3    | ◄────────────────────────────────────────────── |
4    | Пира нет в TOFU → PLAIN_PROBE → plain TCP     |
5    | data (без модификации) ──────────────────────► | Обычные данные, HTTP-запрос не повреждён
6    | Таймаут probe 30 сек → GC чистит conn          | Обычное TCP-соединение
     | apt-get update, DNS, HTTP — всё работает!
```

Повторное подключение к тому же серверу — снова PLAIN_PROBE (пир не в TOFU, модуля нет).
Если позже сервер установит модуль — следующее соединение автоматически станет TCPS.

## Downgrade-атака заблокирована (пир уже в TOFU)

```
Шаг | Клиент (tcps.ko)                              | MITM → Сервер (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1    | SYN + TC option ──►                            | MITM стрипает TC option
2    |                                                | SYN (без TC) ──►  Сервер: клиент в TOFU → NF_DROP!
      |                                                 Или:
1    | SYN + TC option ──► Сервер (tcps.ko)           | SYN-ACK + TC option
2    | ◄── MITM стрипает TC из SYN-ACK                | SYN-ACK (без TC)
3    | Пир в TOFU → NF_DROP! (downgrade detected)     |
```

## MITM стрипает SYN+ACK при первом соединении

**Сервер в ENCRYPTED, клиент в PLAIN_PROBE:**

```
Шаг | Клиент (tcps.ko)                              | MITM → Сервер (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1    | SYN + TC option ──► MITM пропускает SYN ──────► | Сервер: видит TC → ENCRYPTED
2    |                                                | SYN+ACK + TC option ──►
3    | ◄── MITM стрипает TC из SYN+ACK                |
4    | Пира нет в TOFU → PLAIN_PROBE → plain TCP     | Сервер: ENCRYPTED, ожидает MAC
5    | data (без MAC) ──►                             | Сервер: нет MAC → NF_DROP
6    |                                                | Соединение не устанавливается — MITM заблокирован
```

**Старый клиент отправляет probe (обратная совместимость):**

```
Шаг | Клиент (старый tcps.ko)                        | MITM → Сервер (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1-3  | (та же последовательность)                     |
4    | Пира нет в TOFU → PLAIN_PROBE                 |
5    | [probe request + data] ──► (нет MAC)           |
6    |                                                | Сервер: нет MAC → probe marker найден
7    |                                                | → демотирует в PLAIN_PROBE, strip probe
8    |                                                | Сервер: [probe response + data] ──►
9    | ◄── probe response получена                    |
10   | DOWNGRADE DETECTED! → kill=1 → NF_DROP         |
     | Пир добавлен в TOFU → следующие попытки → NF_DROP
```

## Перезагрузка модуля (key rotation)

```
Шаг | Клиент (tcps.ko)                              | Сервер (tcps.ko — перезагружен)
-----|------------------------------------------------|--------------------------------------------
1    | SYN + TC option (epoch_A) ──────────────────► | Видит TC, SYN_RECV
2    |                                                | SYN-ACK + TC option (epoch_B — новый!)
3    | ◄────────────────────────────────────────────── |
4    | Видит новый epoch → TCPS_ENCRYPTED            | TCPS_ENCRYPTED
5    | data: embedded TI (auth_tag с OLD server key)► | tcps_tofu_verify: epoch отличается
6    |                                                | → key rotation: auth_tag может не совпасть
7    |                                                | → accept (encrypted channel защищает TI)
8    |                                                | → TCPS_AUTHENTICATED
9    | ◄ embedded TI (auth_tag = 0, нет ключа клиента) | Сервер не имеет клиента в TOFU (кеш очищен)
10   | tcps_tofu_verify: новый пир, auth_tag=0       |
     | → TOFU trust, регистрация                     | → TCPS_AUTHENTICATED на обеих сторонах
```

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
PostgreSQL, HTTP, SSH — что угодно. Соединения к машинам без модуля — plain TCP (apt-get работает).

Выгрузка модуля:
```bash
rmmod tcps
```

При перезагрузке модуля генерируется новый статический identity-ключ и новый epoch.
TOFU-кеш очищается. При `auto_rotate=1` на другой стороне — ротация принимается
автоматически (auth_tag может не совпасть, но encrypted channel защищает TI).
При `auto_rotate=0` — обеим сторонам нужно перезагрузить модуль.

# Проверка работы

## dmesg — сессии и ошибки

```bash
dmesg | grep tcps
```

Загрузка модуля:
```
tcps: module loaded, ECDH (X25519) + ChaCha20-Poly1305 + TOFU active
tcps: identity fingerprint: a1b2c3d4e5f6a7b8 epoch: 1234567890
```

Успешное соединение (первое — TOFU запоминает):
```
tcps: encrypted session 192.168.1.69:41548 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: TI embedded in data 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: TOFU: new peer 192.168.1.127 fingerprint 9a8b7c6d5e4f3a2b epoch: 1234567890 (auth_tag present — see above for verification result)
tcps: session authenticated (embedded TI) 192.168.1.69:41548 <-> 192.168.1.127:80
```

Успешное соединение (повторное — TOFU + auth_tag верификация):
```
tcps: encrypted session 192.168.1.69:41550 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: session authenticated (embedded TI) 192.168.1.69:41550 <-> 192.168.1.127:80
```

Plain TCP (пир без модуля):
```
tcps: peer 93.184.216.34 has no TCPS module, plain TCP
tcps: probe timeout for 192.168.1.69:41548 <-> 93.184.216.34:80, peer has no module
```

In-band probe — MITM обнаружен (старый клиент):
```
tcps: peer 192.168.1.127 has no TCPS module, probing
tcps: probe sent 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: DOWNGRADE DETECTED! Peer 192.168.1.127 has TCPS module but option was stripped
```

Probe из ENCRYPTED (MITM стрипает только SYN+ACK):
```
tcps: probe from 192.168.1.69 while ENCRYPTED — SYN+ACK was stripped, demoting to PLAIN_PROBE
tcps: probe response sent 192.168.1.127:80 <-> 192.168.1.69:41548
tcps: DOWNGRADE DETECTED! Peer 192.168.1.127 has TCPS module but option was stripped
```

MITM — данные без MAC к ENCRYPTED серверу:
```
tcps: data without MAC from 192.168.1.69 while ENCRYPTED — possible MITM
```

Ротация ключа (перезагрузка модуля на одной стороне, auto_rotate=1):
```
tcps: key rotation detected for peer 192.168.1.127 (epoch 1234567890 -> 987654321)
tcps: old fingerprint 9a8b7c6d5e4f3a2b, new fingerprint deadbeef12345678
tcps: rotation auth_tag mismatch for 192.168.1.127 — sender has old key, accepting (encrypted channel protects TI)
tcps: session authenticated 192.168.1.69:41552 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

Ротация без auth_tag (пир перезагружен, потерял TOFU):
```
tcps: key rotation detected for peer 192.168.1.127 (epoch 1234567890 -> 987654321)
tcps: rotation without auth_tag for 192.168.1.127 — sender has no key for us, accepting (encrypted channel protects TI)
```

Новый пир с auth_tag mismatch (перезагрузка на нашей стороне, у пира наш старый ключ):
```
tcps: TOFU: new peer 192.168.1.127 auth_tag mismatch — sender has our old key or different key, accepting (encrypted channel protects TI)
tcps: TOFU: new peer 192.168.1.127 fingerprint deadbeef12345678 epoch: 987654321 (auth_tag present — see above for verification result)
```

Downgrade обнаружен (MITM стрипает TCPS option от известного пира):
```
tcps: downgrade detected! SYN+ACK without TCPS from known peer 192.168.1.127
tcps: downgrade detected! SYN without TCPS from known peer 192.168.1.127
```

Zero auth_tag для известного пира (downgrade):
```
tcps: zero auth_tag for known peer 192.168.1.127 — possible downgrade
```

MITM-атака (ключ не совпадает, epoch тот же):
```
tcps: MITM detected! Static key mismatch for peer 192.168.1.127 (same epoch 1234567890)
tcps: expected 9a8b7c6d5e4f3a2b, got deadbeef12345678
```

MITM-атака (auth_tag не совпадает — пересылка чужого ключа):
```
tcps: MITM detected! auth_tag mismatch for peer 192.168.1.127
```

Ошибка MAC (пакет подделан или повреждён):
```
tcps: MAC verification failed, dropping
```

Ротация отклонена (auto_rotate=0):
```
tcps: key rotation rejected for peer 192.168.1.127 (auto_rotate=0, epoch 1234567890 -> 987654321)
```

## tcpdump — визуальная проверка шифрования

```bash
tcpdump -i ens18 -A -s0 tcp
```

Признаки работы модуля:

| Признак | Описание |
|---------|----------|
| `unknown-253` в SYN | TC option с ephemeral X25519 pubkey + epoch (40 байт, magic 'T','C') |
| `unknown-253` в данных | TM option с Poly1305 тегом (20 байт, magic 'T','M') |
| Нечитаемые данные | Payload зашифрован ChaCha20 |
| Читаемые данные | Plain TCP — пир без модуля (не в TOFU) |

Примечание: MSS не включается в SYN (TC option занимает все 40 байт опций).
TCP использует default MSS (536) до Path MTU Discovery.

```

# Свойства безопасности

| Свойство | Механизм |
|----------|----------|
| Шифрование | ChaCha20 stream cipher |
| Целостность | Poly1305 MAC (16 байт, per-packet key, AAD covers TCP flags) |
| FIN injection | FIN пакеты требуют MAC, spoofed FIN отбрасывается |
| Forward secrecy | Эфемерные X25519 DH-ключи (dh_priv уничтожается после деривации) |
| MITM-защита | TOFU + auth_tag (Poly1305 MAC 16B, DH pubkeys + ISN в transcript) |
| MITM relay | auth_tag привязан к ISN + эфемерным DH-ключам — пересылка невозможна |
| Ротация ключей | Epoch — детекция перезагрузки, auto-rotate при смене epoch, encrypted channel защищает TI |
| Downgrade-защита | TOFU как список пиров + NF_DROP при strip от известных пиров |
| Downgrade SYN+ACK strip | Сервер дропает данные без MAC → соединение не устанавливается → MITM заблокирован |
| Downgrade first-use (старый клиент) | In-band probe через payload — автодетект MITM при первом соединении |
| Auto-discovery | TOFU-кеш автоматически определяет TCPS/Plain для каждого IP |
| RST injection | Inbound RST дропается без смены состояния; outbound RST ставит kill=1 |
| Timing-атаки | crypto_memneq для MAC и auth_tag |
| Key separation | HKDF-Expand с уникальными лейблами для каждого ключа |
| Приватность ключей | memzero_explicit, только в RAM, на диск не пишутся |
| TI delivery | Embedded TI в payload (Encrypt-then-MAC) — аутентификация с первым data-пакетом |
| TOFU failure | kill=1 при провале TOFU — зашифрованные данные не утекают в приложение |

# Известные ограничения

| Ограничение | Описание |
|-------------|----------|
| IPv4 only | IPv6 пока не поддерживается |
| Нет лимита соединений | Лимит 4096 (tcps_conn_count). При превышении — SYN дропается |
| TOFU kzalloc fail | Соединение отклоняется вместо доверия (return -1) |
| RST delay | Легитимный RST от пира дропается, закрытие через FIN/timeout |
| Pure ACK не аутентифицирован | ACK без FIN и без payload не содержат MAC (overhead). FIN защищён |
| Pure ACK без TI | Если обе стороны шлют только ACK без данных, TI не отправляется → TCPS_TI_TIMEOUT (30 сек) |
| TOFU cache in-memory | Теряется при rmmod, ключи на диск не сохраняются |
| Epoch — эвристика | Не криптографическое доказательство: активный MITM может подменить epoch+ключ при auto_rotate=1 |
| MSS в SYN | TC option (40B) занимает всё пространство опций — MSS не включается. Default 536, PMTU Discovery компенсирует |
| Embedded TI marker | Байт 0x01 в начале payload — при коллизии с app data возможен DoS (дроп пакета) |
| Probe payload-mod MITM | MITM с возможностью модификации payload может стрипать probe (на порядки сложнее, чем strip options) |
| First-use trust | Первое соединение к новому пиру без MITM-детекта — доверяется (как SSH). MITM-детект только при получении данных без MAC к ENCRYPTED серверу |
| Key rotation auth_tag | При ротации auth_tag может не совпасть (отправитель вычислил с нашим старым ключом). Защита: encrypted channel |
| New peer auth_tag | Для новых пиров auth_tag не блокирует регистрацию (encrypted channel защищает TI) |
