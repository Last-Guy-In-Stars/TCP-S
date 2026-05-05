### TCP/S — прозрачное шифрование TCP на 4 уровне

# Архитектура
```
tcps/
├── kernel/                    # Linux kernel module (LKM)
│   ├── tcps.h                 # Заголовок: состояния, константы AEAD, TOFU, TI option, epoch, embedded TI, probe
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
9. **TI delivery** — два механизма:
   - **TI option** (kind=253, 40 байт) — на pure ACK (no payload, no FIN)
   - **Embedded TI** (37 байт в payload) — на первом data-пакете, если pure ACK ещё не отправлен
10. TI option/embedded TI верифицируется через TOFU + auth_tag → состояние TCPS_AUTHENTICATED
11. Работает для всех TCP-сокетов на системе, приложения ничего не знают

# Автообнаружение TCPS-пиров

TOFU-кеш удваивается как **автоматический список TCPS-пиров** — ручная конфигурация не нужна.

**Как это работает:**
- Модуль всегда добавляет TC option в исходящий SYN (пробует TCPS)
- Если SYN+ACK пришёл **с** TC option → пир имеет модуль → TCPS-сессия → IP добавляется в TOFU
- Если SYN+ACK пришёл **без** TC option → проверяем TOFU:
  - Пир **в TOFU** → downgrade-атака! → NF_DROP
  - Пира **нет в TOFU** → включаем **in-band probe** (см. ниже)

**Результат:** `apt-get update`, DNS, HTTP к внешним серверам — всё работает.
Как только обе стороны имеют модуль и хотя бы раз соединились — downgrade блокируется автоматически.

| Сценарий | Пир в TOFU? | Результат |
|----------|------------|-----------|
| SYN без TC (сервер) | Да | NF_DROP — downgrade |
| SYN без TC (сервер) | Нет + enforce=0 | NF_ACCEPT — plain TCP |
| SYN без TC (сервер) | Нет + enforce=1 | NF_DROP — строгий режим |
| SYN+ACK без TC (клиент) | Да | NF_DROP — downgrade |
| SYN+ACK без TC (клиент) | Нет | PLAIN_PROBE → in-band probe |

При `enforce=1` на сервере — даже неизвестные клиенты обязаны иметь модуль.
При `enforce=0` (по умолчанию) — неизвестные клиенты могут подключаться по plain TCP.

# In-band probe — автоматический детект downgrade при первом соединении

Проблема: при первом соединении к новому пиру MITM может стрипнуть TC option из SYN+ACK.
Клиент думает, что модуля нет, и fallback'ает к plain TCP. Классический SSH first-use вектор.

**Решение: in-band probe через payload.** MITM легко стрипает TCP options (заголовок),
но модификация payload гораздо сложнее — нужно трекать TCP stream, корректировать seq/length/checksum.
Большинство MITM-инструментов (arpspoof, ettercap) payload не модифицируют.

**Протокол:**

```
Probe request (клиент → сервер):
[0x02]['T']['P']['R'][static_pub(32)] = 36 байт в начале первого data-пакета

Probe response (сервер → клиент):
[0x03]['T']['P']['S'][static_pub(32)] = 36 байт в начале первого ответа
```

**Поток при MITM (strip TC option):**

1. SYN+ACK без TC → conn переходит в состояние `TCPS_PLAIN_PROBE` (вместо DEAD)
2. Клиент: первый data-пакет → prepend probe request → `probe_sent=1`
3. Сервер: видит маркер `0x02+'TPR'` в payload → strip probe → создаёт conn (PLAIN_PROBE) →
   добавляет клиента в TOFU → логирует warning
4. Сервер: первый data-ответ → prepend probe response → `probe_sent=1`
5. Клиент: видит маркер `0x03+'TPS'` → **DOWNGRADE DETECTED** → `kill=1` → NF_DROP всех пакетов →
   добавляет сервер в TOFU

**Поток при отсутствии модуля на пира:**

1. SYN+ACK без TC → `TCPS_PLAIN_PROBE`
2. Клиент: отправляет probe request в data
3. Сервер (без модуля): probe — это обычные байты в payload, ядро передаёт приложению как есть
4. Приложение может проигнорировать или выдать ошибку (36 лишних байт)
5. Таймаут 30 сек → GC удаляет conn → соединение продолжается как plain TCP

**После детекта downgrade:**
- Соединение убивается (kill=1 → NF_DROP)
- Пир добавляется в TOFU → следующий SYN+ACK без TC → NF_DROP (downgrade по TOFU-кешу)
- MITM не может обойти: даже если перестанет стрипать, TOFU уже защищает

**Ограничения probe:**
- Probe отправляется только в первом data-пакете (если клиент не шлёт данные — probe не уйдёт)
- Probe response отправляется только в первом data-ответе сервера
- Таймаут 30 сек — если за это время нет ответа, probe отменяется
- Приложение видит 36 лишних байт, если сервер не имеет модуля (можно tolerated)
- MITM с payload-modification capability может стрипать probe (но это значительно сложнее, чем strip TCP options)

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

# Защита от MITM (TOFU + auth_tag + epoch)

Статический identity-ключ X25519 генерируется при загрузке модуля. Приватный ключ хранится
только в RAM ядра, никогда не передаётся по сети, на диск не записывается.

**Двухфазный протокол:**

Фаза 1 — SYN/SYN-ACK: эфемерные DH-ключи + epoch → шифрование (forward secrecy)
Фаза 2 — ACK/data после шифрования: TI (option или embedded) со статическим ключом → аутентификация

**TI option (40 байт, pure ACK):** static_pubkey(32) + auth_tag(4)
**Embedded TI (37 байт, payload):** marker(1) + static_pubkey(32) + auth_tag(4)
- auth_tag = ChaCha20-PRF(DH(my_static_priv, peer_static_pub), ISN_client || ISN_server || "TAUT")[:4]
- auth_tag = 0 при первом соединении (нет ключа пира в TOFU-кеше)
- **auth_tag привязан к ISN** — MITM не может ретранслировать чужой TI между разными сессиями

**TOFU (Trust On First Use):**
- Первое соединение: статический pubkey + epoch пира запоминаются в TOFU-кеше (IP → pubkey + epoch)
- Последующие: pubkey сверяется с кешем, auth_tag верифицируется **всегда** (включая нулевой)
- Несовпадение pubkey или auth_tag → MITM обнаружен → NF_DROP
- TOFU-кеш автоматически используется для защиты от downgrade (см. Автообнаружение + Probe)

**Epoch — детекция перезагрузки/ротации ключей:**

При каждой загрузке модуля генерируется случайный 32-битный `epoch`. Он передаётся в TC option
и хранится в TOFU-кеше рядом с pubkey. При несовпадении pubkey:

| Условие | Реакция |
|---------|---------|
| pubkey совпадает | Обычная верификация auth_tag |
| pubkey ≠, epoch ≠ | **Ротация ключа** (вероятно перезагрузка) — auto-accept + warning |
| pubkey ≠, epoch тот же | **MITM** — дропать соединение |

Ротация ключей (новый epoch + новый pubkey) автопринимается при `auto_rotate=1` (по умолчанию).
При `auto_rotate=0` — любая смена ключа = MITM, требуется ручная перезагрузка модуля на обеих сторонах.

**auth_tag предотвращает пересылку чужого pubkey:**
MITM не может подделать auth_tag — для этого нужен статический приватный ключ,
который есть только у легитимного пира. ISN-binding предотвращает relay-атаку
(попытку переслать чужой auth_tag между двумя разными сессиями).

**Ограничение:** первое соединение доверяется без верификации (как SSH),
но in-band probe закрывает это окно для большинства MITM-инструментов.

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
- SYN+ACK без TCPS option от **нового** пира → in-band probe → автодетект MITM
- SYN без TCPS option от клиента, который **уже в TOFU** → NF_DROP (downgrade!)
- TI option не добавился → NF_DROP (соединение блокируется, а не откатывается к plaintext)
- TM option не добавилась → NF_DROP
- `enforce=1` дополнительно дропает SYN от любых клиентов без TCPS option на сервере

**In-band probe** — закрывает окно first-use:
- Если MITM стрипает TC option при первом соединении → probe детектит, что модуль есть → DOWNGRADE DETECTED
- MITM может обойти probe только модифицируя TCP payload (на порядки сложнее, чем strip options)
- После детекта: kill соединения + добавление в TOFU → все будущие соединения защищены

**RST injection**: inbound RST пакеты в зашифрованном состоянии (ENCRYPTED/AUTHENTICATED)
дропаются. Spoofed RST не может разорвать зашифрованную сессию. Соединение закрывается
только через FIN или GC timeout.

**TI timeout**: если TI не получен за 30 секунд (TCPS_TI_TIMEOUT), GC убивает соединение.
Предотвращает вечное зависание в ENCRYPTED без аутентификации.

**Probe timeout**: если probe response не получен за 30 секунд (TCPS_PROBE_TIMEOUT),
GC удаляет conn — пир действительно не имеет модуля, plain TCP продолжается.

# Embedded TI — отправка identity в payload

Проблема: TI option (40 байт) и TM option (20 байт) не помещаются вместе в 60-байтный
TCP заголовок. Если первый пакет после шифрования содержит данные, TI откладывается
до pure ACK — соединение висит в ENCRYPTED без аутентификации.

**Решение**: при `ti_sent==0` и наличии payload, TI встраивается в начало payload:

```
Отправитель:
[TCP hdr+opts][TI prefix(37, plaintext)][encrypted_app_data][TM option(20)]

TI prefix = [0x01][static_pub(32)][auth_tag(4)]
```

- TI prefix **не шифруется** ChaCha20 — избегаем сдвига позиций (position overlap)
- MAC (Poly1305) покрывает **обе части**: prefix + encrypted_data
- Приёмник: проверяет MAC, decrypt, извлекает TI, TOFU-verify, strip 37 байт

Детекция embedded TI: первый байт payload == 0x01. Приёмник вычитает 37 байт,
корректирует IP length и TCP checksum. TCP stack видит только application data.

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
7a   | pure ACK: TI option (static pub + auth_tag) ──► | TOFU + auth_tag верификация
7b   | data: embedded TI (static pub + auth_tag) ───► | TOFU + auth_tag верификация, strip 37B
8    | ◄ TI option или embedded TI                    | TCPS_AUTHENTICATED на обеих сторонах
     | Приложения (nginx/postgres/ssh) ничего не знают
```

## Только одна сторона имеет модуль (авто-fallback)

```
Шаг | Клиент (tcps.ko)                              | Сервер (без модуля)
-----|------------------------------------------------|--------------------------------------------
1    | SYN + TC option (ephemeral pubkey + epoch) ──► | Игнорирует неизвестный option 253
2    |                                                | SYN-ACK (без TC option)
3    | ◄────────────────────────────────────────────── |
4    | Пира нет в TOFU → PLAIN_PROBE → probe sent    |
5    | [0x02][TPR][static_pub] + data ──────────────► | Probe — это обычные байты, ядро передаёт app
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

## Downgrade при первом соединении — заблокирован probe

```
Шаг | Клиент (tcps.ko)                              | MITM → Сервер (tcps.ko)
-----|------------------------------------------------|--------------------------------------------
1    | SYN + TC option ──►                            | MITM стрипает TC option
2    |                                                | SYN (без TC) ──► Сервер: клиента нет в TOFU → plain
3    |                                                | SYN-ACK (без TC) ◄── Сервер
4    | ◄── MITM пропускает SYN-ACK без изменений      |
5    | Пира нет в TOFU → PLAIN_PROBE                  |
6    | [probe request + data] ──►                      | MITM не модифицирует payload → probe доходит!
7    |                                                | Сервер: видит probe marker → создаёт conn, strip probe
8    |                                                | Сервер: [probe response + data] ──►
9    | ◄── MITM не модифицирует payload → probe response доходит!
10   | DOWNGRADE DETECTED! → kill=1 → NF_DROP         |
     | Пир добавлен в TOFU → следующие попытки → NF_DROP
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
автоматически. При `auto_rotate=0` — обеим сторонам нужно перезагрузить модуль.

# Проверка работы

## dmesg — сессии и ошибки

```bash
dmesg | grep tcps
```

Загрузка модуля:
```
tcps: module loaded, ECDH + ChaCha20-Poly1305 + TOFU active
tcps: identity fingerprint: a1b2c3d4e5f6a7b8 epoch: 1234567890
```

Успешное соединение (первое — TOFU запоминает):
```
tcps: encrypted session 192.168.1.69:41548 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: TI option sent 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: TOFU: new peer 192.168.1.127 fingerprint 9a8b7c6d5e4f3a2b epoch: 1234567890
tcps: session authenticated 192.168.1.69:41548 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

Успешное соединение (повторное — TOFU + auth_tag верификация):
```
tcps: encrypted session 192.168.1.69:41550 <-> 192.168.1.127:80 (ECDH+AEAD)
tcps: session authenticated 192.168.1.69:41550 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

Embedded TI (первый data-пакет вместо pure ACK):
```
tcps: TI embedded in data 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: session authenticated (embedded TI) 192.168.1.69:41548 <-> 192.168.1.127:80
```

Plain TCP probe (пир без модуля):
```
tcps: peer 93.184.216.34 has no TCPS module, probing
tcps: probe sent 192.168.1.69:41548 <-> 93.184.216.34:80
tcps: probe timeout for 192.168.1.69:41548 <-> 93.184.216.34:80, peer has no module
```

In-band probe — MITM обнаружен при первом соединении:
```
tcps: peer 192.168.1.127 has no TCPS module, probing
tcps: probe sent 192.168.1.69:41548 <-> 192.168.1.127:80
tcps: DOWNGRADE DETECTED! Peer 192.168.1.127 has TCPS module but option was stripped
```

Сервер: probe получен — MITM стрипает опции:
```
tcps: probe received from 192.168.1.69:41548 — TCPS option was stripped, possible MITM
tcps: probe response sent 192.168.1.127:80 <-> 192.168.1.69:41548
```

Ротация ключа (перезагрузка модуля на одной стороне, auto_rotate=1):
```
tcps: key rotation detected for peer 192.168.1.127 (epoch 1234567890 -> 987654321)
tcps: old fingerprint 9a8b7c6d5e4f3a2b, new fingerprint deadbeef12345678
tcps: session authenticated 192.168.1.69:41552 <-> 192.168.1.127:80 (TOFU+auth_tag)
```

Downgrade обнаружен (MITM стрипает TCPS option от известного пира):
```
tcps: downgrade detected! SYN+ACK without TCPS from known peer 192.168.1.127
tcps: downgrade detected! SYN without TCPS from known peer 192.168.1.127
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
| `unknown-253` в ACK | TI option со static pubkey + auth_tag (40 байт, magic 'T','I') |
| `unknown-253` в данных | TM option с Poly1305 тегом (20 байт, magic 'T','M') |
| Нечитаемые данные | Payload зашифрован ChaCha20 |
| Читаемые данные | Plain TCP — пир без модуля (не в TOFU) |

Примечание: MSS не включается в SYN (TC option занимает все 40 байт опций).
TCP использует default MSS (536) до Path MTU Discovery.

```bash
# На атакующем: ARP-spoofing (strip TC options, но НЕ payload)
sysctl -w net.ipv4.ip_forward=1
arpspoof -i eth0 -t <CLIENT_IP> <SERVER_IP> &
arpspoof -i eth0 -t <SERVER_IP> <CLIENT_IP> &
# iptables: strip TCP option 253 из SYN/SYN+ACK
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 536
# (или просто не модифицировать payload — как arpspoof по умолчанию)

# На клиенте: ПЕРВОЕ соединение (TOFU ещё пуст)
insmod tcps.ko
echo "test" | nc <SERVER_IP> 9000
dmesg | grep tcps
# → "peer <SERVER_IP> has no TCPS module, probing"
# → "probe sent ..."
# → "DOWNGRADE DETECTED! Peer <SERVER_IP> has TCPS module but option was stripped"
# Соединение убито! Данные НЕ дошли до MITM.

# На сервере:
dmesg | grep tcps
# → "probe received from <CLIENT_IP> — TCPS option was stripped, possible MITM"
# → "probe response sent ..."

# Повторное соединение — TOFU защищает:
echo "test2" | nc <SERVER_IP> 9000
# → "downgrade detected! SYN+ACK without TCPS from known peer <SERVER_IP>" → NF_DROP
```

# Свойства безопасности

| Свойство | Механизм |
|----------|----------|
| Шифрование | ChaCha20 stream cipher |
| Целостность | Poly1305 MAC (16 байт, per-packet key, AAD covers TCP flags) |
| FIN injection | FIN пакеты требуют MAC, spoofed FIN отбрасывается |
| Forward secrecy | Эфемерные X25519 DH-ключи, уничтожаются после деривации |
| MITM-защита | TOFU + auth_tag (статический identity ключ) + ISN-binding |
| MITM relay | auth_tag привязан к ISN — пересылка между сессиями невозможна |
| Ротация ключей | Epoch — детекция перезагрузки, auto-rotate при смене epoch |
| Downgrade-защита | TOFU как список пиров + NF_DROP при strip от известных пиров |
| Downgrade first-use | In-band probe через payload — автодетект MITM при первом соединении |
| Auto-discovery | TOFU-кеш автоматически определяет TCPS/Plain для каждого IP |
| RST injection | Inbound RST дропается в зашифрованном состоянии |
| Timing-атаки | crypto_memneq для MAC и auth_tag |
| Key separation | HKDF-Expand с уникальными лейблами для каждого ключа |
| Приватность ключей | memzero_explicit, только в RAM, на диск не пишутся |
| TI delivery | Embedded TI в payload — аутентификация с первым data-пакетом |

# Известные ограничения

| Ограничение | Описание |
|-------------|----------|
| IPv4 only | IPv6 пока не поддерживается |
| auth_tag 4 байта | 32-bit security для identity verification. Увеличение требует пересмотра TI option (40B — максимум TCP options) |
| Нет лимита соединений | Лимит 4096 (tcps_conn_count). При превышении — SYN дропается |
| TOFU kzalloc fail | Соединение отклоняется вместо доверия (return -1) |
| RST delay | Легитимный RST от пира дропается, закрытие через FIN/timeout |
| Pure ACK не аутентифицирован | ACK без FIN и без payload не содержат MAC (overhead). FIN защищён |
| TOFU cache in-memory | Теряется при rmmod, ключи на диск не сохраняются |
| Epoch — эвристика | Не криптографическое доказательство: активный MITM может подменить epoch+ключ при auto_rotate=1 |
| MSS в SYN | TC option (40B) занимает всё пространство опций — MSS не включается. Default 536, PMTU Discovery компенсирует |
| Embedded TI marker | Байт 0x01 в начале payload — при коллизии с app data возможен DoS (дроп пакета) |
| Probe без data | Probe отправляется только в data-пакете. Если клиент не шлёт данные — probe не уйдёт |
| Probe без ответа | Если сервер не шлёт данные — probe response не отправится, таймаут 30 сек |
| Probe payload-mod MITM | MITM с возможностью модификации payload может стрипать probe (на порядки сложнее, чем strip options) |
| Probe + plain server | Сервер без модуля получает 36 лишних байт в payload от probe. Приложение может выдать ошибку |
