### TCP/S — прозрачное шифрование TCP на 4 уровне
# Архитектура
```
tpcs/
├── kernel/                    # Linux kernel module (LKM)
│   ├── tcps.h                 # Заголовок: состояния, структуры коннектов
│   ├── tcps_main.c            # Netfilter hooks (LOCAL_OUT + PRE_ROUTING)
│   ├── tcps_crypto.c          # Curve25519 + ChaCha20 для ядра
│   └── Makefile               # Сборка: make → tcps.ko
│
└── user/                      # Userspace LD_PRELOAD библиотека
    ├── tcps.c                 # Перехват socket/connect/accept/send/recv/close
    ├── tcps_crypto.c          # Curve25519 + ChaCha20 для userspace
    ├── test_server.c          # Обычный TCP-сервер (без TCPS API)
    └── test_client.c          # Обычный TCP-клиент (без TCPS API)
```
Как работает<br>
# Kernel module (tcps.ko):
1. Netfilter hook LOCAL_OUT — добавляет TCP option TC (kind=253) в SYN-пакеты
2. Netfilter hook PRE_ROUTING — обнаруживает TC option в SYN-ACK
3. Если оба хоста поддерживают — после handshake отправляет Curve25519 pubkey как первые 32 байта данных
4. После вычисления shared secret — все TCP-данные шифруются ChaCha20 (stream cipher, размер не меняется)
5. Работает для всех TCP-сокетов на системе, приложения ничего не знают
# LD_PRELOAD библиотека (libtcps.so/.dylib):
1. Перехватывает socket(), connect(), accept(), send(), recv(), close()
2. После TCP-подключения — Curve25519 хэндшейк
3. Всё шифруется ChaCha20, потоковая позиция = счётчик
4. Запуск: DYLD_INSERT_LIBRARIES=./libtcps.dylib ./my_app (macOS) или LD_PRELOAD=./libtcps.so ./my_app (Linux)
# Криптография (без OpenSSL)
- Curve25519 ECDH — 32-байтные ключи, ~300 строк с нуля
- ChaCha20 — stream cipher, XOR на позиции потока, без изменения размера пакетов
- KDF — ChaCha20 как PRF для деривации ключей из shared secret

# Модуль нужно загрузить на обе стороны — и на клиент, и на сервер. 
```
Вот как это работает:

Шаг | Клиент (tcps.ko) | Сервер (tcps.ko)
-----|------------------|------------------
1-2  | SYN + "TC" ──────► | Видит "TC"
3-4  | ◄──── SYN-ACK + "TC" | Оба знают: можно шифровать
5    | ◄────► Обмен Curve25519 pubkey (32b)
6    | Shared secret → ChaCha20 ключи
7    | ◄═══════════════════════════► ChaCha20 поток
     | Приложения (nginx/postgres/curl) ничего не знают
```
Если только одна сторона имеет модуль — TCP option "TC" не будет в ответе, и модуль откатится к обычному TCP (без шифрования). Соединение работает как обычно.
# Развёртывание:
# На сервере и на клиенте (Linux):
cd kernel/
make                    # компилируем tcps.ko
sudo insmod tcps.ko     # загружаем модуль в ядро
# Любое TCP-подключение между этими машинами автоматически шифруется. PostgreSQL, HTTP, SSH — что угодно.
Модуль сидит в netfilter (L4), а не на порту. Он видит каждый TCP-пакет, проходящий через ядро.
