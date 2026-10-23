# AGENTS.md

## Описание проекта

**`tproxy-server`** (`github.com/telegramdesktop/tproxy-server`) — серверная часть концепции Telegram WEB-прокси.
Telegram-клиент сохраняет стандартное обрамление и шифрование MTProxy, но передает все TCP-соединения через собственный WebView-транспорт поверх HTTPS или WebSocket.
Сервер `tproxy-server` принимает мультиплексированные потоки от WebView, разделяет их и локально проксирует в официальный `MTProxy`.

Внешний входящий трафик маскируется под обычный веб-сайт (через reverse proxy Caddy или Nginx). Доступ к bridge-странице осуществляется через capability-токен, вычисляемый из секрета MTProxy и имени хоста.

### Стек технологий
- **Язык**: Go (1.21+) — пакет `log/slog` требует версию Go не ниже 1.21
- **Зависимости**: `github.com/gorilla/websocket`
- **Фронтенд/Bridge**: HTML/JS встроенный runtime для WebView (`internal/bridge/`)
- **Инфраструктура/Развертывание**: Caddy / Nginx (обратный прокси/HTTPS), systemd, nftables (firewall), официальный MTProxy
---

## Структура проекта

```text
lordik-server/
├── .github/
│   └── workflows/
│       └── release.yml              # CI/CD: автосборка под linux/amd64 и публикация GitHub Release при тегах v*.*.*
├── cmd/
│   └── tproxy-server/
│       └── main.go                  # Точка входа сервера: парсинг флагов, инициализация и запуск
├── internal/
│   ├── bridge/                      # Генерация и обслуживание bridge-страницы для WebView (HTML/JS)
│   ├── config/                      # Загрузка и валидация конфигурации, работа с token-ключами
│   ├── frame/                       # Кодирование и декодирование кадров протокола (OPEN, DATA, WINDOW, CLOSE)
│   ├── server/                      # HTTP/WebSocket сервер, маршрутизация, интеграция с сайтом и Caddy
│   └── session/                     # Управление сессиями, токенами доступа и логическими потоками
├── deploy/                          # Скрипты развертывания, systemd-юниты, конфигурация Caddyfile, nginx-tproxy.conf и nftables
├── docs/
│   └── CDN_TRANSPORT_SPEC.md        # Спецификация транспортного протокола CDN-Adaptive / CDN-Stream (GET-only uplink, header sharding, glTF streaming downlink)
├── config.example.json              # Пример основной конфигурации сервера
├── profiles.example.json            # Пример профилей сетевых транспортов/carrier
├── PROTOCOL.md                      # Спецификация сетевого протокола и формата кадров
├── PLAN.md                          # Архитектурный план, ограничения и проектные решения
├── PUBLIC_SITE.md                   # Документация по расширению/хостингу публичного сайта
├── HARDENING.md                     # Инструкции по безопасности и изоляции
├── ANDROID.md / IOS.md              # Документация по реализации клиентской части (Android / iOS)
├── README.md                        # Общее руководство по установке и настройке
└── .omp/
    ├── RULES.md                     # Базовые правила разработки (обратная совместимость)
    └── AGENTS.md                    # Контекст для агентов, описание, структура и реестр особенностей
```

---

## Протокол ведения журнала проблем и особенностей

В процессе разработки любые выявленные проблемы, неочевидные особенности окружения, баги библиотек или архитектурные ограничения **ОБЯЗАТЕЛЬНО** фиксируются в разделе ниже («Журнал проблем и архитектурных особенностей»).

### Правила добавления записей:
1. Описать суть проблемы или особенности.
2. Указать затронутые компоненты / файлы.
3. Описать принятое решение или обходной путь (workaround), чтобы в будущем не решать задачу заново.

---

## Журнал проблем и архитектурных особенностей

*(Пополняется по ходу разработки)*

1. **Обратная совместимость протокола**:
   - Любые изменения формата кадров в `internal/frame`, сетевого протокола в `PROTOCOL.md` или спецификации CDN-транспорта в `docs/CDN_TRANSPORT_SPEC.md` должны сохранять совместимость с существующими клиентами Telegram Desktop / Android / iOS.
2. **Изоляция публичного сайта**:
   - При неверном capability или отсутствии токена сессии запросы должны бесшовно отдавать публичный сайт без утечки информации о наличии прокси.
3. **Особенности работы за обратным прокси Nginx**:
   - **Единичный IP в `X-Forwarded-For`**: `internal/server/server.go:clientIP` ожидает строго один IP-адрес клиента и отклоняет любые списки с запятыми (`invalid forwarding address`). Nginx-переменная `$proxy_add_x_forwarded_for` добавляет IP через запятую к существующему заголовку клиента, что ломает валидацию. Решение: в Nginx всегда использовать `proxy_set_header X-Forwarded-For $remote_addr;`.
   - **Размер тела запроса**: пакеты кадров аплинка от клиентов достигают 2 МиБ. Стандартный лимит Nginx (`client_max_body_size 1m;`) возвращает клиентам `413 Request Entity Too Large`. Решение: установить `client_max_body_size 4m;`.
   - **Отключение буферизации и таймауты**: для потоковой передачи фреймов и long-poll (25 с) в Nginx обязательны `proxy_buffering off;`, `proxy_request_buffering off;`, `proxy_read_timeout 90s;` и `proxy_send_timeout 90s;`.
   - **Приватность и логирование**: capability-токен передается в query-параметре (`?bridge=`), а токен WebSocket-сессии — в `Sec-WebSocket-Protocol`. В Nginx необходимо отключать `access_log` для проксируемого хоста во избежание утечки секретов и активного пробинга.
4. **Специфика окружения Windows для тестов**:
   - Защитные проверки в `internal/config/token_key.go` и `config.go` проверяют строгие POSIX-права файлов (`info.Mode().Perm() & 0077 == 0`). В среде Windows (NTFS) вызовы `os.Stat` не мапят POSIX-права группы/остальных, возвращая `0666`, из-за чего тесты прав файлов (`token_key_file must not be accessible by group or others`) на Windows не проходят. Целевая среда выполнения — Linux x86_64. Для запуска тестов на Windows проверки прав пропускаются при `runtime.GOOS == "windows"`.
5. **Поддержка бэкенда Telemt и PROXY protocol**:
   - **Компоненты**: `internal/config/config.go`, `internal/session/session.go`, `internal/session/proxy_protocol.go`, `internal/server/server.go`.
   - **Архитектура**: добавлена поддержка высокопроизводительного Rust-бэкенда `Telemt` (https://github.com/telemt/telemt) наряду с официальным MTProxy.
   - **Тип бэкенда (`backend_type`)**: `"mtproxy"` (по умолчанию) и `"telemt"`. Задается глобально в `config.json` и/или индивидуально в `profiles.json`.
   - **Транспорт (`backend`)**: для Telemt поддерживается как TCP-loopback (`127.0.0.1:port`), так и UNIX domain сокеты (`unix:/path/to/telemt.sock` или `unix:///path/to/telemt.sock`), что устраняет накладные расходы TCP-стека и повышает изоляцию.
   - **Передача реального IP клиента (`backend_proxy_protocol`)**: `"none"` (по умолчанию), `"v1"` (текстовый) или `"v2"` (бинарный HAProxy PROXY protocol). При создании логического потока в Telemt автоматически отправляется PROXY-заголовок с реальным IP клиента (`clientIP`, полученным из `X-Forwarded-For`), что позволяет Telemt осуществлять точную привязку к DC Telegram и сбор метрик.
   - **Защита от некорректной конфигурации**: официальный MTProxy не поддерживает PROXY protocol и UNIX-сокеты; при попытке указать их для `mtproxy` конфигуратор возвращает явную ошибку валидации.
6. **Модульная фабрика и HTML-шаблоны Bridge-страниц**:
   - **Компоненты**: `internal/bridge/page.go`, `internal/bridge/factory.go`, `internal/bridge/templates/`.
   - **Суть изменения**: Ранее runtime bridge-страницы находился в единственной монолитной переменной `document` в Go-коде `page.go`. Он вынесен в отдельные файлы шаблонов в директории `internal/bridge/templates/`, встроенные в бинарник через `embed.FS`:
     - `bridge.html`: универсальный полнофункциональный шаблон для обратной совместимости.
     - `https.html`: оптимизированный шаблон для HTTP-поллинга без WebSocket.
     - `https_lanes.html`: шаблон для HTTP с мультиплексированием по логическим линиям (lanes).
     - `websocket.html`: оптимизированный шаблон для единого WebSocket-соединения.
     - `websocket_lanes.html`: шаблон для индивидуальных WebSocket-соединений на каждую логическую линию.
     - `cdn.html`: специализированный адаптивный шаблон для CDN-транспортов (`cdn-adaptive`, `cdn-get`, `cdn-body`, `cdn-ws`) с мимикрией под Next.js/HLS, поддержкой Header Sharding, Happy Eyeballs рукопожатия, Streaming Downlink (`ReadableStream`) с авто-откатом к Long-Polling, ETag-кэшированием и анти-буферизацией glTF binary.
   - **Архитектура фабрики (`Factory`)**:
     - Реализован компонент `Factory` с методом `Render(Options)` и иерархическим разрешением шаблонов: сначала проверяется наличие платформо-специфичного шаблона для режима (`platform_carrierMode.html`), затем платформенного (`platform.html`), затем carrier-режима (`carrierMode.html`), с откатом к `bridge.html`.
     - Поддерживается динамическая регистрация и переопределение шаблонов (`RegisterTemplate`).
     - Сохранена полная обратная совместимость: функция `bridge.Render(hostname, basePath, bootstrapToken, carrierMode, batchBytes)` работает прозрачно через синглтон `DefaultFactory()`. Добавлена функция `bridge.RenderWithOptions(opts)` для расширенной генерации.
7. **Поддержка бэкенда прямого подключения к Telegram DC (`direct`)**:
   - **Компоненты**: `internal/config/config.go`, `internal/session/direct.go`, `internal/session/session.go`.
   - **Архитектура**: добавлен бэкенд прямого проксирования (`backend_type: "direct"`), позволяющий серверу при доступности дата-центров Telegram подключаться к ним напрямую по TCP (порт 443) без промежуточного MTProxy или Telemt.
   - **Трансляция рукопожатия и шифрования MTProto**:
     - Клиент подключается к WEB-прокси с использованием MTProxy-секрета (16 байт или `dd` + 16 байт) и шлет 64-байтный заголовок, зашифрованный AES-CTR по производному ключу `sha256(prekey + secret)`.
     - `direct`-бэкенд парсит и расшифровывает клиентский заголовок (`ParseClientHandshake`), извлекая тег протокола (`abridged`, `intermediate`, `padded_intermediate`) и идентификатор DC (`dc_idx`).
     - Для аплинка к дата-центру Telegram бэкенд генерирует легитимный 64-байтный заголовок MTProto Obfuscated2 (`CreateTelegramHandshake`) без использования секретов MTProxy, который ожидает официальный сервер Telegram DC.
     - Потоки данных прозрачно транслируются в обоих направлениях с потоковой перешифровкой (клиент <-> proxy <-> Telegram DC).
   - **Режимы выбора DC и маршрутизация медиа/CDN**:
     - **Автоматический (`"auto"` или пустое значение `backend`)**: бэкенд динамически извлекает `dc_idx` из MTProto рукопожатия клиента (`int16 Little-Endian`).
     - **Основные дата-центры (1–5)**: маршрутизация текстовых сообщений, API и синхронизации (`149.154.175.50:443`, `149.154.167.51:443`, `149.154.175.100:443`, `149.154.167.91:443`, `149.154.171.5:443`).
     - **Media-only дата-центры (-1..-5 и 10001..10005)**: для скачивания/загрузки фото, видео, голосовых и файлов клиент Telegram открывает отдельные параллельные потоки с отрицательными `dc_idx` (`-1`...`-5`). Основные API-серверы (`.51`, `.91`) отклоняют `upload.getFile`. Потоки маршрутизируются на **выделенные Media-only кластеры**:
       - **DC -2**: `149.154.167.151:443` (вместо основного API-сервера `.51`)
       - **DC -4**: `149.154.166.120:443` (вместо основного API-сервера `.91`)
       - **DC -1 / -3 / -5**: `149.154.175.50:443`, `149.154.175.100:443`, `149.154.171.5:443`.
       - При поиске в таблице сначала проверяется точный отрицательный ключ `dc_idx`, и только при его отсутствии выполняется fallback на `abs(dc_idx)`.
     - **CDN дата-центры (203 и -203)**: загрузка публичных медиа и контента крупных каналов маршрутизируется на `91.105.192.100:443`.
     - **Диагностическое логирование**: при подключении каждого потока логируется разобранный тег протокола, `dc_idx` и целевой DC (`direct stream handshake parsed: stream_id, dc, tag, target`).
     - **Статический (`static_dc` или явный `backend: "host:port"` / `backend: "2"`)**: принудительная маршрутизация всех потоков на указанный дата-центр. Поддерживаются номера DC 1..5, -1..-5, 203, -203 и строковые/числовые представления.
   - **Ограничения и валидация**:
     - PROXY protocol не поддерживается протоколом Telegram DC; при попытке указать `backend_proxy_protocol` для `direct` валидатор возвращает явную ошибку.
     - UNIX domain сокеты для `direct` запрещены (только TCP).
   - **Сохранность функционала**: поведение существующих бэкендов `mtproxy` и `telemt` полностью сохранено.
8. **Система структурированного логирования и ротации (`logger`)**:
   - **Компоненты**: `internal/logger/logger.go`, `internal/logger/rotator.go`, `internal/config/config.go`, `cmd/tproxy-server/main.go`, `internal/server/server.go`, `internal/session/session.go`, `internal/session/direct.go`, `internal/bridge/factory.go`.
   - **Архитектура**:
     - Реализована на базе стандартного пакета Go `log/slog` без сторонних зависимостей.
     - Поддерживает уровни логирования (`debug`, `info`, `warn`, `error`) и форматы вывода (`text`, `json`).
     - Поддерживает вывод в `stdout`, `file` или `both` (одновременно в консоль и файл).
     - Реализован компонент `DailyRotatingWriter` с ежедневной ротацией по дате (`YYYY-MM-DD`) и автоматической очисткой файлов старше `max_days`.
   - **Конфигурация в `config.json`**:
     - Секция `logging`: `enabled` (bool), `level` ("debug"|"info"|"warn"|"error"), `format` ("text"|"json"), `output` ("stdout"|"file"|"both"), `dir` (каталог для логов), `prefix` (префикс файлов, по умолчанию "tproxy"), `max_days` (хранение в днях).
   - **Приватность и безопасность**:
     - Категорически исключена утечка MTProxy-секретов и capability-токенов в логах.
     - Точки логирования оперируют именами профилей, числовыми stream_id, IP клиентов и сетевыми статусами без дампа тела секретных рукопожатий и авторизационных заголовков.
     - Предусмотрен хелпер `logger.MaskToken` для безопасного вывода токенов при необходимости.
9. **CLI-команды диагностики и управления (`internal/cli`)**:
   - **Компоненты**: `cmd/tproxy-server/main.go`, `internal/cli/cli.go`, `internal/cli/link.go`, `internal/cli/logs.go`, `internal/cli/test.go`, `internal/config/config.go`.
   - **Подкоманды**:
     - `link`: генерация и вывод готовой ссылки подключения к прокси (`tg://proxy?server=...&port=...&secret=...`, `tg://webproxy?...`, `https://t.me/webproxy?...`). Поддерживает флаги `-config`, `-profiles-file`, `-profile`, `-host`, `-port`, `-type` (proxy, webproxy, https, all), `-base-path`, `-secret`, `-h`.
     - `logs`: просмотр последних N записей журнала (по умолчанию 50) с флагом `-n`, поддержкой ротированных файлов по дате и флагами `-config`, `-dir`, `-file`, `-prefix`, `-h`.
     - `test` (и флаг `-t` для корневой команды): валидация конфигурационного файла и профилей без запуска слушателей портов. Возвращает код 0 при валидной конфигурации и 1 при ошибке.
   - **Обратная совместимость**:
     - Корневой запуск `tproxy-server` без аргументов или с флагами `-config`, `-profiles-file` запускает сервер в обычном режиме без изменений.
     - Все подкоманды и флаги `-h` завершаются с кодом 0 и корректно форматируют справку.
10. **Автоматическая сборка и публикация релизов в GitHub Actions**:
    - **Компоненты**: `.github/workflows/release.yml`.
    - **Архитектура**:
      - Workflow запускается по событию `push` тегов с маской `v*.*.*`.
      - Требует Go 1.21+ (`log/slog`), версия извлекается из `go.mod`.
      - Выполняет чистую статическую кросс-компиляцию бинарника под `linux/amd64` с флагами оптимизации (`CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w"`).
      - Упаковывает бинарник `tproxy-server` вместе с примерами конфигураций `config.example.json`, `profiles.example.json` и документацией `README.md` в архив `.tar.gz`.
      - Автоматически рассчитывает контрольную сумму SHA-256 (`.tar.gz.sha256`).
      - Публикует официальный GitHub Release через `softprops/action-gh-release@v2` с автогенерацией release notes и прикреплением архива и контрольной суммы.
11. **Схема развертывания tproxy-server с Nginx и Telemt**:
    - **Компоненты**: `tproxy-server`, `Nginx`, `Telemt`.
    - **Архитектурная связка**:
      - Внешний трафик по портам 80/443 принимает `Nginx`.
      - `Nginx` для домена проксирует все запросы на HTTP-порт `tproxy-server` (например, `127.0.0.1:18081`).
      - Неавторизованные запросы (без capability-токена или валидного заголовка сессии) `tproxy-server` бесшовно перенаправляет на `public_upstream` (например, `http://127.0.0.1:18080`, где крутится decoy-сайт `Telemt` или внешний сайт).
      - При наличии capability-токена `tproxy-server` отдает защищенную bridge-страницу для Telegram WebView (`carrier_mode: "https"`).
      - Потоки данных MTProxy транслируются в локальный listener `Telemt` с `transport = "mtproxy"` (например, `127.0.0.1:9090`).
      - **Режимы секретов Telemt (`[general.modes]`)**: при подключении через `tproxy-server` со стандартным 16-байтным MTProto-секретом (без префикса `dd`) в `telemt` обязательно должен быть разрешен классический режим (`classic = true`). При `classic = false` Telemt отклоняет рукопожатие клиента на стадии дешифрования фреймов.
12. **Система версионирования и команда автообновления (`update`, `-v`, `version`)**:
    - **Компоненты**: `internal/version/version.go`, `internal/cli/version.go`, `internal/cli/update.go`, `cmd/tproxy-server/main.go`, `.github/workflows/release.yml`.
    - **Архитектура**:
      - В пакете `internal/version` определена глобальная переменная `Version` (по умолчанию `v0.2.1`), инжектируемая флагом линковщика `-ldflags="-X github.com/telegramdesktop/tproxy-server/internal/version.Version=${TAG}"` в CI при публикации релизов.
      - Реализован парсер и компаратор `Compare(v1, v2 string) int` по спецификации SemVer с поддержкой версий с префиксами `v`/`V`, числовых компонентов `major.minor.patch` и pre-release суффиксов.
      - Команда `version` и флаги `-v`, `--version` выводят текущую версию и параметры рантайма (`Info()`) или только версию при флаге `-short`.
      - Команда `update` выполняет запрос к GitHub Releases API (`https://api.github.com/repos/<repo>/releases/latest`), сравнивает версии, скачивает архив под текущую платформу (`linux/amd64` или текущую ОС/архитектуру), валидирует контрольную сумму SHA-256 (`.sha256`) и выполняет распаковку и атомарную замену бинарника на месте.
    - **Отказоустойчивость и безопасность замены бинарника (Rollback)**:
      - Новый бинарник записывается во временный файл в *той же директории*, где находится рабочий исполняемый файл, что гарантирует нахождение на том же файловом разделе для атомарного `os.Rename`.
      - При ошибках доступа (отсутствие прав sudo/root) возвращается понятная ошибка без повреждения работающего сервера.
      - Перед перемещением создается резервная копия (`.tproxy-bak-<pid>`). Если подмена файла срывается, выполняется автоматический откат к оригинальному файлу.
      - Проверка целостности по SHA-256 обязательна перед любыми операциями замены на диске.
13. **Транспортный режим CDN Adaptive (`cdn`, `cdn-adaptive`, `cdn-get`, `cdn-body`, `cdn-ws`)**:
    - **Компоненты**: `docs/CDN_TRANSPORT_SPEC.md`, `internal/config/config.go`, `internal/session/cdn.go`, `internal/session/session.go`, `internal/session/manager.go`, `internal/server/cdn.go`, `internal/server/server.go`, `internal/server/secrets.go`, `internal/bridge/factory.go`, `internal/bridge/templates/cdn.html`.
    - **Архитектура и назначение**:
      - Новый режим сетевого транспорта поверх жестких облачных CDN (Cloudflare, CloudFront, Gcore, Fastly) и корпоративных L7-прокси.
      - Мимикрия трафика под SPA-запросы Next.js / Webpack chunks / HLS-сегменты:
        - `_next/data/{build_id}/collect.json` (POST-рукопожатие).
        - `_next/data/{build_id}/init/{token}/{hello}.json` (GET-рукопожатие для сред с блокировкой POST).
        - `assets/chunks/{short_id}/{seq}_{payload}.bin` (GET конвейер uplink с Header Sharding).
        - `_next/data/{build_id}/sync/{short_id}/{seq}.bin` (POST uplink для CDN с разрешенным POST).
        - `assets/media/{short_id}/seg_{cursor}_{rand}.m4s` (GET downlink long-poll).
        - `_next/data/{build_id}/unload/{short_id}.json` (GET-закрытие сессии).
    - **Сборка потока и буферизация (`ReassemblyBuffer`, `FrameStreamParser`)**:
      - `ReassemblyBuffer` обеспечивает скользящее окно упорядочивания внеочередных HTTP-запросов (по умолчанию 16), предотвращает дублирование (идемпотентность ретраев) и пресекает переполнение окна (`ErrProtocol`).
      - `FrameStreamParser` выполняет потоковую склейку байтовых фрагментов в цельные кадры протокола с защитой от переполнения памяти (`maxPayload + HeaderSize`).
    - **Downlink Piggybacking и MIME-sniffing Resistance (`glTF` 2.0 binary)**:
      - Исходящие кадры прикрепляются прямо в ответы на Uplink (`PiggybackDown`) без задержек.
      - Кадры упаковываются с 12-байтовым заголовком `glTF` 2.0 binary (`magic: 0x676C5446`, `version: 2 (LE)`, `cursor: downCursor (BE)`) с `Content-Type: model/gltf-binary`, что предотвращает эвристический MIME-sniffing и L7-инспекцию CDN.
    - **Защита от активного зондирования (Active Probing Resistance)**:
      - Любые некорректные или неавторизованные запросы мгновенно перенаправляются на Decoy-сайт (`servePublic`) с кодом 404, исключая утечку серверных заголовков прокси.
      - Заголовок `X-Client-Key` мгновенно классифицируется в `carrierCredential`, исключая переборные коллизии.
    - **Стабилизация параллельных потоков и устранение гонок курсоров (CDN Review)**:
      - **Безопасная обработка устаревших курсоров в `PiggybackDown` и `PollCDN`**: при параллельных uplink-запросах (`maxInflight = 6`) приход запроса с устаревшим курсором (`cursor < s.downCursor`) штатно возвращает текущий `s.downCursor` с пустым телом без сброса протокола (`s.protocolFailure()`) и без повторной перекачки трафика.
      - **Устранение взаимной блокировки (deadlock)**: в `PiggybackDown` ошибка протокола вызывает `s.closeLocked()` напрямую без повторного захвата мьютекса `s.mu`.
      - **Сохранение кадров при `ErrBackpressure`**: в `Session` добавлено поле `cdnPendingFrames`, исключающее потерю извлеченных кадров при повторных попытках (HTTP 503).
      - **Гарантированная очистка памяти**: в `closeLocked()` обнуляются `s.cdnReassembly` и `s.cdnPendingFrames`.
      - **Доставка кадра `WELCOME` в `cdn.html`**: корректное чтение ArrayBuffer в `POST` и Base64URL в `GET` с передачей в `deliver()`.
      - **Демультиплексирование батчей в `deliver()` и Android Bridge**: батчи кадров разделяются через `splitFrames()` перед отправкой в порт.
      - **Happy Eyeballs Handshake в `cdn.html`**: параллельный запуск GET через 250 мс при задержке ответа на POST, сокращающий время подключения.
      - **Immediate First Dispatch**: мгновенная отправка первого пакета (0 мс задержки пинга) при `upInflight == 0`.
      - **Оптимизация Base64URL**: блочное кодирование чанками по 4096 байт с поддержкой нативного `Uint8Array.prototype.toBase64` и быстрым `DecodeCDNPayload` на базе `RawURLEncoding`.
      - **Query String Payload и CDN-кэширование**: поддержка передачи URL-части через `?p=...` в `serveCDNChunkGet` (устранение проблем с `NAME_MAX`), расширенные заголовки запрета кэширования (`CDN-Cache-Control`, `Cloudflare-CDN-Cache-Control`, `Surrogate-Control`, `X-Accel-Buffering`) и легковесный ETag (`W/{cursor}-{len}`).
14. **Оптимизация и устранение критических ошибок в direct.go, manager.go и cdn.go**:
    - **Компоненты**: `internal/session/direct.go`, `internal/session/manager.go`, `internal/session/session.go`, `internal/server/cdn.go`.
    - **Устранение утечки счетчика `backendDialsInFlight` и паники `panic("invalid backend dial accounting")`**:
      - В `runDirect()` добавлен флаг `dialAccounted` и гарантированный `defer func() { if !dialAccounted { s.session.backendDialFinished(false) } }()`.
      - При раннем закрытии клиентом потока, ошибке парсинга клиентского рукопожатия (`ParseClientHandshake`) или ошибке резолвинга DC (`ResolveTelegramDC`) счетчик активных попыток подключения гарантированно списывается, исключая блокировку открытия новых потоков на сервере.
    - **First-Byte Deadline для прямого бэкенда**:
      - Ожидание первых 64 байт рукопожатия ограничено таймаутом `BackendDial` через `time.AfterFunc`, что предотвращает зависание горутин и удержание слотов `streamsLive` при открытии клиентом пустых потоков (`OPEN` без `DATA`).
    - **Zero-overhead First Packet (объединение рукопожатия и первого пакета)**:
      - 64-байтный заголовок `tgHandshake` и перешифрованный полезный трафик клиента (`firstData[64:]`) склеиваются in-place в буфере `firstData` и отправляются в сокет Telegram DC единым системным вызовом `connection.Write`.
      - Это сокращает сетевой RTT на 30–150 мс при установке каждого потока к дата-центрам Telegram и объединяет учет окон `backendDrained`.
    - **Защита от запрещенных nonce в `CreateTelegramHandshake`**:
      - В генератор случайного nonce MTProto Obfuscated2 добавлены строгие проверки на совпадение с протокольными тегами `TagIntermediate` (`0xeeeeeeee`), `TagPaddedIntermediate` (`0xdddddddd`), `TagAbridged` (`0xefefefef`) и префиксом TLS-рукопожатий (`0x16`), исключая конфликт распознавания протокола серверами Telegram DC.
    - **Кэширование секрета и снижение уровня логирования потоков**:
      - `s.session.rawSecret` кэшируется при инициализации сессии, исключая повторный парсинг hex/base64-секрета на каждый поток.
      - Логирование разбора рукопожатия потока переведено с `Info` на `Debug`.
    - **Ускорение завершения сессий в `Manager` до $O(1)$**:
      - В структуру `Session` добавлены поля `tokenHash`, `bootstrapHash` и `shortID`.
      - В `sessionFinished` сессия и короткий ID удаляются из мап `m.sessions`, `m.shortSessions` и `m.bootstraps` за $O(1)$ без линейных циклов по всем сессиям сервера под блокировкой глобального мьютекса (с сохранением обратной совместимости fallback-перебора для внешних вызовов без хеша).
    - **Усиление авторизации CDN-маршрутов (`resolveSession`)**:
      - В `internal/server/cdn.go` в функции `resolveSession` для всех операций с данными (`chunks`, `sync`, `media`) теперь обязательно требуется валидный токен в заголовке `X-Client-Key`, токене Bearer или параметре `?k=`, а также сверяется соответствие `shortID` из пути URL с идентификатором сессии. Поиск только по `shortID` изолирован исключительно для закрытия сессии в `serveCDNUnload` при выгрузке страницы.
15. **Комплексная оптимизация производительности и устранение тонких мест CDN/Direct**:
    - **Компоненты**: `internal/server/server.go`, `internal/server/cdn.go`, `internal/session/session.go`, `internal/session/manager.go`, `internal/session/direct.go`, `internal/session/cdn.go`, `internal/bridge/templates/cdn.html`.
    - **Защита от IP-лимитов за CDN (`MaxSessionsPerIP` / `MaxBootstrapsPerIP`)**:
      - В `s.clientIP()` добавлена приоритетная проверка пограничных заголовков CDN и обратных прокси: `CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, а также безопасное извлечение первого клиентского IP из списков `X-Forwarded-For`.
      - Для профилей с CDN-транспортом (`CarrierMode.IsCDN()`) в `manager.IssueBootstrap` и `manager.Create` сняты ограничения `MaxBootstrapsPerIP` и `MaxSessionsPerIP`, предотвращая массовую блокировку пользователей за пограничными узлами Cloudflare/Gcore/CGNAT, при полном сохранении глобальных лимитов емкости и криптографической аутентификации capability-токенов.
    - **Бесконфликтная координация `PollCDN` и `PiggybackDown`**:
      - Если для сессии уже активен выделенный long-poll (`s.downActive == true`), `PiggybackDown` не перехватывает кадры из очереди и не закрывает `s.superseded`, позволяя фоновому поллингу мгновенно доставить данные без лишних переподключений и без риска гонки `unackedCost`.
    - **Защита от переполнения 32-битного курсора glTF в `cdn.html`**:
      - В `cdn.html` проверка прихода пакетов переведена на модульную арифметику серийных номеров RFC 1982: `((parsed.cursor - downCursor | 0) > 0 || downCursor === 0)`, что гарантирует корректную работу при wrap-around счетчика курсоров батчей.
    - **Защита от Half-Open сокетов и TCP Keep-Alive в `direct.go`**:
      - В `net.Dialer` для подключений к дата-центрам Telegram включен `KeepAlive = 30 * time.Second`.
      - Для сокета установлены активные таймауты `SetDeadline` (5 минут по умолчанию) при чтении и записи, исключающие зависание горутин при сетевых «черных дырах».
    - **Пулинг буферов (`sync.Pool`) и векторный I/O (`net.Buffers` / `writev`)**:
      - Внедрен `readBufferPool` (`sync.Pool`) для 64-КиБ буферов чтения в `readLoop` и `directReadLoop`, устраняющий частые аллокации памяти в GC при высоких скоростях трафика.
      - В `writeLoop` и `directWriteLoop` мелкие пачки кадров передаются через `net.Buffers(chunks).WriteTo(connection)`, что в Linux задействует системный вызов `writev` без промежуточного копирования в пользовательском пространстве.
      - В `direct.go` потоковая расшифровка клиента и зашифровка для Telegram DC выполняются строго in-place (`XORKeyStream(data, data)`) в L1-кэше процессора.
    - **Адаптивный Coalescing (Micro-Wait) для Uplink/Piggybacking**:
      - В `PiggybackDownWait` реализовано адаптивное микро-ожидание (до 25 мс) по заголовку `X-Coalesce: 1` при отсутствии активного поллинга, позволяющее упаковать быстрый ответ дата-центра (рукопожатие/эхо) прямо в ответ на запрос загрузки без дополнительного сетевого RTT.
16. **Бесшовное восстановление сессий и миграция потоков (Zero-Drop Session Recovery & Stream Migration)**:
    - **Компоненты**: `internal/session/token.go`, `internal/session/manager.go`, `internal/session/session.go`, `internal/server/server.go`, `internal/server/cdn.go`, `internal/bridge/templates/`.
    - **Архитектура и назначение**:
      - При нестабильной мобильной сети (переключение соты Wi-Fi <-> LTE, смена IP, выход устройства из спящего режима) разрыв транспортного соединения (WebSocket / HTTP long-poll) больше не приводит к уничтожению сессии и обрыву TCP-сокетов Telegram DC / MTProxy / Telemt.
      - Соединения сохраняются на сервере в течение конфигурируемого окна `reconnect_grace` (по умолчанию 2 минуты), а downlink-трафик буферизируется в памяти сессии.
    - **Криптографический токен возобновления (`X-Resume-Token`)**:
      - В `TokenClass` добавлен класс токена `TokenResume` (байт 3). Токен генерируется при создании сессии с 12-байтным случайным nonce, 4-байтным AES-фильтром и 16-байтным HMAC-SHA256, сохраняя 100% стойкость к timing/probing атакам.
      - Поддерживается дуальная аутентификация: восстановление разрешено как по `X-Resume-Token`, так и по оригинальному `X-Session-Token` для обратной совместимости.
    - **Конечная точка `POST /api/v1/resume`**:
      - Позволяет HTTP-клиентам мгновенно синхронизировать счетчик `X-Up-Seq` и курсор `X-Down-Cursor`, а также повторно получить пропущенный буфер недоставленных пакетов (`unacked`).
    - **WebSocket Subprotocols & Socket Takeover**:
      - Добавлены протоколы `tproxy-resume-v1.<resume-token>.<up-seq>.<down-cursor>` и `tproxy-lane-resume-v1.<resume-token>.<lane-id>.<up-seq>.<down-cursor>` с fallback на query-параметры `?resume=...&up=...&down=...`.
      - Реализован механизм атомарного перехвата сокета (`AcquireWebSocketTakeover`): при приходе нового подключения с того же или нового IP старый полуоткрытый сокет немедленно прерывается через `wsSuperseded`, не закрывая сессию и передавая управление новому соединению без сброса потоков.
    - **Автореконнект в Bridge-шаблонах**:
      - В шаблоны `websocket.html`, `websocket_lanes.html` и `bridge.html` встроен экспоненциальный цикл переподключения с сохранением `upSequence` и `downCursor` (до 15 попыток, ~30–45 с), исключающий падение WebView в статус `failed` при кратковременных сбоях сети.
17. **Мультидоменная маршрутизация и виртуальные хосты (VHost) на уровне профилей**:
    - **Компоненты**: `internal/config/config.go`, `internal/session/session.go`, `internal/session/manager.go`, `internal/server/server.go`, `internal/server/cdn.go`, `internal/server/secrets.go`, `internal/cli/link.go`, `profiles.example.json`.
    - **Архитектура и назначение**:
      - Сервер `tproxy-server` поддерживает одновременное обслуживание множества независимых доменов с различными сетевыми транспортами (`websocket-lanes`, `cdn-adaptive`, `https-lanes`), отдельными маскировочными сайтами (decoy) и кастомными upstream-серверами в рамках единого серверного процесса.
      - В `profiles.json` для каждого профиля добавлены опциональные поля виртуального хоста:
        - `hostname`: привязка профиля к конкретному домену (при отсутствии наследуется глобальный `public_hostname`).
        - `base_path`: изолированный префикс пути URL (например, `"assets"` или `"proxy"`).
        - `public_dir`: изолированная директория decoy-сайта для данного домена.
        - `public_upstream`: URL обратного проксирования decoy-сайта для данного домена.
        - `trusted_host_header`: доверенный заголовок для извлечения целевого хоста (например, `"X-Forwarded-Host"` для API Gateway).
        - `trusted_ip_header`: приоритетный заголовок извлечения IP клиента для данного хоста (например, `"CF-Connecting-IP"` для Cloudflare или `"X-Forwarded-For"`).
        - `disable_ip_rate_limit`: отключение лимитов сессий и bootstrap на IP-адрес для проксируемых и CDN-хостов.
    - **Криптографическая изоляция и защита от перекрестного зондирования (Cross-Domain Probing Resistance)**:
      - HMAC-capability токен каждого профиля деривируется с учетом эффективного `hostname` и `base_path`. Один и тот же секрет MTProxy на разных доменах порождает криптографически непересекающиеся capability.
      - При создании сессии (`manager.HasBootstrapForHost`) и обработке любых запросов потоков данных (`/api/v1/up`, `/api/v1/down`, `/api/v1/ws`, `/api/v1/resume`, CDN-чанки) проверяется совпадение домена сессии `session.Profile().Hostname` с целевым виртуальным хостом `vhost.Hostname`. Токены хоста A не могут быть использованы на хосте B — запрос мгновенно отклоняется с кодом 404 без раскрытия прокси-статуса.
      - Изоляция `build_id` в CDN-транспорте: каждый `VHost` генерирует собственный независимый `buildID`, предотвращая перекрестные утечки версий и эвристический фингерпринтинг.
    - **Защита от спуфинга заголовка хоста (`Host Header Spoofing Resistance`)**:
      - Заголовок `trusted_host_header` принимается **только в том случае**, если разобранное имя хоста строго совпадает с зарегистрированным VHost, явно активировавшим данный заголовок. Любые произвольные внешние заголовки `X-Forwarded-Host` на других VHost игнорируются, исключая несанкционированный обход изоляции.
    - **Deduplication и предотвращение утечек ресурсов (`ReverseProxy` / `staticSite`)**:
      - Экземпляры `ReverseProxy` и пулы соединений `http.Transport` дедуплицируются по URL `public_upstream`. При `Shutdown()` все уникальные пулы соединений гарантированно закрываются без утечек дескрипторов сокетов.
      - Статические сайты с одинаковым `public_dir` кэшируются в памяти в единственном экземпляре.
    - **Полная обратная совместимость**:
      - Существующие конфигурации без указания `hostname` в `profiles.json` автоматически наследуют глобальный `public_hostname` и единый decoy-сайт из `config.json`. Все существующие клиенты и контракты MTProxy работают без изменений.
18. **Односторонний бинарный стриминг Downlink (fetch + ReadableStream)**:
    - **Компоненты**: `internal/config/config.go`, `internal/session/cdn.go`, `internal/session/session.go`, `internal/server/cdn.go`, `internal/bridge/templates/cdn.html`.
    - **Архитектура и назначение**:
      - В CDN-режимах (`cdn-adaptive`, `cdn-get`, `cdn-body`, `cdn-ws`) устранена задержка классического HTTP Long-Polling (50–200 мс на батч) путем внедрения непрерывного потокового сброса кадров поверх стандартного HTTP GET без `Upgrade: websocket`.
      - Сервер удерживает HTTP-соединение до `cdn_stream_max_duration_secs` (по умолчанию 45 с) и мгновенно сбрасывает данные клиенту через `http.Flusher` с нулевой задержкой.
    - **Формат бинарного потока и конверты кадров (`Stream Envelope`)**:
      - Первые 12 байт ответа содержат валидный заголовок `glTF 2.0 binary` (`magic: 0x676C5446`, `version: 2 (LE)`, `length: 0xFFFFFFFF`), маскирующий стрим под 3D-модель для CDN L7-фильтров.
      - Последующие порции упаковываются в 8-байтовые конверты:
        - `Next DownCursor` (4 байта, uint32 BE).
        - `Payload ByteLength` (4 байта, uint32 BE).
        - Полезная нагрузка: кадры `SharedFrame` длиной `Payload ByteLength`.
      - При простое каждые `cdn_stream_heartbeat_secs` (10 с) сервер шлет пустой конверт (`ByteLength = 0`) в качестве Heartbeat для поддержания активности TCP-канала через агрессивные таймауты CDN.
    - **Скользящее окно подтверждений и Zero-Loss Replay (`unackedBatches`)**:
      - В структуру `Session` внедрен срез `unackedBatches []sentBatch`.
      - Сервер отслеживает отправленные батчи и освобождает выделенный бюджет памяти сессии (`ackCursorLocked`) при получении подтверждений курсора из Uplink-запросов (`PiggybackDownWait`) или нового стрима.
      - Если клиент переподключается с отстающим курсором, сервер мгновенно выполняет повторную отправку (Zero-Loss Replay) всех пропущенных батчей из `unackedBatches`.
      - Ограничение емкости окна (`cdn_max_unacked_batches` = 32 или 4 МиБ): при отсутствии подтверждений вычитка из `pendingFrames` временно приостанавливается (backpressure).
    - **Клиентский ассемблер и автоматический откат (`cdn.html`)**:
      - Реализован потоковый парсер `createStreamAssembler`: собирает байтовые чанки в кольцевом буфере без квадратичных аллокаций, валидирует glTF префикс и парсит конверты переменной длины.
      - **Probe Fallback**: при первом запуске стрима выставляется таймер 1500 мс. Если промежуточный CDN буферизирует ответ или окружение не поддерживает `ReadableStream`, клиент мгновенно откатывается на классический Long-Polling (`startPollLoop`).
      - **Watchdog**: таймер на 16 с детектирует «тихий» обрыв TCP-сокета и инициирует прозрачное переподключение.
      - **Auto-Ack Uplink**: при активном скачивании данных и отсутствии исходящего трафика клиент отправляет пустой легковесный Uplink-запрос для подтверждения курсора каждые 16 батчей, предотвращая заполнение очереди `unackedBatches`.
19. **Руководство по настройке раздельных профилей (VHost), CDN-транспортов и Nginx**:
    - **Архитектура виртуальных хостов (`profiles.json`)**:
      - Каждый профиль может обслуживать собственный домен (`hostname`), иметь независимый префикс пути (`base_path`), отдельный маскировочный сайт (`public_dir` или `public_upstream`) и кастомные сетевые лимиты.
      - Пример файла `profiles.json` с раздельными профилями (классический WebSocket и облачный CDN):
      ```json
      {
        "profiles": [
          {
            "name": "direct-ws",
            "secret": "ee0102030405060708090a0b0c0d0e0f",
            "carrier_mode": "websocket-lanes",
            "backend_type": "direct",
            "backend": "auto",
            "hostname": "proxy.myhost.com",
            "public_dir": "/var/www/decoy-main",
            "trusted_ip_header": "X-Forwarded-For"
          },
          {
            "name": "cloudflare-cdn",
            "secret": "dd0102030405060708090a0b0c0d0e0f",
            "carrier_mode": "cdn-adaptive",
            "backend_type": "telemt",
            "backend": "127.0.0.1:9090",
            "backend_proxy_protocol": "v2",
            "hostname": "cdn.myhost.com",
            "base_path": "assets",
            "public_upstream": "http://127.0.0.1:3000",
            "trusted_ip_header": "CF-Connecting-IP",
            "disable_ip_rate_limit": true,
            "limits": {
              "cdn_poll_timeout_secs": 12,
              "cdn_max_down_batch_bytes": 524288,
              "cdn_uplink_window_size": 16,
              "cdn_stream_max_duration_secs": 45,
              "cdn_stream_heartbeat_secs": 10,
              "cdn_max_unacked_batches": 32
            }
          }
        ]
      }
      ```
    - **Специфика настройки CDN-профилей**:
      - Режим `carrier_mode`: рекомендуется `"cdn-adaptive"`, который автоматически стартует рукопожатие через Happy Eyeballs (параллельный запуск POST collect и GET init) и выбирает рабочий конвейер с учетом ограничений сети клиента и пограничного CDN.
      - Для работы за проксирующими CDN (Cloudflare, Gcore и др.) обязателен параметр `"trusted_ip_header": "CF-Connecting-IP"` (или `"True-Client-IP"` / `"X-Real-IP"`), а также `"disable_ip_rate_limit": true` во избежание блокировки пользователей за общими пограничными IP-адресами CDN.
    - **Обязательная конфигурация Nginx**:
      - Для предотвращения буферизации стриминга, таймаутов long-poll и ошибок передачи больших чанков Nginx конфигурируется следующим образом:
      ```nginx
      # Upstream к tproxy-server
      upstream tproxy_backend {
          server 127.0.0.1:8080;
          keepalive 32;
      }

      server {
          listen 443 ssl http2;
          server_name cdn.myhost.com proxy.myhost.com;

          ssl_certificate /etc/letsencrypt/live/myhost.com/fullchain.pem;
          ssl_certificate_key /etc/letsencrypt/live/myhost.com/privkey.pem;

          # Приватность: отключаем логи доступа во избежание утечки токенов сессий
          access_log off;
          error_log /var/log/nginx/tproxy_error.log warn;

          # Отключаем сжатие gzip, чтобы не ломать бинарные потоки glTF и чанки
          gzip off;

          # Лимит тела запроса: uplink-пакеты достигают 2 МиБ (+ overhead заголовков)
          client_max_body_size 4m;

          location / {
              proxy_pass http://tproxy_backend;
              proxy_http_version 1.1;

              # Поддержка WebSocket для websocket / websocket-lanes режимов
              proxy_set_header Upgrade $http_upgrade;
              proxy_set_header Connection $connection_upgrade;

              # Передача целевого хоста для корректной маршрутизации виртуальных хостов (VHost)
              proxy_set_header Host $host;

              # Клиентский IP: строго один IP-адрес без запятых!
              proxy_set_header X-Forwarded-For $remote_addr;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;

              # КРИТИЧНО для Streaming Downlink и Long-Polling: отключение буферизации
              proxy_buffering off;
              proxy_request_buffering off;

              # Таймауты: стриминг длится до 45 с, long-poll до 25 с
              proxy_read_timeout 90s;
              proxy_send_timeout 90s;
              proxy_connect_timeout 10s;
          }
      }

      # Карта для корректного переключения заголовка Connection (WebSocket vs Keep-Alive)
      map $http_upgrade $connection_upgrade {
          default upgrade;
          ''      '';
      }
      ```
20. **Устранение задержки пинга и ловушки standalone `WINDOW` в CDN + Direct (`session.go`, `direct.go`)**:
    - **Компоненты**: `internal/session/session.go`, `internal/session/direct.go`, `internal/session/cdn_test.go`, `internal/session/direct_test.go`.
    - **Проблема**:
      - При проверке пинга в Telegram (Proxy Check) клиент отправляет одиночный пакет `OPEN` + `DATA` (104 байта: 64 байта MTProto-рукопожатия + 40 байт `req_pq_multi`).
      - В `runDirect()` отправка в сокет ядра мгновенно триггерит `s.session.backendDrained(s.id, written)`, который генерирует кадр `frame.Window` (104 байта) и будит `s.notify`.
      - Ранее в `PiggybackDownWait` было зашито ожидание всего 25 мс, в то время как TCP Dial + MTProto Handshake + ответ `resPQ` от дата-центра Telegram занимают 30–100 мс. `PiggybackDownWait` по истечении 25 мс забирал одинокий кадр `WINDOW`, инкрементировал `downCursor` и закрывал HTTP-ответ, а параллельный `PollCDN` получал дубликат `WINDOW` без данных.
      - В `PollCDN` приход `s.notify` от `backendDrained` также преждевременно срывал HTTP-ответ, отправляя клиенту пустой возврат 104 байт кредитного окна прямо перед носом у ответа `resPQ`.
      - В `CreateTelegramHandshake` передавался ненормализованный `dcIdx` (> 10000 для старого формата медиа/прокси DC), что приводило к отклонению рукопожатия серверами Telegram.
    - **Решение**:
      - В `session.go` внедрены предикаты `hasPendingDataOrCloseLocked()` и `hasWorthwhilePiggybackLocked()`: если в очереди лежит только одиночный `WINDOW` (< 64 КиБ кредита), он не расходует батч и курсор `downCursor`, а ожидает склейки с реальным `frame.Data` (`resPQ`).
      - В `PiggybackDownWait` микро-ожидание `coalesce` для `BackendDirect` расширено до 150 мс (40 мс для остальных бэкендов) и ожидает появления `DATA` или `CLOSE`.
      - В `PollCDN` цикл поллинга ожидает полноценных кадров (`hasWorthwhilePiggybackLocked()`) и отдает мелкие `WINDOW` только при истечении таймаута поллинга.
      - В `CreateTelegramHandshake` и `ResolveTelegramDC` добавлена нормализация `dcIdx` (`10001..10005` -> `-1..-5`, `-10001..-10005` -> `1..5`).
      - В результате пинг в меню выбора Telegram рассчитывается за 1 сетевой RTT (60–150 мс), объединяя `WINDOW` и `DATA (resPQ)` в первый же HTTP-ответ uplink без ожидания повторных циклов поллинга.
21. **Устранение зависаний при выходе из спящего режима, защита ретраев в фоне и очистка потоков в CDN (`cdn.html`)**:
    - **Компоненты**: `internal/bridge/templates/cdn.html`, `internal/bridge/page_test.go`.
    - **Проблема**:
      - При сворачивании Telegram на Android/iOS/Desktop или переводе устройства в спящий режим JS-движок WebView приостанавливается, а открытые сетевые сокеты сбрасываются ОС или CDN-узлами.
      - При выходе из фона `startStreamLoop` оставался заблокированным на подвисшем вызове `reader.read()`, ожидая истечения таймаута вотчдога (16 с).
      - Во время нахождения в фоне без доступа к сети `sendChunkWithBackoff` быстро исчерпывал бюджет попыток (5 ретраев с интервалом в доли секунды), вызывал `fail()` -> `close(true)` и уничтожал сессию на сервере через `unload`.
      - При возникновении ошибки `cdn.html` отправлял некорректный статус `status('error')` и вызывал `close(true)` без протокольных кадров `CLOSE` (`0x03`) и без обязательного управляющего сообщения `{t: 'close'}` (согласно `PLAN.md`, Section 5). В результате Telegram оставался в бесконечном статусе «Подключение к прокси...».
      - Если сессия истекала за время сна, запросы к серверу перехватывались маскировочным сайтом (Decoy SPA), возвращавшим `200 OK` (`text/html`), что не распознавалось клиентом как ошибка и приводило к молчаливому поглощению ответа.
      - Функция `sendAckOnly()` отправляла `GET 0.bin`, но полностью игнорировала тело ответа, теряя упакованные сервером в piggyback кадры и десинхронизируя курсор `downCursor`.
    - **Решение**:
      - **Отслеживание активных потоков (`activeStreams`) и кодирование кадров (`encodeFrame`)**:
        - Внедрен трекинг клиентских потоков: входящие кадры парсятся через `trackClientFrames`, добавляя stream ID на `0x01` (`Open`) и удаляя на `0x03` (`Close`). В `deliver()` также удаляются закрытые сервером потоки.
        - При фатальном сбое (`fail()`) для всех незакрытых потоков клиенту отправляются явные MTProto-кадры `Close` (`0x03`), отправляется статус `{t: 'status', state: 'failed'}` и сообщение `{t: 'close'}`.
        - Вызов `close(true)` откладывается на 15 мс (`setTimeout`), обеспечивая обработку `{t: 'close'}` нативным кодом Telegram до вызова `port.close()`.
      - **Защита от исчерпания ретраев в фоне (`isBg`)**:
        - В `sendChunkWithBackoff` детектируется фоновое состояние (`document.visibilityState === 'hidden' || navigator.onLine === false`).
        - В фоновом состоянии счетчик фатальных попыток замораживается (`nextRetry = isBg ? retry : retry + 1`), а задержка фиксируется на 2000 мс. При возврате в активный режим доступно до 8 попыток с экспоненциальным backoff.
        - Каждый запрос `fetch` в uplink ограничен 10-секундным таймаутом через `AbortController`, исключая зависание полуоткрытых сокетов.
      - **Мгновенное пробуждение через Set (`wakeSignals`) и хуки жизненного цикла (`onWakeUp`)**:
        - `pause(ms)` регистрирует функции прерывания сна в `const wakeSignals = new Set()`.
        - Обработчик `onWakeUp()` с защитой от дребезга (250 мс) мгновенно будит все заснувшие таймеры `pause`, принудительно абортит `pollController` (срывая подвисший `reader.read()` и немедленно перезапуская стрим с актуальным `downCursor`) и сбрасывает накопленный uplink или посылает ACK.
        - Хук подписан на события `visibilitychange`, `focus`, `online` и `pageshow`.
      - **Валидация decoy-ответов (`processDownlink`) и сохранение downlink в `sendAckOnly`**:
        - `processDownlink` валидирует `Content-Type`: `text/html` немедленно распознается как fallback маскировочного сайта и инициирует `fail()`; `model/gltf-binary` парсится и доставляет полезную нагрузку; `application/json` проверяет флаг `s === 1`; пустые ответы (0 байт) считаются валидными ACK.
        - `sendAckOnly` переведена в `async`, читает `arrayBuffer()` и передает ответ в `processDownlink`, предотвращая потерю кадров и рассинхронизацию.
22. **Выделение cdn-ws streaming в самостоятельные модули и шаблон (`cdn_stream.go`, `cdn_ws.html`)**:
    - **Компоненты**: `internal/server/cdn_stream.go`, `internal/server/cdn.go`, `internal/bridge/templates/cdn_ws.html`, `internal/bridge/templates/cdn.html`.
    - **Суть изменения**:
      - Серверный обработчик стриминга `serveCDNStreamDown` вынесен из монолитного `cdn.go` в отдельный файл `internal/server/cdn_stream.go`.
      - Для режима `carrier_mode = "cdn-ws"` создан специализированный шаблон `internal/bridge/templates/cdn_ws.html`, использующий непрерывный стриминг `ReadableStream` (`startStreamLoop`, `createStreamAssembler`) без отката на поллинг (ошибки стрима сразу инициируют `fail()`).
      - Из общего шаблона `cdn.html` (для режимов `cdn-adaptive`, `cdn-get`, `cdn-body`) удален избыточный код стриминга (`createStreamAssembler`, `startStreamLoop`, переменная `streamSupported`). Шаблон переведен на прямой запуск долгого поллинга (`startPollLoop()`), исключая 1500 мс задержки на пробное подключение в окружениях без поддержки стриминга.
      - Разрешение шаблона в `bridge.Factory.ResolveTemplateName` работает нативно через правило сопоставления префикса и замены дефиса (`modeUnder` -> `cdn_ws.html`).
23. **Стабилизация `cdn-ws` стриминга, устранение дублирования трекинга кадров и авто-откат (`cdn_stream.go`, `cdn_ws.html`)**:
    - **Компоненты**: `internal/server/cdn_stream.go`, `internal/bridge/templates/cdn_ws.html`, `internal/bridge/page_test.go`.
    - **Суть изменений**:
      - **Ранняя установка WriteDeadline для стриминга**: в `cdn_stream.go` вызов `rc := http.NewResponseController(w)` и `rc.SetWriteDeadline(time.Now().Add(15 * time.Second))` перенесены до отправки glTF stream prefix и пустого батча, гарантируя защиту от зависания сокета уже на этапе записи префикса.
      - **Устранение двойного учета кадров в `queueCarrier`**: удален лишний вызов `trackClientFrames(buf)` из `queueCarrier`, поскольку все входящие клиентские пакеты уже гарантированно парсятся и учитываются в `activatePort()`.
      - **Устойчивость к временным сбоям CDN/прокси в `startStreamLoop()`**: ошибки 502/503/504 или сетевые сбои больше не приводят к вызову `fail()` и мгновенному закрытию сессии; фатальными считаются только явные `404`, `410` или `text/html` (перехват decoy-сайтом).
      - **Откат на одиночный poll при буферизации CDN**: если `probeTimer` (1500 мс) прерывает стрим 2 раза подряд из-за буферизации промежуточным CDN, клиент выполняет fallback-запрос `pollOnce()` (`assets/media/{shortId}/seg_{cursor}_{randHex}.m4s`), сбрасывая накопленный буфер кадров.
      - **Неблокирующий ACK при пробуждении в `onWakeUp()`**: при `upPending.length === 0` отправляется `sendAckOnly()` независимо от значения `upInflight`, гарантируя доставку подтверждения и получение данных после переключения сети, даже если предыдущий запрос завис на старом IP-адресе.
24. **Оптимизация выгрузки медиа и предотвращение переполнения окна в CDN (`config.go`, `session.go`, `cdn_ws.html`, `cdn.html`)**:
    - **Компоненты**: `internal/config/config.go`, `internal/session/session.go`, `internal/session/cdn.go`, `internal/server/cdn.go`, `internal/bridge/templates/cdn_ws.html`, `internal/bridge/templates/cdn.html`.
    - **Суть изменений**:
      - **Расширение размера скользящего окна ReassemblyBuffer**:
        - Дефолтное значение `cdn_uplink_window_size` увеличено с 16 до 64 (с поддержкой конфигурирования вплоть до 128). Это позволяет серверу без переполнения (`ErrProtocol`) и без блокировок удерживать до 64 внеочередных чанков (~384 КиБ) при сетевом джиттере на узлах CDN.
        - `ErrLimit` парсера/буфера теперь возвращает клиенту HTTP 503 (`Retry-After: 1`) с сохранением сессии в `handleCDNSessionError`, предотвращая разрыв соединения при пиковом наплыве фрагментов.
      - **Устранение лишней задержки micro-wait (`PiggybackDownWait`) при выгрузке медиа**:
        - В `PiggybackDownWait` ожидание 40–150 мс теперь автоматически пропускается (`coalesce = false`), если в `ReassemblyBuffer` есть пропуски/дыры (`s.cdnReassembly.HasHoles()`), так как сборка цельного кадра невозможна до прихода недостающих фрагментов.
        - В шаблонах `cdn_ws.html` и `cdn.html` заголовок `X-Coalesce` динамически вычисляется как `'1'` только когда `upPending.length === 0 && upInflight <= 1` (одиночный запрос: пинг, рукопожатие, короткий RPC). При выгрузке потока медиа (`upPending.length > 0` или `upInflight > 1`) передается `X-Coalesce: '0'`, гарантируя мгновенный ответ сервера (0 мс) и максимальную пропускную способность конвейера без микропауз.
      - **Нарезка крупных кадров и защита скользящего окна на клиенте**:
        - В `cdn_ws.html` и `cdn.html` добавлена функция `canAdvanceWindow()`, ограничивающая опережение последовательностей (`upSeq - minSeq < maxWindowSpan`, где `maxWindowSpan = 48`), предотвращая дрифт вне серверного окна.
        - Крупные MTProto-кадры `DATA` (до 64 КиБ) разрезаются ровно по границе `maxChunk` (6144 байт для `cdn-get` и 16384 байт для `cdn-body`), гарантируя соответствие лимитам URI и L7-заголовков CDN.
25. **Оптимизация старта сессии, мгновенного пробуждения и разблокировки ACK в CDN-мостах (`cdn_ws.html`, `cdn.html`)**:
    - **Компоненты**: `internal/bridge/templates/cdn_ws.html`, `internal/bridge/templates/cdn.html`, `internal/bridge/page_test.go`.
    - **Суть изменений**:
      - **Оптимизация Happy Eyeballs в `createSession`**:
        - Задержка Happy Eyeballs перед параллельным запуском GET сокращена с 250 мс до 60 мс (`pause(60)`).
        - На сетях с блокировкой POST это ускоряет старт сессии и расчет пинга в Telegram на ~190 мс. При быстром отказе POST (403/404/405) переключение на GET происходит мгновенно (0 мс).
      - **Мгновенное переоткрытие потока чтения при пробуждении (0 мс без паузы)**:
        - Введен флаг состояния `wakingUp`.
        - В `onWakeUp` выставляется `wakingUp = true`. При прерывании `pollController.abort()` секции `catch(e)` в `startStreamLoop` (`cdn_ws.html`) и `startPollLoop` (`cdn.html`) немедленно переходят к следующей итерации без ожидания `pause(150..350)` или `pause(500)`.
        - В `cdn_ws.html` при `wakingUp` сбрасывается `probeConsecutiveTimeouts = 0`, исключая ложное срабатывание probe-таймера.
      - **Трекинг Uplink-контроллеров и сброс зависших сокетов (`abortInflightUplinks`)**:
        - Внедрена коллекция `upControllers = new Set()` с регистрацией `AbortController` для каждого запроса чанка в `sendChunkWithBackoff`.
        - Реализован тиковый таймер глубокого сна (`lastTick`, интервал 1000 мс). При событии `online` или выходе из глубокого сна (`slept = now - lastTick > 2500`) вызывается `abortInflightUplinks()`, немедленно обрывая полуоткрытые сокеты старого IP-адреса и отправляя чанки на быстрый ретрай в новой сети.
        - Все контроллеры также очищаются при `close()`.
      - **Разблокировка `sendAckOnly()` и взаимное исключение**:
        - Из `sendAckOnly()` удалено блокирующее условие `upInflight > 0`.
        - Добавлен флаг `ackInflight` для предотвращения параллельных ACK и таймаут 5000 мс через `AbortController`.
        - При выходе из сна при `upPending.length === 0` подтверждение курсора инициируется немедленно, выталкивая накопившиеся входящие сообщения сервера без ожидания таймаута зависших запросов.
      - **Динамический Coalesce (`X-Coalesce`)**:
        - Заголовок `'X-Coalesce'` строго динамический: `'1'` для одиночных запросов проверки связи/рукопожатия (объединение в 1 RTT) и `'0'` при серии чанков или очереди (нулевая задержка).
26. **Двухпоточный бесшовный стрим «Make-Before-Break» (Overlap Streaming Downlink в `cdn_ws.html`)**:
    - **Компоненты**: `internal/bridge/templates/cdn_ws.html`, `internal/bridge/page_test.go`, `docs/CDN_TRANSPORT_SPEC.md`.
    - **Проблема**:
      - Сервер ограничивает время жизни одного стримингового HTTP-соединения величиной `cdn_stream_max_duration_secs = 45`, чтобы предотвратить 504 таймаут CDN.
      - Ранее клиент ожидал разрыва сокета (`done === true` на 45-й секунде) и только после этого инициировал новый запрос. За время установления нового соединения и прохождения через узлы CDN (80–250 мс) у сессии отсутствовал активный канал приема, что вызывало периодические микрофризы в Telegram.
    - **Решение (Make-Before-Break)**:
      - **Упреждающее открытие параллельного потока на 38-й секунде**:
        - В `runStream(streamId)` при приходе первого чанка заводится таймер `overlapTimer = setTimeout(..., 38000)`.
        - На 38-й секунде (за 7 секунд до закрытия Stream A сервером) клиент инкрементирует `currentStreamId` и запускает Stream B (`runStream(currentStreamId)`).
      - **Множество контроллеров `streamControllers = new Set()`**:
        - Каждый поток регистрирует собственный `AbortController` в `streamControllers` на время жизни и удаляет в блоке `cleanup()`.
        - При закрытии (`close`) или пробуждении (`onWakeUp`) все контроллеры прерываются централизованно.
      - **Атомарное вытеснение и Zero-Loss Replay на сервере**:
        - При поступлении Stream B сервер (`StreamCDN`) закрывает канал `s.superseded` потока Stream A и бесшовно переключает активный сброс кадров на Stream B с 0 мс простоя.
        - Stream A штатно считывает оставшиеся байты, получает `done === true` и завершается без запуска повторного стрима (`streamId < currentStreamId`).
      - **Идемпотентная доставка кадров**:
        - Возможные повторно доставленные сервером батчи из `unackedBatches` при старте Stream B отсекаются по монотонному `downCursor` (`const isNew = ((cursor - downCursor | 0) > 0) || downCursor === 0`), гарантируя доставку в Telegram без дублирования.
27. **Устранение деградации скорости загрузки и скачивания медиа в CDN (`cdn_ws.html`, `cdn.html`, `page_test.go`)**:
    - **Компоненты**: `internal/bridge/templates/cdn_ws.html`, `internal/bridge/templates/cdn.html`, `internal/bridge/page_test.go`.
    - **Проблема**:
      - **Преждевременный сброс в `cdn-get` при Happy Eyeballs**: таймер `pause(60)` в `createSession` гарантированно срабатывал раньше, чем CDN возвращал ответ на `POST /collect.json` (RTT 80–180 мс), запуская параллельный `tryGetInit`. Сессия регистрировалась в медленном режиме `cdn-get` (6 КиБ Base64 в HTTP-заголовках вместо 16 КиБ бинарного POST в теле `cdn-body`), снижая пропускную способность аплинка почти в 3 раза.
      - **Ложный даунгрейд режима в `catch(e)`**: блок `catch(e)` в `sendChunkWithBackoff` безусловно сбрасывал `activeMode = 'cdn-get'` при любой ошибке, включая отмену запроса `abortInflightUplinks()` или срабатывание таймаута `ctrl.abort()`. Если чанк формировался размером 16 КиБ (для `cdn-body`), при ретрае он попадал в ветку `cdn-get`, кодировался в 21.5 КиБ Base64-заголовков (`X-Client-Data-0..7`) и отбивался CDN с кодом 431 Request Header Fields Too Large.
      - **Сброс стрима скачивания при фокусе окна (`focus`)**: в `onWakeUp(false)` при обычном клике по окну Telegram безусловно вызывался `sCtrl.abort()` для всех `streamControllers`, обрывая активный поток скачивания медиа и вызывая фризы в середине файла.
      - **Дублирование веток в `sendChunkWithBackoff`**: в коде присутствовали две повторяющиеся ветки `activeMode === 'cdn-body'`, загромождающие логику.
    - **Решение**:
      - **Двухфазный адаптивный Happy Eyeballs (`createSession`)**:
        - Первые 60 мс: если CDN мгновенно отклоняет POST (код 403/405), сессия мгновенно переключается на `tryGetInit` с нулевой задержкой (0 мс).
        - Если запрос POST находится в пути, ему дается дополнительное окно 120 мс (`pause(120)`, суммарно 180 мс), гарантирующее успешную установку быстрого бинарного режима `cdn-body`.
        - При задержках свыше 180 мс параллельно стартует `tryGetInit(helloBuf, 5000)`, и побеждает первый успешно завершившийся метод.
      - **Фиксация режима POST (`postConfirmed`) и защита от ложного даунгрейда**:
        - Введен флаг `postConfirmed = true`, выставляемый при успешном POST-рукопожатии или при первом подтвержденном POST-чанке.
        - Даунгрейд в `cdn-get` в блоке `catch(e)` и при ошибках HTTP блокируется, если запрос был отменен (`ctrl.signal.aborted`), если `postConfirmed === true`, или если размер буфера превышает лимит заголовков (`buf.byteLength > 6144`).
      - **Изоляция сброса потоков в `onWakeUp`**:
        - Прерывание активных сокетов (`streamControllers`, `pollController`, `abortInflightUplinks`) выполняется **только** при реальном выходе устройства из сна (`slept = now - lastTick > 2500`) или смене сетевого интерфейса (`isOnline === true`).
        - Обычные события `focus`, переключение вкладок или клик по окну не трогают качающиеся потоки и не шлют холостые `sendAckOnly()`.
      - **Чистая архитектура `sendChunkWithBackoff`**: устранено дублирование веток, `cdn-body` обрабатывается единым изолированным блоком.
