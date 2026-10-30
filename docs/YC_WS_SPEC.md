# Спецификация и руководство по настройке транспортного режима `yc-ws` (v1)

**Для Yandex Cloud API Gateway в Telegram WEB Proxy (`tproxy-server` / `lordik-server`)**

---

## 1. Архитектурный контекст и назначение

Режим **`carrier_mode: "yc-ws"`** — это специализированный гибридный транспорт, разработанный для эффективного и безопасного проксирования трафика Telegram через **Yandex Cloud API Gateway**.

### Проблема классического WebSocket в Yandex Cloud API Gateway
В Yandex Cloud API Gateway веб-сокеты работают по бессерверной (serverless / event-driven) модели:
1. Шлюз принимает входящие `wss://` соединения от клиентов и преобразует события сокета в стандартные HTTP POST запросы на бэкенд:
   - `$connect` — установка соединения;
   - `$disconnect` — закрытие соединения;
   - `$default` — передача текстового или бинарного сообщения от клиента.
2. **Критическое ограничение**: тело ответа бэкенда на запрос `$default` **не транслируется** обратно клиенту в сокет. Шлюз просто отдает статус `200 OK` и отбрасывает тело ответа.
3. Единственный штатный механизм отправки данных обратно в веб-сокет в Yandex Cloud — это вызов Management API (`POST https://apigateway.yandexcloud.net/apigateways/v1/web-sockets/{connection_id}/data`), который требует:
   - Создания сервисного аккаунта с ролью `serverless.apigateway.invoker`;
   - Выпуска и постоянной ротации IAM-токенов на сервере;
   - Дополнительного сетевого RTT на каждый пакет к API Яндекса (задержка возрастает на 80–200 мс);
   - Расходования квот вызовов API.

### Архитектурное решение: Гибридный транспорт `yc-ws`
Вместо вызова Management API `tproxy-server` реализует асимметричную схему:
- **Uplink (Клиент ──► Сервер)**:
  - Клиент отправляет кадры через WebSocket (`ws.send()`).
  - YC API Gateway пересылает сообщение методом `POST /_yc/ws/message` на `tproxy-server`.
  - Это обеспечивает мгновенную отправку исходящего трафика (0 мс мобильной задержки очередей).
  - При обрыве или недоступности сокета автоматически задействуется аварийный HTTP POST аплинк (`POST /_yc/up/{short_id}/{seq}.bin`).
- **Downlink (Сервер ──► Клиент)**:
  - Непрерывный потоковый сброс кадров через HTTP GET стриминг (`GET /_yc/stream/{short_id}/stream_{cursor}_{rand}.m4s`) с использованием `ReadableStream` и `http.Flusher`.
  - Трафик упаковывается в бинарные конверты под видом glTF 2.0 3D-модели (`Content-Type: model/gltf-binary`), что предотвращает L7-фильтрацию и буферизацию.
  - Если промежуточный прокси буферизует стрим (срабатывают таймеры probe), клиент автоматически откатывается на Long-Polling (`GET /_yc/poll/{short_id}/seg_{cursor}_{rand}.m4s`).
- **Zero-Loss Window (`wsRecentChunks`)**:
  - Клиент удерживает отправленные по WebSocket чанки в локальной очереди (до 10 элементов).
  - При сбое WebSocket соединения клиент немедленно повторно отправляет неподтвержденные чанки через HTTP POST fallback, исключая потерю пакетов.
- **Коалесценция и нарезка (Coalescing & Slicing)**:
  - Кадры больше 32 КиБ нарезаются по 32768 байт. Мелкие интерактивные кадры склеиваются в батчи до 32 КиБ (WS) или до 64 КиБ (HTTP).
  - Это предотвращает исчерпание номеров последовательности `seq` и строго гарантирует непревышение лимита сообщений Yandex Cloud API Gateway (128 КиБ).

---

## 2. Спецификация OpenAPI для Yandex Cloud API Gateway

Ниже приведен готовый файл конфигурации спецификации `openapi.yaml` для создания API-шлюза в консоли Yandex Cloud.

Замените:
- `<BACKEND_HOST_OR_IP>` — публичный IP-адрес или домен вашего сервера (например, `198.51.100.1` или `origin.myhost.com`);
- `<BACKEND_PORT>` — порт веб-сервера (80 для HTTP, 443 для HTTPS).

```yaml
openapi: 3.0.0
info:
  title: Telegram WebProxy Gateway
  version: 1.0.0

paths:
  # -------------------------------------------------------------
  # 1. Корневой маршрут и bridge-страница (GET /?bridge=...)
  # -------------------------------------------------------------
  /:
    get:
      summary: Bridge Page & Decoy Site Root
      parameters:
        - name: bridge
          in: query
          required: false
          schema:
            type: string
      x-yc-apigateway-integration:
        type: http
        url: http://<BACKEND_HOST_OR_IP>:<BACKEND_PORT>/
        method: GET
        headers:
          Host: '<BACKEND_HOST_OR_IP>'
          X-Forwarded-For: '{sourceIp}'
          X-Forwarded-Host: '<GATEWAY_DOMAIN>'
          X-Forwarded-Proto: 'https'
          '*': '*'
        query:
          '*': '*'

  # -------------------------------------------------------------
  # 2. WebSocket endpoint (/_yc/ws)
  # -------------------------------------------------------------
  /_yc/ws:
    x-yc-apigateway-websocket:
      # Установка соединения (клиент подключается к wss://<domain>/_yc/ws?k=<session_token>)
      $connect:
        x-yc-apigateway-integration:
          type: http
          url: http://<BACKEND_HOST_OR_IP>:<BACKEND_PORT>/_yc/ws/connect
          method: POST
          headers:
            Host: '<BACKEND_HOST_OR_IP>'
            X-Forwarded-For: '{sourceIp}'
            X-Forwarded-Host: '<GATEWAY_DOMAIN>'
            X-Forwarded-Proto: 'https'
        query:
          '*': '*'

      # Передача сообщений от клиента (Uplink frames)
      $default:
        x-yc-apigateway-integration:
          type: http
          url: http://<BACKEND_HOST_OR_IP>:<BACKEND_PORT>/_yc/ws/message
          method: POST
          headers:
            Host: '<BACKEND_HOST_OR_IP>'
            X-Forwarded-For: '{sourceIp}'
            X-Forwarded-Host: '<GATEWAY_DOMAIN>'
            X-Forwarded-Proto: 'https'

      # Закрытие соединения
      $disconnect:
        x-yc-apigateway-integration:
          type: http
          url: http://<BACKEND_HOST_OR_IP>:<BACKEND_PORT>/_yc/ws/disconnect
          method: POST
          headers:
            Host: '<BACKEND_HOST_OR_IP>'
            X-Forwarded-For: '{sourceIp}'
            X-Forwarded-Host: '<GATEWAY_DOMAIN>'
            X-Forwarded-Proto: 'https'

  # -------------------------------------------------------------
  # 3. Маршруты HTTP API, стриминга и маскировочного сайта
  # -------------------------------------------------------------
  /{proxy+}:
    x-yc-apigateway-any-method:
      summary: Proxy all other HTTP requests (session, stream, poll, up, decoy)
      parameters:
        - name: proxy
          in: path
          required: true
          schema:
            type: string
      x-yc-apigateway-integration:
        type: http
        url: http://<BACKEND_HOST_OR_IP>:<BACKEND_PORT>/{proxy}
        method: '{httpMethod}'
        headers:
          Host: '<BACKEND_HOST_OR_IP>'
          X-Forwarded-For: '{sourceIp}'
          X-Forwarded-Host: '<GATEWAY_DOMAIN>'
          X-Forwarded-Proto: 'https'
          '*': '*'
        query:
          '*': '*'
```

> **Важно**: В секции `headers` необходимо указывать `Host: <BACKEND_HOST_OR_IP>` (для корректной валидации TLS-сертификата апстрима) и `X-Forwarded-Host: <GATEWAY_DOMAIN>` (для корректного сопоставления VHost). В маршрутах WebSocket (`/_yc/ws`) не указывайте `'*': '*'`, чтобы предотвратить сброс HTTP/2 потоков в Nginx.

---

## 3. Настройка профилей в `profiles.json`

В файле конфигурации профилей `/etc/tproxy-server/profiles.json` создается отдельный профиль с режимом `yc-ws`.

### Пример профиля с бэкендом `direct` (прямое подключение к Telegram DC)

```json
{
  "profiles": [
    {
      "name": "yandex-gateway-direct",
      "secret": "707172737475767778797a7b7c7d7e7f",
      "carrier_mode": "yc-ws",
      "backend_type": "direct",
      "backend": "auto",
      "hostname": "d5dxxxxxxxxxxxxxxxxx.apigw.yandexcloud.net",
      "public_dir": "/var/www/decoy-yc",
      "trusted_host_header": "X-Forwarded-Host",
      "trusted_ip_header": "X-Forwarded-For",
      "disable_ip_rate_limit": true,
      "limits": {
        "max_sessions": 256,
        "max_streams": 2048,
        "cdn_uplink_window_size": 64,
        "cdn_stream_max_duration_secs": 45,
        "cdn_stream_heartbeat_secs": 10,
        "cdn_max_unacked_batches": 32
      }
    }
  ]
}
```

### Пример профиля с бэкендом `telemt` или официальным `MTProxy`

```json
{
  "profiles": [
    {
      "name": "yandex-gateway-telemt",
      "secret": "808182838485868788898a8b8c8d8e8f",
      "carrier_mode": "yc-ws",
      "backend_type": "telemt",
      "backend": "127.0.0.1:9090",
      "backend_proxy_protocol": "v2",
      "hostname": "tg.mycustomdomain.ru",
      "public_upstream": "http://127.0.0.1:3000",
      "trusted_host_header": "X-Forwarded-Host",
      "trusted_ip_header": "X-Forwarded-For",
      "disable_ip_rate_limit": true
    }
  ]
}
```

### Описание параметров профиля:

| Параметр | Тип | Описание |
|---|---|---|
| `name` | string | Уникальное имя профиля для логов и метрик. |
| `secret` | string | 16-байтный шестнадцатеричный секрет MTProxy (`openssl rand -hex 16`). |
| `carrier_mode` | string | Обязательно `"yc-ws"`. Включает гибридный конвейер Yandex Cloud. |
| `backend_type` | string | Тип бэкенда: `"direct"` (напрямую в Telegram DC), `"telemt"` или `"mtproxy"`. |
| `backend` | string | `"auto"` для direct, либо `IP:порт` / `unix:/path.sock` для MTProxy/Telemt. |
| `hostname` | string | Домен API-шлюза: технический домен YC (`d5d....apigw.yandexcloud.net`) или привязанный кастомный домен. |
| `public_dir` | string | Путь к маскировочному сайту (decoy), отдаваемому при неавторизованных запросах. |
| `public_upstream` | string | Альтернатива `public_dir`: URL локального веб-приложения для проксирования decoy. |
| `trusted_host_header` | string | Обязательно `"X-Forwarded-Host"`. Позволяет серверу распознать исходный хост от шлюза. |
| `trusted_ip_header` | string | Обязательно `"X-Forwarded-For"`. Извлекает реальный IP мобильного клиента. |
| `disable_ip_rate_limit` | bool | Рекомендуется `true`. Отключает лимиты сессий на один IP, так как все запросы идут через разделяемые IP-адреса шлюза Yandex Cloud. |

---

## 4. Настройка Nginx на сервере релея

Если перед `tproxy-server` на вашем сервере установлен Nginx, он должен пропускать запросы от YC API Gateway без буферизации стриминга:

```nginx
upstream tproxy_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name d5dxxxxxxxxxxxxxxxxx.apigw.yandexcloud.net tg.mycustomdomain.ru;

    # Отключаем access-логи для защиты приватности
    access_log off;
    error_log /var/log/nginx/tproxy_yc_error.log warn;

    # Отключаем gzip, чтобы не буферизировать glTF стрим
    gzip off;

    # Допускаем чанки до 4 МиБ
    client_max_body_size 4m;

    location / {
        proxy_pass http://tproxy_backend;
        proxy_http_version 1.1;

        # Проброс исходных заголовков от Yandex Cloud API Gateway
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $http_x_forwarded_host;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
        proxy_set_header X-Yc-Apigateway-Websocket-Connection-Id $http_x_yc_apigateway_websocket_connection_id;

        # КРИТИЧНО для Streaming Downlink и Long-Polling:
        proxy_buffering off;
        proxy_request_buffering off;

        # Таймауты для стрима
        proxy_read_timeout 90s;
        proxy_send_timeout 90s;
        proxy_connect_timeout 10s;
    }
}
```

---

## 5. Генерация ссылки подключения для клиентов

После настройки конфигурации сгенерируйте ссылку подключения через встроенную CLI-утилиту:

```bash
# Генерация стандартной tg:// ссылки
tproxy-server link -config /etc/tproxy-server/config.json -profile yandex-gateway-direct

# Генерация всех форматов ссылок (tg://proxy, tg://webproxy, https://t.me/webproxy)
tproxy-server link -config /etc/tproxy-server/config.json -profile yandex-gateway-direct -type all
```

Пример вывода:
```text
tg://proxy?server=d5dxxxxxxxxxxxxxxxxx.apigw.yandexcloud.net&port=443&secret=707172737475767778797a7b7c7d7e7f
tg://webproxy?server=d5dxxxxxxxxxxxxxxxxx.apigw.yandexcloud.net&port=443&secret=707172737475767778797a7b7c7d7e7f
https://t.me/webproxy?server=d5dxxxxxxxxxxxxxxxxx.apigw.yandexcloud.net&port=443&secret=707172737475767778797a7b7c7d7e7f
```

Передайте полученную ссылку в клиент Telegram (Desktop / Android / iOS). Клиент откроет WebView-мост, подключится к API-шлюзу по защищенному WebSocket каналу и начнет обмен данными.

---

## 6. Диагностика и проверка работоспособности

1. **Проверка конфигурации без запуска**:
   ```bash
   tproxy-server test -config /etc/tproxy-server/config.json
   ```
2. **Проверка логов в реальном времени**:
   ```bash
   journalctl -u tproxy-server -f
   # или через встроенную команду:
   tproxy-server logs -config /etc/tproxy-server/config.json -n 100
   ```
3. **Проверка защиты от зондирования (Active Probing Check)**:
   ```bash
   # Обычный запрос на корень шлюза без capability должен возвращать 200 OK маскировочного сайта:
   curl -i https://d5dxxxxxxxxxxxxxxxxx.apigw.yandexcloud.net/

   # Попытка прямого обращения к внутренним API без авторизации должна возвращать 404:
   curl -i -X POST https://d5dxxxxxxxxxxxxxxxxx.apigw.yandexcloud.net/_yc/session
   curl -i -X POST https://d5dxxxxxxxxxxxxxxxxx.apigw.yandexcloud.net/_yc/ws/connect
   ```
   В обоих случаях сервер не раскрывает заголовков прокси и ведет себя неотличимо от обычного сайта.
