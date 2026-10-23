# Спецификация транспортного протокола `CDN-Adaptive` / `CDN-Stream` (v1)

**Для Telegram WEB Proxy (`tproxy-server` / `lordik-server`)**

## 1. Назначение и концепция

Протокол **CDN-Adaptive (`cdn`, `cdn-get`, `cdn-body`, `cdn-ws`)** — это специализированный L7-транспорт для Telegram WEB Proxy, разработанный для работы через строгие облачные CDN (Cloudflare, CloudFront, Gcore, Fastly и др.) и корпоративные межсетевые экраны (WAF), в том числе в средах, которые **пропускают исключительно HTTP-запросы метода `GET**` и блокируют `POST`, `DELETE` или `WebSocket Upgrade`.

Протокол сохраняет 100% обратную совместимость с клиентским контрактом Telegram (`window.TelegramWebProxy` / `MessagePort`) и форматом бинарных кадров `SharedFrames`, полностью заменяя внешний сетевой слой между WebView и сервером релея.

### Ключевые механизмы стандарта:

1. **GET-Only Uplink (URL + Header Sharding):** Передача бинарных данных от клиента к серверу внутри `GET`-запросов путем комбинированной упаковки полезной нагрузки в query-параметры и шардированные HTTP-заголовки в кодировке `Base64url`.


2. **Sliding Window Pipelining (Скользящее окно отправки):** Параллельная отправка до 6 `GET`-запросов одновременно поверх HTTP/2 или HTTP/3 с буфером сборки (`ReassemblyBuffer`) и потоковым склеивателем кадров (`FrameStreamParser`) на сервере.


3. **Streaming Downlink (`ReadableStream` + glTF 2.0):** Беспрерывная доставка данных от сервера к клиенту с задержкой 0 мс внутри одного долгоживущего `GET`-ответа под видом бинарной 3D-модели (`model/gltf-binary`) с автоматическим откатом (fallback) на классический Long-Polling (`seg_*.m4s`), если узел CDN буферизует поток.


4. **Piggybacking (Попутная доставка):** Мгновенный возврат встречных данных от сервера в теле ответа на входящие Uplink-запросы, а также отправка одиночных `GET 0.bin` для подтверждения курсора (ACK).


5. **Organic SPA Masking & Active Probing Resistance:** Все URL-маршруты мимикрируют под загрузку статики Next.js (`/_next/data/...`) и медиа-сегментов (`/assets/chunks/...`, `/assets/media/...`). Любой неавторизованный запрос неотличимо перенаправляется на публичный сайт-прикрытие (Decoy Site).



---

## 2. Общая схема движения трафика

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                        КЛИЕНТ (Telegram + WebView)                         │
│                                                                            │
│  Telegram App  ◄── SharedFrames (8B hdr + payload) ──►  JS Bridge (cdn_ws) │
└───────────────────────────────────────────────────────────┬────────▲───────┘
                                                            │        │
      Uplink (Клиент ──► Сервер)                            │        │ Downlink (Сервер ──► Клиент)
      Только GET (или POST в cdn-body):                     │        │ 1. Streaming GET (stream_*.m4s)
      • Коалесценция 3 мс, нарезка до 9 КиБ (GET)           │        │    ReadableStream + 8B Envelopes
      • Base64url: 3072 симв. в ?p= + до 8 заголовков       │        │ 2. Fallback Poll GET (seg_*.m4s)
        X-Client-Data-0..7 (по 3072 симв.)                  │        │ 3. Piggyback в ответах на Uplink
      • До 6 параллельных запросов в полете (seq=1,2,3...)  │        │    (Content-Type: model/gltf-binary)
                                                            ▼        │
┌────────────────────────────────────────────────────────────────────┴───────┐
│                   CDN / L7 Proxy (Cloudflare, Gcore и др.)                 │
└───────────────────────────────────────────────────────────┬────────▲───────┘
                                                            │        │
                                                            ▼        │
┌────────────────────────────────────────────────────────────────────┴───────┐
│                         СЕРВЕР РЕЛЕЯ (Go Backend)                          │
│                                                                            │
│  1. Uplink: Декодирование Base64url ──► ReassemblyBuffer (окно 16 чанков)  │
│             ──► FrameStreamParser (склейка SharedFrames) ──► MTProxy / DC  │
│  2. Downlink: Чтение из MTProxy / DC ──► Очередь pendingFrames             │
│             ──► Запись в открытый StreamCDN (Flush) или PiggybackDownWait  │
│                 (с хранением в unackedBatches до подтверждения курсора)    │
└────────────────────────────────────────────────────────────────────────────┘

```

---

## 3. Жизненный цикл сессии и Фазы обмена

### Фаза 1: Загрузка моста (Bootstrap)

1. Клиент открывает в WebView URL `GET https://<Host>/?bridge=<capability>#android=<nonce>`.


2. Сервер проверяет HMAC-ключ `capability` для данного виртуального хоста (`VHost`). При успехе сервер генерирует одноразовый `bootstrap` токен и рендерит HTML-страницу моста (`cdn_ws.html` / `cdn.html`), подставляя:


* `__RELAY_BASE__` — базовый путь;
* `__BOOTSTRAP__` — одноразовый токен создания сессии;
* `__CARRIER_MODE__` — режим профиля (`cdn`, `cdn-get`, `cdn-body`, `cdn-ws`);
* `__BUILD_ID__` — случайный 8-символьный идентификатор сборки (например, `k9x2m4p1`).




3. JS-мост немедленно очищает адресную строку вызовом `history.replaceState(null, '', location.pathname)` и инициализирует внутренний порт (`TelegramWebProxy` или `MessagePort`).



---

### Фаза 2: Создание сессии и Автосогласование (Handshake)

Когда приложение Telegram присылает первый бинарный буфер (содержащий кадр `HELLO` `0x10` и, возможно, первые кадры открытия потоков `OPEN` `0x01`), запускается `createSession(helloBuf)`:

1. **Режим `cdn-get` (Принудительный GET):**
* Буфер `helloBuf` кодируется в `Base64url` (без `=`).


* Отправляется запрос:
```http
GET /_next/data/{build_id}/init/{bootstrap}/{hello_b64}.json HTTP/2
X-Client-Key: {bootstrap}

```





* Сервер создает сессию и возвращает `200 OK` (`application/json`):


```json
{
  "token": "<session_token>",
  "resume_token": "<resume_token>",
  "short_id": "<первые_12_символов_token>",
  "welcome": "<base64url_кадра_WELCOME>",
  "mode": "cdn-get"
}

```





2. **Режим `cdn-body` (Принудительный POST):**
* Отправляется запрос `POST /_next/data/{build_id}/collect.json?k={bootstrap_prefix}` с бинарным телом `helloBuf` и заголовком `X-Client-Key: {bootstrap}`.


* Сервер возвращает кадр `WELCOME` сырыми байтами в теле ответа, а токены — в заголовках `X-Session-Token` и `X-Resume-Token`.




3. **Адаптивный режим (`cdn` / `cdn-adaptive` — Happy Eyeballs):**
* Скрипт стартует `tryPostInit` (таймаут 2000 мс).


* Если за **250 мс** `POST` не завершился успехом, параллельно запускается `tryGetInit` (таймаут 5000 мс).


* Первый успешно ответивший метод фиксирует рабочий режим сессии (`activeMode = 'cdn-body'` или `'cdn-get'`), а второй игнорируется благодаря флагу `initDone = true`.





---

### Фаза 3: Передача данных от Клиента к Серверу (Uplink: Туда)

#### 3.1. Коалесценция и нарезка на чанки (Клиент)

1. Кадры от Telegram (`OPEN`, `DATA`, `CLOSE`, `WINDOW`) поступают в `queueCarrier(buf)`.


2. Скрипт коалесцирует (склеивает) пакеты в очереди `upPending` с микро-задержкой **3 мс** (или отправляет мгновенно, если сейчас `upInflight === 0`).


3. Функция `flushUplink()` собирает из очереди до **64 элементов** в единый бинарный буфер `merged` суммарным размером:
* до **9 216 байт (9 КиБ)** для режима `cdn-get` (что дает ровно `12 288` символов в `Base64url`);


* до **16 384 байт (16 КиБ)** для режима `cdn-body`.




4. Чанку присваивается строго возрастающий порядковый номер `seq = upSeq++` (начиная с `1`).


5. Поддерживается параллельный конвейер до **`maxInflight = 6`** одновременных запросов в полете.



#### 3.2. Упаковка в HTTP GET запрос (URL + Header Sharding)

В режиме `cdn-get` бинарный чанк (до 9 216 байт) переводится в строку `Base64url` (до 12 288 символов) и разрезается на части по **3 072 символа**:

* **Первые 3 072 символа** передаются в query-параметре `?p=`.


* **Оставшиеся символы** раскладываются по заголовкам `X-Client-Data-0` ... `X-Client-Data-7` (до 3 072 символов в каждый заголовок).



Пример запроса отправки данных:

```http
GET /assets/chunks/{shortId}/{seq}.bin?p={первые_3072_символа_b64} HTTP/2
X-Client-Key: {sessionToken}
X-Request-ID: {seq}.{downCursor}.0
X-Down-Cursor: {downCursor}
X-Coalesce: 1
X-Client-Data-0: {символы_3072..6144}
X-Client-Data-1: {символы_6144..9216}
X-Client-Data-2: {символы_9216..12288}

```


*(В режиме `cdn-body` те же байты отправляются в теле `POST /_next/data/{buildId}/sync/{shortId}/{seq}.bin` с теми же служебными заголовками)*.

#### 3.3. Сборка и упорядочивание на Сервере (`ProcessUpCDN`)

Так как 6 параллельных `GET`-запросов идут через CDN независимо, они могут приходить на сервер **не по порядку** (например, `seq=3` пришел раньше `seq=2`), а один крупный кадр `SharedFrame` (до 64 КиБ) оказывается разрезанным между несколькими `GET`-запросами:

1. **Декодирование (`DecodeCDNPayload`):** Сервер склеивает параметр `p` и заголовки `X-Client-Data-0..7`, декодируя `Base64url` обратно в сырые байты `chunk`.


2. **Буфер упорядочивания (`ReassemblyBuffer`):**
* Если `seq < expectedUpSeq` — это дубликат от ретрая; сервер игнорирует полезную нагрузку и возвращает `200 OK` (идемпотентность).


* Если `seq > expectedUpSeq` (в пределах окна `16`) — чанк сохраняется в память (`outOfOrder[seq]`), и HTTP-запрос сразу завершается успехом, не блокируя соединение.


* Если `seq == expectedUpSeq` — чанк передается в парсер кадров, после чего из `outOfOrder` в цикле проталкиваются все следующие подряд чанки (`expectedUpSeq + 1`, `+ 2` и т.д.).




3. **Потоковый парсер кадров (`FrameStreamParser`):** Накапливает байты между границами чанков и вырезает цельные кадры (`[type:1B][stream_id:3B][len:4B][payload]`), отправляя их в локальный MTProxy или напрямую в дата-центры Telegram (`Direct DC`).



---

### Фаза 4: Передача данных от Сервера к Клиенту (Downlink: Обратно)

Доставка данных обратно клиенту работает по **трем взаимодополняющим каналам**, синхронизированным единым монотонно растущим курсором `downCursor`.

#### Канал 1: Непрерывный потоковый канал (`Streaming Downlink` — Основной)

Сразу после создания сессии JS-мост открывает потоковый `GET`-запрос:

```http
GET /assets/media/{shortId}/stream_{downCursor}_{randHex}.m4s HTTP/2
X-Client-Key: {sessionToken}
X-Stream-Poll: 1

```

**Как сервер формирует поток (`serveCDNStreamDown`):**

1. Выставляет заголовки `Content-Type: model/gltf-binary` и `X-Accel-Buffering: no`, запрещающие сжатие, кэширование и буферизацию на Nginx/Caddy и CDN.


2. **Стартовый префикс (12 байт):** Немедленно отправляет валидный 12-байтовый заголовок формата **glTF 2.0 binary** (`magic: 0x676C5446` `"glTF"`, `version: 2`, `length: 0xFFFFFFFF`) и вызывает `flusher.Flush()`. Это проходит проверку MIME-sniffing на CDN.


3. **Стартовый Heartbeat (8 байт):** Сразу следом отправляет пустой конверт `[cursor: u32 BE][length: 0 (u32 BE)]` и делает `flusher.Flush()`. Это гарантирует, что первые **20 байт** придут в браузер мгновенно, позволяя JS-мосту за `1500 мс` (`probeTimer`) убедиться, что CDN не буферизует поток.


4. **Пакеты данных (Stream Envelopes):** Пока соединение открыто (до 45 секунд), каждый новый батч кадров от Telegram упаковывается в 8-байтовый конверт и сбрасывается в сокет через `Flush()`:


```text
+-----------------------------------+-----------------------------------+
|   New DownCursor (uint32 BE, 4B)  |  Batch ByteLength (uint32 BE, 4B) |
+-----------------------------------+-----------------------------------+
|                  SharedFrames Payload (N bytes...)                    |
+-----------------------------------------------------------------------+

```




5. **Heartbeats в простое:** Если данных от Telegram нет в течение **10 секунд**, сервер отправляет 8-байтовый конверт с `Batch ByteLength = 0`. На клиенте работает `watchdogTimer` (16 секунд): если за 16 с не пришло ни одного байта (например, при переключении с Wi-Fi на LTE), клиент обрывает зависший запрос и тут же открывает новый со своего последнего `downCursor`.

6. **Бесшовный двухпоточный стриминг «Make-Before-Break» (Overlap Downlink):**
Для предотвращения обрыва по 504 таймауту CDN сервер удерживает соединение не более `cdn_stream_max_duration_secs = 45`.
Клиент (`cdn_ws.html`) не ждет закрытия сокета сервером: на **38-й секунде** (`overlapTimer = 38000 мс`, за 7 секунд до закрытия) клиент упреждающе открывает параллельный поток Stream B (`stream_{downCursor}_{randHex}.m4s`).
При поступлении Stream B сервер в `StreamCDN` закрывает канал вытеснения (`s.superseded`) потока Stream A и бесшовно переключает активный сброс кадров на Stream B с 0 мс простоя.
Поток Stream A дочитывает остаток буфера, завершается естественным путем (`done === true`) и выходит без повторного запуска стрима (`streamId < currentStreamId`), а возможные повторно отправленные батчи из `unackedBatches` фильтруются по `downCursor` (`((cursor - downCursor | 0) > 0)`).

#### Канал 2: Попутная доставка в ответах на Uplink (`Piggybacking` + `ACK`)

Каждый раз, когда сервер обрабатывает Uplink-запрос (`GET /assets/chunks/...` или `POST /sync/...`), он читает переданный клиентом `downCursor` из заголовка `X-Request-ID` / `X-Down-Cursor`:

1. **Очистка подтвержденных батчей (Ack Pruning):** Все батчи в скользящем окне сервера `unackedBatches` с курсором `<= clientCursor` удаляются из памяти сервера.


2. **Выдача данных:** Если в этот момент нет активного стрима (`!s.downActive`), сервер ждет до 25 мс (`X-Coalesce: 1`), собирает готовые кадры и возвращает их прямо в теле ответа на Uplink-запрос:


* **Если есть данные:** статус `200 OK`, `Content-Type: model/gltf-binary`, тело: `[12 байт glTF заголовка с новым курсором в байтах 8..12] + [SharedFrames]`.


* **Если данных нет (или они уже идут через активный стрим):** статус `200 OK`, `Content-Type: application/json`, тело: `{"s":1,"c":<downCursor>}`.




3. **Явный ACK (`sendAckOnly`):** Если клиент получил по стриму **16 батчей подряд**, ничего не отправляя в ответ (`upInflight === 0`), он шлет легкий запрос `GET /assets/chunks/{shortId}/0.bin?p=&r={rand}` (`seq = 0`), чтобы сдвинуть окно подтверждения на сервере и освободить `unackedBatches`.



#### Канал 3: Автоматический Fallback на Long-Polling (`PollCDN`)

Если прокси или CDN буферизует потоковые ответы (`probeTimer` на 1.5 с срабатывает 2 раза подряд без получения первых 20 байт), JS-мост автоматически переключается на батчевый Long-Polling:

```http
GET /assets/media/{shortId}/seg_{downCursor}_{randHex}.m4s HTTP/2
X-Client-Key: {sessionToken}

```


Сервер удерживает запрос до **12 секунд** и при появлении первого же батча отдает его целиком с 12-байтовым заголовком glTF и закрывает HTTP-ответ.

---

### Фаза 5: Гарантия доставки без потерь (Zero-Loss Replay и Работа во сне)

1. **Zero-Loss Replay (Защита от обрыва посреди стрима):**
* Сервер хранит отправленные, но еще не подтвержденные клиентом батчи в очереди `unackedBatches` (до 32 батчей).


* Клиент обновляет свой `downCursor` **только после того**, как полностью вычитал конверт из потока и передал кадры в `TelegramWebProxy`.


* Если соединение оборвалось на полпути, клиент открывает новый `stream_{downCursor}_*.m4s` со старым `downCursor`. Сервер видит, что в `unackedBatches` есть батчи с курсором `> downCursor`, и первым делом повторно высылает их в новый поток без потери ни единого байта.




2. **Защита при сворачивании приложения (Background / Sleep Recovery):**
* Когда приложение свернуто (`document.visibilityState === 'hidden'`) или пропала сеть (`navigator.onLine === false`), ОС блокирует фоновые сокеты.


* В этом состоянии `sendChunkWithBackoff` **не сжигает лимит фатальных попыток** (`nextRetry` замораживается), а переходит в режим редких попыток (раз в 2 секунды), сохраняя сессию живой.


* При разворачивании приложения (`visibilitychange -> visible`, `online`, `focus`, `pageshow`) срабатывает `onWakeUp()`:


1. Мгновенно пробуждаются все таймеры ожидания (`wakeSignals`);


2. Сбрасывается зависший поток чтения (`pollController.abort()`), тут же открывая свежий запрос;


3. Запускается отправка накопленной очереди `flushUplink()` или `sendAckOnly()`.






3. **Штатное и аварийное закрытие (`close` / `fail`):**
* При закрытии вкладки отправляется `GET /_next/data/{buildId}/unload/{shortId}.json?t={now}` с `keepalive: true` и заголовком `X-Client-Key`.


* Если сессия на сервере истекла (вернулся `404`/`410` или HTML-страница сайта-прикрытия `text/html`), вызывается `fail()`: мост рассылает в клиент Telegram кадры закрытия `CLOSE (0x03)` для всех активных `activeStreams`, статус `{t:'status', state:'failed'}` и команду `{t:'close'}`, что заставляет клиент Telegram мгновенно пересоздать WebView-сессию.





---

## 4. Сводная таблица HTTP-маршрутов стандарта

| Назначение | Метод | Шаблон URL | Формат запроса | Формат ответа |
| --- | --- | --- | --- | --- |
| **Инициализация (GET)** | `GET` | `/_next/data/{buildId}/init/{bootstrap}/{helloB64}.json`<br> | `helloB64` в URL + `X-Client-Key`<br> | `application/json` (`token`, `short_id`, `welcome`)

 |
| **Инициализация (POST)** | `POST` | `/_next/data/{buildId}/collect.json?k={prefix}`<br> | Binary `HELLO` в body + `X-Client-Key`<br> | `application/octet-stream` (Binary `WELCOME`) + заголовки

 |
| **Uplink + Piggyback (GET)** | `GET` | `/assets/chunks/{shortId}/{seq}.bin?p={b64_part0}`<br> | `?p=` (3072 симв.) + `X-Client-Data-0..7`<br> | `model/gltf-binary` (с данными) или `application/json` `{"s":1,"c":N}`<br> |
| **Uplink + Piggyback (POST)** | `POST` | `/_next/data/{buildId}/sync/{shortId}/{seq}.bin`<br> | Binary chunk (до 16 КиБ) в body

 | `model/gltf-binary` (с данными) или `application/json` `{"s":1,"c":N}`<br> |
| **ACK курсора** | `GET` | `/assets/chunks/{shortId}/0.bin?p=&r={rand}`<br> | `seq = 0`, пустой `p`, `X-Down-Cursor`<br> | `model/gltf-binary` или `application/json` `{"s":1,"c":N}`<br> |
| **Downlink Stream** | `GET` | `/assets/media/{shortId}/stream_{cursor}_{rand}.m4s`<br> | Заголовок `X-Stream-Poll: 1`<br> | Поток `model/gltf-binary`: `12B glTF` + поток `[cursor:4B][len:4B][data]`<br> |
| **Downlink Poll (Fallback)** | `GET` | `/assets/media/{shortId}/seg_{cursor}_{rand}.m4s`<br> | Курсор в имени файла + `X-Client-Key`<br> | Одиночный батч `model/gltf-binary` (`12B glTF + data`) или JSON по таймауту 12 с

 |
| **Закрытие сессии** | `GET` | `/_next/data/{buildId}/unload/{shortId}.json?t={ts}`<br> | `keepalive: true` + `X-Client-Key`<br> | `application/json` `{"s":1}`<br> |

---

## 5. Бинарные форматы заголовков

### 1. Внутренний кадр протокола (`SharedFrame` — Big-Endian, 8 байт)

Используется внутри всех полезных нагрузок между клиентом и релеем:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type (u8)   |                Stream ID (u24 BE)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload Length (u32 BE)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload (N bytes...)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

* `Type`: `0x01` (`OPEN`), `0x02` (`DATA`), `0x03` (`CLOSE`), `0x04` (`WINDOW`), `0x10` (`HELLO`), `0x11` (`WELCOME`), `0x1f` (`BYE`).



### 2. Заголовок одиночного батча `glTF 2.0` (12 байт — для Piggyback и PollCDN)

```text
Байты 0..3  : 0x67 0x6C 0x54 0x46 ("glTF" ASCII)
Байты 4..7  : 0x02 0x00 0x00 0x00 (uint32 LE = 2, версия glTF)
Байты 8..11 : DownCursor (uint32 BE — новый курсор после этого батча)
Байты 12..N : Полезная нагрузка (один или несколько кадров SharedFrame)

```

### 3. Формат потока `glTF 2.0 Stream` (для `Streaming Downlink`)

```text
[Стартовый префикс ответа — отправляется 1 раз при открытии HTTP-ответа (12 байт)]:
  Байты 0..3  : 0x67 0x6C 0x54 0x46 ("glTF" ASCII)
  Байты 4..7  : 0x02 0x00 0x00 0x00 (uint32 LE = 2)
  Байты 8..11 : 0xFF 0xFF 0xFF 0xFF (маркер потокового режима)

[Повторяющиеся конверты (Stream Envelopes) — отправляются на каждый Flush]:
  Байты 0..3  : Next DownCursor (uint32 BE)
  Байты 4..7  : Envelope Payload Length (uint32 BE, 0 = Heartbeat)
  Байты 8..M  : SharedFrames Batch (присутствует, если Length > 0)

```
