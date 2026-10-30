# План оптимизации производительности CDN-Stream (SSE/Streaming Downlink в cdn-ws)

## Context
Требуется оптимизировать транспортный режим `cdn-ws` (SSE/ReadableStream CDN streaming) для максимального ускорения времени первого подключения (рукопожатие и пинг) и скорости потоковой загрузки/выгрузки медиаданных. План полностью утвержден, исключает голодание ACK при скачивании медиа, склеивает стартовый префикс и envelope в 20-байтовый пакет на стеке, буферизует конверты батчей для устранения фрагментации HTTP-чанков, расширяет конвейер отправки и устраняет аллокации памяти при декодировании заголовков и отдаче ответов. Изменения сохраняют 100% обратную совместимость с `docs/CDN_TRANSPORT_SPEC.md`, контрактом `PROTOCOL.md`, остальными сетевыми мостами и набором проверок `page_test.go`.

## Approach

### 1. Оптимизация клиентского шаблона `internal/bridge/templates/cdn_ws.html`

- **Connect Phase (0 мс задержки старта рукопожатия)**:
  - В `createSession(helloBuf)` заменить `scheduleFlush()` на синхронный `flushUplink()`. Пакеты `OPEN` и первый MTProto Obfuscated2 пакет рукопожатия (`req_pq_multi`), накопленные в `fastPending`, уходят на сервер синхронно со стартом `startStreamLoop()` в том же тике событийного цикла.

- **Расширение конвейера Uplink без переполнения L7-заголовков CDN**:
  - `maxInflight`: увеличить с 6 до **8** (в HTTP/2 и HTTP/3 мультиплексирование 8 потоков на одном соединении не ограничено 6 сокетами HTTP/1.1; 1 слот резервируется под `fastPending`, 7 слотов непрерывно прокачивают медиа).
  - `maxChunkBytes`: увеличить с 4500 до **6000** байт (ровно 2000 символов Base64url в `?p=` и 2 заголовка `X-Client-Data-0..1` по 3000 символов; общий размер запроса ~8.5 КиБ гарантированно укладывается в лимиты Cloudflare/Nginx/Caddy).
  - `maxWindowSpan`: увеличить с 14 до **32** (при серверном окне `CDNUplinkWindowSize = 64` это предотвращает блокировку окна `canAdvanceWindow()` при сетевом джиттере).

- **Быстрый сброс «залипших» на CDN чанков (Fast Retransmit)**:
  - В `sendChunkWithBackoff` уменьшить таймаут первой попытки с 3500 мс до **2500 мс** (`const timeoutMs = retry === 0 ? 2500 : 5000`). Если запрос зависает на узле CDN, он прерывается и переотправляется с новым `&r=` за 2.5 с вместо 3.5–4 с.

- **Ликвидация голодания ACK и замерзания стрима (Smart ACK Dispatch)**:
  - В `runStream` внутри `assembler.feed(...)`:
    ```javascript
    if ((downCursor - lastSentAckCursor) >= 4) {
      if (hasPendingUplink() && upInflight < maxInflight) {
        flushUplink();
      } else {
        sendAckOnly();
      }
    }
    ```
  - В `sendAckOnly()`: сразу при входе фиксировать `lastSentAckCursor = cur;`. В блоке `finally` добавить проверку: если за время полета ACK прибыло еще $\ge 4$ батчей (`if (!closed && sessionToken && (downCursor - lastSentAckCursor) >= 4)`), вызывать `flushUplink()` (при наличии данных) или повторный `sendAckOnly()`.
  - В `onWakeUp` строго сохранить сниппет `else if(upPending.length===0&&(isOnline||slept)){ sendAckOnly(); }` для 100% совместимости с `page_test.go`.

- **Быстрый реконнект стрима (`runStream`)**:
  - В блоке `catch(e)` функции `runStream` снизить паузу перед переподключением упавшего стрима со `150 + rand(200)` мс до `20 + rand(30)` мс.

- **Zero-Copy Transferable в `deliver`**:
  - В `deliver(batchBuf)` передавать кадры в Telegram через `port.postMessage(frame.data, [frame.data])` с передачей владения буфером.

### 2. Оптимизация серверного стриминга `internal/server/cdn_stream.go`

- **Склейка стартового префикса и первого конверта (20 байт) на стеке (0 аллокаций в куче)**:
  - В `serveCDNStreamDown` заменить два раздельных `w.Write` и `flusher.Flush` на единую запись:
    ```go
    var initPkt [20]byte
    copy(initPkt[0:12], session.GLTFStreamHeader[:])
    binary.BigEndian.PutUint32(initPkt[12:16], uint32(cursor))
    binary.BigEndian.PutUint32(initPkt[16:20], 0)
    if _, err := w.Write(initPkt[:]); err != nil {
        return
    }
    flusher.Flush()
    ```
  - Устраняет 1 syscall, 1 TLS-запись и 1 HTTP-чанк. Клиентский `reader.read()` получает glTF заголовок и первый конверт в едином сетевом пакете и мгновенно гасит `probeTimer`.

- **Буферизация конверта и тела батча (`bufio.WriterSize(w, 64*1024)`)**:
  - Обернуть `w` в `bw := bufio.NewWriterSize(w, 64*1024)`.
  - В `onBatch` записывать `session.WriteBatchEnvelope(bw, cur, body)`, затем `bw.Flush()` и `flusher.Flush()`.
  - Предотвращает отправку 8-байтового конверта отдельным мелким HTTP-чанком перед телом батча.

### 3. Оптимизация серверной обработки без аллокаций `internal/server/cdn.go`

- **Предвычисленный массив заголовков `X-Client-Data-0..7`**:
  - Задать пакетную переменную:
    ```go
    var clientDataHeaders = [8]string{
        "X-Client-Data-0", "X-Client-Data-1", "X-Client-Data-2", "X-Client-Data-3",
        "X-Client-Data-4", "X-Client-Data-5", "X-Client-Data-6", "X-Client-Data-7",
    }
    ```
  - В `serveCDNChunkGet` собирать заголовки через индексацию `clientDataHeaders[i]` без `fmt.Sprintf`.

- **Zero-Allocation `writeCDNDownlinkResponse`**:
  - Исключить выделение и копирование памяти через `session.WrapGLTF`. Записывать 12-байтовый glTF-заголовок напрямую из стекового буфера `var hdr [12]byte` и затем `batch` в сокет с заголовком `Content-Length: 12 + len(batch)`.
  - Для пустых ответов `{"s":1,"c":N}` формировать байты через `strconv.AppendUint` без `fmt.Sprintf`.

### 4. Проверка и валидация `session.go` и `config.go`

- В `internal/session/session.go:1054` подтверждено наличие `signal(s.notify)` при освобождении батчей в `ackCursorLocked`.
- В `internal/config/config.go:462` подтверждено дефолтное значение `CDNUplinkWindowSize: 64`.

## Critical files & anchors

1. `internal/bridge/templates/cdn_ws.html`:
   - Строка 24–26: `maxInflight = 8`, `maxChunkBytes = 6000`, `maxWindowSpan = 32`.
   - Строка 208: `createSession` — синхронный `flushUplink()`.
   - Строка 343: `sendChunkWithBackoff` — таймаут 2500 мс, заголовок 3000 символов на чанк.
   - Строка 417: `sendAckOnly` — фиксация `lastSentAckCursor = cur` и досыл в `finally`.
   - Строка 620: `runStream` (`assembler.feed`) — порог 4 батча и Smart ACK Dispatch.
   - Строка 657: `runStream` (`catch`) — пауза реконнекта `20 + rand(30)` мс.
   - Строка 577: `onWakeUp` — сохранение `else if(upPending.length===0&&(isOnline||slept)){ sendAckOnly(); }`.

2. `internal/server/cdn_stream.go`:
   - `serveCDNStreamDown`: 20-байтовый стек-буфер `initPkt` + один `flusher.Flush()`.
   - Буферизация `bw := bufio.NewWriterSize(w, 64*1024)`.

3. `internal/server/cdn.go`:
   - `clientDataHeaders`: статическая таблица имен заголовков.
   - `serveCDNChunkGet`: сбор заголовков по статической таблице.
   - `writeCDNDownlinkResponse`: прямая запись 12-байтового заголовка glTF без `WrapGLTF`.

## Verification

1. **Unit-тесты и рендеринг моста**:
   - `go test -v ./internal/bridge` — проверка `TestRenderCDNWSBridgeLifecycleAndRecovery` (все сниппеты сохранены).
   - `go test -v ./internal/server` — проверка маршрутизации CDN, `serveCDNStreamDown`, `writeCDNDownlinkResponse`.
   - `go test -v ./internal/session` — проверка `StreamCDN`, `Push`, `ackCursorLocked`.
   - `go test ./...` — успешная компиляция и прохождение 100% тестов репозитория.

2. **Проверка инвариантов протокола**:
   - Размер полезной нагрузки чанка: 6000 байт -> 8000 символов Base64url (2000 в query `?p=`, по 3000 в `X-Client-Data-0..1`).
   - Изоляция других режимов: шаблоны `cdn.html`, `websocket.html`, `https.html`, `yc_ws.html` остаются нетронутыми.

## Assumptions & contingencies
- Изменения оптимизируют исключительно код режима `cdn-ws` и общие серверные утилиты CDN.
- При возникновении исключения в старых WebView при передаче transfer list в `port.postMessage`, вызов защищен стандартным поведением браузера.
