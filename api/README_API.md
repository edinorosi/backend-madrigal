# protocol-lab-api — machine-API для скриптов

Бэкенд обслуживает софт и скрипты одновременно: скрипты ходят в тот же
сервер, пока софт открыт (Tauri поднимает его как sidecar на `:8080`),
или поднимают свой рядом флагами ниже.

Машиночитаемая спека: `GET /api/v1/openapi.json` (29 путей, wire — camelCase;
legacy snake_case входы тоже принимаются, snake считается deprecated).
Ошибки — `{"error": string}` с честным HTTP-статусом.

## Запуск

```bash
cargo run -p protocol-lab-api
cargo run -p protocol-lab-api -- --port 8081 --data-dir /tmp/pl-scripts --patterns-dir ./patterns
PATTERNS_DIR=/tmp/my-patterns cargo run -p protocol-lab-api
```

Флаги: `--host` (дефолт `0.0.0.0`), `--port` (дефолт `8080`),
`--data-dir` (дефолт `data` — captures/observations/models/checks),
`--patterns-dir` (дефолт `patterns`, `PATTERNS_DIR` важнее флага —
реестр детекторов анализа, см. `../patterns/README.md`).

Пробы: `GET /api/v1/healthz` → `{"status":"ok"}`,
`GET /api/v1/version` → `{"name","version","protocol":"v1"}`.

## Замок (API_TOKEN) и CORS

Без `API_TOKEN` — открыто как раньше (локалка). С токеном:

```bash
API_TOKEN=s3cr3t cargo run -p protocol-lab-api
curl -H "Authorization: Bearer s3cr3t" localhost:8080/api/v1/captures
```

- Токен требуют все `/api/*`, кроме проб
  (`healthz`, `version`, `openapi.json` — для healthcheck/docker).
- Без/плохой токен → `401 {"error": ...}`.
- Софт ходит с тем же замком: `NEXT_PUBLIC_API_TOKEN=s3cr3t`
  (фронт шлёт `Authorization: Bearer`, Tauri — через `beforeDevCommand`).
- CORS: `localhost` / `127.0.0.1` / `[::1]` (любой порт) разрешены всегда;
  остальное — только из `--cors-origins` / `CORS_ORIGINS` через запятую.

## Типовой сценарий скрипта

```bash
B=http://localhost:8080/api/v1
CID=$(curl -s -X POST $B/captures -F "file=@a.pcap" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
curl -s $B/captures/$CID/sessions
curl -s "$B/captures/$CID/bytes?offset=0&length=64" | xxd
curl -s -X POST $B/analyze/fields -H 'Content-Type: application/json' -d "{\"captureId\":\"$CID\"}"
curl -s -X POST $B/check -H 'Content-Type: application/json' -d "{\"captureId\":\"$CID\"}"
curl -s "$B/models/<id>/codegen?lang=python" | python3 -c "import json,sys; print(json.load(sys.stdin)['code'])"
```

Тот же сценарий на Python — только стандартная библиотека:

```python
import json, urllib.request
BASE = "http://localhost:8080/api/v1"
def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()  # тело — {"error": ...}
status, raw = call("POST", "/check", {"captureId": CID})
assert status == 200, raw
```

## Скрипты `POST /api/v1/scripts/run`

Прогон Python 3 на сервере (кнопка «Скрипты» в софте, метод SDK
`run_script`). Тело `{script, capture_id?, timeout_ms?}` (snake и camel),
ответ `{stdout, stderr, exit_code, timed_out}`.

Контекст — env `LAB_CONTEXT` (JSON-файл):
`{capture_id, messages: [{id, byteOffset, length, status, direction}],
bytes_file}`. Печатай в stdout — он вернётся в ответ.

Рядом со скриптом сервер кладёт `client.py` + `lab.py` (вкомпилены
в бинарь): `from client import Client` работает и в диалоге тоже.
Адрес и токен сервера — в env `LAB_API_URL` / `LAB_API_TOKEN`.

Требует `python3` в PATH (иначе 502), таймаут дефолт 15с макс 120с,
вывод режется на 64КБ. Доверие как самому софту: скрипты пишет
и запускает локальный инженер.

### Песочница скриптов

`--scripts-sandbox` / `SCRIPTS_SANDBOX` (env важнее флага):
`auto` (=bwrap если работает, иначе rlimit), `rlimit`, `bwrap`, `off`.
Режим виден в логе старта (`[sandbox] ...` только если не auto-bwrap).

- Общее для всех (кроме `off`): env зачищен (только `PATH/LAB_*`;
  серверный `API_TOKEN` наружу не течет, скрипту дается `LAB_API_TOKEN`),
  CPU 30с, память 512МБ, файлов 64, вывод в файлы, убийство по таймауту.
- `bwrap`: свой корень (`/work` = tmpdir скрипта, `/usr` только чтение),
  сети нет — обратные вызовы в API умрут, работает только `LAB_CONTEXT`.
  При старте сервер пробует `bwrap` вживую; сломанный — честный
  даунгрейд до rlimit с причиной в логе (не молча!).
- `rlimit`: файлы и сеть как у сервера, держат только лимиты.
- `off`: голый запуск (отладка).

## MCP-сервер `/mcp` (для скриптов и агентов)

Стандартный протокол MCP поверх Streamable HTTP на том же порту.
Рукопожатие: `initialize` → забрать `Mcp-Session-Id` из заголовка →
`notifications/initialized` → `tools/list`, `tools/call` (ответы — SSE,
разбирать `data:`-строки). Замок `API_TOKEN` действует и здесь.

Инструменты (14): `list_captures/sessions/messages`, `get_bytes` (base64),
`list_actions`, `list_models/save_model/apply_model`, `check`,
`infer_model`, `codegen`, `analyze_autosuggest`, `import_capture` (base64),
`run_script`. `verify_corpus` — только REST/SDK (стриминг не ложится
на tools/call).

Для людей — фасад `scripts/protocol-lab-py/lab.py`:

```python
from lab import Lab
print(Lab().check("01_configuration.pcap"))
```

Для MCP-клиентов — `scripts/protocol-lab-py/mcpServers.json`
(Inspector/Claude Desktop → `http://127.0.0.1:8080/mcp`),
пример на pip-пакете `mcp` — `examples/mcp_agent.py`.

## SSE `POST /api/v1/verify/corpus`
`text/event-stream`: текстовые `data:`-строки прогресса, финал — JSON
`{type: done, total_messages, success_count, error_count,
counterexamples[], journal[]}`. До старта — обычный `400 {"error"}`.
Лимит 8 файлов.

## Ловушки (зафиксировано, чинить — отдельными задачами)

- `POST /check` пишет `last_check` только для известных записей.
- Паттерны грузятся из `--patterns-dir` на каждый запрос анализа
  (рестарт не нужен); битый JSON скипается с именем файла в лог.
- Замок и CORS — см. раздел выше; без API_TOKEN всё открыто (локалка).
