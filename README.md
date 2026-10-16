# backend-madrigal

Бэкенд «Лаборатории протоколов»: Rust (cargo-workspace `core` + `api`),
Axum, HTTP на `:8080`. Парсит PCAP, хранит проекты, применяет модели разбора.

## Запуск

```bash
cargo run -p protocol-lab-api                 # http://localhost:8080
# флаги: --host --port --data-dir --patterns-dir; заголовок: API_TOKEN, CORS_ORIGINS
```

Пробы: `GET /api/v1/healthz`, `GET /api/v1/version`, спека `GET /api/v1/openapi.json`.

## Как он связан с фронтендом

Проект разворачивается двумя репозиториями-соседями: этот `backend-madrigal/` и
`frontend-madrigal/`. Полные инструкции по всем способам запуска (веб в Docker,
Tauri-инсталлятор в Docker, нативная сборка Tauri, готовый инсталлятор) — в
`frontend-madrigal/edinoros/README.md`. Кратко:

| Способ | Что делает бэкенд |
|---|---|
| Docker веб | поднимается контейнером на `:8080` (образ из этого репо) |
| Docker Tauri / нативно | бьётся как sidecar-бинарь `protocol-lab-api` рядом с приложением |
| Готовый инсталлятор | уже вкомпилён внутрь пакета |

Docker-образ: `Dockerfile` (build-стадия компилит бинарь, рантайм — `debian:bookworm-slim`).
Скрипты для фичи «Скрипты» лежат в `scripts/protocol-lab-py/`.
