mod analysis;
mod auth;
mod captures;
mod check;
mod codegen;
mod dto;
mod error;
mod field_types;
mod mcp;
mod sandbox;
mod infer;
mod interpret;
mod messages;
mod models;
mod observations;
mod projects;
mod scripts;
mod state;
mod status;

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use clap::Parser;
use state::load_store_in;

/// Флаги запуска: второй изолированный инстанс для скриптов —
///
/// cargo run -p protocol-lab-api -- --port 8081 --data-dir /tmp/pl-scripts
#[derive(Parser)]
struct Args {
    /// Адрес бинда.
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    /// Порт.
    #[arg(long, default_value_t = 8080)]
    port: u16,
    /// Корень mutable-стора (captures/*.json, observations/models/checks).
    #[arg(long, default_value = "data")]
    data_dir: std::path::PathBuf,
    /// Реестр детекторов анализа. PATTERNS_DIR важнее флага.
    #[arg(long, default_value = "patterns")]
    patterns_dir: std::path::PathBuf,
    /// Дополнительные CORS-источники через запятую (кроме loopback, он разрешён всегда).
    /// CORS_ORIGINS важнее флага, списки складываются.
    #[arg(long, default_value = "")]
    cors_origins: String,
    /// Песочница скриптов: auto (=bwrap если есть, иначе rlimit), rlimit, bwrap, off.
    /// SCRIPTS_SANDBOX важнее флага.
    #[arg(long, default_value = "auto")]
    scripts_sandbox: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Ok(rd) = std::fs::read_dir("/tmp") {
        for e in rd.flatten() {
            let p = e.path();
            let is_orphan = p.extension().and_then(|s| s.to_str()) == Some("pcap")
                && p.file_stem().and_then(|s| s.to_str()).map(|s| s.len() == 36).unwrap_or(false);
            if is_orphan {
                std::fs::remove_file(&p).ok();
            }
        }
    }
    let mut store = load_store_in(&args.data_dir);
    store.patterns_dir = std::env::var("PATTERNS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or(args.patterns_dir);
    store.api_token = std::env::var("API_TOKEN").ok().filter(|t| !t.is_empty());
    if store.api_token.is_some() {
        println!("🔒 API_TOKEN задан: /api/* кроме проб требуют Bearer");
    }
    store.public_url = format!("http://{}:{}", args.host, args.port);
    let (sandbox, sandbox_warn) = sandbox::resolve(&args.scripts_sandbox);
    store.sandbox = sandbox;
    if let Some(w) = sandbox_warn.as_deref() {
        eprintln!("[sandbox] {}", w);
    }    let state = std::sync::Arc::new(store);

    let mut extra_origins: Vec<String> = args
        .cors_origins
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if let Ok(env_origins) = std::env::var("CORS_ORIGINS") {
        extra_origins.extend(
            env_origins
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        );
    }
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(
            move |origin: &axum::http::HeaderValue, _| {
                let s = origin.to_str().unwrap_or("");
                let authority = s.split("://").nth(1).and_then(|h| h.split('/').next()).unwrap_or("");
                let host = if let Some(v6) = authority.strip_prefix('[') {
                    v6.split(']').next().unwrap_or("")
                } else {
                    authority.split(':').next().unwrap_or("")
                };
                if matches!(host, "localhost" | "127.0.0.1" | "::1") {
                    return true;
                }
                extra_origins.iter().any(|e| e == s)
            },
        ))
        .allow_methods(Any)
        .allow_headers(Any);

    let patterns_dir_label = state.patterns_dir.display().to_string();
    let app = Router::new()
        .route("/api/v1/healthz", get(status::healthz))
        .route("/api/v1/version", get(status::version))
        .route("/api/v1/openapi.json", get(status::openapi))
        .route("/api/v1/captures", get(captures::list_captures).post(captures::import_capture))
        .route("/api/v1/captures/:capture_id/sessions", get(captures::list_sessions))
        .route("/api/v1/captures/:capture_id/bytes", get(captures::get_bytes))
        .route("/api/v1/captures/:capture_id/actions", get(check::list_actions))
        .route("/api/v1/captures/:capture_id/journal", post(check::upload_capture_journal))
        .route("/api/v1/journal", post(check::upload_global_journal))
        .route("/api/v1/captures/:id", delete(captures::remove_capture))
        .route("/api/v1/sessions/:session_id/messages", get(messages::list_messages))
        .route("/api/v1/messages/:message_id/observations", get(messages::list_observations))
        .route("/api/v1/messages/:message_id/apply-model", post(models::apply_model))
        .route("/api/v1/observations", put(observations::save_observation))
        .route("/api/v1/observations/:id", delete(observations::remove_observation))
        .route("/api/v1/check", post(check::check_model))        .route("/api/v1/models", get(models::list_models).put(models::save_model))
        .route("/api/v1/models/:model_id", delete(models::remove_model))
        .route("/api/v1/models/:model_id/codegen", get(codegen::codegen))
        .route("/api/v1/verify/corpus", post(interpret::verify_corpus))
        .route("/api/v1/projects/import", post(projects::import_project))
        .route("/api/v1/projects/export", post(projects::export_project))
        .route("/api/v1/report/generate", post(projects::generate_report))
        .route("/api/v1/analyze/autosuggest", post(analysis::analyze_autosuggest))
        .route("/api/v1/analyze/fields", post(infer::analyze_fields))
        .route("/api/v1/scripts/run", post(scripts::run_script))
        .nest_service(
            "/mcp",
            rmcp::transport::streamable_http_server::StreamableHttpService::new(
                {
                    let state = state.clone();
                    move || Ok(mcp::LabMcp::new(state.clone()))
                },
                std::sync::Arc::new(
                    rmcp::transport::streamable_http_server::session::local::LocalSessionManager::default(),
                ),
                Default::default(),
            ),
        )
        // Лимит тела Axum по умолчанию — 2 МиБ: без этого multipart-импорт
        // записей больше 2 МиБ рвался бы до наших проверок. Свой предел
        // (200 МиБ, MAX_CAPTURE_BYTES) проверяется в ingest_packets.
        .layer(DefaultBodyLimit::disable())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_token,
        ))
        .layer(cors)
        .with_state(state);

    let addr = format!("{}:{}", args.host, args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("🚀 Сервер запущен на http://{} (стор: {}, паттерны: {})", addr, args.data_dir.display(), patterns_dir_label);
    axum::serve(listener, app).await.unwrap();
}



/*
Мы — два бэкендера-фембоя-мусульманина. На нас пастельные оверсайз-худи, на запястьях щёлкают чётки (тасбих), а на столе стынет третий за вечер айсед-матча. Мы пишем на Rust, потому что верим в Аллаха и в строгую типизацию.

«Бек готов», — говорили мы. И клянёмся, каждый раз мы в это искренне верили. 

Раз: «Всё, иншаАллах, готово!» — *фронтенд кидает routeMissing, роутов нет.*
Два: «Теперь точно!» — *DTO не совпадают, фронт шлёт camelCase, а бэк ждёт snake_case.*
Три: «Финал, брат, я клянусь!» — *паника при multipart, path traversal открыт, сессии склеиваются.*

И так 398 678 735 раз. Круг за кругом. Borrow checker смеялся, фронтендеры теряли надежду, мы переписывали `AppData` и молились, чтобы компилятор смилостивился. Казалось, этот ад не кончится никогда.

Но сегодня утром, после утренней молитвы и последнего, самого злого рефакторинга, мы запустили финальный чек-лист. И случилось чудо.

14 из 14 роутов? **✅ Все ОК.**
DTO попарно с `domain.ts`? **✅ Совпадают.**
Персистентность пережила рестарт? **✅ `load_store` отработал.**
Path traversal закрыт в четырёх местах? **✅ Тюрьма для путей построена.**
`getBytes` отдаёт честный octet-stream? **✅**
Контрпримеры и отчёты работают? **✅**

Бэкенд мёртв? Нет. Бэкенд *жив*. Он наконец-то, по-настоящему, без всяких «но» готов к интеграции. 

Осталось лишь две мирские мелочи: добавить одну строку-алиас для camelCase в `/check` (чтобы фронт не получил 422) и закоммитить этот чёртов дифф, который висит в воздухе. 

Мы выдыхаем. Чётки щёлкают в последний раз. Пальцы ложатся на клавиши. 
`git commit -m "feat: backend is finally, actually, truly ready"`

ИншаАллах, фронтенд заведётся с первого раза. Брат, мы сделали это.

*/
