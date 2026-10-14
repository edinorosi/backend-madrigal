mod analysis;
mod captures;
mod check;
mod dto;
mod error;
mod flows;
mod interpret;
mod messages;
mod models;
mod observations;
mod projects;
mod state;

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use state::load_store;

#[tokio::main]
async fn main() {
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
    let state = std::sync::Arc::new(load_store());

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/v1/captures", get(captures::list_captures).post(captures::import_capture))
        .route("/api/v1/captures/:capture_id/sessions", get(captures::list_sessions))
        .route("/api/v1/captures/:capture_id/bytes", get(captures::get_bytes))
        .route("/api/v1/captures/:capture_id/actions", get(check::list_actions))
        .route("/api/v1/captures/:id", delete(captures::remove_capture))
        .route("/api/v1/sessions/:session_id/messages", get(messages::list_messages))
        .route("/api/v1/messages/:message_id/observations", get(messages::list_observations))
        .route("/api/v1/messages/:message_id/apply-model", post(models::apply_model))
        .route("/api/v1/observations", put(observations::save_observation))
        .route("/api/v1/observations/:id", delete(observations::remove_observation))
        .route("/api/v1/check", post(check::check_model))
        .route("/api/v1/models", get(models::list_models).put(models::save_model))
        .route("/api/v1/models/:model_id", delete(models::remove_model))
        .route("/api/v1/projects", post(projects::create_project).get(projects::get_projects))
        .route("/api/v1/projects/:id", get(projects::get_project))
        .route("/api/v1/projects/:id/captures", post(projects::upload_capture))
        .route("/api/v1/projects/:id/observations", post(observations::add_observation))
        .route("/api/v1/flows/:session_id/bytes", post(flows::get_flow_bytes))
        .route("/api/v1/interpret/apply", post(interpret::apply_interpretation))
        .route("/api/v1/verify/corpus", post(interpret::verify_corpus))
        .route("/api/v1/projects/import", post(projects::import_project))
        .route("/api/v1/projects/export", post(projects::export_project))
        .route("/api/v1/report/generate", post(projects::generate_report))
        .route("/api/v1/analyze/autosuggest", post(analysis::analyze_autosuggest))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 Сервер запущен на http://0.0.0.0:8080");
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
