use axum::Json;
use serde_json::{json, Value};

// здоровье, крутится в ретрае пока не будет 200 x_x.
pub(crate) async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub(crate) async fn version() -> Json<Value> {
    Json(json!({
        "name": "protocol-lab-api",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "v1",
    }))
}

// из файла в джейсон
pub(crate) async fn openapi() -> Json<Value> {
    let raw = include_str!("openapi.json");
    let value: Value = serde_json::from_str(raw).expect("openapi.json must be valid JSON");
    Json(value)
}
