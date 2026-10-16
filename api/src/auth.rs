use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::state::AppState;

/// Пробы без токена: healthcheck/docker и чтение спеки работают без секретов.
fn is_public(path: &str) -> bool {
    matches!(
        path,
        "/api/v1/healthz" | "/api/v1/version" | "/api/v1/openapi.json"
    )
}

fn bearer_ok(headers: &HeaderMap, token: &str) -> bool {
    let Some(v) = headers.get(axum::http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(s) = v.to_str() else {
        return false;
    };
    let Some(got) = s.strip_prefix("Bearer ") else {
        return false;
    };
    got == token
}

/// Замок: если API_TOKEN задан — все /api/* кроме проб требуют
/// `Authorization: Bearer <токен>`, иначе 401 JSON.
/// Без токена (дефолт локалки) — открыто как раньше.
pub(crate) async fn require_token(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let configured = state
        .api_token
        .as_ref()
        .map(|t| !t.is_empty())
        .unwrap_or(false);
    if !configured || is_public(req.uri().path()) {
        return next.run(req).await;
    }
    match &state.api_token {
        Some(token) if bearer_ok(req.headers(), token) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(crate::dto::ErrorResponse {
                error: "Unauthorized: нужен Authorization: Bearer <API_TOKEN>".to_string(),
            }),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_probes() {
        assert!(is_public("/api/v1/healthz"));
        assert!(is_public("/api/v1/version"));
        assert!(is_public("/api/v1/openapi.json"));
        assert!(!is_public("/api/v1/captures"));
        assert!(!is_public("/api/v1/healthz/extra"));
    }

    #[test]
    fn bearer_parsing() {
        let mut h = HeaderMap::new();
        assert!(!bearer_ok(&h, "s3cr3t"));
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer s3cr3t".parse().unwrap(),
        );
        assert!(bearer_ok(&h, "s3cr3t"));
        assert!(!bearer_ok(&h, "other"));
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Token s3cr3t".parse().unwrap(),
        );
        assert!(!bearer_ok(&h, "s3cr3t"));
    }
}
