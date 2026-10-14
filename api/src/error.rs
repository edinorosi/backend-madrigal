use std::path::Path as StdPath;

use axum::{http::StatusCode, Json};

use crate::dto;

pub(crate) fn api_error(msg: &str, status: StatusCode) -> (StatusCode, Json<dto::ErrorResponse>) {
    (status, Json(dto::ErrorResponse { error: msg.to_string() }))
}

pub(crate) fn jail_path(raw: &str) -> Result<std::path::PathBuf, String> {
    let p = StdPath::new(raw).canonicalize().map_err(|_| "file not found".to_string())?;
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?.canonicalize().map_err(|e| e.to_string())?;
    if p.starts_with(&cwd) || p.starts_with("/tmp") { Ok(p) } else { Err("path outside allowed dirs".to_string()) }
}
