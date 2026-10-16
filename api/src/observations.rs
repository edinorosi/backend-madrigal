use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    Json,
};

use crate::dto::Observation;
use crate::error::api_error;
use crate::state::{persist_global, AppState};

pub(crate) async fn save_observation(
    State(state): State<AppState>,
    Json(obs): Json<Observation>,
) -> StatusCode {
    state
        .observations
        .write()
        .unwrap()
        .insert(obs.id.clone(), obs);
    persist_global(&state);
    StatusCode::NO_CONTENT
}


pub(crate) async fn remove_observation(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    eprintln!("[observations] remove {id}");
    {
        let mut observations = state.observations.write().unwrap();
        if observations.remove(&id).is_none() {
            return Err(api_error("Observation not found", StatusCode::NOT_FOUND));
        }
        
        // прости Аллах за код выше
    }
    persist_global(&state);
    Ok(StatusCode::NO_CONTENT)
}
