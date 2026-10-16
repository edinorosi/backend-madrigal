use axum::{extract::State, http::StatusCode, Json};
use serde_json::json;

use crate::error::{api_error, jail_path};
use crate::state::AppState;

pub(crate) async fn analyze_autosuggest(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>
) -> Result<Json<serde_json::Value>, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    let file_path = body["file_path"].as_str().or_else(|| body["filePath"].as_str()).unwrap_or("no_file.pcap");
    suggest_for_file(&state.patterns_dir, file_path).map(Json)
}

/// Гипотезы разбора без axum-обёрток — переиспользуется MCP-инструментом.
pub(crate) fn suggest_for_file(
    patterns_dir: &std::path::Path,
    file_path: &str,
) -> Result<serde_json::Value, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    let path = match jail_path(file_path) {
        Ok(p) => p,
        Err(e) if e == "file not found" => return Err(api_error(&e, StatusCode::NOT_FOUND)),
        Err(e) => return Err(api_error(&e, StatusCode::FORBIDDEN)),
    };
    let packets = match protocol_lab_core::pcap::reader::read_pcap(&path) {
        Ok(p) => p,
        Err(e) => return Err(api_error(&e.to_string(), StatusCode::BAD_REQUEST)),
    };

    let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);
    if sessions.is_empty() {
        return Err(api_error("No sessions found", StatusCode::NOT_FOUND));
    }

    // все сессии подряд (раньше была только sessions[0]): c2s-потоки клеим,
    // чтобы гипотезы строились по всей записи, а не по первому соединению
    let mut clean_bytes: Vec<u8> = Vec::new();
    let mut sessions_used = 0usize;
    for session in &sessions {
        let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session);
        let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);
        let mut session_bytes = 0usize;
        for chunk in &chunks {
            if let protocol_lab_core::tcp::stream::StreamChunk::Data { packet_index, .. } = chunk {
                if let Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                    clean_bytes.extend_from_slice(&pkt.payload); //пакистан родненький, привет
                    session_bytes += pkt.payload.len();
                }
            }
        }
        if session_bytes > 0 {
            sessions_used += 1;
        }
    }

    if clean_bytes.len() < 10 {
        return Ok(json!({"hypotheses": [], "message": "Недостаточно данных для анализа"}));
    }

    let registry = protocol_lab_core::patterns::load_registry(patterns_dir);
    let mut hypotheses: Vec<serde_json::Value> = protocol_lab_core::patterns::run_all(&registry, &clean_bytes)
        .into_iter()
        .map(|f| {
            json!({
                "type": f.ftype,
                "confidence": f.confidence,
                "reason": f.reason,
                "suggested_framing": f.framing,
                "pattern_id": f.pattern_id,
            })
        })
        .collect();

    hypotheses.sort_by(|a, b| {
        b["confidence"].as_f64().unwrap_or(0.0)
            .partial_cmp(&a["confidence"].as_f64().unwrap_or(0.0))
            .unwrap()
    });

    Ok(json!({
        "file": file_path,
        "total_bytes_analyzed": clean_bytes.len(),
        "sessions_analyzed": sessions_used,
        "hypotheses": hypotheses
    }))
}
