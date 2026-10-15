use axum::Json;
use serde_json::json;

use crate::error::jail_path;

pub(crate) async fn analyze_autosuggest(
    Json(body): Json<serde_json::Value>
) -> Json<serde_json::Value> {
    let file_path = body["file_path"].as_str().unwrap_or("no_file.pcap");
    let path = match jail_path(file_path) { Ok(p) => p, Err(e) => return Json(json!({"error": e})) };

    let packets = match protocol_lab_core::pcap::reader::read_pcap(&path) {
        Ok(p) => p,
        Err(e) => return Json(json!({"error": e.to_string()})),
    };

    let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);
    if sessions.is_empty() {
        return Json(json!({"error": "No sessions found"}));
    }

    let session = &sessions[0];
    let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session);
    let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);

    let mut clean_bytes: Vec<u8> = Vec::new();
    for chunk in &chunks {
        if let protocol_lab_core::tcp::stream::StreamChunk::Data { packet_index, .. } = chunk {
            if let Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                clean_bytes.extend_from_slice(&pkt.payload); //пакистан родненький, привет
            }
        }
    }

    if clean_bytes.len() < 10 {
        return Json(json!({"hypotheses": [], "message": "Недостаточно данных для анализа"}));
    }

    let registry = protocol_lab_core::patterns::load_registry(std::path::Path::new("patterns"));
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

    Json(json!({
        "file": file_path,
        "total_bytes_analyzed": clean_bytes.len(),
        "hypotheses": hypotheses
    }))




}
