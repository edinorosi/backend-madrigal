use std::path::Path as StdPath;

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

    let mut hypotheses = Vec::new(); //гипотезы

    for size in [4, 8, 12, 16, 24, 32, 64, 128] {
        if clean_bytes.len() % size == 0 && (clean_bytes.len() / size) >= 3 {
            
            hypotheses.push(json!({
                "type": "fixed_size",
                "confidence": 0.85,
                "reason": format!("Длина потока ({}) идеально делится на {}. Найдено {} сообщений.", clean_bytes.len(), size, clean_bytes.len() / size),
                "suggested_framing": {"type": "fixed", "size": size}
            }));
            break;
        }
    }

    for prefix_bytes in [1,2] {
        let mut valid_count = 0;
        let mut total_checked = 0;
        let mut offset = 0;

        while offset + prefix_bytes <= clean_bytes.len() {
            let len = if prefix_bytes == 1 {
                clean_bytes[offset] as usize
            } else {
                u16::from_be_bytes([clean_bytes[offset], clean_bytes[offset+1]]) as usize
            };

            if len > 0 && len < 4096 && offset + prefix_bytes + len <= clean_bytes.len() {
                valid_count += 1;
                offset += prefix_bytes + len;
            } else {
                break;
            }
            total_checked += 1;
        }

        if total_checked >= 3 && (valid_count as f64 / total_checked as f64) > 0.7 {
            hypotheses.push(json!({
                "type": "length_prefixed",
                "confidence": 0.90,
                "reason": format!("Первые {} байта успешно интерпретируются как длина payload в {} сообщениях.", prefix_bytes, valid_count),
                "suggested_framing": {"type": "length_prefixed", "size_bytes": prefix_bytes}
            }));
            break;
        }
    }

    let sync_words = [[0xAA, 0x55], [0x55, 0xAA], [0xFF, 0x00], [0x00, 0xFF], [0x7E, 0x7E]];
    for &sync in &sync_words {
        let mut count = 0;
        for i in 0..clean_bytes.len().saturating_sub(1) {
            if clean_bytes[i] == sync[0] && clean_bytes[i+1] == sync[1] {
                count += 1;
            }
        }
        if count >= 3 {
            let sync_hex = format!("{:02X} {:02X}", sync[0], sync[1]);
            hypotheses.push(json!({
                "type": "sync_word",
                "confidence": 0.75,
                "reason": format!("Найден повторяющийся маркер {} {} раз(а). Возможно, это начало фрейма.", sync_hex, count),
                "suggested_framing": {"type": "sync_word", "sync": sync_hex}
            }));

        }
    }

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
