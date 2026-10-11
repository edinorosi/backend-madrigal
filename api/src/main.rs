use axum::{
    routing::post,
    Router,
    Json,
    extract::Path as AxumPath,
};
use serde_json::json;
use uuid::Uuid;
use std::path::Path as StdPath;
use protocol_lab_core::tcp::stream::StreamChunk;
use protocol_lab_core::interpreter::{apply_rule, InterpretationRule, FieldType};

async fn get_flow_bytes(
    AxumPath(session_id): AxumPath<String>,
    Json(body): Json<serde_json::Value>
) -> Json<serde_json::Value> {

    //fkkf[ ,f,f[]]

    let file_path = body["file_path"].as_str().unwrap_or("no_file.pcap");
    let path = StdPath::new(file_path);

    let packets = match protocol_lab_core::pcap::reader::read_pcap(path) {
        Ok(p) => p,
        Err(e) => return Json(json!({"error": e.to_string()})),
    };

    let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);
    let idx: usize = session_id.parse().unwrap_or(0);
    
    if idx >= sessions.len() {
        return Json(json!({"error": "Session not found"}));
    }
    let session = &sessions[idx];

    let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session);
    let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);

    let result: Vec<serde_json::Value> = chunks.into_iter().map(|chunk| {
        match chunk {
            StreamChunk::Data { flow_offset, lenght, packet_index } => {
                let hex_data = match session.packets.iter().find(|p| p.index == packet_index) {
                    Some(pkt) => pkt.payload.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
                    None => format!("ERR: global packet_index {} not found", packet_index),
                };
            
                json!({
                    "type": "data",
                    "offset": flow_offset,
                    "length": lenght,
                    "packet_index": packet_index,
                    "hex": hex_data
                })
            }
            StreamChunk::Gap { flow_offset, missing_bytes } => {
                json!({
                    "type": "gap",
                    "offset": flow_offset,
                    "missing_bytes": missing_bytes
                })
            }
            _ => json!({"type": "unknown"})
        }
    }).collect();

    Json(json!({"flow": "client_to_server", "chunks": result}))
}

async fn apply_interpretation(
    Json(body): Json<serde_json::Value>
) -> Json<serde_json::Value> {
    let file_path = body["file_path"].as_str().unwrap_or("no_file.pcap");
    let session_idx: usize = body["session_id"].as_u64().unwrap_or(0) as usize;
    let offset: usize = body["offset"].as_u64().unwrap_or(0) as usize;

    let rule_name = body["rule"]["name"].as_str().unwrap_or("unknown");
    let rule_type_str = body["rule"]["type"].as_str().unwrap_or("u8");

    let field_type = match rule_type_str {
        "u16_big" => FieldType::U16Big,
        _ => FieldType::U8,
    };

    let rule = InterpretationRule {
        name: rule_name.to_string(),
        offset: 0,
        field_type,
    };

    let path = StdPath::new(file_path);
    let packets = match protocol_lab_core::pcap::reader::read_pcap(path) {
        Ok(p) => p,
        Err(e) => return Json(json!({"error": e.to_string()})),
    };

    let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);
    if session_idx >= sessions.len() {
        return Json(json!({"error": "Session not found"}));
    }
    let session = &sessions[session_idx];

    let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session);
    let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);

    let mut clean_bytes: Vec<u8> = Vec::new();
    for chunk in &chunks {
        if let StreamChunk::Data { packet_index, .. } = chunk {
            if let Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                clean_bytes.extend_from_slice(&pkt.payload);
            }
        }
    }
    
    if offset >= clean_bytes.len() {
        return Json(json!({"error": "Offset out of bounds"}));
    }

    let data_slice = &clean_bytes[offset..];
    match apply_rule(data_slice, &rule) {
        Some(parsed) => Json(json!({"success": true, "field": parsed})),
        None => Json(json!({"success": false, "error": "Not enough bytes"})),
    }
}

async fn create_project() -> Json<serde_json::Value> {
    let id = Uuid::new_v4().to_string();
    Json(json!({ "id": id, "status": "created" }))
}

async fn upload_capture(
    AxumPath(id): AxumPath<String>,
    Json(body): Json<serde_json::Value>
) -> Json<serde_json::Value> {
    let file_path = body["file_path"].as_str().unwrap_or("no_file.pcap");
    let path = StdPath::new(file_path);

    match protocol_lab_core::pcap::reader::read_pcap(path) {
        Ok(packets) => {
            let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);
            Json(json!({ 
                "project_id": id, 
                "packets_found": packets.len(),
                "sessions_found": sessions.len() 
            }))
        }
        Err(e) => Json(json!({ "error": e.to_string() }))
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/v1/projects", post(create_project))
        .route("/api/v1/projects/:id/captures", post(upload_capture))
        .route("/api/v1/flows/:session_id/bytes", post(get_flow_bytes))
        .route("/api/v1/interpret/apply", post(apply_interpretation));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 Сервер запущен на http://0.0.0.0:8080");
    axum::serve(listener, app).await.unwrap();
}