use axum::{extract::Path as AxumPath, Json};
use serde_json::json;

use crate::error::jail_path;

pub(crate) async fn get_flow_bytes(
    AxumPath(session_id): AxumPath<String>,
    Json(body): Json<serde_json::Value>
) -> Json<serde_json::Value> {

    //fkkf[ ,f,f[]]

    let file_path = body["file_path"].as_str().unwrap_or("no_file.pcap");
    let path = match jail_path(file_path) { Ok(p) => p, Err(e) => return Json(json!({"error": e})) };

    let packets = match protocol_lab_core::pcap::reader::read_pcap(&path) {
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
            protocol_lab_core::tcp::stream::StreamChunk::Data { flow_offset, length, packet_index } => {
                let hex_data = match session.packets.iter().find(|p| p.index == packet_index) {
                    Some(pkt) => pkt.payload.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
                    None => format!("ERR: global packet_index {} not found", packet_index),
                };
            
                json!({
                    "type": "data",
                    "offset": flow_offset,
                    "length": length,
                    "packet_index": packet_index,
                    "hex": hex_data
                })
            }
            protocol_lab_core::tcp::stream::StreamChunk::Gap { flow_offset, missing_bytes } => {
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
