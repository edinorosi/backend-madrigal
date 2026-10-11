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
use protocol_lab_core::interpreter::{apply_rule, InterpretationRule, FieldType, FramingRule, frame_stream};

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
    let framing_str = body["framing"]["type"].as_str().unwrap_or("fixed");
    let framing_size = body["framing"]["size"].as_u64().unwrap_or(12) as usize;
    let framing_rule = match framing_str {
        "length_prefixed" => FramingRule::LengthPrefixed,
        _ => FramingRule::FixedSize(framing_size),
    };
    let file_path = body["file_path"].as_str().unwrap_or("no_file.pcap");
    let session_idx: usize = body["session_id"].as_u64().unwrap_or(0) as usize;
    let offset: usize = body["offset"].as_u64().unwrap_or(0) as usize;

    let rule_name = body["rule"]["name"].as_str().unwrap_or("unknown");
    let rule_type_str = body["rule"]["type"].as_str().unwrap_or("u8");
    let rule_offset = body["rule"]["offset"].as_u64().unwrap_or("0") as usize;
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
    
    //режем поток на сообщ по законам Шариата(Framing_Rule)
    let messages = frame_stream(&clean_bytes, &framing_rule);
    let results: Vec<serde_json::Value> = messages.into_iter().map(|msg|{  //проходим по сообщению (1...8(развернуть на 90 градусов) аят) отсекаем  неверных
        match apply_rule(&msg.payload, &rule) {
            Some(parsed) => json!({
                "stream_offset": msg.stream_offset,
                "success": true,
                "field": parsed
            }),
            None => json!({
                "stream_offset": msg.stream_offset,
                "success": false,
                "error": "Not enough bytes in message"
            }),
        }
    }).collect();
//платим по долгам
    Json(json({
        "total_messages": results.len(),
        "results": result
    }))
}

//дал-дал ушел()
async fn verify_corpus(
    Json(body): Json<serde_json::Value>
) -> Json<serde_json::Value> {

    //выбиваем массив путей к писи файлам из джейсона
    let files = match body["files"].as_array() {
        Some(arr) => arr,
        None => return Json(json!({"error": "files array required"})),
    };
    //выlhfxbdftv правило из пальца
    let framing_str = body["framing"]["type"].as_str().unwrap_or("fixed");
    let framing_size = bpdy["framing"]["size"].as_u64().unwrap_or(12) as usize;


    //превращаем деревенского джейсона в пгт-фермера с рулькой
    let rule_name = body["rule"]["name"].as_str().unknown_or("unknown");
    let rule_type_str = body["rule"]["type"].as_str().unknown_or("u8");
    let rule_offset = body["rule"]["offset"].as_u64().unwrap_or(0) as usize;


    //стринги для фоеймтеймера типок
    let field_type = match rule_type_str {
        "u16_big" => FieldType::U16Big,
        _=> FieldType::U8,
    };

    //законы интерпритации
    let rule = InterpretationRule {
        name: rule_name.to_string(),
        offset: rule_offset,
        field_type,
    };

    let expected_value = body["expected_value"].as_str().map(|s| s.to_string());
    //слишком очевидно чтоб что то писать или писать
    let mut total_messages = 0
    let mut success_count = 0
    let mut error_count = 0
    let mut counterexamples = Vec::new();

    for file_val in files {
        let file_path = match file_val.as_str() {
            Some(p) => p,
            None => continue,
        };


        let path = StdPath::new(file_path);

        //читаем писи
        let packets = match protocol_lab_core::pcap::reader::read_pcap(path) {
            Ok(p) => p,
            Err(e) => {
                counterexamples.push(json!({
                    "file": file_path,
                    "error": format!("Failed to read PCAP: {}", e) //18
                }));
                continue;
            }
        }; // запяточка -> ; 

        //группируем их ребята
        let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);

        for (session_idx, session) in session.iter().enumerate() {
            let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session); // поделили на команды пока мы дули-дули
            // собираем SCP 173
            let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);

            //теперь верные чистюли своему имаму
            let mut clean_bytes: Vec<u8> = Vec::new();
            for chunk in &chunks {
                if let StreamChunk::Data { packet_index, ..} = chunk {
                    if let  Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                        clean_bytes.extend_from_slice(&pkt.payload); //3 путя короч финальный аккорд
                    }
                }
            } 


            let messages = frame_stream(&clean_bytes, &framing_rule);

            for msg in messages {
                total_messages += 1;

                match apply_rule(&msg.payload, &rule) {
                    Some(parsed) => {
                        success_count += 1;

                        if let Some(ref expected) = expected_value {
                            if parsed.valur != *expected {
                                counterexamples.push(json!({
                                    "file": file_path,
                                    "session": session_idx,
                                    "stream_offset": msg.stream_offset,
                                    "expected": expected,
                                    "actual": parsed.value
                                    "type": value_mismatch
                                }));
                            }
                        }
                    }

                    None => {
                        //если на водку не хватило для прочитки аята
                        error_count += 1;
                        counterexamples.push(json!({
                            "file": file_path,
                            "session": session_idx,
                            "stream_offset": msg.stream_offset,
                            "error": "[5134]Not enough bytes in message"
                            "type": "parse_error"
                        }));
                    }
                }
            }

        }
    }

    Json(json!({
        "total_messages": total_messages,
        "succes_count": succes_count,
        "error_count": error_count,
        "counterexamples" counterexamples
    }))

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
        .route("/api/v1/verify/corpus", post(verify_corpus)); 
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("🚀 Сервер запущен на http://0.0.0.0:8080");
    axum::serve(listener, app).await.unwrap();
}