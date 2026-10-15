use std::convert::Infallible;

use axum::{http::StatusCode, response::sse::{Event, KeepAlive, Sse}, Json};
use axum::response::IntoResponse;
use serde_json::json;

use crate::error::{api_error, jail_path};

pub(crate) async fn apply_interpretation(
    Json(body): Json<serde_json::Value>
) -> Result<Json<serde_json::Value>, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    let framing_str = body["framing"]["type"].as_str().unwrap_or("fixed");
    let framing_size = body["framing"]["size"].as_u64().unwrap_or(12) as usize;
    let framing_rule = match framing_str {
        "length_prefixed" => protocol_lab_core::interpreter::FramingRule::LengthPrefixed,
        _ => protocol_lab_core::interpreter::FramingRule::FixedSize(framing_size),
    };
    let file_path = body["file_path"].as_str().or_else(|| body["filePath"].as_str()).unwrap_or("no_file.pcap");
    let session_idx: usize = body["session_id"].as_u64().or_else(|| body["sessionId"].as_u64()).unwrap_or(0) as usize;
    let _offset: usize = body["offset"].as_u64().unwrap_or(0) as usize;

    let rule_name = body["rule"]["name"].as_str().unwrap_or("unknown");
    let rule_type_str = body["rule"]["type"].as_str().unwrap_or("u8");
    let rule_offset = body["rule"]["offset"].as_u64().unwrap_or(0) as usize;
    let field_type = match rule_type_str {
        "u16_big" => protocol_lab_core::interpreter::FieldType::U16Big,
        _ => protocol_lab_core::interpreter::FieldType::U8,
    };

    let rule = protocol_lab_core::interpreter::InterpretationRule {
        name: rule_name.to_string(),
        offset: rule_offset,
        field_type,
    };

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
    if session_idx >= sessions.len() {
        return Err(api_error("Session not found", StatusCode::NOT_FOUND));
    }
    let session = &sessions[session_idx];

    let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session);
    let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);
    let mut gap_offsets: Vec<usize> = Vec::new();

    let mut clean_bytes: Vec<u8> = Vec::new();
    for chunk in &chunks {
        match chunk {
            protocol_lab_core::tcp::stream::StreamChunk::Data { packet_index, ..} => {
                if let Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                    clean_bytes.extend_from_slice(&pkt.payload);
                } 
            }
            protocol_lab_core::tcp::stream::StreamChunk::Gap { flow_offset, .. } => {
                gap_offsets.push(*flow_offset);
            }
            _ => {} //игнорируем анонимных
        }
    }
    
    //режем поток на сообщ по законам Шариата(Framing_Rule)
    let messages = protocol_lab_core::interpreter::frame_stream(&clean_bytes, &framing_rule);
    let results: Vec<serde_json::Value> = messages.into_iter().map(|msg|{  //проходим по сообщению (1...8(развернуть на 90 градусов) аят) отсекаем  неверных
        let is_after_gap = gap_offsets.iter().any(|&gap_off| msg.stream_offset >= gap_off);
        if is_after_gap { //сообщение после дырки
            return json!({
                "stream_offset": msg.stream_offset,
                "success": false,
                "error": "Data after TCP Gap (unreliable)",
                "type": "incomplete"
            });
        }
        match protocol_lab_core::interpreter::apply_rule(&msg.payload, &rule) { //пробуем применять правила 
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
    Ok(Json(json!({
        "total_messages": results.len(),
        "results": results
    })))
}

//дал-дал ушел()
pub(crate) async fn verify_corpus(
    Json(body): Json<serde_json::Value>
) -> impl IntoResponse {

    let files = match body["files"].as_array() { //пирсинг файлов входных
        Some(arr) => arr.clone(),
        None => return api_error("files array required", StatusCode::BAD_REQUEST).into_response(),
    };
    
    if files.len() > 8 {
        return api_error("too many files", StatusCode::BAD_REQUEST).into_response();
    }
    
    let framing_str = body["framing"]["type"].as_str().unwrap_or("fixed");
    let framing_size = body["framing"]["size"].as_u64().unwrap_or(12) as usize;
    let rule_name = body["rule"]["name"].as_str().unwrap_or("unknown");
    let rule_type_str = body["rule"]["type"].as_str().unwrap_or("u8");
    let rule_offset = body["rule"]["offset"].as_u64().unwrap_or(0) as usize;
    let expected_value = body["expected_value"].as_str().or_else(|| body["expectedValue"].as_str()).map(|s| s.to_string());

    let journal_path = body["journal_path"].as_str().or_else(|| body["journalPath"].as_str()).map(|s| s.to_string());
    let mut journal_entries: Vec<serde_json::Value> = Vec::new();
    if let Some(j_path) = journal_path {
        if let Some(mut rdr) = jail_path(&j_path).ok().and_then(|jp| csv::Reader::from_path(&jp).ok()) {
            for result in rdr.deserialize() {
                if let Ok(record) = result {
                    journal_entries.push(record);
                }
            }
        }
    }

    let framing_rule = match framing_str {  //правила 
        "length_prefixed" => protocol_lab_core::interpreter::FramingRule::LengthPrefixed,
        _ => protocol_lab_core::interpreter::FramingRule::FixedSize(framing_size),
    };
    
    let field_type = match rule_type_str {
        "u16_big" => protocol_lab_core::interpreter::FieldType::U16Big,
        _ => protocol_lab_core::interpreter::FieldType::U8,
    };

    let rule = protocol_lab_core::interpreter::InterpretationRule {
        name: rule_name.to_string(),
        offset: rule_offset,
        field_type,
    };


    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<Event, Infallible>>(); //готовим канал для стрима


    tokio::spawn(async move { //асинхронное фоновое выполнееи
        let mut total_messages = 0;
        let mut success_count = 0;
        let mut error_count = 0;
        let mut counterexamples = Vec::new();

        let total_files = files.len();

        for (file_idx, file_val) in files.iter().enumerate() {
            let file_path = match file_val.as_str() {
                Some(p) => p.to_string(),
                None => continue,
            };


            let _ = tx.send(Ok(Event::default().data(&format!("Обработка файла {}/{}: {}", file_idx + 1, total_files, file_path)))); // отправка события типо что началась обработка файла

            let path = match jail_path(&file_path) {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx.send(Ok(Event::default().data(&format!("Ошибка пути {}: {}", file_path, e))));
                    continue;
                }
            };
            let packets = match protocol_lab_core::pcap::reader::read_pcap(&path) {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx.send(Ok(Event::default().data(&format!("Ошибка чтения {}: {}", file_path, e))));
                    continue;
                }
            };

            let sessions = protocol_lab_core::pcap::session::group_into_sessions(&packets);
            let total_sessions = sessions.len();

            for (session_idx, session) in sessions.iter().enumerate() {
                
                let _ = tx.send(Ok(Event::default().data(&format!("  Сессия {}/{}...", session_idx + 1, total_sessions)))); //

                let (flow_c2s, _) = protocol_lab_core::pcap::session::split_into_flows(session);
                let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow_c2s.packets);

                let mut clean_bytes: Vec<u8> = Vec::new();
                let mut gap_offsets: Vec<usize> = Vec::new();

                for chunk in &chunks {
                    match chunk {
                        protocol_lab_core::tcp::stream::StreamChunk::Data { packet_index, .. } => {
                            if let Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                                clean_bytes.extend_from_slice(&pkt.payload);
                            }
                        }
                        protocol_lab_core::tcp::stream::StreamChunk::Gap { flow_offset, .. } => {
                            gap_offsets.push(*flow_offset);
                        }
                        _ => {}
                    }
                }

                let messages = protocol_lab_core::interpreter::frame_stream(&clean_bytes, &framing_rule);

                for msg in messages {
                    total_messages += 1;

                    let is_after_gap = gap_offsets.iter().any(|&gap_off| msg.stream_offset >= gap_off);
                    if is_after_gap {
                        counterexamples.push(json!({
                            "file": file_path, 
                            "session": session_idx, 
                            "stream_offset": msg.stream_offset,
                            "error": "Data after TCP Gap", 
                            "type": "incomplete"
                        }));
                        continue;
                    }

                    match protocol_lab_core::interpreter::apply_rule(&msg.payload, &rule) {
                        Some(parsed) => {
                            success_count += 1;
                            if let Some(ref expected) = expected_value {
                                if parsed["value"] != *expected {
                                    counterexamples.push(json!({
                                        "file": file_path, 
                                        "session": session_idx, 
                                        "stream_offset": msg.stream_offset,
                                        "expected": expected, 
                                        "actual": parsed["value"], 
                                        "type": "value_mismatch"
                                    }));
                                }
                            }
                        }
                        None => {
                            error_count += 1;
                            counterexamples.push(json!({
                                "file": file_path, 
                                "session": session_idx, 
                                "stream_offset": msg.stream_offset,
                                "error": "Not enough bytes", 
                                "type": "parse_error"
                            }));
                        }
                    }
                }
            }
        }

        // 4. Отправляем финальный результат
        let final_result = json!({
            "type": "done",
            "total_messages": total_messages,
            "success_count": success_count,
            "error_count": error_count,
            "counterexamples": counterexamples,
            "journal": journal_entries
        });
        let _ = tx.send(Ok(Event::default().data(&final_result.to_string())));
    });

    // 5. Возвращаем SSE стрим
    Sse::new(tokio_stream::wrappers::UnboundedReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}
