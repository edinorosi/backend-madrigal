use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use crate::check::{load_actions, parse_iso};
use crate::dto::{Action, Model, ModelField, ModelRule, ModelRuleCondition};
use crate::error::{api_error, jail_path};
use crate::state::AppState;

struct Sample {
    bytes: Vec<u8>,
    ts_us: i64,
}

fn pick_framing(body: &Value) -> Option<protocol_lab_core::interpreter::FramingRule> {
    use protocol_lab_core::interpreter::FramingRule;
    match body.get("framing").and_then(|f| f.get("type")).and_then(|t| t.as_str()) {
        Some("fixed") => {
            let size = body.get("framing").and_then(|f| f.get("size")).and_then(|s| s.as_u64()).unwrap_or(0) as usize;
            if size == 0 {
                None
            } else {
                Some(FramingRule::FixedSize(size))
            }
        }
        Some("length_prefixed") => Some(FramingRule::LengthPrefixed),
        Some("length_prefixed_u16") => Some(FramingRule::LengthPrefixedU16Big),
        _ => None,
    }
}

fn reframe(
    session: &protocol_lab_core::pcap::types::Session,
    framing: &protocol_lab_core::interpreter::FramingRule,
) -> Vec<(Vec<u8>, i64)> {
    let (c2s, s2c) = protocol_lab_core::pcap::session::split_into_flows(session);
    let mut out = Vec::new();
    for flow in [&c2s, &s2c] {
        let chunks = protocol_lab_core::tcp::reassembler::TcpReassembler::reassemble(&flow.packets);
        let mut clean: Vec<u8> = Vec::new();
        let mut marks: Vec<(usize, i64)> = Vec::new();
        for chunk in &chunks {
            if let protocol_lab_core::tcp::stream::StreamChunk::Data { packet_index, .. } = chunk {
                if let Some(pkt) = session.packets.iter().find(|p| p.index == *packet_index) {
                    if !pkt.payload.is_empty() {
                        marks.push((clean.len(), pkt.timestamp_us as i64));
                        clean.extend_from_slice(&pkt.payload);
                    }
                }
            }
        }
        for msg in protocol_lab_core::interpreter::frame_stream(&clean, framing) {
            let mut ts = marks.first().map(|(_, t)| *t).unwrap_or(0);
            for (off, t) in &marks {
                if *off <= msg.stream_offset {
                    ts = *t;
                } else {
                    break;
                }
            }
            out.push((msg.payload, ts));
        }
    }
    out
}

fn label_frames(
    frames: &[(Vec<u8>, i64)],
    actions: &[(Action, Option<i64>, Option<i64>)],
) -> Vec<protocol_lab_core::infer::LabeledSample> {
    frames
        .iter()
        .map(|(bytes, ts)| {
            let mut expected = None;
            for (a, s, e) in actions {
                match (*s, *e) {
                    (Some(st), Some(en)) if *ts >= st && *ts <= en => {
                        expected = a.value;
                        break;
                    }
                    _ => {}
                }
            }
            if expected.is_none() {
                let mut best: Option<(f64, i64)> = None;
                for (a, s, e) in actions {
                    if let (Some(v), Some(anchor)) = (a.value, s.or(*e)) {
                        let dt = (*ts - anchor).abs();
                        if dt <= 60_000_000 && best.map(|(_, bdt)| dt < bdt).unwrap_or(true) {
                            best = Some((v, dt));
                        }
                    }
                }
                expected = best.map(|(v, _)| v);
            }
            protocol_lab_core::infer::LabeledSample { bytes: bytes.clone(), expected }
        })
        .collect()
}

pub(crate) async fn analyze_fields(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    infer_capture(&state, &body).await.map(Json)
}

/// Вывод модели из журнала без axum-обёрток — переиспользуется MCP-инструментом.
pub(crate) async fn infer_capture(
    state: &AppState,
    body: &Value,
) -> Result<Value, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    let capture_id = body
        .get("capture_id")
        .or_else(|| body.get("captureId"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let wanted_file = state
        .captures
        .read()
        .unwrap()
        .get(capture_id)
        .map(|c| c.file_name.clone())
        .unwrap_or_default();
    if wanted_file.is_empty() {
        return Err(api_error("Capture not found", StatusCode::NOT_FOUND));
    }
    let framing = pick_framing(&body);
    let framing_used = body
        .get("framing")
        .and_then(|f| f.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("per-packet")
        .to_string();
    let mut samples: Vec<Sample> = Vec::new();
    match framing {
        Some(ref rule) => {
            let src = format!("{}/source.pcap", crate::state::capture_dir_in(&state.data_dir, capture_id));
            let path = jail_path(&src).map_err(|e| api_error(&e, StatusCode::NOT_FOUND))?;
            let packets = protocol_lab_core::pcap::reader::read_pcap(&path)
                .map_err(|e| api_error(&format!("PCAP parse error: {}", e), StatusCode::BAD_REQUEST))?;
            for session in protocol_lab_core::pcap::session::group_into_sessions(&packets).iter() {
                for (bytes, ts) in reframe(session, rule) {
                    if !bytes.is_empty() {
                        samples.push(Sample { bytes, ts_us: ts });
                    }
                }
            }
        }
        None => {
            let sids: Vec<String> = state
                .sessions
                .read()
                .unwrap()
                .values()
                .filter(|s| s.capture_id == capture_id)
                .map(|s| s.id.clone())
                .collect();
            let msgs = state.messages.read().unwrap();
            for m in msgs.values().filter(|m| sids.contains(&m.session_id)) {
                let bytes = crate::models::message_bytes(state, m);
                if bytes.is_empty() {
                    continue;
                }
                if let Some(ts) = parse_iso(&m.timestamp) {
                    samples.push(Sample { bytes, ts_us: ts });
                }
            }
        }
    }
    let journal_raw = body
        .get("journal_path")
        .or_else(|| body.get("journalPath"))
        .and_then(|v| v.as_str())
        .unwrap_or("fixtures/action_journal.csv");
    let journal = match crate::error::jail_path(journal_raw) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => return Err(api_error(&e, StatusCode::BAD_REQUEST)),
    };
    let actions = load_actions(&wanted_file, &journal);
    let frames: Vec<(Vec<u8>, i64)> = samples.iter().map(|s| (s.bytes.clone(), s.ts_us)).collect();
    let labeled = label_frames(&frames, &actions);
    let labeled_count = labeled.iter().filter(|l| l.expected.is_some()).count();
    let proposals = protocol_lab_core::infer::infer_rules(&labeled);
    let now = chrono::Utc::now().to_rfc3339();
    let model_id = format!("infer-{}", uuid::Uuid::new_v4());
    let mut rules = Vec::new();
    let mut evidence = Vec::new();
    let mut order: Vec<usize> = (0..proposals.len()).collect();
    order.sort_by_key(|&i| (proposals[i].opcode.is_none() as u8, proposals[i].fields.is_empty() as u8, proposals[i].length));
    for idx in order {
        let p = &proposals[idx];
        let rid = format!("rule-{}", uuid::Uuid::new_v4());
        let name = match p.opcode {
            Some(o) => format!("opcode 0x{:02X} / len {}", o, p.length),
            None => format!("len {}", p.length),
        };
        if p.fields.is_empty() {
            evidence.push(json!({
                "rule_id": rid,
                "opcode": p.opcode,
                "msg_len": p.length,
                "samples": p.samples,
                "labeled": p.labeled,
                "fields": [],
                "skipped": "no confident fields — правило не создано, кластер виден здесь",
            }));
            continue;
        }
        rules.push(ModelRule {
            id: rid.clone(),
            name,
            condition: ModelRuleCondition {
                opcode: p.opcode,
                opcodes: None,
                length_equals: None,
                max_message_length: None,
                message_length: Some(p.length as u32),
                terms: None,
            },
            fields: p
                .fields
                .iter()
                .map(|f| ModelField {
                    name: f.name.clone(),
                    field_type: f.ftype.clone(),
                    offset: Value::from(f.offset as u64),
                    length: Value::from(f.length as u64),
                    note: Some(format!("{}/{}", f.matches, f.total)),
                })
                .collect(),
        });
        evidence.push(json!({
            "rule_id": rid,
            "opcode": p.opcode,
            "msg_len": p.length,
            "samples": p.samples,
            "labeled": p.labeled,
            "fields": p.fields.iter().map(|f| json!({
                "name": f.name, "offset": f.offset, "length": f.length,
                "type": f.ftype, "matches": f.matches, "total": f.total,
            })).collect::<Vec<_>>(),
        }));
    }
    let model = Model {
        id: model_id,
        name: format!("auto {}", wanted_file),
        status: "draft".to_string(),
        rules,
        created_at: now.clone(),
        updated_at: now,
    };
    Ok(json!({
        "model": model,
        "evidence": evidence,
        "framing_used": framing_used,
        "samples": samples.len(),
        "labeled": labeled_count,
        "clusters": proposals.len(),
    }))
}
