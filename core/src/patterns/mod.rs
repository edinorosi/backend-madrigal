use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Pattern {
    pub id: String,
    pub name: String,
    pub kind: String,
    /// Движок детектора: fixed-size | length-prefixed | sync-word.
    /// Пусто — legacy: движок выводится из `id` (три штатных id работают как раньше).
    pub detector: Option<String>,
    pub enabled: bool,
    pub params: Value,
    pub output: Value,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub pattern_id: String,
    pub ftype: String,
    pub confidence: f64,
    pub reason: String,
    pub framing: Value,
}

fn arr_u64(params: &Value, key: &str) -> Vec<u64> {
    params
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|n| n.as_u64()).collect())
        .unwrap_or_default()
}

fn num_u64(params: &Value, key: &str, default: u64) -> u64 {
    params.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
}

fn num_f64(params: &Value, key: &str, default: f64) -> f64 {
    params
        .get(key)
        .and_then(|v| v.as_f64())
        .unwrap_or(default)
}

fn str_list(params: &Value, key: &str) -> Vec<String> {
    params
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|n| n.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_hex_word(word: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = word
        .split_whitespace()
        .map(|t| u8::from_str_radix(t, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

fn validate(file_label: &str, value: &Value) -> Option<Pattern> {
    let id = match value.get("id")?.as_str() {
        Some(s) if !s.is_empty() => s,
        _ => {
            eprintln!("[patterns] пропуск {}: нужен непустой id", file_label);
            return None;
        }
    };
    let kind = match value.get("kind")?.as_str() {
        Some(s) if !s.is_empty() => s,
        _ => {
            eprintln!("[patterns] пропуск {}: нужен непустой kind", file_label);
            return None;
        }
    };
    let params = match value.get("params") {
        Some(p) if p.is_object() => p.clone(),
        _ => {
            eprintln!("[patterns] пропуск {}: нужен params-объект", file_label);
            return None;
        }
    };
    Some(Pattern {
        id: id.to_string(),
        name: value
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(id)
            .to_string(),
        kind: kind.to_string(),
        detector: value
            .get("detector")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        enabled: value
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        params,
        output: value.get("output").cloned().unwrap_or(Value::Null),
    })
}

pub fn load_registry(dir: &Path) -> Vec<Pattern> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if p.file_name().and_then(|s| s.to_str()) == Some("schema.json") {
                continue; // схема валидации, не паттерн
            }
            files.push(p);
        }
    }
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[patterns] пропуск {}: {}", path.display(), e);
                continue;
            }
        };
        let value: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[patterns] пропуск {}: {}", path.display(), e);
                continue;
            }
        };
        match validate(&path.display().to_string(), &value) {
            Some(p) => out.push(p),
            None => {}
        }
    }
    out
}

fn run_fixed(pattern: &Pattern, bytes: &[u8]) -> Option<Finding> {
    let sizes = arr_u64(&pattern.params, "sizes");
    let sizes: Vec<usize> = if sizes.is_empty() {
        vec![4, 8, 12, 16, 24, 32, 64, 128]
    } else {
        sizes.iter().map(|s| *s as usize).collect()
    };
    let min_messages = num_u64(&pattern.params, "min_messages", 3) as usize;
    let confidence = num_f64(&pattern.params, "confidence", 0.85);
    for size in sizes {
        if size == 0 {
            continue;
        }
        if bytes.len() % size == 0 && (bytes.len() / size) >= min_messages {
            return Some(Finding {
                pattern_id: pattern.id.clone(),
                ftype: "fixed_size".to_string(),
                confidence,
                reason: format!(
                    "Длина потока ({}) идеально делится на {}. Найдено {} сообщений.",
                    bytes.len(),
                    size,
                    bytes.len() / size
                ),
                framing: serde_json::json!({"type": "fixed", "size": size}),
            });
        }
    }
    None
}

fn run_length_prefixed(pattern: &Pattern, bytes: &[u8]) -> Option<Finding> {
    let prefixes = arr_u64(&pattern.params, "prefix_bytes");
    let prefixes: Vec<usize> = if prefixes.is_empty() {
        vec![1, 2]
    } else {
        prefixes.iter().map(|p| *p as usize).collect()
    };
    let max_len = num_u64(&pattern.params, "max_len", 4096) as usize;
    let min_messages = num_u64(&pattern.params, "min_messages", 3) as usize;
    let min_rate = num_f64(&pattern.params, "min_rate", 0.7);
    let confidence = num_f64(&pattern.params, "confidence", 0.9);
    for prefix_bytes in prefixes {
        if prefix_bytes == 0 || prefix_bytes > 2 {
            continue;
        }
        let mut valid_count = 0usize;
        let mut total_checked = 0usize;
        let mut offset = 0usize;
        while offset + prefix_bytes <= bytes.len() {
            let len = if prefix_bytes == 1 {
                bytes[offset] as usize
            } else {
                u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize
            };
            if len > 0 && len < max_len && offset + prefix_bytes + len <= bytes.len() {
                valid_count += 1;
                offset += prefix_bytes + len;
            } else {
                break;
            }
            total_checked += 1;
        }
        if total_checked >= min_messages
            && (valid_count as f64 / total_checked as f64) > min_rate
        {
            return Some(Finding {
                pattern_id: pattern.id.clone(),
                ftype: "length_prefixed".to_string(),
                confidence,
                reason: format!(
                    "Первые {} байта успешно интерпретируются как длина payload в {} сообщениях.",
                    prefix_bytes, valid_count
                ),
                framing: serde_json::json!({"type": "length_prefixed", "size_bytes": prefix_bytes}),
            });
        }
    }
    None
}

fn run_sync_word(pattern: &Pattern, bytes: &[u8]) -> Vec<Finding> {
    let mut words = str_list(&pattern.params, "words");
    if words.is_empty() {
        words = vec![
            "AA 55".to_string(),
            "55 AA".to_string(),
            "FF 00".to_string(),
            "00 FF".to_string(),
            "7E 7E".to_string(),
        ];
    }
    let min_count = num_u64(&pattern.params, "min_count", 3) as usize;
    let confidence = num_f64(&pattern.params, "confidence", 0.75);
    let mut out = Vec::new();
    for word in words {
        let sync = match parse_hex_word(&word) {
            Some(b) => b,
            None => continue,
        };
        if sync.len() > bytes.len() {
            continue;
        }
        let mut count = 0usize;
        for i in 0..bytes.len().saturating_sub(sync.len() - 1) {
            if bytes[i..].starts_with(&sync) {
                count += 1;
            }
        }
        if count >= min_count {
            let sync_hex = sync
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            out.push(Finding {
                pattern_id: pattern.id.clone(),
                ftype: "sync_word".to_string(),
                confidence,
                reason: format!(
                    "Найден повторяющийся маркер {} {} раз(а). Возможно, это начало фрейма.",
                    sync_hex, count
                ),
                framing: serde_json::json!({"type": "sync_word", "sync": sync_hex}),
            });
        }
    }
    out
}

/// Движок паттерна: поле `detector`, иначе legacy-совпадение по `id`.
/// Пустая строка — неизвестный движок, паттерн пропускается с варнингом.
fn engine_of(pattern: &Pattern) -> &str {
    if let Some(d) = pattern.detector.as_deref() {
        return d;
    }
    match pattern.id.as_str() {
        "fixed-size" | "length-prefixed" | "sync-word" => pattern.id.as_str(),
        _ => "",
    }
}

pub fn run_all(patterns: &[Pattern], bytes: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    for pattern in patterns.iter().filter(|p| p.enabled) {
        match engine_of(pattern) {
            "fixed-size" => {
                if let Some(f) = run_fixed(pattern, bytes) {
                    out.push(f);
                }
            }
            "length-prefixed" => {
                if let Some(f) = run_length_prefixed(pattern, bytes) {
                    out.push(f);
                }
            }
            "sync-word" => out.extend(run_sync_word(pattern, bytes)),
            other => eprintln!(
                "[patterns] неизвестный движок {:?} (id={:?}), пропуск",
                other, pattern.id
            ),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(id: &str, params: Value) -> Pattern {
        Pattern {
            id: id.to_string(),
            name: id.to_string(),
            kind: "framing".to_string(),
            detector: None,
            enabled: true,
            params,
            output: Value::Null,
        }
    }

    fn pattern_with_detector(id: &str, detector: &str, params: Value) -> Pattern {
        let mut p = pattern(id, params);
        p.detector = Some(detector.to_string());
        p
    }

    #[test]
    fn fixed_size_from_params() {
        let p = pattern("fixed-size", serde_json::json!({"sizes": [8], "min_messages": 3, "confidence": 0.5}));
        let f = run_fixed(&p, &[0u8; 24]).unwrap();
        assert_eq!(f.confidence, 0.5);
        assert_eq!(f.framing["size"], 8);
        assert!(run_fixed(&p, &[0u8; 20]).is_none());
    }

    #[test]
    fn length_prefixed_from_params() {
        let p = pattern(
            "length-prefixed",
            serde_json::json!({"prefix_bytes": [1], "max_len": 4096, "min_messages": 2, "min_rate": 0.5, "confidence": 0.9}),
        );
        let bytes = [3u8, 10, 20, 30, 2, 40, 50];
        let f = run_length_prefixed(&p, &bytes).unwrap();
        assert_eq!(f.framing["size_bytes"], 1);
    }

    #[test]
    fn sync_word_from_params() {
        let p = pattern(
            "sync-word",
            serde_json::json!({"words": ["AA 55"], "min_count": 2, "confidence": 0.7}),
        );
        let bytes = [0xAA, 0x55, 0x01, 0xAA, 0x55, 0x02];
        let found = run_sync_word(&p, &bytes);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].framing["sync"], "AA 55");
    }

    #[test]
    fn invalid_registry_entries_skipped() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("protocol_lab_patterns_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ok.json"), r#"{"id":"fixed-size","kind":"framing","params":{"sizes":[8]}}"#).unwrap();
        std::fs::write(dir.join("bad.json"), r#"{"id": 123"#).unwrap();
        std::fs::write(dir.join("noid.json"), r#"{"kind":"framing","params":{}}"#).unwrap();
        std::fs::write(dir.join("txt.txt"), "hello").unwrap();
        let loaded = load_registry(&dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "fixed-size");
        assert!(loaded[0].enabled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_patterns_skipped() {
        let mut p = pattern("fixed-size", serde_json::json!({"sizes": [8]}));
        p.enabled = false;
        assert!(run_all(&[p], &[0u8; 24]).is_empty());
    }

    #[test]
    fn detector_field_routes_custom_id() {
        // свой id + detector: новый файл без правки кода заводится
        let p = pattern_with_detector(
            "my-sizes",
            "fixed-size",
            serde_json::json!({"sizes": [8], "min_messages": 3}),
        );
        let found = run_all(&[p], &[0u8; 24]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pattern_id, "my-sizes");
    }

    #[test]
    fn legacy_id_still_routes_without_detector() {
        // без detector: три штатных id работают как раньше
        let p = pattern("sync-word", serde_json::json!({"words": ["AA 55"], "min_count": 1}));
        assert_eq!(engine_of(&p), "sync-word");
        let found = run_all(&[p], &[0xAA, 0x55, 0x01]);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn unknown_detector_skipped() {
        let p = pattern_with_detector("weird", "nope-engine", serde_json::json!({}));
        assert!(run_all(&[p], &[0u8; 24]).is_empty());
    }

    #[test]
    fn validate_reads_detector() {
        let v: Value = serde_json::from_str(
            r#"{"id":"custom","kind":"framing","detector":"fixed-size","params":{"sizes":[4]}}"#,
        )
        .unwrap();
        let p = validate("custom.json", &v).unwrap();
        assert_eq!(p.detector.as_deref(), Some("fixed-size"));
        assert!(validate("noid.json", &serde_json::json!({"kind":"framing","params":{}})).is_none());
    }
}
