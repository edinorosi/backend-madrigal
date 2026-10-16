/// Канонический реестр типов полей модели.
///
/// Один источник правды для бэкенда: `models.rs` (разбор и проверка),
/// `codegen.rs` (генерация декодеров) и валидация `save_model`.
/// Фронтовое зеркало — `frontend/edinoros/src/lib/field-types.ts`;
/// при изменении списка править оба и текст `MODEL_HELP.fieldType.
pub(crate) struct FieldTypeInfo {
    pub id: &'static str,
    /// Фиксированный размер в байтах; None — переменный (string/bytes/hex).
    pub size: Option<usize>,
    pub signed: bool,
    /// Участвует ли в числовом сравнении (check first_numeric, decode).
    pub numeric: bool,
}

pub(crate) const FIELD_TYPES: &[FieldTypeInfo] = &[
    FieldTypeInfo { id: "uint8", size: Some(1), signed: false, numeric: true },
    FieldTypeInfo { id: "int8", size: Some(1), signed: true, numeric: true },
    FieldTypeInfo { id: "uint16be", size: Some(2), signed: false, numeric: true },
    FieldTypeInfo { id: "uint16le", size: Some(2), signed: false, numeric: true },
    FieldTypeInfo { id: "int16be", size: Some(2), signed: true, numeric: true },
    FieldTypeInfo { id: "int16le", size: Some(2), signed: true, numeric: true },
    FieldTypeInfo { id: "uint32be", size: Some(4), signed: false, numeric: true },
    FieldTypeInfo { id: "uint32le", size: Some(4), signed: false, numeric: true },
    FieldTypeInfo { id: "int32be", size: Some(4), signed: true, numeric: true },
    FieldTypeInfo { id: "int32le", size: Some(4), signed: true, numeric: true },
    FieldTypeInfo { id: "string", size: None, signed: false, numeric: false },
    FieldTypeInfo { id: "bytes", size: None, signed: false, numeric: false },
    FieldTypeInfo { id: "hex", size: None, signed: false, numeric: false },
];

pub(crate) fn is_known_type(ftype: &str) -> bool {
    FIELD_TYPES.iter().any(|t| t.id == ftype)
}

pub(crate) fn known_types_list() -> String {
    FIELD_TYPES.iter().map(|t| t.id).collect::<Vec<_>>().join(", ")
}

pub(crate) fn decode_number(bytes: &[u8], ftype: &str) -> Option<f64> {
    match ftype {
        "uint8" => bytes.first().map(|b| *b as f64),
        "int8" => bytes.first().map(|b| (*b as i8) as f64),
        "uint16be" => (bytes.len() >= 2).then(|| u16::from_be_bytes([bytes[0], bytes[1]]) as f64),
        "uint16le" => (bytes.len() >= 2).then(|| u16::from_le_bytes([bytes[0], bytes[1]]) as f64),
        "int16be" => (bytes.len() >= 2).then(|| i16::from_be_bytes([bytes[0], bytes[1]]) as f64),
        "int16le" => (bytes.len() >= 2).then(|| i16::from_le_bytes([bytes[0], bytes[1]]) as f64),
        "uint32be" => (bytes.len() >= 4).then(|| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64),
        "uint32le" => (bytes.len() >= 4).then(|| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64),
        "int32be" => (bytes.len() >= 4).then(|| i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64),
        "int32le" => (bytes.len() >= 4).then(|| i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64),
        _ => None,
    }
}

fn hex_u32(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

pub(crate) fn format_field_value(bytes: &[u8], ftype: &str) -> String {
    match ftype {
        "uint8" => {
            if bytes.is_empty() {
                return "—".to_string();
            }
            format!("0x{:02X}", bytes[0])
        }
        "int8" => {
            if bytes.is_empty() {
                return "—".to_string();
            }
            format!("{}", bytes[0] as i8)
        }
        "uint16be" => {
            if bytes.len() < 2 {
                return "—".to_string();
            }
            format!("0x{:04X}", u16::from_be_bytes([bytes[0], bytes[1]]))
        }
        "uint16le" => {
            if bytes.len() < 2 {
                return "—".to_string();
            }
            format!("0x{:04X}", u16::from_le_bytes([bytes[0], bytes[1]]))
        }
        "int16be" => {
            if bytes.len() < 2 {
                return "—".to_string();
            }
            format!("{}", i16::from_be_bytes([bytes[0], bytes[1]]))
        }
        "int16le" => {
            if bytes.len() < 2 {
                return "—".to_string();
            }
            format!("{}", i16::from_le_bytes([bytes[0], bytes[1]]))
        }
        "uint32be" => {
            if bytes.len() < 4 {
                return "—".to_string();
            }
            format!(
                "0x{:08X}",
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            )
        }
        "uint32le" => {
            if bytes.len() < 4 {
                return "—".to_string();
            }
            format!(
                "0x{:08X}",
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            )
        }
        "int32be" => {
            if bytes.len() < 4 {
                return "—".to_string();
            }
            format!(
                "{}",
                i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            )
        }
        "int32le" => {
            if bytes.len() < 4 {
                return "—".to_string();
            }
            format!(
                "{}",
                i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            )
        }
        "string" => bytes
            .iter()
            .map(|b| {
                if (0x20..=0x7e).contains(b) {
                    *b as char
                } else {
                    '·'
                }
            })
            .collect(),
        "hex" => {
            if bytes.is_empty() {
                return "—".to_string();
            }
            hex_u32(bytes)
        }
        _ => format!("{} Б", bytes.len()),
    }
}

/// Разбор textual `equals` кастомного условия под тип.
/// Числа: десятичные (`-5`, `2100`) или `0x`-hex; строки — как есть (непустые);
/// bytes/hex — hex-пары через пробел (`"AA 55"`).
pub(crate) enum ExpectedValue {
    Num(i64),
    Bytes(Vec<u8>),
}

pub(crate) fn parse_expected(ftype: &str, text: &str) -> Option<ExpectedValue> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let info = FIELD_TYPES.iter().find(|i| i.id == ftype)?;
    if info.numeric {
        let v: i64 = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            i64::from_str_radix(h, 16).ok()?
        } else {
            t.parse().ok()?
        };
        let (min, max) = match (info.size, info.signed) {
            (Some(1), false) => (0, 255),
            (Some(1), true) => (-128, 127),
            (Some(2), false) => (0, 65535),
            (Some(2), true) => (-32768, 32767),
            (Some(4), false) => (0, 4294967295),
            (Some(4), true) => (-2147483648, 2147483647),
            _ => return None,
        };
        if v < min || v > max {
            return None;
        }
        Some(ExpectedValue::Num(v))
    } else if ftype == "string" {
        Some(ExpectedValue::Bytes(t.as_bytes().to_vec()))
    } else {
        let hexed: String = t.split_whitespace().collect();
        if hexed.len() % 2 != 0 || hexed.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(hexed.len() / 2);
        let chars: Vec<char> = hexed.chars().collect();
        for pair in chars.chunks(2) {
            let s: String = pair.iter().collect();
            out.push(u8::from_str_radix(&s, 16).ok()?);
        }
        Some(ExpectedValue::Bytes(out))
    }
}

/// Сравнение среза байтов с ожиданием под тип.
pub(crate) fn bytes_match(slice: &[u8], ftype: &str, expected: &ExpectedValue) -> bool {
    match expected {
        ExpectedValue::Num(v) => decode_number(slice, ftype).map(|d| (d - *v as f64).abs() < 1e-9).unwrap_or(false),
        ExpectedValue::Bytes(want) => slice.len() >= want.len() && &slice[..want.len()] == want.as_slice(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_covers_frontend_list() {
        for t in ["uint8", "int8", "uint16be", "uint16le", "uint32be", "uint32le",
                  "int16be", "int16le", "int32be", "int32le", "bytes", "string", "hex"] {
            assert!(is_known_type(t), "missing {t}");
        }
        assert!(!is_known_type("u8"));
        assert!(!is_known_type(""));
    }

    #[test]
    fn signed_and_le_roundtrip() {
        assert_eq!(decode_number(&[0xFF], "int8"), Some(-1.0));
        assert_eq!(decode_number(&[0xFF, 0xFE], "int16le"), Some(-257.0));
        assert_eq!(decode_number(&[0xFF, 0xFE], "uint16le"), Some(0xFEFF as f64));
        assert_eq!(decode_number(&[0xFF, 0xFF, 0xFF, 0xFF], "int32be"), Some(-1.0));
        assert_eq!(format_field_value(&[0xFF], "int8"), "-1");
        assert_eq!(format_field_value(&[0x01, 0x02], "uint16le"), "0x0201");
        assert_eq!(format_field_value(&[0xAA, 0x55], "hex"), "AA 55");
        assert_eq!(format_field_value(&[0xAA], "nope"), "1 Б");
    }

    #[test]
    fn expected_parsing() {
        assert!(matches!(parse_expected("uint8", "0xFF"), Some(ExpectedValue::Num(255))));
        assert!(parse_expected("uint8", "256").is_none());
        assert!(matches!(parse_expected("int8", "-5"), Some(ExpectedValue::Num(-5))));
        assert!(parse_expected("int8", "128").is_none());
        assert!(matches!(parse_expected("string", "Lab"), Some(ExpectedValue::Bytes(_))));
        assert!(parse_expected("string", "  ").is_none());
        assert!(matches!(parse_expected("hex", "AA 55"), Some(ExpectedValue::Bytes(_))));
        assert!(parse_expected("hex", "XYZ").is_none());
        assert!(parse_expected("nope", "1").is_none());
        assert!(bytes_match(&[0xAA, 0x55, 0x01], "hex", &ExpectedValue::Bytes(vec![0xAA, 0x55])));
        assert!(!bytes_match(&[0xAA], "hex", &ExpectedValue::Bytes(vec![0xAA, 0x55])));
    }
}
