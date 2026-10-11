use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    U8,
    U16Big,
    U16Little,
    U32Big,
    U32Little,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterpretationRule {
    pub name: String,
    pub offset: usize,
    pub field_type: FieldType,
}

impl FieldType {
    pub fn size(&self) -> usize {
        match self {
            FieldType::U8 => 1,
            FieldType::U16Big | FieldType::U16Little => 2,
            FieldType::U32Big | FieldType::U32Little => 4,
        }
    }
}

/// Применяет правило к срезу байт (срез уже смещён вызывателем).
/// Возвращает JSON-значение вида {"name":..,"offset":..,"length":..,"value":..}
/// или None если байт не хватает.
pub fn apply_rule(data: &[u8], rule: &InterpretationRule) -> Option<serde_json::Value> {
    let size = rule.field_type.size();
    if data.len() < size {
        return None;
    }
    let value: u64 = match rule.field_type {
        FieldType::U8 => data[0] as u64,
        FieldType::U16Big => u16::from_be_bytes([data[0], data[1]]) as u64,
        FieldType::U16Little => u16::from_le_bytes([data[0], data[1]]) as u64,
        FieldType::U32Big => u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64,
        FieldType::U32Little => u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64,
    };
    Some(serde_json::json!({
        "name": rule.name,
        "offset": rule.offset,
        "length": size,
        "value": value,
    }))
}
