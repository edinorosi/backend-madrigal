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
//применяем правило к данным
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FramingRule {
    FixedSize(usize), //у сообщ фикс размер
    LengthPrefixed, //первый байт= размер тела
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub stream_offset: usize,
    pub payload: Vec<u8>, 
}


pub fn frame_stream(data: &[u8], rule:&FramingRule)-> Vec<Message> {
    let mut messages = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        match rule {
            FramingRule::FixedSize(size) => {
                //Если используется правило фикс размер то эта херня
                if offset + size > data.len() { break; }
                let payload = data[offset..offset + size].to_vec(); // удаляем крайнюю плоть
                messages.push(Message {stream_offset: offset, payload});
                offset += size;
            }
            //Длина в начале ,а не в конче
            FramingRule::LengthPrefixed => {
                if offset + 1 > data.len() {break; }
                let len = data[offset] as usize;
                if offset + 1 + len > data.len() {break; }
                let payload = data[offset + 1..offset + 1 + len].to_vec(); //кастрация 
                messages.push(Message {stream_offset: offset, payload});
                offset += 1 + len;

            }
        }
    }
    messages
}