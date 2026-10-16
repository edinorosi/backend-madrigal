use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Capture {
    pub id: String,
    pub file_name: String,
    pub imported_at: String,
    pub size_bytes: u64,
    pub session_count: u32,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SessionTuple {
    pub source: Endpoint,
    pub destination: Endpoint,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub capture_id: String,
    pub tuple: SessionTuple,
    pub message_count: u32,
    pub started_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MessageField {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub value: String,
    pub range: ByteRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub id: String,
    pub session_id: String,
    pub packet_number: u32,
    pub byte_offset: u64,
    pub direction: String,
    pub role: String,
    pub length: u64,
    pub status: String,
    pub label: String,
    pub timestamp: String,
    pub interpretation: String,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    pub fields: Vec<MessageField>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub id: String,
    pub message_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub obs_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<ByteRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hypothesis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    pub id: String,
    pub timestamp: String,
    pub name: String,
    pub description: String,
    pub value: Option<f64>,
    pub expected_message_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub offset: serde_json::Value,
    pub length: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelRuleCondition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcodes: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length_equals: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_message_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms: Option<Vec<CondTerm>>,
}

/// Кастомное условие: срез `type` по смещению `offset` равен `equals.
/// Числа — десятичные или 0x; string — как есть; bytes/hex — hex-пары.
/// Все заданные terms AND-ятся с остальными полями условия.
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CondTerm {
    pub offset: u32,
    #[serde(rename = "type")]
    pub term_type: String,
    pub equals: String,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelRule {
    pub id: String,
    pub name: String,
    pub condition: ModelRuleCondition,
    pub fields: Vec<ModelField>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Model {
    pub id: String,
    pub name: String,
    pub status: String,
    pub rules: Vec<ModelRule>,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CheckRow {
    pub id: String,
    pub action_id: String,
    pub time: String,
    pub action: String,
    pub expected: Option<f64>,
    pub extracted: String,
    pub status: String,
    pub message_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CheckSummary {
    pub total: u32,
    pub ok: u32,
    pub partial: u32,
    pub unknown: u32,
    pub error: u32,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JournalUploadResult {
    pub actions: u32,
    pub skipped: u32,
    pub scope: String,
    pub source: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub rows: Vec<CheckRow>,
    pub summary: CheckSummary,
    pub model_id: Option<String>,
    pub model_name: Option<String>,
}