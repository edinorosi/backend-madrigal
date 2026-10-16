use rmcp::{
    handler::server::wrapper::Parameters,
    model::CallToolResult,
    tool, tool_handler, tool_router,
    ErrorData as McpError, ServerHandler,
};
use schemars::JsonSchema;
use serde::Deserialize;

use base64::Engine as _;

use crate::state::AppState;

fn internal(message: String) -> McpError {
    McpError::internal_error(message, None)
}

fn not_found(what: &str) -> McpError {
    McpError::resource_not_found(format!("{} не найдено", what), None)
}

// ---------- параметры инструментов ----------

#[derive(Deserialize, JsonSchema)]
struct NoArgs {}

#[derive(Deserialize, JsonSchema)]
struct CaptureId {
    /// id записи из list_captures
    capture_id: String,
}

#[derive(Deserialize, JsonSchema)]
struct SessionQuery {
    /// id сессии из list_sessions
    session_id: String,
    /// request | response; пусто — обе стороны
    direction: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct BytesQuery {
    capture_id: String,
    /// смещение от начала потока записи
    offset: u64,
    length: u64,
}

#[derive(Deserialize, JsonSchema)]
struct MessageId {
    message_id: String,
}

#[derive(Deserialize, JsonSchema)]
struct ApplyQuery {
    message_id: String,
    model_id: String,
}

#[derive(Deserialize, JsonSchema)]
struct CheckQuery {
    capture_id: String,
    model_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct SaveModelQuery {
    /// полная модель (Model, camelCase)
    model: crate::dto::Model,
}

#[derive(Deserialize, JsonSchema)]
struct FileQuery {
    /// путь к pcap; jail: cwd и /tmp
    file_path: String,
}

#[derive(Deserialize, JsonSchema)]
struct CodegenQuery {
    model_id: String,
    /// rust | python | c
    lang: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct ImportQuery {
    /// имя файла для стора
    filename: String,
    /// содержимое pcap base64
    base64: String,
}

#[derive(Deserialize, JsonSchema)]
struct RunScriptQuery {
    /// код на Python 3
    script: String,
    capture_id: Option<String>,
    timeout_ms: Option<u64>,
}

// ---------- сервер ----------

#[derive(Clone)]
pub(crate) struct LabMcp {
    state: AppState,
}

impl LabMcp {
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[tool_router]
impl LabMcp {
    #[tool(description = "Список записей pcap")]
    async fn list_captures(&self, _p: Parameters<NoArgs>) -> Result<CallToolResult, McpError> {
        let list: Vec<crate::dto::Capture> =
            self.state.captures.read().unwrap().values().cloned().collect();
        Ok(CallToolResult::structured(serde_json::json!(list)))
    }

    #[tool(description = "Сессии записи")]
    async fn list_sessions(
        &self,
        Parameters(p): Parameters<CaptureId>,
    ) -> Result<CallToolResult, McpError> {
        if !self.state.captures.read().unwrap().contains_key(&p.capture_id) {
            return Err(not_found("Запись"));
        }
        let mut list: Vec<crate::dto::Session> = self
            .state
            .sessions
            .read()
            .unwrap()
            .values()
            .filter(|s| s.capture_id == p.capture_id)
            .cloned()
            .collect();
        list.sort_by(|a, b| a.started_at.cmp(&b.started_at));
        Ok(CallToolResult::structured(serde_json::json!(list)))
    }

    #[tool(description = "Сообщения сессии, упорядоченные по времени")]
    async fn list_messages(
        &self,
        Parameters(p): Parameters<SessionQuery>,
    ) -> Result<CallToolResult, McpError> {
        let all = self.state.messages.read().unwrap();
        let mut list: Vec<crate::dto::Message> = all
            .values()
            .filter(|m| {
                m.session_id == p.session_id
                    && p.direction.as_ref().map(|d| &m.direction == d).unwrap_or(true)
            })
            .cloned()
            .collect();
        if list.is_empty() && !self.state.sessions.read().unwrap().contains_key(&p.session_id) {
            return Err(not_found("Сессия"));
        }
        list.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(CallToolResult::structured(serde_json::json!(list)))
    }

    #[tool(description = "Сырые байты потока записи (base64). offset от начала потока")]
    async fn get_bytes(
        &self,
        Parameters(p): Parameters<BytesQuery>,
    ) -> Result<CallToolResult, McpError> {
        let raw = self.state.raw_bytes.read().unwrap();
        let bytes = raw.get(&p.capture_id).ok_or_else(|| not_found("Запись"))?;
        let start = p.offset as usize;
        let end = start.saturating_add(p.length as usize);
        if end > bytes.len() {
            return Err(McpError::invalid_params("Range out of bounds", None));
        }
        Ok(CallToolResult::structured(serde_json::json!({
            "mime": "application/octet-stream",
            "length": end - start,
            "base64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD, &bytes[start..end]
            ),
        })))
    }

    #[tool(description = "Журнал действий записи")]
    async fn list_actions(
        &self,
        Parameters(p): Parameters<CaptureId>,
    ) -> Result<CallToolResult, McpError> {
        let wanted = self
            .state
            .captures
            .read()
            .unwrap()
            .get(&p.capture_id)
            .map(|c| c.file_name.clone())
            .unwrap_or_default();
        if wanted.is_empty() {
            return Err(not_found("Запись"));
        }
        let actions: Vec<(crate::dto::Action, _, _)> =
            crate::check::load_actions_for_capture(&self.state, &p.capture_id, &wanted).0;
        let out: Vec<crate::dto::Action> = actions.into_iter().map(|(a, _, _)| a).collect();
        Ok(CallToolResult::structured(serde_json::json!(out)))
    }

    #[tool(description = "Наблюдения сообщения")]
    async fn list_observations(
        &self,
        Parameters(p): Parameters<MessageId>,
    ) -> Result<CallToolResult, McpError> {
        if !self.state.messages.read().unwrap().contains_key(&p.message_id) {
            return Err(not_found("Сообщение"));
        }
        let list: Vec<crate::dto::Observation> = self
            .state
            .observations
            .read()
            .unwrap()
            .values()
            .filter(|o| o.message_id == p.message_id)
            .cloned()
            .collect();
        Ok(CallToolResult::structured(serde_json::json!(list)))
    }

    #[tool(description = "Список моделей разбора")]
    async fn list_models(&self, _p: Parameters<NoArgs>) -> Result<CallToolResult, McpError> {
        let list: Vec<crate::dto::Model> =
            self.state.models.read().unwrap().values().cloned().collect();
        Ok(CallToolResult::structured(serde_json::json!(list)))
    }

    #[tool(description = "Сохранить модель (upsert по id, типы валидируются)")]
    async fn save_model(
        &self,
        Parameters(p): Parameters<SaveModelQuery>,
    ) -> Result<CallToolResult, McpError> {
        let mut model = p.model;
        crate::models::store_model(&self.state, &mut model).map_err(internal)?;
        Ok(CallToolResult::structured(serde_json::json!({"status": "saved", "id": model.id})))
    }

    #[tool(description = "Применить модель к сообщению, вернуть поля")]
    async fn apply_model(
        &self,
        Parameters(p): Parameters<ApplyQuery>,
    ) -> Result<CallToolResult, McpError> {
        let fields = crate::models::apply_to_message(&self.state, &p.message_id, &p.model_id)
            .map_err(|e| {
                if e.contains("not found") {
                    not_found("Сообщение/модель")
                } else {
                    internal(e)
                }
            })?;
        Ok(CallToolResult::structured(serde_json::json!(fields)))
    }

    #[tool(description = "Прогнать модель по журналу: {rows, summary}")]
    async fn check(
        &self,
        Parameters(p): Parameters<CheckQuery>,
    ) -> Result<CallToolResult, McpError> {
        let result = crate::check::check_capture(&self.state, &p.capture_id, p.model_id);
        Ok(CallToolResult::structured(serde_json::json!(result)))
    }

    #[tool(description = "Сгенерировать декодер из модели (rust/python/c)")]
    async fn codegen(
        &self,
        Parameters(p): Parameters<CodegenQuery>,
    ) -> Result<CallToolResult, McpError> {
        let model = self
            .state
            .models
            .read()
            .unwrap()
            .get(&p.model_id)
            .cloned()
            .ok_or_else(|| not_found("Модель"))?;
        let out = crate::codegen::render_codegen(&model, p.lang.as_deref().unwrap_or("rust"));
        Ok(CallToolResult::structured(out))
    }

    #[tool(description = "Гипотезы разбора для pcap-файла (только первая сессия/c2s)")]
    async fn analyze_autosuggest(
        &self,
        Parameters(p): Parameters<FileQuery>,
    ) -> Result<CallToolResult, McpError> {
        crate::analysis::suggest_for_file(&self.state.patterns_dir, &p.file_path)
            .map(CallToolResult::structured)
            .map_err(|(status, err)| {
                McpError::internal_error(
                    format!("{}: {}", status.as_u16(), err.error),
                    None,
                )
            })
    }

    #[tool(description = "Вывести модель из журнала (не сохраняет, только предлагает)")]
    async fn infer_model(
        &self,
        Parameters(p): Parameters<CaptureId>,
    ) -> Result<CallToolResult, McpError> {
        let body = serde_json::json!({"capture_id": p.capture_id});
        crate::infer::infer_capture(&self.state, &body)
            .await
            .map(CallToolResult::structured)
            .map_err(|(status, err)| {
                McpError::internal_error(
                    format!("{}: {}", status.as_u16(), err.error),
                    None,
                )
            })
    }

    #[tool(description = "Импорт pcap из base64 в новую запись")]
    async fn import_capture(
        &self,
        Parameters(p): Parameters<ImportQuery>,
    ) -> Result<CallToolResult, McpError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(p.base64.as_bytes())
            .map_err(|e| McpError::invalid_params(format!("bad base64: {}", e), None))?;
        match crate::captures::ingest_packets(&self.state, p.filename, bytes) {
            Ok(c) => Ok(CallToolResult::structured(serde_json::json!(c))),
            Err((status, err)) => Err(McpError::internal_error(
                format!("{}: {}", status.as_u16(), err.error),
                None,
            )),
        }
    }

    #[tool(description = "Выполнить Python-скрипт на сервере (контекст в LAB_CONTEXT, вывод из stdout)")]
    async fn run_script(
        &self,
        Parameters(p): Parameters<RunScriptQuery>,
    ) -> Result<CallToolResult, McpError> {
        let body = crate::scripts::ScriptBody {
            script: p.script,
            capture_id: p.capture_id,
            timeout_ms: p.timeout_ms,
        };
        crate::scripts::execute_script(&self.state, body)
            .await
            .map(CallToolResult::structured)
            .map_err(|(status, err)| {
                McpError::internal_error(
                    format!("{}: {}", status.as_u16(), err.error),
                    None,
                )
            })
    }
}

#[tool_handler]
impl ServerHandler for LabMcp {
    fn get_info(&self) -> rmcp::model::ServerConfig {
        let mut info = rmcp::model::ServerConfig::default();
        info.instructions = Some(
            "Лаборатория протоколов: разбор бинарного обмена поверх TCP. \
             check сверяет модель с журналом; codegen выгружает декодер; \
             run_script выполняет Python с контекстом записи."
                .into(),
        );
        info
    }
}
