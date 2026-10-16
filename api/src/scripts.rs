use std::time::Duration;

use axum::{extract::State, http::StatusCode, Json};
use serde_json::json;

use crate::error::api_error;
use crate::state::AppState;

/// Либа для скриптов обоих миров: вкомпилена в бинарь, кладётся рядом
/// с запускаемым скриптом — `from client import Client` работает и в диалоге.
/// Путь от api/src/: api/ -> backend/ -> корень -> scripts/.
const CLIENT_PY: &str = include_str!("../../../scripts/protocol-lab-py/client.py");
const LAB_PY: &str = include_str!("../../../scripts/protocol-lab-py/lab.py");

/// Хелпер диагностических скриптов термостенда: вкомпилен в бинарь, кладётся
/// рядом с запускаемым скриптом — `from _common import *` работает и в диалоге
/// «Скрипты», и через MCP. Путь от api/src/: src/ -> api/ -> backend/ -> fixtures/.
const DIAG_COMMON_PY: &str = include_str!("../../fixtures/diagnostics/_common.py");
/// Данные для тех же скриптов: зеркалятся в tmpdir/fixtures (см. ниже),
/// т.к. в песочнице хостовые пути недоступны — только /work.
const DIAG_JOURNAL_CSV: &str = include_str!("../../fixtures/action_journal.csv");
const DIAG_BASE_PCAP: &[u8] = include_bytes!("../../fixtures/research/03_combined_messages.pcap");
const DIAG_PC: &[(&str, &[u8])] = &[
    ("01_retransmission.pcap", include_bytes!("../../fixtures/diagnostics/01_retransmission.pcap")),
    ("02_reordered.pcapng", include_bytes!("../../fixtures/diagnostics/02_reordered.pcapng")),
    ("03_missing_segment.pcap", include_bytes!("../../fixtures/diagnostics/03_missing_segment.pcap")),
    ("04_snaplen_truncated.pcapng", include_bytes!("../../fixtures/diagnostics/04_snaplen_truncated.pcapng")),
    ("05_conflicting_overlap.pcap", include_bytes!("../../fixtures/diagnostics/05_conflicting_overlap.pcap")),
    ("06_missing_beginning.pcapng", include_bytes!("../../fixtures/diagnostics/06_missing_beginning.pcapng")),
    ("07_checksum_offload.pcap", include_bytes!("../../fixtures/diagnostics/07_checksum_offload.pcap")),
    ("08_bad_checksum.pcapng", include_bytes!("../../fixtures/diagnostics/08_bad_checksum.pcapng")),
];

/// Лимиты серверного прогона скриптов.
const DEFAULT_TIMEOUT_MS: u64 = 15_000;
const MAX_TIMEOUT_MS: u64 = 120_000;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_SCRIPT_BYTES: usize = 256 * 1024;

#[derive(serde::Deserialize)]
pub(crate) struct ScriptBody {
    /// Код на Python 3 (stdin/stdout — текст).
    pub script: String,
    /// Запись для контекста (сообщения + файл байтов).
    #[serde(default, alias = "captureId")]
    pub capture_id: Option<String>,
    /// Таймаут мс (дефолт 15000, максимум 120000).
    #[serde(default, alias = "timeoutMs")]
    pub timeout_ms: Option<u64>,
}

fn truncate(mut v: Vec<u8>) -> String {
    let clipped = v.len() > MAX_OUTPUT_BYTES;
    v.truncate(MAX_OUTPUT_BYTES);
    let mut s = String::from_utf8_lossy(&v).into_owned();
    if clipped {
        s.push_str("\n…[обрезано]");
    }
    s
}

/// Прогон Python-скрипта для автоматизации внутри софта.
///
/// Контекст через env: `LAB_CONTEXT` — JSON-файл
/// `{capture_id, messages:[{id,byteOffset,length,status}], bytes_file}`.
/// Печатай в stdout — он вернётся в `stdout` ответа.
/// Доверие как самому софту: скрипты пишет и запускает локальный инженер.
pub(crate) async fn run_script(
    State(state): State<AppState>,
    Json(body): Json<ScriptBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    execute_script(&state, body).await.map(Json)
}

/// Прямой запуск без bwrap: зачищенный env, cwd=tmpdir, вывод в файлы.
fn direct_command(
    script_path: &std::path::Path,
    tmp: &std::path::Path,
    env: &[(String, String)],
    out_file: std::fs::File,
    err_file: std::fs::File,
) -> tokio::process::Command {
    let mut c = tokio::process::Command::new("python3");
    c.arg(script_path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(tmp)
        .stdout(out_file)
        .stderr(err_file)
        .kill_on_drop(true);
    for (k, v) in env {
        c.env(k, v);
    }
    c
}

/// Тело прогона без axum-обёрток — переиспользуется MCP-инструментом.
pub(crate) async fn execute_script(
    state: &AppState,
    body: ScriptBody,
) -> Result<serde_json::Value, (StatusCode, Json<crate::dto::ErrorResponse>)> {
    if body.script.is_empty() || body.script.len() > MAX_SCRIPT_BYTES {
        return Err(api_error("Пустой или слишком большой script", StatusCode::BAD_REQUEST));
    }
    let timeout_ms = body.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).clamp(1, MAX_TIMEOUT_MS);

    let tmp = tempfile::tempdir().map_err(|e| api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
    let script_path = tmp.path().join("script.py");
    let context_path = tmp.path().join("context.json");
    std::fs::write(&script_path, body.script.as_bytes())
        .map_err(|e| api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
    // либа обоих миров рядом со скриптом: from client import Client работает везде
    std::fs::write(tmp.path().join("client.py"), CLIENT_PY)
        .map_err(|e| api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
    std::fs::write(tmp.path().join("lab.py"), LAB_PY)
        .map_err(|e| api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
    // _common для диагностических скриптов + зеркало fixtures/ (журнал, база,
    // 8 pcap): скрипты видят только tmpdir (/work в песочнице), поэтому данные
    // едут вместе со скриптом, а путь отдаём через PL_FIXTURES (bwrap сам
    // переписывает его на /work-аналог).
    std::fs::write(tmp.path().join("_common.py"), DIAG_COMMON_PY)
        .map_err(|e| api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
    let fx = tmp.path().join("fixtures");
    std::fs::create_dir_all(fx.join("research")).ok();
    std::fs::create_dir_all(fx.join("diagnostics")).ok();
    std::fs::write(fx.join("action_journal.csv"), DIAG_JOURNAL_CSV).ok();
    std::fs::write(fx.join("research").join("03_combined_messages.pcap"), DIAG_BASE_PCAP).ok();
    for (name, bytes) in DIAG_PC {
        std::fs::write(fx.join("diagnostics").join(name), bytes).ok();
    }

    let mut context = json!({"capture_id": body.capture_id});
    if let Some(cid) = body.capture_id.as_deref() {
        let sessions = state.sessions.read().unwrap();
        let sids: Vec<String> = sessions
            .values()
            .filter(|s| s.capture_id == cid)
            .map(|s| s.id.clone())
            .collect();
        let messages = state.messages.read().unwrap();
        let list: Vec<serde_json::Value> = messages
            .values()
            .filter(|m| sids.contains(&m.session_id))
            .map(|m| {
                json!({
                    "id": m.id,
                    "byteOffset": m.byte_offset,
                    "length": m.length,
                    "status": m.status,
                    "direction": m.direction,
                })
            })
            .collect();
        let bytes_path = tmp.path().join("stream.bin");
        if let Some(raw) = state.raw_bytes.read().unwrap().get(cid) {
            std::fs::write(&bytes_path, raw)
                .map_err(|e| api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
            context["bytes_file"] = json!(bytes_path.to_string_lossy());
        }
        context["messages"] = json!(list);
    }
    std::fs::write(&context_path, serde_json::to_vec(&context).unwrap_or_default())
        .map_err(|e| api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    let out_path = tmp.path().join("stdout.txt");
    let err_path = tmp.path().join("stderr.txt");
    let out_file = std::fs::File::create(&out_path)
        .map_err(|e| api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
    let err_file = std::fs::File::create(&err_path)
        .map_err(|e| api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    // базовый env скрипта; родительский НЕ наследуется (изоляция:
    // секреты сервера вроде API_TOKEN наружу не текут, только LAB_API_TOKEN)
    let mut script_env: Vec<(String, String)> = vec![
        ("LAB_CONTEXT".to_string(), context_path.to_string_lossy().to_string()),
        ("LAB_API_URL".to_string(), state.public_url.clone()),
        ("PL_FIXTURES".to_string(), fx.to_string_lossy().to_string()),
    ];
    if let Some(token) = state.api_token.as_deref() {
        script_env.push(("LAB_API_TOKEN".to_string(), token.to_string()));
    }

    // bwrap мог пропасть после старта — тогда слабый режим + пометка в stderr
    let mut downgraded_note = String::new();
    let use_bwrap = matches!(state.sandbox, crate::sandbox::Sandbox::Bwrap);
    let raw = matches!(state.sandbox, crate::sandbox::Sandbox::Off);
    let mut cmd = if use_bwrap {
        let (bin, args) = crate::sandbox::bwrap_command(tmp.path(), &script_env);
        if !std::path::Path::new(&bin).exists() {
            downgraded_note = "bwrap пропал, слабый режим rlimit\n".to_string();
            direct_command(&script_path, tmp.path(), &script_env, out_file, err_file)
        } else {
            let mut c = tokio::process::Command::new(bin);
            c.args(args).stdout(out_file).stderr(err_file).kill_on_drop(true);
            c
        }
    } else {
        direct_command(&script_path, tmp.path(), &script_env, out_file, err_file)
    };
    #[cfg(unix)]
    if !raw && !use_bwrap {
        // rlimit только прямому запуску: на bwrap-родителе NPROC роняет
        // его fork (лимит считается на всех детей юзера); внутри песочницы
        // лимиты ставит python-бутстрап (см. sandbox::bwrap_command)
        unsafe {
            cmd.pre_exec(|| {
                crate::sandbox::apply_rlimits();
                Ok(())
            });
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| api_error(&format!("Нет python3: {}", e), StatusCode::BAD_GATEWAY))?;

    let status = tokio::time::timeout(Duration::from_millis(timeout_ms), child.wait()).await;
    let (code, timed_out) = match status {
        Ok(Ok(s)) => (s.code().unwrap_or(-1), false),
        Ok(Err(e)) => return Err(api_error(&e.to_string(), StatusCode::INTERNAL_SERVER_ERROR)),
        Err(_) => {
            let _ = child.kill().await;
            let code = child.wait().await.ok().and_then(|s| s.code()).unwrap_or(-1);
            (code, true)
        }
    };
    let read_capped = |p: &std::path::Path| {
        std::fs::read(p)
            .map(truncate)
            .unwrap_or_default()
    };
    let mut stderr = read_capped(&err_path);
    stderr.insert_str(0, &downgraded_note);
    if timed_out {
        stderr.push_str(&format!("Таймаут {} мс", timeout_ms));
    }
    Ok(json!({
        "stdout": read_capped(&out_path),
        "stderr": stderr,
        "exit_code": code,
        "timed_out": timed_out,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_caps_output() {
        let s = truncate(vec![b'x'; MAX_OUTPUT_BYTES + 10]);
        assert!(s.ends_with("[обрезано]"));
        assert_eq!(truncate(b"ok".to_vec()), "ok");
    }
}
