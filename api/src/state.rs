use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::dto::{Capture, CheckResult, Message, Model, Observation, Session};

pub struct AppData {
    pub captures: RwLock<HashMap<String, Capture>>,
    pub sessions: RwLock<HashMap<String, Session>>,
    pub messages: RwLock<HashMap<String, Message>>,
    pub observations: RwLock<HashMap<String, Observation>>,
    pub models: RwLock<HashMap<String, Model>>,
    pub last_check: RwLock<HashMap<String, CheckResult>>,
    pub raw_bytes: RwLock<HashMap<String, Vec<u8>>>, // хранение пустых писи-файлы 
}

// ВАЖНО: Здесь должно быть AppData, а не AppState, чтобы не было цикла
pub type AppState = Arc<AppData>;

pub(crate) fn capture_dir(id: &str) -> String { 
    format!("data/captures/{}", id) 
} // папка одного capture

pub(crate) fn save_json(path: &str, v: &impl serde::Serialize) { // запись любого стора в JSON

    if let Some(p) = std::path::Path::new(path).parent() { 
        std::fs::create_dir_all(p).ok(); 
    } 

    if let Ok(b) = serde_json::to_vec_pretty(v) { 
        std::fs::write(path, b).ok(); 
    }
}


pub(crate) fn persist_capture(state: &AppState, id: &str) { // сохранить один capture целиком
    let dir = capture_dir(id);

    if let Some(c) = state.captures.read().unwrap().get(id) { 
        save_json(&format!("{}/meta.json", dir), c); 
    } 

    let sess: Vec<Session> = state.sessions
        .read()
        .unwrap()
        .values()
        .filter(|s| s.capture_id == id)
        .cloned()
        .collect(); // его сессии

    save_json(&format!("{}/sessions.json", dir), &sess);

    let sids: Vec<String> = sess.iter().map(|s| s.id.clone()).collect(); // id сессий

    let msgs: Vec<Message> = state.messages.read().unwrap().values().filter(|m| sids.contains(&m.session_id)).cloned().collect(); // его сообщения

    save_json(&format!("{}/messages.json", dir), &msgs); // пишем сообщения

    if let Some(b) = state.raw_bytes
        .read()
        .unwrap()
        .get(id) { 
            std::fs::create_dir_all(&dir).ok(); 
            std::fs::write(format!("{}/stream.bin", dir), b).ok(); 
        } 
} 


pub(crate) fn persist_global(state: &AppState) { // сохранить наблюдения и модели

    let obs: Vec<Observation> = state.observations.read()
        .unwrap()
        .values()
        .cloned()
        .collect();
    save_json("data/observations.json", &obs); 
    let mods: Vec<Model> = state.models.read()// все модели
        .unwrap()
        .values()
        .cloned()
        .collect(); 
    save_json("data/models.json", &mods);
    save_json("data/checks.json", &*state.last_check.read().unwrap()); 

} 


pub(crate) fn load_store() -> AppData { // загрузка всего stora
    let mut captures = HashMap::new();
    let mut sessions = HashMap::new();
    let mut messages = HashMap::new();
    let mut raw_bytes = HashMap::new();
    if let Ok(dirs) = std::fs::read_dir("data/captures") {
        for e in dirs.flatten() { // каждая папка
            let id = e.file_name().to_string_lossy().to_string(); // id = имя папки
            let base = format!("data/captures/{}", id);
            if let Ok(b) = std::fs::read(format!("{}/meta.json", base)) { if let Ok(c) = serde_json::from_slice::<Capture>(&b) { captures.insert(c.id.clone(), c); } } // мета (ЗАПРЕЩЕНА В РФ)
            if let Ok(b) = std::fs::read(format!("{}/sessions.json", base)) { if let Ok(v) = serde_json::from_slice::<Vec<Session>>(&b) { for s in v { sessions.insert(s.id.clone(), s); } } } // сессии
            if let Ok(b) = std::fs::read(format!("{}/messages.json", base)) { if let Ok(v) = serde_json::from_slice::<Vec<Message>>(&b) { for m in v { messages.insert(m.id.clone(), m); } } } // сообщения
            if let Ok(b) = std::fs::read(format!("{}/stream.bin", base)) { raw_bytes.insert(id, b); } // поток
        } 
    }
    let mut observations = HashMap::new(); // наблюдения
    if let Ok(b) = std::fs::read("data/observations.json") { if let Ok(v) = serde_json::from_slice::<Vec<Observation>>(&b) { for o in v { observations.insert(o.id.clone(), o); } } } // грузим наблюдения
    let mut models = HashMap::new(); // модели
    if let Ok(b) = std::fs::read("data/models.json") { if let Ok(v) = serde_json::from_slice::<Vec<Model>>(&b) { for m in v { models.insert(m.id.clone(), m); } } } // грузим модели
    let mut last_check = HashMap::new();
    if let Ok(b) = std::fs::read("data/checks.json") { if let Ok(v) = serde_json::from_slice::<HashMap<String, CheckResult>>(&b) { last_check = v; } }
    AppData { captures: RwLock::new(captures), sessions: RwLock::new(sessions), messages: RwLock::new(messages), observations: RwLock::new(observations), models: RwLock::new(models), raw_bytes: RwLock::new(raw_bytes), last_check: RwLock::new(last_check) } // собираем стор
} 
