use axum::{
    extract::{Path as AxumPath, Query, State},
    Json,
};

use crate::dto::{Message, Observation};
use crate::state::AppState;

#[derive(serde::Deserialize)]
struct MsgQuery { direction: Option<String> }


pub(crate) async fn list_messages(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Query(q): Query<MsgQuery>,
) -> Json<Vec<Message>> {
    let msgs = state.messages.read().unwrap();  //читаем месаги
    let mut list: Vec<Message> = msgs.values()      // идём по всем месагам
        .filter(|m| m.session_id == session_id) //только эта сессия
        .filter(|m| match &q.direction {        //фильтруем по направлению
            None => true,                       //если нет query то обе стороны
            Some(d) => &m.direction == d,       // с query одна сторона
        })
        .cloned() // клонируем из-за RwLock
        .collect();
    list.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Json(list)
}

pub(crate) async fn list_observations(
    State(state): State<AppState>, //состояние с обсервайшн
    AxumPath(message_id): AxumPath<String>, 
) -> Json<Vec<Observation>> {
    let obs = state.observations.read().unwrap(); //всё читаем
    let list = obs.values() // фильтруем по айдишке месаги
        .filter(|o| o.message_id == message_id)
        .cloned()
        .collect();
    Json(list)
}
