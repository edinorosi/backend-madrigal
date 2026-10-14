use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::hash::Hash;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPacket {  //структура пакета
    pub index: usize,
    pub timestamp_us: u64,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32, 
    pub ack: u32, 
    pub flags: TcpFlags, 
    pub payload: Vec<u8>, 
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)] 
pub struct TcpFlags {
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub ack: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]  // Hash для HashMap, Eq для сравнения
pub struct SessionKey {  // Уникальный идентификатор сессии (4-ка адресов)
    pub client_ip: Ipv4Addr,   // IP клиента
    pub client_port: u16,      // Порт клиента
    pub server_ip: Ipv4Addr,   // IP сервера
    pub server_port: u16,      // Порт сервера
}

#[derive(Debug, Clone, Serialize, Deserialize)]  // Сессия = все пакеты одного TCP-соединения
pub struct Session {
    pub key: SessionKey,         // Идентификатор сессии
    pub packets: Vec<RawPacket>, // Все пакеты этой сессии (оба направления)
    pub first_timestamp: u64,    // Время первого пакета (для синхронизации с журналом)
    pub last_timestamp: u64,     // Время последнего пакета
    pub epoch: u32,
    pub roles_known: bool,
    pub diagnostics: SessionDiagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]  // Направление потока
pub enum FlowDirection {
    ClientToServer,  // От клиента к серверу
    ServerToClient,  // От сервера к клиенту
}

#[derive(Debug, Clone, Serialize, Deserialize)]  // Направленный поток (одно направление)
pub struct Flow {
    pub session_key: SessionKey, // К какой сессии относится
    pub direction: FlowDirection, // Направление (c2s или s2c)
    pub packets: Vec<RawPacket>, // Только пакеты этого направления
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]  // Диагностика сессии (требование 7.3)
pub struct SessionDiagnostics {
    pub handshake_complete: bool,   // Был ли полный SYN → SYN-ACK
    pub has_gaps: bool,             // Были ли пропуски в seq numbers
    pub has_retransmissions: bool,  // Были ли дубликаты пакетов
    pub missing_start: bool,        // Первый пакет не SYN (начало недоступно)
    pub has_conflicting_overlap: bool,
}