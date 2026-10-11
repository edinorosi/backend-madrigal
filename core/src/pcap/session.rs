use std::collections::HashMap;
use std::net::Ipv4Addr;


use super::types::{RawPacket, Session, SessionKey, Flow, FlowDirection};

pub fn group_into_sessions(packets: &[RawPacket]) -> Vec<Session> { //группировка сессий и типо возврат списка сессий пакистана
    let mut sessions_map: HashMap<SessionKey, Vec<RawPacket>> = HashMap::new();
    
    for packet in packets {
        let key = identify_session(packet);

        sessions_map.entry(key)
            .or_default()
            .push(packet.clone());
    }

    sessions_map.into_iter()
        .map(|(key, mut pkts) | {
            pkts.sort_by_key(|p| p.timestamp_us); //сортируем пакистан gj dhtvtyb
            let first = pkts.first().map(|p| p.timestamp_us).unwrap_or(0);
            let last = pkts.last().map(|p| p.timestamp_us).unwrap_or(0);
            
            Session {
                key,
                packets: pkts,
                first_timestamp: first,
                last_timestamp: last,
            }
        })
        .collect()
}

fn identify_session(packet: &RawPacket) -> SessionKey {
    let src = Ipv4Addr::from(packet.src_ip);
    let dst = Ipv4Addr::from(packet.dst_ip);

    //тут крч ебанутая проверка оба > 1024 или оба <= 1024, используем лексикографическое сравнение IP
    let is_src_client = if packet.src_port > 1024 && packet.dst_port <= 1024 {
        true
    } else if packet.src_port <= 1024 && packet.dst_port > 1024 {
        false
    } else {
        src < dst
    };

    if is_src_client {
        SessionKey { 
            client_ip: src, 
            client_port: packet.src_port, 
            server_ip: dst, 
            server_port: packet.dst_port
        }
    } else {
       SessionKey {
            client_ip: dst,
            client_port: packet.dst_port,
            server_ip: src,
            server_port: packet.src_port,
        }
    }
}

//кушаем сухарики и разделяем сессию на два потока (клиент-сервер и наоброт)
pub fn split_into_flows(session: &Session) -> (Flow, Flow) {
    let mut client_to_server = Vec::new();
    let mut server_to_client = Vec::new();

    for packet in &session.packets {
        if is_from_client(packet, &session.key) {
            client_to_server.push(packet.clone());
        } else {
            server_to_client.push(packet.clone());
        }
    }

    (
        Flow {
            session_key: session.key.clone(),
            direction: FlowDirection::ClientToServer,
            packets: client_to_server,
        },
        Flow {
            session_key: session.key.clone(),
            direction: FlowDirection::ServerToClient,
            packets: server_to_client,
        }
    )
}


//проверка кто отправил пакет 20кг
fn is_from_client(packet: &RawPacket, key: &SessionKey) -> bool {
    packet.src_ip == key.client_ip.octets() && packet.src_port == key.client_port
}





