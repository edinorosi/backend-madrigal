use std::collections::HashMap;
use std::net::Ipv4Addr;


use super::diagnostics::analyze_session;
use super::types::{RawPacket, Session, SessionDiagnostics, SessionKey, Flow, FlowDirection};

#[derive(PartialEq, Eq, Hash)]
struct TupleKey {
    client_ip: Ipv4Addr,
    client_port: u16,
    server_ip: Ipv4Addr,
    server_port: u16,
}

struct OpenConnection {
    packets: Vec<RawPacket>,
    isn: Option<u32>,
    closed: bool,
    client: Option<(Ipv4Addr, u16)>,
}

pub fn group_into_sessions(packets: &[RawPacket]) -> Vec<Session> { //группировка сессий и типо возврат списка сессий пакистана
    let mut ordered: Vec<&RawPacket> = packets.iter().collect();
    ordered.sort_by_key(|p| (p.timestamp_us, p.index));

    let mut groups: HashMap<TupleKey, Vec<OpenConnection>> = HashMap::new();

    for packet in ordered {
        let tuple = identify_tuple(packet);
        let connections = groups.entry(tuple).or_default();

        let syn_start = packet.flags.syn && !packet.flags.ack;

        let need_new = match connections.last() {
            None => true,
            Some(current) => {
                if !syn_start {
                    false
                } else if current.closed {
                    true
                } else if let Some(open_isn) = current.isn {
                    open_isn != packet.seq
                } else {
                    current.packets.iter().any(|p| !p.payload.is_empty())
                }
            }
        };

        if need_new {
            connections.push(OpenConnection {
                packets: Vec::new(),
                isn: None,
                closed: false,
                client: None,
            });
        }

        let current = connections.last_mut().unwrap();

        if syn_start {
            if current.isn.is_none() {
                current.isn = Some(packet.seq);
            }
            if current.client.is_none() {
                current.client = Some((Ipv4Addr::from(packet.src_ip), packet.src_port));
            }
        }

        current.packets.push(packet.clone());

        if packet.flags.rst || packet.flags.fin {
            current.closed = true;
        }
    }

    let mut sessions: Vec<Session> = Vec::new();

    for (_tuple, connections) in groups {
        for (epoch, connection) in connections.into_iter().enumerate() {
            let mut pkts = connection.packets;
            if pkts.is_empty() {
                continue;
            }
            pkts.sort_by_key(|p| p.timestamp_us); //сортируем пакистан gj dhtvtyb
            let first = pkts.first().map(|p| p.timestamp_us).unwrap_or(0);
            let last = pkts.last().map(|p| p.timestamp_us).unwrap_or(0);

            let key = match connection.client {
                Some((client_ip, client_port)) => {
                    let head = &pkts[0];
                    let same_direction = Ipv4Addr::from(head.src_ip) == client_ip && head.src_port == client_port;
                    if same_direction {
                        SessionKey {
                            client_ip,
                            client_port,
                            server_ip: Ipv4Addr::from(head.dst_ip),
                            server_port: head.dst_port,
                        }
                    } else {
                        SessionKey {
                            client_ip,
                            client_port,
                            server_ip: Ipv4Addr::from(head.src_ip),
                            server_port: head.src_port,
                        }
                    }
                }
                None => identify_session(&pkts[0]),
            };
            let mut session = Session {
                key,
                packets: pkts,
                first_timestamp: first,
                last_timestamp: last,
                epoch: epoch as u32,
                roles_known: connection.client.is_some(),
                diagnostics: SessionDiagnostics::default(),
            };
            session.diagnostics = analyze_session(&session);
            sessions.push(session);
        }
    }

    sessions.sort_by(|a, b| {
        a.first_timestamp
            .cmp(&b.first_timestamp)
            .then_with(|| a.key.cmp(&b.key))
            .then_with(|| a.epoch.cmp(&b.epoch))
    });
    sessions
}

fn identify_tuple(packet: &RawPacket) -> TupleKey {
    let key = identify_session(packet);
    TupleKey {
        client_ip: key.client_ip,
        client_port: key.client_port,
        server_ip: key.server_ip,
        server_port: key.server_port,
    }
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
