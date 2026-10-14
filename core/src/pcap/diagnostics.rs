use std::collections::HashSet;
use super::types::{Session, SessionDiagnostics};
use super::session::split_into_flows;
use crate::tcp::reassembler::TcpReassembler;
use crate::tcp::stream::StreamChunk;


//анализ и диагностика сессии
pub fn analyze_session(session: &Session) -> SessionDiagnostics {
    let mut has_syn = false; //флаг запроса на подключени
    let mut has_syn_ack = false; //ответ на запрос о подключении
    let mut has_retransmit = false; //лаги или потери :(
    let mut has_syn_seen = false;

    let mut seen_seqs: HashSet<u32> = HashSet::new(); //множется увиденных seq номеров

    for pkt in &session.packets {
        if pkt.flags.syn && !pkt.flags.ack {has_syn = true;} // Читых SYN
        if pkt.flags.syn && pkt.flags.ack {has_syn_ack = true;} // SYN-ACK
        if pkt.flags.syn {has_syn_seen = true;}
    }

    let (flow_c2s, flow_s2c) = split_into_flows(session); //раздел на потоки
    let mut chunks = TcpReassembler::reassemble(&flow_c2s.packets); //сбор потоков
    chunks.extend(TcpReassembler::reassemble(&flow_s2c.packets));

    let has_gaps = chunks.iter().any(|c| matches!(c, StreamChunk::Gap { .. })); //есть ли gap 
    let has_conflicting_overlap = chunks.iter().any(|c| matches!(c, StreamChunk::Overlap { .. }));

    for flow in [&flow_c2s, &flow_s2c] {
        seen_seqs.clear();
        for pkt in flow.packets.iter().filter(|p| !p.payload.is_empty()) {
            if !seen_seqs.insert(pkt.seq) {
                has_retransmit = true;
            }
        }
    }

    SessionDiagnostics {
        handshake_complete: has_syn && has_syn_ack,  // SYN + SYN-ACK
        has_gaps,                                    //дырочки в потоке
        has_retransmissions: has_retransmit,         // Ретрансмиты типр использовалось ли поток повторно уже когда то
        missing_start: !has_syn_seen,                // проблемс
        has_conflicting_overlap,
    }
}
