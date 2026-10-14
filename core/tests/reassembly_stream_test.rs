mod common;

use protocol_lab_core::pcap::reader::read_pcap;
use protocol_lab_core::pcap::session::{group_into_sessions, split_into_flows};
use protocol_lab_core::pcap::types::{RawPacket, TcpFlags};
use protocol_lab_core::tcp::reassembler::TcpReassembler;
use protocol_lab_core::tcp::stream::StreamChunk;

fn packet(index: usize, timestamp_us: u64, seq: u32, payload: Vec<u8>, fin: bool) -> RawPacket {
    RawPacket {
        index,
        timestamp_us,
        src_ip: [10, 0, 0, 1],
        dst_ip: [10, 0, 0, 2],
        src_port: 40000,
        dst_port: 46123,
        seq,
        ack: 0,
        flags: TcpFlags {
            syn: false,
            fin,
            rst: false,
            ack: true,
        },
        payload,
        truncated: false,
    }
}

#[test]
fn sequence_wraparound_orders_correctly() {
    let first = packet(0, 100, 0xFFFF_FFFE, vec![1, 2], false);
    let second = packet(1, 200, 0x0000_0000, vec![3, 4], false);

    let chunks = TcpReassembler::reassemble(&[second, first]);

    assert_eq!(chunks.len(), 2);
    match &chunks[0] {
        StreamChunk::Data { flow_offset, length, .. } => {
            assert_eq!(*flow_offset, 0);
            assert_eq!(*length, 2);
        }
        other => panic!("ожидался Data, получено {:?}", other),
    }
    match &chunks[1] {
        StreamChunk::Data { flow_offset, length, .. } => {
            assert_eq!(*flow_offset, 2);
            assert_eq!(*length, 2);
        }
        other => panic!("ожидался Data, получено {:?}", other),
    }
}

#[test]
fn fin_consumes_one_sequence_number() {
    let with_fin = packet(0, 100, 1000, vec![1, 2, 3], true);
    let next = packet(1, 200, 1004, vec![4, 5], false);

    let chunks = TcpReassembler::reassemble(&[with_fin, next]);

    assert_eq!(chunks.len(), 2);
    assert!(matches!(chunks[0], StreamChunk::Data { length: 3, .. }));
    assert!(matches!(chunks[1], StreamChunk::Data { length: 2, .. }));
}

#[test]
fn conflicting_overlap_is_reported_and_bytes_kept() {
    let first = packet(0, 100, 1000, vec![1, 2, 3], false);
    let second = packet(1, 200, 1002, vec![9, 9], false);

    let chunks = TcpReassembler::reassemble(&[first, second]);

    assert_eq!(chunks.len(), 3);
    assert!(matches!(
        chunks[0],
        StreamChunk::Data { flow_offset: 0, length: 3, .. }
    ));
    match &chunks[1] {
        StreamChunk::Overlap {
            flow_offset,
            length,
            chosen_packet,
            conflicting_packets,
        } => {
            assert_eq!(*flow_offset, 2);
            assert_eq!(*length, 1);
            assert_eq!(*chosen_packet, 0);
            assert_eq!(conflicting_packets, &vec![1]);
        }
        other => panic!("ожидался Overlap, получено {:?}", other),
    }
    match &chunks[2] {
        StreamChunk::Data { flow_offset, length, .. } => {
            assert_eq!(*flow_offset, 3);
            assert_eq!(*length, 1);
        }
        other => panic!("ожидался Data, получено {:?}", other),
    }
}

#[test]
fn identical_overlap_stays_silent() {
    let first = packet(0, 100, 1000, vec![1, 2, 3], false);
    let second = packet(1, 200, 1002, vec![3, 4], false);

    let chunks = TcpReassembler::reassemble(&[first, second]);

    assert_eq!(chunks.len(), 2);
    assert!(chunks
        .iter()
        .all(|chunk| matches!(chunk, StreamChunk::Data { .. })));
}

#[test]
fn fixture_conflicting_overlap_produces_overlap_chunk() {
    let packets = read_pcap(&common::fixtures_dir().join("diagnostics/05_conflicting_overlap.pcap"))
        .expect("чтение фикстуры");
    let sessions = group_into_sessions(&packets);

    let overlaps: usize = sessions
        .iter()
        .flat_map(|session| {
            let (c2s, s2c) = split_into_flows(session);
            let mut all = TcpReassembler::reassemble(&c2s.packets);
            all.extend(TcpReassembler::reassemble(&s2c.packets));
            all
        })
        .filter(|chunk| matches!(chunk, StreamChunk::Overlap { .. }))
        .count();

    assert!(overlaps > 0, "конфликтное перекрытие не обнаружено");
}

#[test]
fn fixture_missing_segment_produces_gap() {
    let packets = read_pcap(&common::fixtures_dir().join("diagnostics/03_missing_segment.pcap"))
        .expect("чтение фикстуры");
    let sessions = group_into_sessions(&packets);

    let gaps: usize = sessions
        .iter()
        .flat_map(|session| {
            let (c2s, s2c) = split_into_flows(session);
            let mut all = TcpReassembler::reassemble(&c2s.packets);
            all.extend(TcpReassembler::reassemble(&s2c.packets));
            all
        })
        .filter(|chunk| matches!(chunk, StreamChunk::Gap { .. }))
        .count();

    assert!(gaps > 0, "пропуск сегмента не обнаружен");
}

#[test]
fn fixture_retransmission_does_not_duplicate_bytes() {
    let packets = read_pcap(&common::fixtures_dir().join("diagnostics/01_retransmission.pcap"))
        .expect("чтение фикстуры");
    let sessions = group_into_sessions(&packets);
    assert_eq!(sessions.len(), 1);

    let (c2s, s2c) = split_into_flows(&sessions[0]);
    let chunks = TcpReassembler::reassemble(&c2s.packets);
    let mut other = TcpReassembler::reassemble(&s2c.packets);

    let stream_len: usize = chunks
        .iter()
        .chain(other.iter())
        .filter_map(|chunk| match chunk {
            StreamChunk::Data { length, .. } => Some(*length),
            _ => None,
        })
        .sum();
    let payload_len: usize = c2s
        .packets
        .iter()
        .chain(s2c.packets.iter())
        .map(|p| p.payload.len())
        .sum();

    assert!(stream_len < payload_len, "ретрансмит не был отброшен");
    assert!(!chunks
        .iter()
        .any(|chunk| matches!(chunk, StreamChunk::Gap { .. })));
    assert!(!chunks
        .iter()
        .any(|chunk| matches!(chunk, StreamChunk::Overlap { .. })));

    let mut position = 0usize;
    for chunk in &chunks {
        if let StreamChunk::Data { flow_offset, .. } = chunk {
            assert_eq!(*flow_offset, position);
        }
        if let StreamChunk::Data {
            flow_offset,
            length,
            ..
        } = chunk
        {
            position = flow_offset + length;
        }
    }
    let _ = s2c;
}

#[test]
fn fixture_combined_messages_reassembly_is_deterministic() {
    let packets = read_pcap(&common::fixtures_dir().join("research/03_combined_messages.pcap"))
        .expect("чтение фикстуры");

    let run = || {
        let sessions = group_into_sessions(&packets);
        let all: Vec<serde_json::Value> = sessions
            .iter()
            .flat_map(|session| {
                let (c2s, s2c) = split_into_flows(session);
                let mut chunks = TcpReassembler::reassemble(&c2s.packets);
                chunks.extend(TcpReassembler::reassemble(&s2c.packets));
                chunks
            })
            .map(|chunk| serde_json::to_value(&chunk).expect("сериализация"))
            .collect();
        all
    };

    let first = run();
    let second = run();
    assert!(!first.is_empty());
    assert_eq!(first, second);
}
