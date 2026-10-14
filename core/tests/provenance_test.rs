mod common;

use protocol_lab_core::pcap::reader::read_pcap_with;
use protocol_lab_core::pcap::session::{group_into_sessions, split_into_flows};
use protocol_lab_core::tcp::reassembler::TcpReassembler;
use protocol_lab_core::tcp::stream::{locate, StreamChunk};
use std::fs;

fn read(relative: &str) -> protocol_lab_core::pcap::reader::ReadResult {
    read_pcap_with(&common::fixtures_dir().join(relative), Default::default())
        .unwrap_or_else(|e| panic!("{}: {}", relative, e))
}

fn all_flows(sessions: &[protocol_lab_core::pcap::types::Session]) -> Vec<Vec<StreamChunk>> {
    sessions
        .iter()
        .flat_map(|session| {
            let (c2s, s2c) = split_into_flows(session);
            let mut flows: Vec<Vec<StreamChunk>> = Vec::new();
            flows.push(TcpReassembler::reassemble(&c2s.packets));
            flows.push(TcpReassembler::reassemble(&s2c.packets));
            flows
        })
        .collect()
}

#[test]
fn every_payload_sits_at_its_payload_offset_in_file() {
    let relative = "research/01_configuration.pcap";
    let result = read(relative);
    let file_bytes = fs::read(common::fixtures_dir().join(relative)).expect("чтение файла");

    for packet in &result.packets {
        let base = result
            .payload_offsets
            .get(&packet.index)
            .expect("смещение payload");
        let start = *base as usize;
        let end = start + packet.payload.len();
        assert!(end <= file_bytes.len(), "пакет {} вне файла", packet.index);
        assert_eq!(
            &file_bytes[start..end],
            &packet.payload[..],
            "payload пакета {} не совпадает с файлом",
            packet.index
        );
    }
}

#[test]
fn locate_maps_stream_bytes_to_packets_and_file() {
    let relative = "research/01_configuration.pcap";
    let result = read(relative);
    let file_bytes = fs::read(common::fixtures_dir().join(relative)).expect("чтение файла");
    let sessions = group_into_sessions(&result.packets);
    let (c2s, _) = split_into_flows(&sessions[0]);
    let chunks = TcpReassembler::reassemble(&c2s.packets);

    let mut stream: Vec<u8> = Vec::new();
    for chunk in &chunks {
        if let StreamChunk::Data {
            flow_offset,
            length,
            packet_index,
        } = chunk
        {
            let packet = result
                .packets
                .iter()
                .find(|p| p.index == *packet_index)
                .expect("пакет");
            let start = packet.payload.len() - length;
            assert_eq!(*flow_offset, stream.len());
            stream.extend_from_slice(&packet.payload[start..]);
        }
    }
    assert!(!stream.is_empty());

    let probes = [
        0usize,
        1,
        stream.len() / 2,
        stream.len() / 3,
        stream.len() - 1,
    ];
    for offset in probes {
        let origin = locate(&chunks, &result.packets, &result.payload_offsets, offset)
            .expect("locate");
        let packet = result
            .packets
            .iter()
            .find(|p| p.index == origin.packet_index)
            .expect("пакет");
        assert_eq!(packet.payload[origin.payload_offset], stream[offset]);
        assert_eq!(
            file_bytes[origin.file_offset as usize],
            stream[offset],
            "байт потока {} не совпадает с файлом",
            offset
        );
    }
}

#[test]
fn locate_returns_none_on_gap() {
    let result = read("diagnostics/03_missing_segment.pcap");
    let sessions = group_into_sessions(&result.packets);
    let flows = all_flows(&sessions);

    let (chunks, gap_offset) = flows
        .iter()
        .find_map(|chunks| {
            let gap = chunks.iter().find_map(|chunk| match chunk {
                StreamChunk::Gap { flow_offset, .. } => Some(*flow_offset),
                _ => None,
            })?;
            Some((chunks, gap))
        })
        .expect("gap должен присутствовать");

    assert!(locate(
        chunks,
        &result.packets,
        &result.payload_offsets,
        gap_offset
    )
    .is_none());
}

#[test]
fn locate_uses_payload_suffix_after_overlap() {
    let relative = "diagnostics/05_conflicting_overlap.pcap";
    let result = read(relative);
    let file_bytes = fs::read(common::fixtures_dir().join(relative)).expect("чтение файла");
    let sessions = group_into_sessions(&result.packets);
    let flows = all_flows(&sessions);

    let mut checked = false;
    for chunks in &flows {
        for (i, chunk) in chunks.iter().enumerate() {
            let overlap_end = match chunk {
                StreamChunk::Overlap {
                    flow_offset,
                    length,
                    ..
                } => flow_offset + length,
                _ => continue,
            };
            let tail_flow = match chunks.get(i + 1) {
                Some(StreamChunk::Data {
                    flow_offset,
                    length,
                    ..
                }) if *flow_offset == overlap_end => (*flow_offset, *length),
                _ => continue,
            };

            let origin = locate(chunks, &result.packets, &result.payload_offsets, tail_flow.0)
                .expect("locate хвостового байта");
            let packet = result
                .packets
                .iter()
                .find(|p| p.index == origin.packet_index)
                .expect("пакет");
            assert_eq!(origin.payload_offset, packet.payload.len() - tail_flow.1);

            let rest = &packet.payload[origin.payload_offset..];
            let start = origin.file_offset as usize;
            assert_eq!(&file_bytes[start..start + rest.len()], rest);
            checked = true;
        }
    }
    assert!(checked, "хвостовой Data-чанк после Overlap не найден");
}
