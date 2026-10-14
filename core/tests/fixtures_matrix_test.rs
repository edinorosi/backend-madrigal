mod common;

use protocol_lab_core::pcap::reader::read_pcap_with;
use protocol_lab_core::pcap::session::{group_into_sessions, split_into_flows};
use protocol_lab_core::tcp::reassembler::TcpReassembler;
use protocol_lab_core::tcp::stream::StreamChunk;
use std::collections::HashSet;
use std::fs;

const ALL_FIXTURES: [&str; 12] = [
    "research/01_configuration.pcap",
    "research/02_variations.pcapng",
    "research/03_combined_messages.pcap",
    "additional/04_new_observations.pcapng",
    "diagnostics/01_retransmission.pcap",
    "diagnostics/02_reordered.pcapng",
    "diagnostics/03_missing_segment.pcap",
    "diagnostics/04_snaplen_truncated.pcapng",
    "diagnostics/05_conflicting_overlap.pcap",
    "diagnostics/06_missing_beginning.pcapng",
    "diagnostics/07_checksum_offload.pcap",
    "diagnostics/08_bad_checksum.pcapng",
];

fn read(relative: &str) -> protocol_lab_core::pcap::reader::ReadResult {
    read_pcap_with(&common::fixtures_dir().join(relative), Default::default())
        .unwrap_or_else(|e| panic!("{}: {}", relative, e))
}

fn flows(relative: &str) -> (Vec<Vec<u8>>, Vec<Vec<StreamChunk>>) {
    let packets = read(relative).packets;
    let sessions = group_into_sessions(&packets);
    let mut streams = Vec::new();
    let mut all_chunks = Vec::new();
    for session in &sessions {
        let (c2s, s2c) = split_into_flows(session);
        for flow in [&c2s, &s2c] {
            let chunks = TcpReassembler::reassemble(&flow.packets);
            let mut bytes: Vec<u8> = Vec::new();
            for chunk in &chunks {
                if let StreamChunk::Data {
                    length,
                    packet_index,
                    ..
                } = chunk
                {
                    let packet = packets
                        .iter()
                        .find(|p| p.index == *packet_index)
                        .expect("пакет");
                    let start = packet.payload.len() - length;
                    bytes.extend_from_slice(&packet.payload[start..]);
                }
            }
            streams.push(bytes);
            all_chunks.push(chunks);
        }
    }
    (streams, all_chunks)
}

fn reference() -> Vec<Vec<u8>> {
    let (streams, _) = flows("research/03_combined_messages.pcap");
    assert_eq!(streams.len(), 2);
    streams
}

#[test]
fn all_12_fixtures_load_with_complete_provenance() {
    let mut shas: HashSet<String> = HashSet::new();
    for relative in ALL_FIXTURES {
        let result = read(relative);
        assert!(!result.packets.is_empty(), "{}", relative);
        assert_eq!(result.file_offsets.len(), result.packets.len(), "{}", relative);
        assert_eq!(
            result.payload_offsets.len(),
            result.packets.len(),
            "{}",
            relative
        );
        assert_eq!(result.diagnostics.sha256.len(), 64, "{}", relative);
        assert!(
            shas.insert(result.diagnostics.sha256.clone()),
            "sha256 повторяется: {}",
            relative
        );

        let file = fs::read(common::fixtures_dir().join(relative)).expect("чтение файла");
        for packet in &result.packets {
            if packet.truncated {
                continue;
            }
            let base = result.payload_offsets[&packet.index] as usize;
            let end = base + packet.payload.len();
            assert!(
                end <= file.len(),
                "{} пакет {} вне файла",
                relative,
                packet.index
            );
            assert_eq!(
                &file[base..end],
                &packet.payload[..],
                "{} payload пакета {} не привязан к файлу",
                relative,
                packet.index
            );
        }
    }
}

#[test]
fn intact_variants_reassemble_identically_to_reference() {
    let reference = reference();

    for relative in [
        "diagnostics/01_retransmission.pcap",
        "diagnostics/02_reordered.pcapng",
        "diagnostics/05_conflicting_overlap.pcap",
        "diagnostics/07_checksum_offload.pcap",
        "diagnostics/08_bad_checksum.pcapng",
    ] {
        let (streams, _) = flows(relative);
        assert_eq!(streams.len(), 2, "{}", relative);
        assert_eq!(streams[0], reference[0], "{} c2s", relative);
        assert_eq!(streams[1], reference[1], "{} s2c", relative);
    }
}

#[test]
fn defect_variants_lose_only_their_defect() {
    let reference = reference();

    let (streams, _) = flows("diagnostics/03_missing_segment.pcap");
    assert_eq!(streams[0], reference[0], "03 c2s");
    assert_eq!(
        streams[1],
        reference[1][35..],
        "03 s2c теряет префикс 35 байт"
    );

    let (streams, _) = flows("diagnostics/04_snaplen_truncated.pcapng");
    assert_eq!(streams[0], reference[0], "04 c2s");
    assert!(
        streams[1].len() < reference[1].len(),
        "04 s2c должен быть короче"
    );

    let (streams, _) = flows("diagnostics/06_missing_beginning.pcapng");
    assert!(
        streams[0].len() < reference[0].len(),
        "06 c2s должен быть короче"
    );
    assert_eq!(streams[1], reference[1], "06 s2c");
}

#[test]
fn defect_variants_report_their_conditions() {
    let (streams, chunks) = flows("diagnostics/03_missing_segment.pcap");
    let gaps: Vec<(usize, usize)> = chunks
        .iter()
        .flatten()
        .filter_map(|chunk| match chunk {
            StreamChunk::Gap {
                flow_offset,
                missing_bytes,
            } => Some((*flow_offset, *missing_bytes)),
            _ => None,
        })
        .collect();
    assert_eq!(gaps, vec![(0, 35)], "03: единственный gap в начале s2c");
    assert_eq!(streams[1].len() + 35, reference()[1].len());

    let result = read("diagnostics/04_snaplen_truncated.pcapng");
    assert_eq!(result.diagnostics.truncated, 1);
    assert!(
        group_into_sessions(&result.packets)
            .iter()
            .any(|s| s.diagnostics.has_gaps),
        "04: усечение должно давать пропуск в потоке"
    );

    let sessions = group_into_sessions(&read("diagnostics/06_missing_beginning.pcapng").packets);
    assert!(sessions.iter().all(|s| s.diagnostics.missing_start));
    assert!(sessions.iter().all(|s| !s.roles_known));
}

#[test]
fn reference_experiment_carries_requests_and_device_responses() {
    let streams = reference();
    let c2s = String::from_utf8_lossy(&streams[0]);
    let s2c = String::from_utf8_lossy(&streams[1]);

    assert!(c2s.contains("North"), "запросы клиента не содержат label");
    assert!(s2c.contains("Lab"), "ответы устройства не видны");
    assert_eq!(streams[0].len(), 79);
    assert_eq!(streams[1].len(), 279);
}
