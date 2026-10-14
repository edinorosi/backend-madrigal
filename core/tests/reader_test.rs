mod common;

use protocol_lab_core::pcap::reader::{
    read_pcap_with, ChecksumPolicy, ChecksumStatus, ReadOptions,
};

fn read(relative: &str) -> protocol_lab_core::pcap::reader::ReadResult {
    read_pcap_with(&common::fixtures_dir().join(relative), ReadOptions::default())
        .unwrap_or_else(|e| panic!("{}: {}", relative, e))
}

#[test]
fn clean_fixtures_have_no_diagnostics() {
    for relative in [
        "research/01_configuration.pcap",
        "research/02_variations.pcapng",
        "research/03_combined_messages.pcap",
        "additional/04_new_observations.pcapng",
    ] {
        let result = read(relative);
        let d = &result.diagnostics;
        assert_eq!(d.frames_total, d.packets_tcp, "{}", relative);
        assert_eq!(d.dropped_malformed, 0, "{}", relative);
        assert_eq!(d.dropped_non_ipv4, 0, "{}", relative);
        assert_eq!(d.dropped_non_tcp, 0, "{}", relative);
        assert_eq!(d.truncated, 0, "{}", relative);
        assert_eq!(d.checksum_invalid, 0, "{}", relative);
        assert_eq!(d.checksum_offload, 0, "{}", relative);
        assert_eq!(d.checksum_valid, d.packets_tcp, "{}", relative);
    }
}

#[test]
fn snaplen_truncation_is_visible_and_payload_not_filled() {
    let result = read("diagnostics/04_snaplen_truncated.pcapng");
    let d = &result.diagnostics;

    assert_eq!(d.truncated, 1);
    assert_eq!(d.relaxed_parsed, 1);
    assert_eq!(d.dropped_malformed, 0);
    assert_eq!(d.checksum_unchecked, 1);

    let cut = result.packets.iter().find(|p| p.truncated).expect("усечённый пакет");
    assert!(cut.payload.iter().any(|b| *b != 0));
}

#[test]
fn offload_and_bad_checksum_are_different() {
    let offload = read("diagnostics/07_checksum_offload.pcap");
    assert!(offload.diagnostics.checksum_offload > 0);
    assert_eq!(offload.diagnostics.checksum_invalid, 0);

    let bad = read("diagnostics/08_bad_checksum.pcapng");
    assert_eq!(bad.diagnostics.checksum_invalid, 1);
    assert_eq!(bad.diagnostics.checksum_offload, 0);

    let invalid_index = bad
        .checksums
        .iter()
        .find(|(_, status)| **status == ChecksumStatus::Invalid)
        .map(|(index, _)| *index)
        .expect("пакет с неверным checksum");
    assert_eq!(bad.packets.iter().filter(|p| p.index == invalid_index).count(), 1);
}

#[test]
fn checksum_policy_reject_fails_only_on_invalid() {
    let options = ReadOptions {
        checksum_policy: ChecksumPolicy::Reject,
    };

    let path = common::fixtures_dir().join("diagnostics/08_bad_checksum.pcapng");
    assert!(read_pcap_with(&path, options.clone()).is_err());

    let path = common::fixtures_dir().join("diagnostics/07_checksum_offload.pcap");
    assert!(read_pcap_with(&path, options.clone()).is_ok());

    let path = common::fixtures_dir().join("research/01_configuration.pcap");
    assert!(read_pcap_with(&path, options).is_ok());
}

#[test]
fn checksum_policy_ignore_disables_checks() {
    let options = ReadOptions {
        checksum_policy: ChecksumPolicy::Ignore,
    };
    let path = common::fixtures_dir().join("diagnostics/08_bad_checksum.pcapng");
    let result = read_pcap_with(&path, options).expect("чтение");
    assert_eq!(result.diagnostics.checksum_unchecked, result.diagnostics.packets_tcp);
    assert_eq!(result.diagnostics.checksum_invalid, 0);
}

#[test]
fn sha256_is_stable_and_distinct_per_file() {
    let first = read("research/01_configuration.pcap");
    let second = read("research/01_configuration.pcap");
    let other = read("research/02_variations.pcapng");

    assert_eq!(first.diagnostics.sha256, second.diagnostics.sha256);
    assert_ne!(first.diagnostics.sha256, other.diagnostics.sha256);
    assert_eq!(first.diagnostics.sha256.len(), 64);
    assert_eq!(first.diagnostics.file_size, second.diagnostics.file_size);
}

#[test]
fn file_offsets_cover_every_parsed_packet() {
    for relative in [
        "research/01_configuration.pcap",
        "research/02_variations.pcapng",
    ] {
        let result = read(relative);
        assert_eq!(result.file_offsets.len(), result.packets.len(), "{}", relative);
        for (index, offset) in &result.file_offsets {
            assert!(*offset < result.diagnostics.file_size, "{}", relative);
            assert!(result.packets.iter().any(|p| p.index == *index), "{}", relative);
        }
    }
}
