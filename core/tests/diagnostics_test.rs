mod common;

use protocol_lab_core::pcap::reader::read_pcap;
use protocol_lab_core::pcap::session::group_into_sessions;

fn sessions_of(relative: &str) -> Vec<protocol_lab_core::pcap::types::Session> {
    let packets = read_pcap(&common::fixtures_dir().join(relative)).expect("чтение фикстуры");
    group_into_sessions(&packets)
}

#[test]
fn fixture_missing_beginning_flags_roles_and_start() {
    let sessions = sessions_of("diagnostics/06_missing_beginning.pcapng");
    assert!(!sessions.is_empty());

    for session in &sessions {
        assert!(session.diagnostics.missing_start, "missing_start не выставлен");
        assert!(!session.diagnostics.handshake_complete, "handshake объявлен полным");
        assert!(!session.roles_known, "роли сторон объявлены определёнными");
    }
}

#[test]
fn fixture_conflicting_overlap_flagged_in_diagnostics() {
    let sessions = sessions_of("diagnostics/05_conflicting_overlap.pcap");
    assert!(sessions
        .iter()
        .any(|s| s.diagnostics.has_conflicting_overlap));
}

#[test]
fn fixture_missing_segment_flags_gap() {
    let sessions = sessions_of("diagnostics/03_missing_segment.pcap");
    assert!(sessions.iter().any(|s| s.diagnostics.has_gaps));
}

#[test]
fn fixture_retransmission_flags_retransmit() {
    let sessions = sessions_of("diagnostics/01_retransmission.pcap");
    assert!(sessions
        .iter()
        .any(|s| s.diagnostics.has_retransmissions));
}

#[test]
fn clean_research_sessions_have_full_handshake() {
    for relative in [
        "research/01_configuration.pcap",
        "research/02_variations.pcapng",
        "research/03_combined_messages.pcap",
    ] {
        let sessions = sessions_of(relative);
        for session in &sessions {
            assert!(session.diagnostics.handshake_complete, "{}", relative);
            assert!(!session.diagnostics.missing_start, "{}", relative);
            assert!(!session.diagnostics.has_gaps, "{}", relative);
            assert!(!session.diagnostics.has_conflicting_overlap, "{}", relative);
            assert!(session.roles_known, "{}", relative);
        }
    }
}
