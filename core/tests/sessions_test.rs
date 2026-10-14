mod common;

use protocol_lab_core::pcap::session::group_into_sessions;

#[test]
fn session_counts_match_manifest() {
    let manifest = common::manifest();
    let files = manifest["files"].as_object().expect("files в манифесте");
    for (relative, meta) in files {
        let expected = meta["sessions"].as_u64().expect("sessions") as usize;
        let packets = common::read_fixture(relative);
        let sessions = group_into_sessions(&packets);
        assert_eq!(sessions.len(), expected, "файл {}", relative);
    }
}

#[test]
fn sequential_connections_are_separate_sessions() {
    let packets = common::read_fixture("research/01_configuration.pcap");
    let sessions = group_into_sessions(&packets);

    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].key, sessions[1].key);
    assert!(sessions[0].last_timestamp <= sessions[1].first_timestamp);
    assert!(sessions[0].roles_known && sessions[1].roles_known);
}

#[test]
fn session_order_is_deterministic() {
    let packets = common::read_fixture("research/01_configuration.pcap");
    let first = group_into_sessions(&packets);
    let second = group_into_sessions(&packets);

    assert_eq!(first.len(), second.len());
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(a.first_timestamp, b.first_timestamp);
        assert_eq!(a.key, b.key);
        assert_eq!(a.epoch, b.epoch);
        assert_eq!(a.packets.len(), b.packets.len());
    }
}

#[test]
fn session_packets_are_chronological() {
    for relative in [
        "research/01_configuration.pcap",
        "research/02_variations.pcapng",
        "research/03_combined_messages.pcap",
        "additional/04_new_observations.pcapng",
    ] {
        let packets = common::read_fixture(relative);
        for session in group_into_sessions(&packets) {
            for pair in session.packets.windows(2) {
                assert!(
                    pair[0].timestamp_us <= pair[1].timestamp_us,
                    "{}: пакеты вне порядка времени",
                    relative
                );
            }
        }
    }
}
