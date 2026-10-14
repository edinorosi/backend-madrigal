use protocol_lab_core::pcap::reader::read_pcap;
use protocol_lab_core::pcap::types::RawPacket;
use std::path::{Path, PathBuf};

pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
}

pub fn read_fixture(relative: &str) -> Vec<RawPacket> {
    let path = fixtures_dir().join(relative);
    read_pcap(&path).unwrap_or_else(|e| panic!("не удалось прочитать {}: {}", relative, e))
}

pub fn manifest() -> serde_json::Value {
    let path = fixtures_dir().join("dataset_manifest.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("не удалось прочитать {}: {}", path.display(), e));
    serde_json::from_str(&text).unwrap()
}
