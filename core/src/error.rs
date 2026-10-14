use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")] 
    Io(#[from] std::io::Error),

    #[error("PCAP parse error: {0}")]
    PcapParse(String),
    
    #[error("TCP reassembly error: {0}")]
    Reassembly(String),

    #[error("Checksum policy error: {0}")]
    Checksum(String),
}