use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag="type")]
pub enum StreamChunk {
    Data {
        flow_offset: usize,
        lenght: usize,
        packet_index: usize,
    },
    Gap {   
        flow_offset: usize,
        missing_bytes: usize,
    },
    Overlap {
        flow_offset: usize,
        length: usize,
        chosen_packet: usize,
        conflicting_packets: Vec<usize>,
    },
}