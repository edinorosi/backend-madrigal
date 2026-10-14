use serde::{Deserialize, Serialize};

use crate::pcap::types::RawPacket;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag="type")]
pub enum StreamChunk {
    Data {
        flow_offset: usize,
        length: usize,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteOrigin {
    pub packet_index: usize,
    pub file_offset: u64,
    pub payload_offset: usize,
}

pub fn locate(
    chunks: &[StreamChunk],
    packets: &[RawPacket],
    payload_file_offsets: &HashMap<usize, u64>,
    stream_offset: usize,
) -> Option<ByteOrigin> {
    let (flow_offset, length, packet_index) = chunks.iter().find_map(|chunk| match chunk {
        StreamChunk::Data {
            flow_offset,
            length,
            packet_index,
        } if stream_offset >= *flow_offset && stream_offset < flow_offset + length => {
            Some((*flow_offset, *length, *packet_index))
        }
        _ => None,
    })?;

    let packet = packets.iter().find(|p| p.index == packet_index)?;
    let chunk_position = stream_offset - flow_offset;
    let payload_offset = packet.payload.len().checked_sub(length)? + chunk_position;
    let payload_base = *payload_file_offsets.get(&packet_index)?;

    Some(ByteOrigin {
        packet_index,
        file_offset: payload_base + payload_offset as u64,
        payload_offset,
    })
}