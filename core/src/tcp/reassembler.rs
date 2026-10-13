use super::stream::StreamChunk;
use crate::pcap::types::RawPacket;

pub struct TcpReassembler;

impl TcpReassembler {
    pub fn reassemble(packets: &[RawPacket]) -> Vec<StreamChunk> { //отборщик пакетов в отборный массив
        if packets.is_empty() {
            return Vec::new(); 
        }

        let mut sorted: Vec<&RawPacket> = packets.iter()
            .filter(|p| !p.payload.is_empty())
            .collect();
        sorted.sort_by_key(|p| p.seq); //убираем говно

        let mut chunks = Vec::new();
        let mut next_expected_seq = sorted[0].seq; //номер первого элемента (пздц сложно)
        let mut flow_offset: usize = 0;

        for packet in sorted {
            let pkt_end = packet.seq.wrapping_add(packet.payload.len() as u32);
            
            if packet.seq > next_expected_seq { //пакет позже чем надо
                let gap_size = (packet.seq - next_expected_seq) as usize;
                chunks.push(StreamChunk::Gap {
                    flow_offset,
                    missing_bytes: gap_size,
                });
                flow_offset += gap_size;
                next_expected_seq = packet.seq;
            }

            if pkt_end <= next_expected_seq { // типо мы вышли за рамки пакета 
                continue;
            }

            if packet.seq < next_expected_seq {
                let overlap_start = (next_expected_seq - packet.seq) as usize; // начало новой части
                let new_data = &packet.payload[overlap_start..];
                chunks.push(StreamChunk::Data {
                    flow_offset,
                    length: new_data.len(),
                    packet_index: packet.index
                }); //добавили новый чанк (дополнение прошлого)

                flow_offset += new_data.len();
                next_expected_seq = pkt_end;
                continue;
            }

            chunks.push(StreamChunk::Data {
                flow_offset,
                length: packet.payload.len(),
                packet_index: packet.index
            });
            flow_offset += packet.payload.len();
            next_expected_seq = pkt_end;
        }
        chunks
    }
}