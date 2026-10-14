use super::stream::StreamChunk;
use crate::pcap::types::RawPacket;

struct RangeInfo {
    seq_start: i64,
    flow_start: usize,
    length: usize,
    packet_index: Option<usize>,
    data_start: Option<usize>,
}

fn find_range(ranges: &[RangeInfo], seq: i64) -> Option<&RangeInfo> {
    let idx = ranges.partition_point(|r| r.seq_start <= seq);
    if idx == 0 {
        return None;
    }
    let range = &ranges[idx - 1];
    if seq < range.seq_start + range.length as i64 {
        Some(range)
    } else {
        None
    }
}

fn flow_pos(ranges: &[RangeInfo], seq: i64) -> Option<usize> {
    let idx = ranges.partition_point(|r| r.seq_start <= seq);
    if idx == 0 {
        return None;
    }
    let range = &ranges[idx - 1];
    let offset = seq - range.seq_start;
    if offset <= range.length as i64 {
        Some(range.flow_start + offset as usize)
    } else {
        None
    }
}

pub struct TcpReassembler;

impl TcpReassembler {
    pub fn reassemble(packets: &[RawPacket]) -> Vec<StreamChunk> { //отборщик пакетов в отборный массив
        if packets.is_empty() {
            return Vec::new(); 
        }

        let mut sorted: Vec<&RawPacket> = packets.iter()
            .filter(|p| !p.payload.is_empty())
            .collect();
        if sorted.is_empty() {
            return Vec::new();
        }

        let base = sorted
            .iter()
            .min_by_key(|p| (p.timestamp_us, p.index))
            .map(|p| p.seq)
            .unwrap_or(0);
        let anchor = packets
            .iter()
            .find(|p| p.flags.syn)
            .map(|p| p.seq.wrapping_add(1));
        let base = anchor.unwrap_or(base);
        sorted.sort_by_key(|p| (p.seq.wrapping_sub(base) as i32, p.timestamp_us, p.index)); //убираем говно

        let mut chunks = Vec::new();
        let mut ranges: Vec<RangeInfo> = Vec::new();
        let mut data_bytes: Vec<u8> = Vec::new();
        let mut flow_offset: usize = 0;
        let mut next_expected_rel: Option<i64> = if anchor.is_some() { Some(0) } else { None }; //номер первого элемента (пздц сложно)

        for packet in sorted {
            let rel = packet.seq.wrapping_sub(base) as i32 as i64;
            let fin_len = if packet.flags.fin { 1i64 } else { 0 };
            let pkt_end = rel + packet.payload.len() as i64 + fin_len;

            let expected = match next_expected_rel {
                None => rel,
                Some(value) => value,
            };
            if next_expected_rel.is_none() {
                next_expected_rel = Some(rel);
            }

            if rel > expected { //пакет позже чем надо
                let gap_size = (rel - expected) as usize;
                chunks.push(StreamChunk::Gap {
                    flow_offset,
                    missing_bytes: gap_size,
                });
                ranges.push(RangeInfo {
                    seq_start: expected,
                    flow_start: flow_offset,
                    length: gap_size,
                    packet_index: None,
                    data_start: None,
                });
                flow_offset += gap_size;
                next_expected_rel = Some(rel);
            }

            let expected = next_expected_rel.unwrap();

            if pkt_end <= expected { // типо мы вышли за рамки пакета 
                report_conflict(
                    &mut chunks,
                    &ranges,
                    &data_bytes,
                    packet,
                    rel,
                    pkt_end,
                    flow_offset,
                );
                continue;
            }

            if rel < expected {
                let overlap_start = (expected - rel) as usize; // начало новой части

                report_conflict(
                    &mut chunks,
                    &ranges,
                    &data_bytes,
                    packet,
                    rel,
                    expected,
                    flow_offset,
                );

                let new_data = &packet.payload[overlap_start..];
                chunks.push(StreamChunk::Data {
                    flow_offset,
                    length: new_data.len(),
                    packet_index: packet.index
                }); //добавили новый чанк (дополнение прошлого)

                ranges.push(RangeInfo {
                    seq_start: expected,
                    flow_start: flow_offset,
                    length: new_data.len(),
                    packet_index: Some(packet.index),
                    data_start: Some(data_bytes.len()),
                });
                data_bytes.extend_from_slice(new_data);
                flow_offset += new_data.len();
                next_expected_rel = Some(pkt_end);
                continue;
            }

            chunks.push(StreamChunk::Data {
                flow_offset,
                length: packet.payload.len(),
                packet_index: packet.index
            });
            ranges.push(RangeInfo {
                seq_start: rel,
                flow_start: flow_offset,
                length: packet.payload.len(),
                packet_index: Some(packet.index),
                data_start: Some(data_bytes.len()),
            });
            data_bytes.extend_from_slice(&packet.payload);
            flow_offset += packet.payload.len();
            next_expected_rel = Some(pkt_end);
        }
        chunks
    }
}

fn report_conflict(
    chunks: &mut Vec<StreamChunk>,
    ranges: &[RangeInfo],
    data_bytes: &[u8],
    packet: &RawPacket,
    rel: i64,
    region_end: i64,
    flow_offset: usize,
) {
    let cover_len = (region_end - rel).min(packet.payload.len() as i64);
    if cover_len <= 0 {
        return;
    }

    let mut first_conflict: Option<i64> = None;
    for i in 0..cover_len {
        let seq = rel + i;
        let range = match find_range(ranges, seq) {
            Some(range) => range,
            None => continue,
        };
        let data_start = match range.data_start {
            Some(value) => value,
            None => continue,
        };
        let chosen = data_bytes[data_start + (seq - range.seq_start) as usize];
        if chosen != packet.payload[i as usize] {
            first_conflict = Some(seq);
            break;
        }
    }

    let first_conflict = match first_conflict {
        Some(value) => value,
        None => return,
    };

    let start = flow_pos(ranges, rel).unwrap_or(flow_offset);
    let end = flow_pos(ranges, region_end).unwrap_or(flow_offset);
    if end <= start {
        return;
    }

    let chosen_packet = find_range(ranges, first_conflict)
        .and_then(|range| range.packet_index)
        .unwrap_or(packet.index);

    chunks.push(StreamChunk::Overlap {
        flow_offset: start,
        length: end - start,
        chosen_packet,
        conflicting_packets: vec![packet.index],
    });
}
