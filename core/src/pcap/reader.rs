use etherparse::{LaxPacketHeaders, NetHeaders, PacketHeaders, TransportHeader};
use pcap_parser::{PcapBlockOwned, PcapError, create_reader};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Cursor;
use std::path::Path;

use super::types::{RawPacket, TcpFlags};
use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumPolicy {
    Ignore,
    Warn,
    Reject,
}

impl Default for ChecksumPolicy {
    fn default() -> Self {
        ChecksumPolicy::Warn
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumStatus {
    Valid,
    Invalid,
    OffloadSuspected,
    Unchecked,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureDiagnostics {
    pub frames_total: u32,
    pub packets_tcp: u32,
    pub dropped_malformed: u32,
    pub dropped_non_ipv4: u32,
    pub dropped_non_tcp: u32,
    pub truncated: u32,
    pub relaxed_parsed: u32,
    pub checksum_valid: u32,
    pub checksum_invalid: u32,
    pub checksum_offload: u32,
    pub checksum_unchecked: u32,
    pub file_size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct ReadOptions {
    pub checksum_policy: ChecksumPolicy,
}

impl Default for ReadOptions {
    fn default() -> Self {
        ReadOptions {
            checksum_policy: ChecksumPolicy::Warn,
        }
    }
}

pub struct ReadResult {
    pub packets: Vec<RawPacket>,
    pub diagnostics: CaptureDiagnostics,
    pub file_offsets: HashMap<usize, u64>,
    pub payload_offsets: HashMap<usize, u64>,
    pub checksums: HashMap<usize, ChecksumStatus>,
}

enum FrameClass {
    Tcp {
        packet: RawPacket,
        checksum: ChecksumStatus,
        relaxed: bool,
        payload_file_offset: u64,
    },
    NonTcp,
    NonIpv4,
    Malformed,
}

pub fn read_pcap(path: &Path) -> Result<Vec<RawPacket>, Error> {
    Ok(read_pcap_with(path, ReadOptions::default())?.packets)
}

pub fn read_pcap_with(path: &Path, options: ReadOptions) -> Result<ReadResult, Error> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = format!("{:x}", hasher.finalize());

    let mut reader =
        create_reader(65536, Cursor::new(bytes.as_slice())).map_err(|e| Error::PcapParse(format!("{e:?}")))?;

    let mut packets = Vec::new();
    let mut diagnostics = CaptureDiagnostics {
        file_size: bytes.len() as u64,
        sha256,
        ..Default::default()
    };
    let mut file_offsets: HashMap<usize, u64> = HashMap::new();
    let mut payload_offsets: HashMap<usize, u64> = HashMap::new();
    let mut checksums: HashMap<usize, ChecksumStatus> = HashMap::new();
    let mut index: usize = 0;
    let mut block_offset: u64 = 0;

    loop {
        match reader.next() {
            Ok((block_size, block)) => {
                let data: Option<(u64, &[u8], u64, bool)> = match &block {
                    PcapBlockOwned::Legacy(b) => {
                        let ts_us = b.ts_sec as u64 * 1_000_000 + b.ts_usec as u64;
                        Some((ts_us, b.data, block_offset + 16, b.caplen < b.origlen))
                    }
                    PcapBlockOwned::LegacyHeader(_) => None,
                    PcapBlockOwned::NG(b) => match b {
                        pcap_parser::Block::EnhancedPacket(epb) => {
                            let ts = ((epb.ts_high as u64) << 32) | epb.ts_low as u64;
                            Some((ts, epb.data, block_offset + 28, epb.caplen < epb.origlen))
                        }
                        pcap_parser::Block::SimplePacket(spb) => {
                            Some((0, spb.data, block_offset + 12, false))
                        }
                        _ => None,
                    },
                };

                if let Some((timestamp_us, frame, frame_offset, truncated)) = data {
                    diagnostics.frames_total += 1;
                    if truncated {
                        diagnostics.truncated += 1;
                    }

                    match parse_raw_packet(frame, timestamp_us, index, truncated, frame_offset, options.checksum_policy) {
                        FrameClass::Tcp {
                            packet,
                            checksum,
                            relaxed,
                            payload_file_offset,
                        } => {
                            diagnostics.packets_tcp += 1;
                            if relaxed {
                                diagnostics.relaxed_parsed += 1;
                            }
                            match checksum {
                                ChecksumStatus::Valid => diagnostics.checksum_valid += 1,
                                ChecksumStatus::Invalid => diagnostics.checksum_invalid += 1,
                                ChecksumStatus::OffloadSuspected => diagnostics.checksum_offload += 1,
                                ChecksumStatus::Unchecked => diagnostics.checksum_unchecked += 1,
                            }
                            file_offsets.insert(index, frame_offset);
                            payload_offsets.insert(index, payload_file_offset);
                            checksums.insert(index, checksum);
                            packets.push(packet);
                        }
                        FrameClass::NonTcp => diagnostics.dropped_non_tcp += 1,
                        FrameClass::NonIpv4 => diagnostics.dropped_non_ipv4 += 1,
                        FrameClass::Malformed => diagnostics.dropped_malformed += 1,
                    }
                    // index = номер пакета в capture, а не только TCP
                    index += 1;
                }
                block_offset += block_size as u64;
                reader.consume(block_size);
            }
            Err(PcapError::Eof) => break,
            // Пакет не влез в 64-КиБ окно чтения — долить буфер и
            // повторить, а не молча обрезать capture на полуслове.
            Err(PcapError::Incomplete(_)) => match reader.refill() {
                Ok(()) => continue,
                Err(PcapError::Eof) => {
                    diagnostics.truncated += 1;
                    break;
                }
                Err(e) => return Err(Error::PcapParse(format!("{e:?}"))),
            },
            Err(e) => return Err(Error::PcapParse(format!("{e:?}"))),
        }
    }

    if options.checksum_policy == ChecksumPolicy::Reject && diagnostics.checksum_invalid > 0 {
        return Err(Error::Checksum(format!(
            "политика reject: {} пакетов с неверным TCP checksum",
            diagnostics.checksum_invalid
        )));
    }

    Ok(ReadResult {
        packets,
        diagnostics,
        file_offsets,
        payload_offsets,
        checksums,
    })
}

fn parse_raw_packet(
    data: &[u8],
    timestamp_us: u64,
    index: usize,
    truncated: bool,
    frame_offset: u64,
    policy: ChecksumPolicy,
) -> FrameClass {
    // Большинство захватов — Ethernet, fallback на сырой IP.
    if let Some(headers) = PacketHeaders::from_ethernet_slice(data)
        .ok()
        .or_else(|| PacketHeaders::from_ip_slice(data).ok())
    {
        let link_len = headers.link.as_ref().map(|l| l.header_len()).unwrap_or(0)
            + headers.link_exts.iter().map(|h| h.header_len()).sum::<usize>();
        return classify_frame(
            data,
            link_len,
            headers.net.as_ref(),
            headers.transport.as_ref(),
            headers.payload.slice(),
            truncated,
            false,
            timestamp_us,
            index,
            frame_offset,
            policy,
        );
    }

    if let Ok(headers) = LaxPacketHeaders::from_ethernet(data) {
        let link_len = headers.link.as_ref().map(|l| l.header_len()).unwrap_or(0)
            + headers.link_exts.iter().map(|h| h.header_len()).sum::<usize>();
        return classify_frame(
            data,
            link_len,
            headers.net.as_ref(),
            headers.transport.as_ref(),
            headers.payload.slice(),
            truncated,
            true,
            timestamp_us,
            index,
            frame_offset,
            policy,
        );
    }

    if let Ok(headers) = LaxPacketHeaders::from_ip(data) {
        let link_len = headers.link.as_ref().map(|l| l.header_len()).unwrap_or(0)
            + headers.link_exts.iter().map(|h| h.header_len()).sum::<usize>();
        return classify_frame(
            data,
            link_len,
            headers.net.as_ref(),
            headers.transport.as_ref(),
            headers.payload.slice(),
            truncated,
            true,
            timestamp_us,
            index,
            frame_offset,
            policy,
        );
    }

    FrameClass::Malformed
}

fn classify_frame(
    frame: &[u8],
    link_len: usize,
    net: Option<&NetHeaders>,
    transport: Option<&TransportHeader>,
    payload: &[u8],
    truncated: bool,
    relaxed: bool,
    timestamp_us: u64,
    index: usize,
    frame_offset: u64,
    policy: ChecksumPolicy,
) -> FrameClass {
    let (src_ip, dst_ip) = match net {
        Some(NetHeaders::Ipv4(hdr, _)) => (hdr.source, hdr.destination),
        Some(NetHeaders::Ipv6(_, _)) | Some(NetHeaders::Arp(_)) => return FrameClass::NonIpv4,
        None => return FrameClass::Malformed,
    };

    let tcp = match transport {
        Some(TransportHeader::Tcp(t)) => t,
        Some(_) => return FrameClass::NonTcp,
        None => return FrameClass::Malformed,
    };

    let checksum = match policy {
        ChecksumPolicy::Ignore => ChecksumStatus::Unchecked,
        ChecksumPolicy::Warn | ChecksumPolicy::Reject => {
            verify_tcp_checksum(frame, link_len, net, transport)
        }
    };

    let ipv4_header_len = match net {
        Some(NetHeaders::Ipv4(hdr, _)) => hdr.header_len() as u64,
        _ => 0,
    };
    let payload_file_offset =
        frame_offset + link_len as u64 + ipv4_header_len + tcp.header_len() as u64;

    let packet = RawPacket {
        index,
        timestamp_us,
        src_ip,
        dst_ip,
        src_port: tcp.source_port,
        dst_port: tcp.destination_port,
        seq: tcp.sequence_number,
        ack: tcp.acknowledgment_number,
        flags: TcpFlags {
            syn: tcp.syn,
            fin: tcp.fin,
            rst: tcp.rst,
            ack: tcp.ack,
        },
        payload: payload.to_vec(),
        truncated: truncated || relaxed,
    };

    FrameClass::Tcp {
        packet,
        checksum,
        relaxed,
        payload_file_offset,
    }
}

fn verify_tcp_checksum(
    frame: &[u8],
    link_len: usize,
    net: Option<&NetHeaders>,
    transport: Option<&TransportHeader>,
) -> ChecksumStatus {
    let ipv4 = match net {
        Some(NetHeaders::Ipv4(ipv4, _)) => ipv4,
        _ => return ChecksumStatus::Unchecked,
    };
    if !matches!(transport, Some(TransportHeader::Tcp(_))) {
        return ChecksumStatus::Unchecked;
    }

    let ip_start = link_len;
    let ip_header_len = ipv4.header_len();
    let ip_total = ipv4.total_len as usize;
    let segment_end = ip_start + ip_total;

    if ip_total < ip_header_len + 20 || segment_end > frame.len() {
        return ChecksumStatus::Unchecked;
    }

    let segment = &frame[ip_start + ip_header_len..segment_end];
    let stored = u16::from_be_bytes([segment[16], segment[17]]);

    let mut pseudo: u32 = 0;
    for word in ipv4.source.chunks(2) {
        pseudo += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    for word in ipv4.destination.chunks(2) {
        pseudo += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    pseudo += 0x0006;
    pseudo += (ip_total - ip_header_len) as u16 as u32;
    let pseudo_folded = fold_sum(pseudo);

    if fold_sum(pseudo + sum_bytes(segment)) == 0xFFFF {
        return ChecksumStatus::Valid;
    }
    if stored == pseudo_folded || stored == !pseudo_folded {
        return ChecksumStatus::OffloadSuspected;
    }
    if stored == 0x0000 {
        return ChecksumStatus::OffloadSuspected;
    }
    ChecksumStatus::Invalid
}

fn sum_bytes(bytes: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    sum
}

fn fold_sum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}
