use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap_parser::{PcapBlockOwned, PcapError, create_reader};
use std::fs::File;
use std::path::Path;

use super::types::{RawPacket, TcpFlags};
use crate::error::Error;

pub fn read_pcap(path: &Path) -> Result<Vec<RawPacket>, Error> {
    let file = File::open(path)?;
    let mut reader = create_reader(65536, file).map_err(|e| Error::PcapParse(format!("{e:?}")))?;

    let mut packets = Vec::new();
    let mut index: usize = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                let data: Option<(u64, &[u8])> = match &block {
                    PcapBlockOwned::Legacy(b) => {
                        let ts_us = b.ts_sec as u64 * 1_000_000 + b.ts_usec as u64;
                        Some((ts_us, b.data))
                    }
                    PcapBlockOwned::LegacyHeader(_) => None,
                    PcapBlockOwned::NG(b) => match b {
                        pcap_parser::Block::EnhancedPacket(epb) => {
                            let ts = ((epb.ts_high as u64) << 32) | epb.ts_low as u64;
                            Some((ts, epb.data))
                        }
                        pcap_parser::Block::SimplePacket(spb) => Some((0, spb.data)),
                        _ => None,
                    },
                };

                if let Some((timestamp_us, frame)) = data {
                    if let Some(pkt) = parse_raw_packet(frame, timestamp_us, index) {
                        packets.push(pkt);
                    }
                    // index = номер пакета в capture, а не только TCP
                    index += 1;
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => break,
            Err(e) => return Err(Error::PcapParse(format!("{e:?}"))),
        }
    }

    Ok(packets)
}

fn parse_raw_packet(data: &[u8], timestamp_us: u64, index: usize) -> Option<RawPacket> {
    // Большинство захватов — Ethernet, fallback на сырой IP.
    let headers = PacketHeaders::from_ethernet_slice(data)
        .ok()
        .or_else(|| PacketHeaders::from_ip_slice(data).ok())?;

    let (src_ip, dst_ip) = match &headers.net? {
        NetHeaders::Ipv4(hdr, _) => (hdr.source, hdr.destination),
        NetHeaders::Ipv6(_, _) => return None,
        NetHeaders::Arp(_) => return None,
    };

    let tcp = match headers.transport? {
        TransportHeader::Tcp(t) => t,
        _ => return None,
    };

    Some(RawPacket {
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
        payload: headers.payload.slice().to_vec(),
    })
}
