use brass_aphid_wire_messages::codec::DecodeValue;
use brass_aphid_wire_messages::protocol::{ClientHello, HandshakeMessageHeader, RecordHeader};
use etherparse::{IpHeader, LinkSlice, NetHeaders, SlicedPacket, TransportSlice};
use pcap_parser::{parse_pcap, Capture, Linktype, PcapCapture};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

/// A struct to track a TCP connection
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct TcpFlow {
    source: SocketAddr,
    destination: SocketAddr,
}

/// A struct to store TCP packet data
///
/// This generic lifetime parameter will generally be the lifetime of the
/// PcapCapture object which owns the actual packet content.
struct TcpContent<'a> {
    seq_number: u32,
    data: &'a [u8],
}

pub fn reassemble_tcp_streams<'a>(
    capture: PcapCapture<'a>,
) -> HashMap<TcpFlow, Vec<TcpContent<'a>>> {
    // LINUX_SLL is the type of header format that is used in the pcap.
    assert_eq!(capture.get_datalink(), Linktype::LINUX_SLL);

    let total_blocks = capture.blocks.len();

    let header_parsed = capture
        .blocks
        .iter()
        .map(|block| SlicedPacket::from_linux_sll(block.data).unwrap())
        .filter(|block| block.net.is_some()) // should be IP packets
        .filter(|block| matches!(block.transport, Some(TransportSlice::Tcp(_)))) // should be TCP
        .map(|block| {
            let network_data = block.net.unwrap();
            let (destination_ip, source_ip) = {
                let ipv4 = network_data.ipv4_ref().map(|ipv4_packet| {
                    let header = ipv4_packet.header();
                    let destination = IpAddr::V4(header.destination_addr());
                    let source = IpAddr::V4(header.source_addr());
                    (destination, source)
                });

                let ipv6 = network_data.ipv6_ref().map(|ipv4_packet| {
                    let header = ipv4_packet.header();
                    let destination = IpAddr::V6(header.destination_addr());
                    let source = IpAddr::V6(header.source_addr());
                    (destination, source)
                });

                match (ipv4, ipv6) {
                    (None, None) => panic!("network packet type was not IP"),
                    (None, Some(routing)) => routing,
                    (Some(routing), None) => routing,
                    (Some(_), Some(_)) => unreachable!("packet can not be both ipv4 and ipv6"),
                }
            };

            let tcp_data = match block.transport.unwrap() {
                TransportSlice::Tcp(tcp_slice) => tcp_slice,
                _ => {
                    unreachable!("we already filtered on this");
                }
            };
            let source_port = tcp_data.source_port();
            let destination_port = tcp_data.destination_port();

            let destination: SocketAddr = (destination_ip, destination_port).into();
            let source: SocketAddr = (source_ip, source_port).into();
            let flow = TcpFlow {
                destination,
                source,
            };

            let content = TcpContent {
                seq_number: tcp_data.sequence_number(),
                data: tcp_data.payload(),
            };

            (flow, content)
        });

    let mut connections: HashMap<TcpFlow, Vec<TcpContent>> = HashMap::new();
    for (flow, content) in header_parsed {
        connections.entry(flow).or_default().push(content);
    }

    for contents in connections.values_mut() {
        contents.sort_by_key(|content| content.seq_number);
    }

    println!("{} TCP flows reconstructed", connections.len());

    let double_counted: usize = connections
        .values()
        .filter(|tcp_contents| {
            let unique_packet_numbers: HashSet<u32> = tcp_contents
                .iter()
                .map(|content| content.seq_number)
                .collect();
            let double_counted = tcp_contents.len() != unique_packet_numbers.len();
            double_counted
        })
        .count();
    println!("double counter: {double_counted}");

    // todo: double check that if the seq number 0 (1?) is the same, then the contents
    // should also be the same.

    // actually, I don't think that's true

    // also I think we _only_ need sequence number one (for the initial stuff).
    // actually, I think we also want to look at the server hellos?
    // although I don't think that the PSK is gonna be visible in that.

    connections
}

// /// Given the path to some pcap, this will read in the pcap file and reassemble all
// /// of the various TCP streams that were presented.
// ///
// /// Returns a vector of tuples, where each tuple contains:
// /// - The destination IP address
// /// - The reassembled TCP data stream as a vector of bytes
// pub fn reassemble_tcp_streams(pcap_path: &str) {
//     // Read the pcap file
//     let pcap_data = std::fs::read(pcap_path).unwrap();

//     // Parse the pcap file
//     let (remaining, capture) = parse_pcap(&pcap_data).unwrap();
//     assert!(remaining.is_empty());

//     // Track TCP connections and their packets
//     let mut connections: HashMap<TcpFlow, Vec<TcpContent>> = HashMap::new();

//     // filter down to IP packets
//     // filter down to TCP packets

//     // Process each packet in the capture
//     for block in capture.blocks.iter() {
//         // Extract the packet data
//         let packet_data = block.data;
//         let sliced_packet = SlicedPacket::from_linux_sll(block.data).unwrap();

//         // ip address information is contained in the network header (IP)
//         let network_data = sliced_packet.net.unwrap();
//         assert!(network_data.is_ip());
//         let (destination_ip, source_ip) = {
//             let ipv4 = network_data.ipv4_ref().map(|ipv4_packet| {
//                 let header = ipv4_packet.header();
//                 let destination = IpAddr::V4(header.destination_addr());
//                 let source = IpAddr::V4(header.source_addr());
//                 (destination, source)
//             });

//             let ipv6 = network_data.ipv6_ref().map(|ipv4_packet| {
//                 let header = ipv4_packet.header();
//                 let destination = IpAddr::V6(header.destination_addr());
//                 let source = IpAddr::V6(header.source_addr());
//                 (destination, source)
//             });

//             match (ipv4, ipv6) {
//                 (None, None) => panic!("network packet type was not IP"),
//                 (None, Some(routing)) => routing,
//                 (Some(routing), None) => routing,
//                 (Some(_), Some(_)) => unreachable!("packet can not be both ipv4 and ipv6"),
//             }
//         };

//         // port information is contained in the transport header (TCP)
//         let tcp_data = match sliced_packet.transport.unwrap() {
//             TransportSlice::Tcp(tcp_slice) => tcp_slice,
//             _ => {
//                 println!("not a recognized packet type, skipping");
//                 continue;
//             }
//         };
//         let source_port = tcp_data.source_port();
//         let destination_port = tcp_data.destination_port();

//         let destination: SocketAddr = (destination_ip, destination_port).into();
//         let source: SocketAddr = (source_ip, source_port).into();
//         let flow = TcpFlow {
//             destination,
//             source,
//         };

//         let content = TcpContent {
//             seq_number: tcp_data.sequence_number(),
//             data: tcp_data.payload().to_vec(),
//         };

//         // TODO: a TCP Flow may be reused after some duration.
//         connections.entry(flow).or_default().push(content);
//     }

//     println!("observed {} flows", connections.len());
// }

fn try_client_hello(mut data: &[u8]) -> Option<ClientHello> {
    let (record_header, data) = RecordHeader::decode_from(data).ok()?;
    let (message_header, data) = HandshakeMessageHeader::decode_from(data).ok()?;
    ClientHello::decode_from_exact(data).ok()
}

#[cfg(test)]
mod tests {
    use std::hash::Hash;

    use brass_aphid_wire_messages::{codec::{DecodeValue, EncodeValue}, protocol::RecordHeader};
    use pcap_parser::{parse_pcap, Capture, Linktype};

    use super::*;

    const PCAP_PATH: &str = "/home/ubuntu/traffic.pcap";

    #[test]
    fn read_pcap() {
        let pcap = std::fs::read(PCAP_PATH).unwrap();
        let (remaining, captures) = parse_pcap(&pcap).unwrap();
        println!("header: {:?}", captures.header);
        let link = captures.get_datalink();
        println!("link type: {link:?}");
        assert_eq!(link, Linktype::LINUX_SLL);
        let frames = captures.blocks.iter().next().unwrap();
    }

    #[test]
    fn reassemble() {
        let pcap = std::fs::read(PCAP_PATH).unwrap();
        let (remaining, captures) = parse_pcap(&pcap).unwrap();
        println!("header: {:?}", captures.header);
        let streams = reassemble_tcp_streams(captures);

        let mut found_client_hello = 0;
        let client_hellos: Vec<ClientHello> = streams
            .values()
            .filter_map(|contents| {
                contents
                    .iter()
                    .find(|contents| try_client_hello(contents.data).is_some())
                    .map(|content| try_client_hello(content.data).unwrap())
            })
            .collect();
        let mut distinct_client_hellos: HashMap<usize, ClientHello> = HashMap::new();
        for ch in client_hellos {
            let ch_length = ch.encode_to_vec().unwrap().len();
            distinct_client_hellos.insert(ch_length, ch.clone());
        };
        println!("{distinct_client_hellos:#?}");
    }
}
