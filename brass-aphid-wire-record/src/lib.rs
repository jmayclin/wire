use brass_aphid_wire_messages::{codec::DecodeValue, protocol::{ContentType, RecordHeader}};


struct Record<'a> {
    header: RecordHeader,
    payload: &'a mut [u8],
}

enum Payload<'a> {
    Application(&'a mut [u8]),
    Handshake(&'a mut [u8]),
    Alert(&'a mut [u8]),
    CCS,
}

struct Tls13RecordState {

}

enum ProtocolVersion {
    /// The record contents are not encrypted
    /// Used for the initial message of TLS 1.3 handshakes, or the entire legacy TLS
    /// handshake sequence
    Plaintext,
    Tls13(),
    Tls12(),
}

struct RecordProcotol {

}

impl RecordProcotol {
    /// content type is the "real" content type, not the content type of the outer
    /// record header
    fn encapsulate_record(&self, content_type: ContentType, payload: &[u8], record_out: &mut [u8]) {
        // match 
    }

    fn decap_record_in_place<'a, 'b>(&'a self, record: &'b mut[u8]) -> Payload<'b> {
        Payload::CCS
    }
}

trait RecordProtocol {
    /// encapsulate in place
    fn encap<'a, 'b>(&'a self, content_type: ContentType, payload: &'b mut [u8]) -> Record <'b>;

    /// decapsulate in place
    fn decap_record_in_place<'a, 'b>(&'a self, record: &'b mut[u8]) -> Payload<'b>;
}

struct Plaintext;
impl RecordProtocol for Plaintext {
    fn encap<'a, 'b>(&'a self, content_type: ContentType, payload: &'b mut [u8]) -> Record<'b> {
        let header = RecordHeader {
            content_type,
            protocol_version: todo!(),
            record_length: payload.len() as u16,
        };
    }

    fn decap_record_in_place<'a, 'b>(&'a self, record: &'b mut[u8]) -> Payload<'b> {
        let (record_header, remaining) = RecordHeader::decode_from(record).unwrap();
        todo!("NEED TO DO");
        // match record_header.content_type {
        //     ContentType::Invalid => panic!("uh oh"),
        //     ContentType::ChangeCipherSpec => Pay,
        //     ContentType::Alert => Payload::Alert(remaining),
        //     ContentType::Handshake => todo!(),
        //     ContentType::ApplicationData => todo!(),
        //     ContentType::Unknown(_) => todo!(),
        // }
    }
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
