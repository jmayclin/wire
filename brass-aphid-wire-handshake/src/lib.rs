use brass_aphid_wire_messages::protocol::content_value::HandshakeMessageValue;

struct Psk {
    public: Vec<u8>,
    private: Vec<u8>,
}

struct Client {
    psks: Vec<Psk>,
}

struct HandshakeState {}

impl HandshakeState {
    fn process_message(message: &HandshakeMessageValue) {}
}

struct Server {
    psks: Vec<Psk>,
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
