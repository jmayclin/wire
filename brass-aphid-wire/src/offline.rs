//! This module contains utilities for "offline" decryption.
//!
//! E.g. we want to be able to look at the Go TLS conversation.

use std::{io::Read, path::Path};

use byteorder::{ByteOrder, ReadBytesExt};

use crate::{
    codec::DecodeValue,
    decryption::{key_manager::KeyManager, Mode},
    key_log::NssLog,
    prefixed_list::PrefixedBlob,
};

struct Conversation {
    /// a list of the writes made in the TLS Conversation
    writes: Vec<(Mode, Vec<u8>)>,
    /// a list of the keys from the key logging callback
    keys: Vec<NssLog>,
}

impl Conversation {
    fn transcript(filepath: &Path) -> std::io::Result<Vec<(Mode, Vec<u8>)>> {
        let transcript = std::fs::read(filepath)?;
        let mut buffer = transcript.as_slice();

        let mut parsed_transcript = Vec::new();
        while !buffer.is_empty() {
            let peer = buffer.read_u8()?;
            let peer = match peer {
                b'c' => Mode::Client,
                b's' => Mode::Server,
                _ => panic!("{peer} is an unallowed character"),
            };

            let length = buffer.read_u64::<byteorder::BigEndian>()?;
            println!("length: {length}");
            let mut bytes = vec![0; length as usize];
            buffer.read_exact(&mut bytes)?;

            parsed_transcript.push((peer, bytes));
        }
        Ok(parsed_transcript)
    }

    fn keys(filepath: &Path) -> KeyManager {
        let keys = std::fs::read_to_string(filepath).unwrap();
        let manager = KeyManager::new();
        for line in keys.lines() {
            let key = NssLog::from_log_line(line).unwrap();
            manager.register_key(key);
        }
        manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decryption::stream_decrypter::StreamDecrypter;
    use std::{path::PathBuf, str::FromStr};

    const GO_RESOURCES: &str = "../go-tls-transcript/resources";

    #[test]
    fn go_server_auth() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .init();

        let path = PathBuf::from_str(GO_RESOURCES).unwrap();
        let transcript_path = path.join("server_auth_transcript.bin");
        let key_path = path.join("server_auth_keys.log");

        let transcript = Conversation::transcript(&transcript_path).unwrap();
        assert_eq!(transcript.len(), 5);

        let keys = Conversation::keys(&key_path);

        let mut decrypter = StreamDecrypter::new(keys);
        for (sender, data) in transcript {
            decrypter.record_tx(&data, sender);
            decrypter.decrypt_records(sender).unwrap();
        }

        decrypter.dump_transcript("resources/traces/go.log");
    }

    #[test]
    fn go_with_nst() {
        let path = PathBuf::from_str(GO_RESOURCES).unwrap();
        let transcript_path = path.join("resumption_transcript.bin");
        let key_path = path.join("resumption_keys.log");

        let transcript = Conversation::transcript(&transcript_path).unwrap();
        let keys = Conversation::keys(&key_path);

        let mut decrypter = StreamDecrypter::new(keys);
        for (sender, data) in transcript {
            decrypter.record_tx(&data, sender);
            decrypter.decrypt_records(sender).unwrap();
        }

        decrypter.dump_transcript("resources/traces/go_nst.log");
    }
}
