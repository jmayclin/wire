//! This module contains utilities for "offline" decryption.
//!
//! E.g. we want to be able to look at the Go TLS conversation.

use std::{io::Read, path::Path};

use byteorder::{ByteOrder, ReadBytesExt};

use crate::{
    decryption::{key_manager::KeyManager, Mode},
    key_log::NssLog,
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
    use brass_aphid_wire_messages::{
        codec::DecodeValue,
        protocol::{ClientHello, HandshakeMessageHeader, RecordHeader},
    };

    use super::*;
    use crate::decryption::{stream_decrypter::StreamDecrypter, transcript};
    use std::{path::PathBuf, str::FromStr};

    const GO_RESOURCES: &str = "../go-tls-transcript/resources";
    const JAVA_RESOURCES: &str = "../java-tls-transcript/resources";
    const OSSL_RESOURCES: &str = "../openssl-tls-transcript/resources";
    const CAPABILITY_COMPENDIUM: &str = "../capability-compendium/resources/";

    #[test]
    fn go_transcripts() {
        // Set up tracing for better debugging
        // tracing_subscriber::fmt()
        //     .with_max_level(tracing::Level::TRACE)
        //     .init();

        // Base path for Go resources
        let base_path = PathBuf::from_str(GO_RESOURCES).unwrap();
        let output_folder = PathBuf::from_str(CAPABILITY_COMPENDIUM)
            .unwrap()
            .join("handshakes");
        println!("outputting to : {output_folder:?}");

        // Find all directories that start with "go" (Go version directories)
        let entries = std::fs::read_dir(&base_path).unwrap();

        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();

            // Extract version from directory name
            let version = path.file_name().and_then(|name| name.to_str()).unwrap();
            println!("Processing Go version: {}", version);

            // Process server auth transcript
            let server_auth_transcript_path = path.join("server_auth_transcript.bin");
            let server_auth_key_path = path.join("server_auth_keys.log");

            // Process resumption transcript
            let resumption_transcript_path = path.join("resumption_transcript.bin");
            let resumption_key_path = path.join("resumption_keys.log");

            for (transcript, key, name) in [
                (
                    server_auth_transcript_path,
                    server_auth_key_path,
                    "server_auth",
                ),
                (
                    resumption_transcript_path,
                    resumption_key_path,
                    "resumption",
                ),
            ] {
                let transcript = Conversation::transcript(&transcript).unwrap();
                let keys = Conversation::keys(&key);

                let mut decrypter = StreamDecrypter::new(keys);
                for (sender, data) in transcript {
                    decrypter.record_tx(&data, sender);
                    decrypter
                        .decrypt_records(sender)
                        .expect("Failed to decrypt server auth record");
                }

                let output_file = output_folder.join(format!("go_{version}_{name}.log"));
                println!("output_file: {output_file:?}");
                decrypter.dump_transcript(&output_file);
            }
        }
    }

    #[test]
    fn java_client_hellos() {
        // Set up tracing for better debugging
        // tracing_subscriber::fmt()
        //     .with_max_level(tracing::Level::TRACE)
        //     .init();
        let output_folder = PathBuf::from_str(CAPABILITY_COMPENDIUM)
            .unwrap()
            .join("client_hellos");

        let base_path = PathBuf::from_str(JAVA_RESOURCES).unwrap();
        let java_versions = std::fs::read_dir(&base_path).unwrap();

        for entry in java_versions {
            let entry = entry.unwrap();
            let path = entry.path();

            // Extract version from directory name
            let version = path.file_name().and_then(|name| name.to_str()).unwrap();

            println!("Processing Java client hello: {}", version);

            let client_hello = path.join("client_hello.bin");
            let client_hello = std::fs::read(client_hello).unwrap();
            let buffer = client_hello.as_slice();

            let (record_header, buffer) = RecordHeader::decode_from(buffer).unwrap();
            let (message_header, buffer) = HandshakeMessageHeader::decode_from(buffer).unwrap();
            let client_hello = ClientHello::decode_from_exact(buffer).unwrap();

            let transcript = format!("{:#?}", client_hello);
            let output_file = output_folder.join(format!("java_{version}.log"));
            // let output_path = format!("resources/traces/java_{}_client_hello.log", version);

            std::fs::write(output_file, transcript).unwrap();
        }
    }

    #[test]
    fn ossl_client_hellos() {
        // Set up tracing for better debugging
        // tracing_subscriber::fmt()
        //     .with_max_level(tracing::Level::TRACE)
        //     .init();
        let output_folder = PathBuf::from_str(CAPABILITY_COMPENDIUM)
            .unwrap()
            .join("client_hellos");

        let base_path = PathBuf::from_str(OSSL_RESOURCES).unwrap();
        let openssl_versions = std::fs::read_dir(&base_path).unwrap();

        for entry in openssl_versions {
            let entry = entry.unwrap();
            let path = entry.path();

            // Extract version from directory name
            let version = path.file_name().unwrap().to_str().unwrap();

            println!("Processing openssl client hello: {}", version);

            let client_hello = path.join("client_hello.bin");
            let client_hello = std::fs::read(client_hello).unwrap();
            let buffer = client_hello.as_slice();

            let (record_header, buffer) = RecordHeader::decode_from(buffer).unwrap();
            let (message_header, buffer) = HandshakeMessageHeader::decode_from(buffer).unwrap();
            let client_hello = ClientHello::decode_from_exact(buffer).unwrap();

            let transcript = format!("{:#?}", client_hello);
            let output_file = output_folder.join(format!("{version}.log"));
            // let output_path = format!("resources/traces/java_{}_client_hello.log", version);

            std::fs::write(output_file, transcript).unwrap();
        }
    }
}
