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
    fn go_transcripts() {
        // Set up tracing for better debugging
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .init();
        
        // Base path for Go resources
        let base_path = PathBuf::from_str(GO_RESOURCES).unwrap();
        
        // Find all directories that start with "go" (Go version directories)
        let entries = std::fs::read_dir(&base_path).expect("Failed to read resources directory");
        
        for entry in entries {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();
            
            // Skip if not a directory or doesn't start with "go"
            if !path.is_dir() || !path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("go"))
                .unwrap_or(false) {
                continue;
            }
            
            // Extract version from directory name
            let version = path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown");
            
            println!("Processing Go version: {}", version);
            
            // Process server auth transcript
            let server_auth_transcript_path = path.join("server_auth_transcript.bin");
            let server_auth_key_path = path.join("server_auth_keys.log");
            
            if server_auth_transcript_path.exists() && server_auth_key_path.exists() {
                let transcript = Conversation::transcript(&server_auth_transcript_path)
                    .expect("Failed to read server auth transcript");
                let keys = Conversation::keys(&server_auth_key_path);
                
                let mut decrypter = StreamDecrypter::new(keys);
                for (sender, data) in transcript {
                    decrypter.record_tx(&data, sender);
                    decrypter.decrypt_records(sender).expect("Failed to decrypt server auth record");
                }
                
                let output_path = format!("resources/traces/go_{}.log", version);
                decrypter.dump_transcript(&output_path);
                println!("Generated server auth log: {}", output_path);
            }
            
            // Process resumption transcript
            let resumption_transcript_path = path.join("resumption_transcript.bin");
            let resumption_key_path = path.join("resumption_keys.log");
            
            if resumption_transcript_path.exists() && resumption_key_path.exists() {
                let transcript = Conversation::transcript(&resumption_transcript_path)
                    .expect("Failed to read resumption transcript");
                let keys = Conversation::keys(&resumption_key_path);
                
                let mut decrypter = StreamDecrypter::new(keys);
                for (sender, data) in transcript {
                    decrypter.record_tx(&data, sender);
                    decrypter.decrypt_records(sender).expect("Failed to decrypt resumption record");
                }
                
                let output_path = format!("resources/traces/go_{}_nst.log", version);
                decrypter.dump_transcript(&output_path);
                println!("Generated resumption log: {}", output_path);
            }
        }
    }
}
