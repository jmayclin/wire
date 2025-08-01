use crate::{
    codec::{DecodeValue, DecodeValueWithContext},
    decryption::{
        key_manager::KeyManager, key_space::SecretSpace, stream_decrypter::ConversationState, Mode,
    },
    protocol::{
        content_value::{ContentValue, HandshakeMessageValue},
        Alert, ChangeCipherSpec, ContentType, RecordHeader,
    },
};
use std::{collections::VecDeque, fmt::Debug, io::ErrorKind};

/// A TlsStream is generally responsible for handling the framing and decrypting
/// of the TLS Record protocol.
///
/// Consider the following scenario
/// ```text
/// messages ->   |------m1------|--------m2------|--------m3-------|
/// records  ->   |----r1----|-------r2---|-----r3------|----r4-----|
/// packets  ->   |--p1--|---p2---|---p3--|---p4--|--p5----|---p6---|
/// ```
///
/// Assume (without loss of generality) that each read call returns an individual,
/// single packet.
///
/// ### Packet Buffering
///
/// We won't be able to decrypt `r1` until we have received both `p1` and `p2`.
/// To handle this we buffer all the reads in `byte_buffer` until the full record
/// is available.
///
/// ### Record Buffering
/// Depending on different key logging implementations, we won't be able to decrypt
/// the record immediately. We buffer complete records in `record_buffer` until
/// the decryption keys are available.
///
/// Even once we're able to decrypt records, We won't be able to parse `m1` until
/// we have received both `r1` and `r2`. We buffer the decrypted plaintext in
/// `plaintext_content_stream`
///
/// Note that the content_stream will only ever hold a single content type.
///
/// TODO: shenanigans here. We either have to "poll_decrypt" each time we have
/// gotten a full record, or we need to poll_decrypt when we see a new content
/// type (before we add it to the stream). I like the first option because it's
/// less modality.
///
/// THOUGHT: Can obfuscated records have multiple inner content types in them? I
/// think the answer is no. And if the answer is yes then 😭.
#[derive(Debug)]
pub struct TlsStream {
    sender: Mode,
    /// all tx calls are buffered here until there is enough to read a message
    byte_buffer: Vec<u8>,

    /// records are buffered here until keys are available to decrypt them
    record_buffer: VecDeque<Vec<u8>>,

    plaintext_content_stream: VecDeque<u8>,
    plaintext_content_type: ContentType,
    key_space: SecretSpace,
    needs_next_key_space: bool,
    // key space
    // wants new key stream
}

impl TlsStream {
    pub fn new(sender: Mode) -> Self {
        Self {
            sender,
            byte_buffer: Default::default(),
            record_buffer: Default::default(),
            plaintext_content_stream: Default::default(),
            // first data is alert, and also it shouldn't matter
            plaintext_content_type: ContentType::Handshake,
            key_space: SecretSpace::Plaintext,
            needs_next_key_space: false,
        }
    }

    /// Add bytes to a TLS stream.
    ///
    /// In the case of a DecryptingPipe, this is the method called by the Read &
    /// Write IO methods.
    ///
    /// This method will not do any decryption, but will try and assemble existing
    /// data into complete records.
    pub fn feed_bytes(&mut self, data: &[u8]) -> std::io::Result<()> {
        // first buffer into byte buffer.
        tracing::info!(
            "feeding {:?} bytes, record buffer currently {}",
            data.len(),
            self.record_buffer.len()
        );
        self.byte_buffer.extend_from_slice(data);

        // get all of the records
        while let Some(record) = self.byte_buffer_has_record() {
            // TODO: record header size constant
            let record_and_header_len = record.record_length as usize + 5;
            // pop the record off the front of the byte buffer
            let record = self.byte_buffer.drain(..record_and_header_len).collect();
            // store it in the record buffer
            self.record_buffer.push_back(record);
        }

        tracing::info!("record buffer now {}", self.record_buffer.len());

        Ok(())
    }

    /// Attempt to decrypt available bytes.
    pub fn digest_bytes(
        &mut self,
        state: &mut ConversationState,
        key_manger: &KeyManager,
    ) -> std::io::Result<Vec<ContentValue>> {
        tracing::trace!("digesting bytes from {:?}", self.sender);
        // precondition: any data currently in plaintext_content_stream must have the
        // same content type as what we are about to decrypt. If that's not true,
        // then it means that we were unable to "clear out" the data in a previous
        // content type and the data is malformed

        // check if "needed keyspace" is some, before popping off the record.
        // e.g. once we have seen the finished message we should

        let mut content = Vec::new();

        loop {
            // don't try to get the next space if there isn't anything to read
            // otherwise we'd try and grab the handshake keys for the client before
            // reading the server hello
            if self.plaintext_content_stream.is_empty() && self.record_buffer.is_empty() {
                return Ok(content);
            }

            if self.needs_next_key_space {
                let next_space = match &self.key_space {
                    SecretSpace::Plaintext => key_manger
                        .handshake_space(
                            self.sender,
                            state.client_random.as_ref().unwrap(),
                            state.selected_cipher.unwrap(),
                        )
                        .map(SecretSpace::Handshake),
                    SecretSpace::Handshake(_) => key_manger
                        .first_application_space(
                            self.sender,
                            state.client_random.as_ref().unwrap(),
                            state.selected_cipher.unwrap(),
                        )
                        .map(|space| SecretSpace::Application(space, 0)),
                    SecretSpace::Application(key_space, current_key_epoch) => Some(
                        SecretSpace::Application(key_space.key_update(), *current_key_epoch + 1),
                    ),
                };

                match next_space {
                    Some(space) => {
                        self.key_space = space;
                        self.needs_next_key_space = false;
                    }
                    None => {
                        // give up on decrypting now, and hope that the next time
                        // digest bytes is called we will have the keys that we need
                        tracing::warn!(
                            "Needed next space after {:?}, but it was unavailable",
                            self.key_space
                        );
                        return Ok(content);
                    }
                }
            }

            // if there are records, deframe. otherwise return
            let (content_type, record_payload) = match self.record_buffer.pop_front() {
                Some(record) => self.key_space.deframe_record(&record)?,
                None => return Ok(content),
            };

            // make sure that the record is the right type.
            //
            // If we are switching content types, then we should have received a
            // full message (and been able to decrypt it) so the stream should be
            // empty.
            if self.plaintext_content_stream.is_empty() {
                self.plaintext_content_type = content_type;
            } else if content_type != self.plaintext_content_type {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "unable to fully parse plaintext stream, malformed message",
                ));
            }

            // add the record into the plaintext stream
            self.plaintext_content_stream.extend(record_payload);

            tracing::trace!(
                "plaintext stream length: {:?}",
                self.plaintext_content_stream.len()
            );

            loop {
                let message = Self::plaintext_stream_message(
                    self.plaintext_content_type,
                    &mut self.plaintext_content_stream,
                    state,
                );
                let value = match message {
                    // we got a value, yay!
                    Ok(Some(content)) => content,
                    // we didn't have enough data for a value, but maybe if we shove
                    // more records onto the stream then we will.
                    Ok(None) => break,
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                    // something went wrong
                    Err(e) => return Err(e),
                };

                tracing::trace!("from plaintext stream: {value:?}");
                // TODO: handle hello retries. Maybe a method that the TlsStream
                // can call to reset the key space? Prevent the "next key space"
                // thing?

                // client hello is end of client plaintext
                if matches!(
                    value,
                    ContentValue::Handshake(HandshakeMessageValue::ClientHello(_))
                ) {
                    self.needs_next_key_space = true;
                }
                // server hello is end of server plaintext
                if matches!(
                    value,
                    ContentValue::Handshake(HandshakeMessageValue::ServerHello(_))
                ) {
                    self.needs_next_key_space = true;
                }
                // server finished is end of server handshake space
                // client finished is end of client handshake space
                if matches!(
                    value,
                    ContentValue::Handshake(HandshakeMessageValue::Finished(_))
                ) {
                    self.needs_next_key_space = true;
                }

                // server/client has updated their keys
                // If the peer update was requested, then we will update when the
                // peer sends their own KeyUpdate message.
                if matches!(
                    value,
                    ContentValue::Handshake(HandshakeMessageValue::KeyUpdate(_))
                ) {
                    self.needs_next_key_space = true;
                }

                // update the connection state
                if let ContentValue::Handshake(HandshakeMessageValue::ClientHello(s)) = &value {
                    state.client_random = Some(s.random.to_vec());
                }
                if let ContentValue::Handshake(HandshakeMessageValue::ServerHello(s)) = &value {
                    state.selected_cipher = Some(s.cipher_suite);
                    state.selected_protocol = Some(s.selected_version()?);
                    tracing::info!("setting cipher and selected version: {state:?}");
                }

                content.push(value);
            }
            // while let Some(value) = Self::plaintext_stream_message(
            //     self.plaintext_content_type,
            //     &mut self.plaintext_content_stream,
            //     state,
            // )
            // .map_err(|e| {
            //     tracing::error!("{e}");
            //     e
            // })? {

            // }
        }
    }

    /// attempt to decrypt a record header from `byte_buffer`.
    ///
    /// A `Some` return value means that
    /// - a record header was successfully decrypted
    /// - the byte_buffer contains the full record
    fn byte_buffer_has_record(&self) -> Option<RecordHeader> {
        let (record_header, remaining) =
            match RecordHeader::decode_from(self.byte_buffer.as_slice()) {
                Ok(decode) => decode,
                // TODO: we should only return None if there isn't enough data to
                // decrypt the RecordHeader. We should bubble up different parsing errors.
                Err(e) => return None,
            };

        if remaining.len() >= record_header.record_length as usize {
            Some(record_header)
        } else {
            None
        }
    }

    /// parse a message/content value from the plaintext stream.
    ///
    /// The
    fn plaintext_stream_message(
        content_type: ContentType,
        stream: &mut VecDeque<u8>,
        state: &ConversationState,
    ) -> std::io::Result<Option<ContentValue>> {
        stream.make_contiguous();
        let (buffer, empty) = stream.as_slices();
        assert!(empty.is_empty());

        // TODO: neater handling.
        // Can't rely on EOF because some things can be zero sized
        if buffer.is_empty() {
            return Ok(None);
        }

        tracing::info!(
            "plaintext stream length before message pull of {content_type:?}: {:?}",
            stream.len()
        );
        let (value, buffer) = match content_type {
            ContentType::Invalid => panic!("invalid"),
            ContentType::ChangeCipherSpec => {
                let (ccs, record_buffer) = ChangeCipherSpec::decode_from(buffer)?;
                (ContentValue::ChangeCipherSpec(ccs), record_buffer)
            }
            ContentType::Alert => {
                let (alert, buffer) = Alert::decode_from(buffer)?;
                (ContentValue::Alert(alert), buffer)
            }
            ContentType::Handshake => {
                let (handshake_message, inner_buffer) =
                    match (state.selected_protocol, state.selected_cipher) {
                        (Some(protocol), Some(cipher)) => {
                            HandshakeMessageValue::decode_from_with_context(
                                buffer,
                                (protocol, cipher),
                            )?
                        }
                        _unknown_state => HandshakeMessageValue::decode_from(buffer)?,
                    };
                (ContentValue::Handshake(handshake_message), inner_buffer)
            }
            ContentType::ApplicationData => (
                // we consume the entire stream for application data, no message length
                ContentValue::ApplicationData(buffer.to_vec()),
                [].as_slice(),
            ),
        };

        let consumed = stream.len() - buffer.len();
        for _ in 0..consumed {
            // TODO: vectorized instead
            stream.pop_front();
        }

        tracing::info!(
            "plaintext stream length after message pull: {:?}",
            stream.len()
        );

        Ok(Some(value))
    }
}
