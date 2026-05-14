use brass_aphid_wire_messages::{
    codec::EncodeValue,
    protocol::{
        extensions::{ClientHelloExtension, ClientHelloExtensionData, ExtensionType},
        ClientHello,
    },
};

pub mod decryption;

pub mod key_log;
pub mod offline;
#[cfg(test)]
pub mod testing;
pub mod transcript_verification;

trait ClientCapability {
    fn client_capability(&self) -> String;
}

fn hex_encode<T: EncodeValue>(parameters: &[T]) -> String {
    parameters
        .iter()
        .map(|v| v.encode_to_vec().unwrap())
        .map(|v| {
            assert_eq!(v.len(), 2);
            hex::encode(v)
        })
        .collect::<Vec<String>>()
        .join("")
}

impl ClientCapability for brass_aphid_wire_messages::protocol::ClientHello {
    fn client_capability(&self) -> String {
        let supported_protocols = {
            match &self.extensions {
                Some(extensions) => {
                    let supported_version = extensions.list().iter().find_map(|ext| {
                        if let ClientHelloExtensionData::SupportedVersions(versions) =
                            &ext.extension_data
                        {
                            Some(versions)
                        } else {
                            None
                        }
                    });

                    match supported_version {
                        Some(versions) => versions.versions.clone().into_inner(),
                        // the client didn't send the supported versions extension
                        None => vec![self.protocol_version],
                    }
                }
                None => vec![self.protocol_version],
            }
        };

        let ciphers = self.offered_ciphers.clone().into_inner();

        let get_groups = |client_hello: &ClientHello| {
            client_hello
                .extensions
                .as_ref()?
                .list()
                .iter()
                .find_map(|ext| {
                    if let ClientHelloExtensionData::SupportedGroups(groups) = &ext.extension_data {
                        Some(groups.named_curve_list.clone().into_inner())
                    } else {
                        None
                    }
                })
        };
        let maybe_groups = get_groups(self).map(|g| hex_encode(&g)).unwrap_or_default();

        let get_signatures = |client_hello: &ClientHello| {
            client_hello
                .extensions
                .as_ref()?
                .list()
                .iter()
                .find_map(|ext| {
                    if let ClientHelloExtensionData::SignatureScheme(sigs) = &ext.extension_data {
                        Some(sigs.supported_signature_algorithms.clone().into_inner())
                    } else {
                        None
                    }
                })
        };
        let maybe_sigs = get_signatures(self)
            .map(|s| hex_encode(&s))
            .unwrap_or_default();

        let chunks = [
            hex_encode(&supported_protocols),
            hex_encode(&ciphers),
            maybe_groups,
            maybe_sigs,
        ];

        chunks.join(",")
    }
}
