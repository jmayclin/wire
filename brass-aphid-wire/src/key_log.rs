/// https://nss-crypto.org/reference/security/nss/legacy/key_log_format/index.html
#[derive(Debug)]
pub struct NssLog {
    pub label: String,
    pub client_random: Vec<u8>,
    pub secret: Vec<u8>,
}

impl NssLog {
    pub fn from_log_line(log_line: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = log_line.split_whitespace().collect();
        if parts.len() != 3 {
            anyhow::bail!("unacceptable line {log_line}");
        }

        Ok(Self {
            label: parts[0].to_string(),
            client_random: hex::decode(parts[1])?,
            secret: hex::decode(parts[2])?,
        })
        // let label = parts[0].to_string();
        // let client_random = hex::decode(parts[1])?;
        // let secret = hex::decode(parts[2])?;

        // match parts[0] {
        //     "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => {
        //         self.client_random = Some(hex::decode(parts[1]).unwrap_or_default());
        //         self.client_handshake_traffic_secret =
        //             Some(hex::decode(parts[2]).unwrap_or_default());
        //     }
        //     "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
        //         self.server_handshake_traffic_secret =
        //             Some(hex::decode(parts[2]).unwrap_or_default());
        //     }
        //     "CLIENT_TRAFFIC_SECRET_0" => {
        //         self.client_application_traffic_secret =
        //             Some(hex::decode(parts[2]).unwrap_or_default());
        //     }
        //     "SERVER_TRAFFIC_SECRET_0" => {
        //         self.server_application_traffic_secret =
        //             Some(hex::decode(parts[2]).unwrap_or_default());
        //     }
        //     "CLIENT_RANDOM" => {
        //         self.client_random = Some(hex::decode(parts[1]).unwrap_or_default());
        //         self.master_secret = Some(hex::decode(parts[2]).unwrap_or_default());
        //     }
        //     _ => {}
        // }
        // Ok(())
    }
}
