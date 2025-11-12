/// https://nss-crypto.org/reference/security/nss/legacy/key_log_format/index.html
#[derive(Debug)]
pub struct NssLog {
    /// e.g. "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
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
    }
}
