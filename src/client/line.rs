//! One REALITY-authenticated LINE to an entry.

use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::net::TcpStream;

use crate::{
    config::node::LineConfig,
    protocol::{
        reality::{
            AuthPlaintext, CLIENT_VERSION, ClientKeyAgreement, build_client_hello, complete,
        },
        vless::{Destination, UserId},
    },
};

use super::session::{VisionTunnel, VisionTunnelError};

const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// A compiled LINE ready to establish tunnels.
#[derive(Clone, Debug)]
pub struct Line {
    address: String,
    port: u16,
    user_id: UserId,
    public_key: [u8; 32],
    short_id: [u8; 8],
    server_name: String,
}

/// A LINE could not be compiled or established.
#[derive(Debug)]
pub enum LineError {
    /// Configuration field was invalid.
    Config(&'static str),
    /// TCP dial failed.
    Dial(std::io::Error),
    /// REALITY handshake failed.
    Handshake(crate::protocol::reality::ClientHandshakeError),
    /// Vision / VLESS session failed.
    Session(VisionTunnelError),
}

impl std::fmt::Display for LineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("REALITY LINE failed")
    }
}

impl std::error::Error for LineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Dial(e) => Some(e),
            Self::Handshake(e) => Some(e),
            Self::Session(e) => Some(e),
            Self::Config(_) => None,
        }
    }
}

impl Line {
    /// Compiles one LINE from validated configuration.
    pub fn from_config(config: &LineConfig) -> Result<Self, LineError> {
        let user_id = parse_uuid(&config.id).ok_or(LineError::Config("id"))?;
        let public_key =
            decode_public_key(&config.public_key).ok_or(LineError::Config("publicKey"))?;
        let short_id = parse_short_id(&config.short_id).ok_or(LineError::Config("shortId"))?;
        Ok(Self {
            address: config.address.clone(),
            port: config.port,
            user_id,
            public_key,
            short_id,
            server_name: config.server_name.clone(),
        })
    }

    /// Dials the entry, completes REALITY, and opens a Vision tunnel to `destination`.
    pub async fn establish(&self, destination: &Destination) -> Result<VisionTunnel, LineError> {
        let addr = resolve_line_address(&self.address, self.port)
            .await
            .map_err(LineError::Dial)?;
        let mut stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                LineError::Dial(std::io::Error::new(std::io::ErrorKind::TimedOut, "dial"))
            })?
            .map_err(LineError::Dial)?;

        let keys = ClientKeyAgreement::generate().map_err(map_hello)?;
        let now = unix_now();
        let auth = AuthPlaintext {
            version: CLIENT_VERSION,
            time: now,
            short_id: self.short_id,
        };
        let (hello, auth_key) =
            build_client_hello(&self.server_name, ALPN, &keys, &self.public_key, auth)
                .map_err(map_hello)?;

        // Write ClientHello record first.
        let record = hello.record();
        tokio::io::AsyncWriteExt::write_all(&mut stream, &record)
            .await
            .map_err(LineError::Dial)?;
        tokio::io::AsyncWriteExt::flush(&mut stream)
            .await
            .map_err(LineError::Dial)?;

        let session = complete(&mut stream, &hello, &keys, &auth_key, ALPN)
            .await
            .map_err(LineError::Handshake)?;

        VisionTunnel::connect(stream, session, self.user_id, destination)
            .await
            .map_err(LineError::Session)
    }
}

fn parse_uuid(value: &str) -> Option<UserId> {
    let uuid = uuid::Uuid::parse_str(value).ok()?;
    Some(UserId::new(*uuid.as_bytes()))
}

fn decode_public_key(value: &str) -> Option<[u8; 32]> {
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(value).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

fn parse_short_id(value: &str) -> Option<[u8; 8]> {
    if value.is_empty() || value.len() > 16 || !value.len().is_multiple_of(2) {
        return None;
    }
    let mut output = [0_u8; 8];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = decode_hex(pair[0])?;
        let low = decode_hex(pair[1])?;
        *output.get_mut(index)? = (high << 4) | low;
    }
    Some(output)
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

async fn resolve_line_address(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    if let Ok(ip) = host.parse() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address"))
}

fn map_hello(error: crate::protocol::reality::HelloError) -> LineError {
    match error {
        crate::protocol::reality::HelloError::Entropy => LineError::Config("entropy"),
        _ => LineError::Config("client hello"),
    }
}
