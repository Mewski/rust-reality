//! Loopback SOCKS5 no-auth CONNECT acceptor.

use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::protocol::{
    socks5::{
        DecodeError, EncodeError, MethodResponse, decode_connect_request, decode_method_request,
        encode_method_response,
    },
    vless::Destination,
};

use super::line::{Line, LineError};

/// SOCKS5 refusal / protocol failure.
#[derive(Debug)]
pub(super) enum Socks5Error {
    /// Protocol decode failed.
    Protocol(DecodeError),
    /// Protocol encode failed.
    Encode(EncodeError),
    /// LINE establishment failed.
    Line(LineError),
    /// Socket I/O failed.
    Io(std::io::Error),
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SOCKS5 inbound failed")
    }
}

impl std::error::Error for Socks5Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Encode(e) => Some(e),
            Self::Line(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

/// Handles one SOCKS5 client connection through `line`.
pub(super) async fn handle_connection(
    mut local: TcpStream,
    bound: SocketAddr,
    line: &Line,
) -> Result<(), Socks5Error> {
    let destination = negotiate_and_read_request(&mut local).await?;
    match line.establish(&destination).await {
        Ok(mut tunnel) => {
            write_connect_reply(&mut local, 0x00, bound)
                .await
                .map_err(Socks5Error::Io)?;
            // Best-effort relay; errors end the session.
            let _ = tunnel.relay(&mut local).await;
            Ok(())
        }
        Err(error) => {
            let _ = write_connect_reply(&mut local, map_line_rep(&error), bound).await;
            Err(Socks5Error::Line(error))
        }
    }
}

async fn negotiate_and_read_request(stream: &mut TcpStream) -> Result<Destination, Socks5Error> {
    let mut buf = vec![0_u8; 512];
    let mut filled = 0_usize;
    // Method negotiation.
    loop {
        if filled >= buf.len() {
            return Err(Socks5Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 method offer too large",
            )));
        }
        let n = stream
            .read(&mut buf[filled..])
            .await
            .map_err(Socks5Error::Io)?;
        if n == 0 {
            return Err(Socks5Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "SOCKS5 peer closed",
            )));
        }
        filled += n;
        match decode_method_request(&buf[..filled]) {
            Ok(method) => {
                let mut reply = [0_u8; 2];
                encode_method_response(MethodResponse::NoAuthentication, &mut reply)
                    .map_err(Socks5Error::Encode)?;
                stream.write_all(&reply).await.map_err(Socks5Error::Io)?;
                // Carry trailing bytes into CONNECT parse.
                let trailing = method.trailing().to_vec();
                return read_connect(stream, trailing).await;
            }
            Err(DecodeError::IncompleteInput { .. }) => continue,
            Err(error) => return Err(Socks5Error::Protocol(error)),
        }
    }
}

async fn read_connect(
    stream: &mut TcpStream,
    mut pending: Vec<u8>,
) -> Result<Destination, Socks5Error> {
    let mut buf = vec![0_u8; 512];
    loop {
        match decode_connect_request(&pending) {
            Ok(request) => return Ok(request.destination().clone()),
            Err(DecodeError::IncompleteInput { .. }) => {}
            Err(error) => return Err(Socks5Error::Protocol(error)),
        }
        let n = stream.read(&mut buf).await.map_err(Socks5Error::Io)?;
        if n == 0 {
            return Err(Socks5Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "SOCKS5 CONNECT truncated",
            )));
        }
        pending.extend_from_slice(&buf[..n]);
        if pending.len() > 1024 {
            return Err(Socks5Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 CONNECT too large",
            )));
        }
    }
}

async fn write_connect_reply(
    stream: &mut TcpStream,
    rep: u8,
    bound: SocketAddr,
) -> std::io::Result<()> {
    // VER REP RSV ATYP BND.ADDR BND.PORT — IPv4 form.
    let mut reply = [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let ip = match bound.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
    };
    reply[4..8].copy_from_slice(&ip.octets());
    reply[8..10].copy_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&reply).await?;
    stream.flush().await
}

fn map_line_rep(error: &LineError) -> u8 {
    match error {
        LineError::Dial(_) => 0x05, // connection refused
        LineError::Handshake(_) | LineError::Session(_) => 0x05,
        LineError::Config(_) => 0x01, // general failure
    }
}
