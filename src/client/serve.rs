//! Client accept loop for loopback SOCKS5.

use std::{io, sync::Arc};

use tokio::net::TcpListener;

use crate::config::node::ClientConfig;

use super::{
    line::{Line, LineError},
    socks5_inbound::handle_connection,
};

/// Client runtime failure.
#[derive(Debug)]
pub enum ClientRuntimeError {
    /// Configuration could not compile a LINE.
    Line(LineError),
    /// Listener bind failed.
    Bind(io::Error),
    /// Accept failed.
    Accept(io::Error),
}

impl std::fmt::Display for ClientRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("client runtime failed")
    }
}

impl std::error::Error for ClientRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Line(e) => Some(e),
            Self::Bind(e) | Self::Accept(e) => Some(e),
        }
    }
}

/// Runs the client until the process is cancelled.
pub async fn run_client(config: &ClientConfig) -> Result<(), ClientRuntimeError> {
    let line_config = config
        .lines
        .first()
        .ok_or(ClientRuntimeError::Line(LineError::Config("lines")))?;
    let line = Arc::new(Line::from_config(line_config).map_err(ClientRuntimeError::Line)?);

    let listener_cfg = config
        .listeners
        .first()
        .ok_or(ClientRuntimeError::Line(LineError::Config("listeners")))?;
    let bind = std::net::SocketAddr::new(
        std::net::IpAddr::V4(listener_cfg.ipv4_address()),
        listener_cfg.port,
    );
    // Force loopback when unspecified slipped through.
    let bind = if bind.ip().is_unspecified() {
        std::net::SocketAddr::from(([127, 0, 0, 1], listener_cfg.port))
    } else {
        bind
    };
    let listener = TcpListener::bind(bind)
        .await
        .map_err(ClientRuntimeError::Bind)?;
    let bound = listener.local_addr().map_err(ClientRuntimeError::Bind)?;
    eprintln!("rust-reality client listening socks5 on {bound}");

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(ClientRuntimeError::Accept)?;
        let line = Arc::clone(&line);
        tokio::spawn(async move {
            let _ = handle_connection(stream, bound, &line).await;
        });
    }
}
