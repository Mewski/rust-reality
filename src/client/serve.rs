//! Client accept loops for loopback SOCKS5 and HTTP CONNECT.

use std::{io, sync::Arc};

use tokio::net::TcpListener;

use crate::config::node::{ClientConfig, InboundProtocol, ListenerConfig};

use super::{
    http_inbound,
    line::{Line, LineError},
    socks5_inbound,
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

    if config.listeners.is_empty() {
        return Err(ClientRuntimeError::Line(LineError::Config("listeners")));
    }

    let mut joins = Vec::with_capacity(config.listeners.len());
    for listener_cfg in &config.listeners {
        let (listener, bound) = open_listener(listener_cfg).await?;
        let protocol = listener_cfg.protocol.unwrap_or(InboundProtocol::Socks5);
        eprintln!(
            "rust-reality client listening {} on {bound}",
            protocol.as_str()
        );
        let line = Arc::clone(&line);
        joins.push(tokio::spawn(async move {
            accept_loop(listener, bound, protocol, line).await
        }));
    }

    let (result, _index, _rest) = futures_util::future::select_all(joins).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(join) => Err(ClientRuntimeError::Accept(io::Error::other(
            join.to_string(),
        ))),
    }
}

async fn open_listener(
    listener_cfg: &ListenerConfig,
) -> Result<(TcpListener, std::net::SocketAddr), ClientRuntimeError> {
    let bind = std::net::SocketAddr::new(
        std::net::IpAddr::V4(listener_cfg.ipv4_address()),
        listener_cfg.port,
    );
    let bind = if bind.ip().is_unspecified() {
        std::net::SocketAddr::from(([127, 0, 0, 1], listener_cfg.port))
    } else {
        bind
    };
    let listener = TcpListener::bind(bind)
        .await
        .map_err(ClientRuntimeError::Bind)?;
    let bound = listener.local_addr().map_err(ClientRuntimeError::Bind)?;
    Ok((listener, bound))
}

async fn accept_loop(
    listener: TcpListener,
    bound: std::net::SocketAddr,
    protocol: InboundProtocol,
    line: Arc<Line>,
) -> Result<(), ClientRuntimeError> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(ClientRuntimeError::Accept)?;
        let line = Arc::clone(&line);
        tokio::spawn(async move {
            match protocol {
                InboundProtocol::Socks5 => {
                    let _ = socks5_inbound::handle_connection(stream, bound, &line).await;
                }
                InboundProtocol::Http => {
                    let _ = http_inbound::handle_connection(stream, &line).await;
                }
            }
        });
    }
}
