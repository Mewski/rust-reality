//! Local SOCKS5 / HTTP CONNECT client that dials authenticated REALITY LINEs.
//!
//! The client role terminates no public REALITY identity. It accepts loopback
//! SOCKS5 CONNECT and/or HTTP CONNECT, opens one LINE (REALITY → VLESS → Vision),
//! and relays bytes.

mod http_inbound;
mod line;
mod serve;
mod session;
mod socks5_inbound;

pub use line::{Line, LineError};
pub use serve::{ClientRuntimeError, run_client};
pub use session::VisionTunnel;
