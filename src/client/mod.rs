//! Local SOCKS5 client that dials authenticated REALITY LINEs.
//!
//! The client role terminates no public REALITY identity. It accepts loopback
//! SOCKS5 CONNECT, opens one LINE (REALITY → VLESS → Vision), and relays bytes.

mod line;
mod serve;
mod session;
mod socks5_inbound;

pub use line::{Line, LineError};
pub use serve::{ClientRuntimeError, run_client};
pub use session::VisionTunnel;
