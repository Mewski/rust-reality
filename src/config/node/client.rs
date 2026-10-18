//! The client role: local SOCKS5 inbound and one or more REALITY LINEs.
//!
//! A client node terminates no public REALITY identity. It listens locally,
//! authenticates outbound to an entry, and relays application bytes through
//! VLESS + REALITY + Vision. Single-LINE selection is the first shipping shape;
//! multi-LINE selection remains a later PR.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{dns::DnsConfig, listener::ListenerConfig, log::LogConfig, runtime::RuntimeConfig};

/// A local client node.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientConfig {
    /// Always `client`.
    pub role: ClientRole,
    /// Local SOCKS5 listening endpoints. Defaults are loopback-only.
    pub listeners: Vec<ListenerConfig>,
    /// Authenticated LINEs to an entry. Exactly one LINE is required in PR3.
    pub lines: Vec<LineConfig>,
    /// Name resolution for LINE addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
    /// Logging destination and retention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<LogConfig>,
    /// Resource posture and expert limit overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeConfig>,
}

/// The role tag of a client node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientRole {
    /// The only accepted value.
    Client,
}

/// One REALITY-authenticated LINE to an entry.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LineConfig {
    /// Optional label for diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Entry host or IP without a scheme or port.
    pub address: String,
    /// Entry TCP port.
    pub port: u16,
    /// Authorized user UUID (canonical hyphenated form).
    pub id: String,
    /// Entry REALITY public key (URL-safe unpadded base64, 32 bytes).
    pub public_key: String,
    /// Short ID assigned to this user (even-length hex, 2..=16 characters).
    pub short_id: String,
    /// Server-accepted SNI / serverName.
    pub server_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_single_line_client() {
        let json = r#"{
  "role": "client",
  "listeners": [{"port": 10808, "ipv4": "127.0.0.1"}],
  "lines": [{
    "address": "127.0.0.1",
    "port": 8443,
    "id": "11111111-1111-4111-8111-111111111111",
    "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "shortId": "0102030405060708",
    "serverName": "www.example.com"
  }]
}"#;
        let parsed: ClientConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.role, ClientRole::Client);
        assert_eq!(parsed.listeners.len(), 1);
        assert_eq!(parsed.lines.len(), 1);
        assert_eq!(parsed.lines[0].port, 8443);
    }
}
