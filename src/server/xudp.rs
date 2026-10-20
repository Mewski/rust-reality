//! Server-side XUDP association over Direct UDP egress.
//!
//! Framing and Vision UDP/443 policy live in [`crate::protocol::vless`] (`encode_xudp_packet` / `decode_xudp_packet`).
//! This module owns UDP sockets, GlobalID affinity, resource limits, and
//! fail-closed handling for unsupported outbounds (NXR / Handoff).

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;

use crate::protocol::vless::{
    Address, Destination, XudpCodecError, XudpGlobalId, XudpPacket, XudpSessionStatus,
    decode_xudp_packet, encode_xudp_packet,
};

/// Maximum concurrent GlobalID-keyed associations retained by this process.
pub const XUDP_MAX_ASSOCIATIONS: usize = 256;

/// Idle time after which an association is eligible for cleanup.
pub const XUDP_ASSOCIATION_IDLE: Duration = Duration::from_secs(60);

/// Maximum UDP payload accepted from an XUDP frame (matches codec bound).
pub const XUDP_MAX_DATAGRAM: usize = crate::protocol::vless::XUDP_MAX_PAYLOAD_LEN;

/// One FD-budget unit charged per Direct UDP socket.
pub const XUDP_FD_UNITS: u32 = 1;

/// Why an XUDP session cannot use a selected outbound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XudpOutboundUnsupported {
    Nxr,
    Handoff,
    Block,
    /// SOCKS5 or any other non-Direct outbound.
    Other,
}

impl fmt::Display for XudpOutboundUnsupported {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nxr => formatter.write_str(
                "XUDP over NXR is not supported; configure a Direct route for UDP destinations",
            ),
            Self::Handoff => formatter.write_str(
                "XUDP over Handoff is not supported; configure a Direct route for UDP destinations",
            ),
            Self::Block => formatter.write_str("XUDP destination is blocked by routing"),
            Self::Other => formatter
                .write_str("XUDP requires a Direct outbound; this route is not UDP-capable"),
        }
    }
}

impl Error for XudpOutboundUnsupported {}

/// Public classification of a routed outbound for XUDP eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XudpRouteClass {
    /// Builtin or equivalent Direct TCP/UDP egress.
    Direct,
    Nxr,
    Handoff,
    Block,
    /// SOCKS5 or other non-UDP-capable outbounds.
    Unsupported,
}

/// Returns `Ok(())` only when the route class can carry XUDP (Direct).
pub fn require_direct_xudp_route(class: XudpRouteClass) -> Result<(), XudpOutboundUnsupported> {
    match class {
        XudpRouteClass::Direct => Ok(()),
        XudpRouteClass::Nxr => Err(XudpOutboundUnsupported::Nxr),
        XudpRouteClass::Handoff => Err(XudpOutboundUnsupported::Handoff),
        XudpRouteClass::Block => Err(XudpOutboundUnsupported::Block),
        XudpRouteClass::Unsupported => Err(XudpOutboundUnsupported::Other),
    }
}

/// Errors from server XUDP association handling.
#[derive(Debug)]
pub enum XudpSessionError {
    Codec(XudpCodecError),
    Outbound(XudpOutboundUnsupported),
    Io(std::io::Error),
    AssociationLimit,
    FdBudgetExhausted,
    MissingNewDestination,
    /// Keep/New carried a destination but the caller did not supply an
    /// authorized rewrite (routing/DNS/outbound must run first).
    UnauthorizedRewrite,
    ResolveFailed,
    IdleTimeout,
    AssociationConflict,
    /// Client sent a Vision Direct command on an XUDP (UDP-only) session.
    UnexpectedVisionDirect,
}

impl fmt::Display for XudpSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "XUDP framing error: {error}"),
            Self::Outbound(error) => error.fmt(formatter),
            Self::Io(error) => write!(formatter, "XUDP UDP I/O error: {error}"),
            Self::AssociationLimit => write!(
                formatter,
                "XUDP association limit ({XUDP_MAX_ASSOCIATIONS}) reached"
            ),
            Self::FdBudgetExhausted => formatter.write_str("XUDP UDP socket FD budget exhausted"),
            Self::MissingNewDestination => {
                formatter.write_str("XUDP New frame missing UDP destination")
            }
            Self::UnauthorizedRewrite => {
                formatter.write_str("XUDP destination rewrite was not authorized by routing policy")
            }
            Self::ResolveFailed => formatter.write_str("XUDP destination could not be resolved"),
            Self::IdleTimeout => formatter.write_str("XUDP association idle timeout"),
            Self::AssociationConflict => {
                formatter.write_str("XUDP GlobalID association conflict while initializing")
            }
            Self::UnexpectedVisionDirect => {
                formatter.write_str("Vision Direct is not valid on an XUDP session")
            }
        }
    }
}

impl Error for XudpSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Outbound(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<XudpCodecError> for XudpSessionError {
    fn from(error: XudpCodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<XudpOutboundUnsupported> for XudpSessionError {
    fn from(error: XudpOutboundUnsupported) -> Self {
        Self::Outbound(error)
    }
}

/// Resolve a VLESS [`Destination`] to a UDP [`SocketAddr`] for Direct egress.
pub fn destination_to_socket_addr(
    destination: &Destination,
) -> Result<SocketAddr, XudpSessionError> {
    match destination.address() {
        Address::Ipv4(addr) => Ok(SocketAddr::from((*addr, destination.port()))),
        Address::Ipv6(addr) => Ok(SocketAddr::from((*addr, destination.port()))),
        Address::Domain(_) => Err(XudpSessionError::ResolveFailed),
    }
}

/// GlobalID map (cone-NAT affinity), mirroring stock `XUDPManager`.
///
/// Use [`process_xudp_global_map`] for the process-wide instance. Capacity
/// [`XUDP_MAX_ASSOCIATIONS`] is enforced on that shared map, not per session.
#[derive(Default)]
pub struct XudpGlobalMap {
    inner: Mutex<HashMap<XudpGlobalId, GlobalEntry>>,
}

struct GlobalEntry {
    expire: Instant,
    status: GlobalStatus,
    /// Authenticated VLESS user that owns this GlobalID while it is Active
    /// (or still Expiring pending purge). Prevents cross-user claim of a live id.
    owner: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GlobalStatus {
    Active,
    Expiring,
}

impl XudpGlobalMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or refresh an active GlobalID for `owner`.
    ///
    /// Capacity [`XUDP_MAX_ASSOCIATIONS`] is process-wide. An Active (or still
    /// Expiring) id owned by a *different* user fails closed with
    /// [`XudpSessionError::AssociationConflict`] — no cross-user takeover.
    pub fn activate(
        &self,
        id: XudpGlobalId,
        owner: [u8; 16],
        now: Instant,
    ) -> Result<(), XudpSessionError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.purge_locked(&mut guard, now);
        if let Some(entry) = guard.get_mut(&id) {
            if entry.owner != owner {
                return Err(XudpSessionError::AssociationConflict);
            }
            entry.status = GlobalStatus::Active;
            entry.expire = now + XUDP_ASSOCIATION_IDLE;
            return Ok(());
        }
        if guard.len() >= XUDP_MAX_ASSOCIATIONS {
            return Err(XudpSessionError::AssociationLimit);
        }
        guard.insert(
            id,
            GlobalEntry {
                expire: now + XUDP_ASSOCIATION_IDLE,
                status: GlobalStatus::Active,
                owner,
            },
        );
        Ok(())
    }

    /// Mark an association expiring (stock puts a one-minute grace).
    pub fn expire(&self, id: XudpGlobalId, now: Instant) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get_mut(&id) {
            entry.status = GlobalStatus::Expiring;
            entry.expire = now + XUDP_ASSOCIATION_IDLE;
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Returns whether no GlobalID associations are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn purge_locked(&self, map: &mut HashMap<XudpGlobalId, GlobalEntry>, now: Instant) {
        map.retain(|_, entry| !(entry.status == GlobalStatus::Expiring && now >= entry.expire));
    }

    pub fn purge(&self, now: Instant) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.purge_locked(&mut guard, now);
    }
}

/// Returns the process-wide GlobalID association map (stock `XUDPManager`).
///
/// All Vision XUDP sessions share this map so capacity and affinity accounting
/// are truly process-wide, not per Mux/TLS session.
pub fn process_xudp_global_map() -> &'static XudpGlobalMap {
    static GLOBALS: OnceLock<XudpGlobalMap> = OnceLock::new();
    GLOBALS.get_or_init(XudpGlobalMap::new)
}

/// One Direct UDP association for an XUDP Mux session (session id 0).
pub struct XudpDirectAssociation {
    socket: UdpSocket,
    destination: SocketAddr,
    /// Last VLESS destination used for Keep frames that omit an address.
    last_destination: Destination,
    global_id: Option<XudpGlobalId>,
    last_activity: Instant,
    uplink_datagrams: u64,
    downlink_datagrams: u64,
}

impl XudpDirectAssociation {
    /// Bind an ephemeral UDP socket and remember the first destination.
    pub async fn open(
        destination: &Destination,
        global_id: Option<XudpGlobalId>,
        owner: [u8; 16],
        globals: &XudpGlobalMap,
        now: Instant,
    ) -> Result<Self, XudpSessionError> {
        let addr = destination_to_socket_addr(destination)?;
        if let Some(id) = global_id {
            globals.activate(id, owner, now)?;
        }
        let bind = match addr {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        };
        let socket = UdpSocket::bind(bind).await.map_err(XudpSessionError::Io)?;
        Ok(Self {
            socket,
            destination: addr,
            last_destination: destination.clone(),
            global_id,
            last_activity: now,
            uplink_datagrams: 0,
            downlink_datagrams: 0,
        })
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub fn uplink_datagrams(&self) -> u64 {
        self.uplink_datagrams
    }

    pub fn downlink_datagrams(&self) -> u64 {
        self.downlink_datagrams
    }

    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Apply one decoded uplink XUDP packet: send UDP after an authorized rewrite.
    ///
    /// When `packet.destination` is present (New, or Keep rewrite), the caller
    /// MUST supply `authorized_destination`: the same logical destination after
    /// canonical routing, DNS resolution, and Direct-only outbound checks.
    /// Associations never inherit a prior Direct decision across a rewrite.
    pub async fn handle_uplink_packet(
        &mut self,
        packet: &XudpPacket,
        authorized_destination: Option<&Destination>,
        now: Instant,
    ) -> Result<(), XudpSessionError> {
        match packet.status {
            XudpSessionStatus::End | XudpSessionStatus::KeepAlive => {
                self.last_activity = now;
                return Ok(());
            }
            XudpSessionStatus::New | XudpSessionStatus::Keep => {}
        }
        if packet.destination.is_some() {
            let dest = authorized_destination.ok_or(XudpSessionError::UnauthorizedRewrite)?;
            self.destination = destination_to_socket_addr(dest)?;
            self.last_destination = dest.clone();
        } else if packet.status == XudpSessionStatus::New {
            return Err(XudpSessionError::MissingNewDestination);
        }
        if !packet.payload.is_empty() {
            self.socket
                .send_to(&packet.payload, self.destination)
                .await
                .map_err(XudpSessionError::Io)?;
            self.uplink_datagrams = self.uplink_datagrams.saturating_add(1);
        }
        self.last_activity = now;
        Ok(())
    }

    /// Receive one downlink UDP datagram and encode an XUDP Keep frame.
    pub async fn recv_downlink_frame(
        &mut self,
        buf: &mut [u8],
        output: &mut Vec<u8>,
        now: Instant,
    ) -> Result<usize, XudpSessionError> {
        let (n, from) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(XudpSessionError::Io)?;
        // Preserve peer address in the Keep frame so multi-address sessions work.
        let dest = socket_addr_to_destination(from);
        output.clear();
        encode_xudp_packet(&dest, &buf[..n], false, None, true, output)?;
        self.last_destination = dest;
        self.destination = from;
        self.downlink_datagrams = self.downlink_datagrams.saturating_add(1);
        self.last_activity = now;
        Ok(output.len())
    }

    pub fn close(self, globals: &XudpGlobalMap, now: Instant) {
        if let Some(id) = self.global_id {
            globals.expire(id, now);
        }
    }
}

fn socket_addr_to_destination(addr: SocketAddr) -> Destination {
    match addr {
        SocketAddr::V4(v4) => Destination::new(Address::Ipv4(*v4.ip()), v4.port()),
        SocketAddr::V6(v6) => Destination::new(Address::Ipv6(*v6.ip()), v6.port()),
    }
}

/// Decode and drain complete XUDP frames from a Vision plaintext buffer.
pub fn drain_xudp_frames(buffer: &mut Vec<u8>) -> Result<Vec<XudpPacket>, XudpSessionError> {
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < buffer.len() {
        match decode_xudp_packet(&buffer[offset..]) {
            Ok((packet, consumed)) => {
                offset += consumed;
                packets.push(packet);
            }
            Err(XudpCodecError::Truncated { .. }) => break,
            Err(error) => return Err(XudpSessionError::Codec(error)),
        }
    }
    if offset > 0 {
        buffer.drain(..offset);
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::vless::VISION_FLOW;
    use std::net::Ipv4Addr;

    #[test]
    fn direct_outbound_is_allowed() {
        require_direct_xudp_route(XudpRouteClass::Direct).unwrap();
    }

    #[test]
    fn nxr_and_handoff_fail_closed() {
        assert_eq!(
            require_direct_xudp_route(XudpRouteClass::Nxr),
            Err(XudpOutboundUnsupported::Nxr)
        );
        assert_eq!(
            require_direct_xudp_route(XudpRouteClass::Handoff),
            Err(XudpOutboundUnsupported::Handoff)
        );
        assert_eq!(
            require_direct_xudp_route(XudpRouteClass::Block),
            Err(XudpOutboundUnsupported::Block)
        );
    }

    #[test]
    fn process_global_map_is_shared_across_calls() {
        let a = process_xudp_global_map() as *const XudpGlobalMap;
        let b = process_xudp_global_map() as *const XudpGlobalMap;
        assert_eq!(a, b);
    }

    #[test]
    fn global_map_respects_capacity_and_expire() {
        let map = XudpGlobalMap::new();
        let now = Instant::now();
        for i in 0..XUDP_MAX_ASSOCIATIONS {
            let mut id = [0_u8; 8];
            id[0] = (i / 256) as u8;
            id[1] = (i % 256) as u8;
            map.activate(id, [1; 16], now).unwrap();
        }
        assert!(matches!(
            map.activate([0xff; 8], [1; 16], now),
            Err(XudpSessionError::AssociationLimit)
        ));
        map.expire([0, 0, 0, 0, 0, 0, 0, 0], now);
        map.purge(now + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
        assert!(map.len() < XUDP_MAX_ASSOCIATIONS);
        map.activate([0xff; 8], [1; 16], now).unwrap();
    }

    #[test]
    fn drain_frames_round_trip() {
        let dest = Destination::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 9);
        let mut wire = Vec::new();
        encode_xudp_packet(&dest, b"ping", true, Some([1; 8]), false, &mut wire).unwrap();
        encode_xudp_packet(&dest, b"pong", false, None, false, &mut wire).unwrap();
        let mut buffer = wire;
        let packets = drain_xudp_frames(&mut buffer).unwrap();
        assert!(buffer.is_empty());
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].payload, b"ping");
        assert_eq!(packets[1].payload, b"pong");
        let _ = VISION_FLOW;
    }

    #[tokio::test]
    async fn direct_udp_echo_round_trip() {
        let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let dest = socket_addr_to_destination(echo_addr);
        let globals = XudpGlobalMap::new();
        let now = Instant::now();
        let mut assoc = XudpDirectAssociation::open(&dest, Some([9; 8]), [9; 16], &globals, now)
            .await
            .unwrap();

        let packet = {
            let mut wire = Vec::new();
            encode_xudp_packet(&dest, b"hello-xudp", true, Some([9; 8]), false, &mut wire).unwrap();
            decode_xudp_packet(&wire).unwrap().0
        };
        assoc
            .handle_uplink_packet(&packet, packet.destination.as_ref(), Instant::now())
            .await
            .unwrap();

        let mut buf = [0_u8; 64];
        let (n, from) = echo.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-xudp");
        echo.send_to(b"echo-ok", from).await.unwrap();

        let mut out = Vec::new();
        let mut recv_buf = [0_u8; 2048];
        assoc
            .recv_downlink_frame(&mut recv_buf, &mut out, Instant::now())
            .await
            .unwrap();
        let (reply, _) = decode_xudp_packet(&out).unwrap();
        assert_eq!(reply.payload, b"echo-ok");
        assert_eq!(reply.status, XudpSessionStatus::Keep);
        assert_eq!(assoc.uplink_datagrams(), 1);
        assert_eq!(assoc.downlink_datagrams(), 1);
        assoc.close(&globals, Instant::now());
    }

    #[tokio::test]
    async fn uplink_rewrite_without_authorization_fails_closed() {
        let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let dest = socket_addr_to_destination(echo.local_addr().unwrap());
        let globals = XudpGlobalMap::new();
        let mut assoc = XudpDirectAssociation::open(&dest, None, [2; 16], &globals, Instant::now())
            .await
            .unwrap();
        let blocked = Destination::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, 1)), 9);
        let packet = {
            let mut wire = Vec::new();
            encode_xudp_packet(&blocked, b"nope", false, None, true, &mut wire).unwrap();
            decode_xudp_packet(&wire).unwrap().0
        };
        assert!(packet.destination.is_some());
        let err = assoc
            .handle_uplink_packet(&packet, None, Instant::now())
            .await
            .expect_err("rewrite without authorization must fail closed");
        assert!(matches!(err, XudpSessionError::UnauthorizedRewrite));
        assert_eq!(assoc.uplink_datagrams(), 0);
        assoc.close(&globals, Instant::now());
    }

    #[test]
    fn keep_rewrite_route_class_red_green() {
        // GREEN: Direct remains eligible.
        require_direct_xudp_route(XudpRouteClass::Direct).unwrap();
        // RED: a later Keep rewrite that routes to Block/Handoff/NXR must not
        // inherit the prior Direct decision — same fail-closed classifier.
        assert_eq!(
            require_direct_xudp_route(XudpRouteClass::Block),
            Err(XudpOutboundUnsupported::Block)
        );
        assert_eq!(
            require_direct_xudp_route(XudpRouteClass::Handoff),
            Err(XudpOutboundUnsupported::Handoff)
        );
        assert_eq!(
            require_direct_xudp_route(XudpRouteClass::Nxr),
            Err(XudpOutboundUnsupported::Nxr)
        );
    }

    #[tokio::test]
    async fn association_close_then_purge_releases_global_slot() {
        let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let dest = socket_addr_to_destination(echo.local_addr().unwrap());
        let globals = XudpGlobalMap::new();
        let now = Instant::now();
        let gid = [7_u8; 8];
        let assoc = XudpDirectAssociation::open(&dest, Some(gid), [7; 16], &globals, now)
            .await
            .unwrap();
        assert_eq!(globals.len(), 1);
        // close marks the GlobalID expired; purge drops it (control-EOF / cancel path).
        assoc.close(&globals, now);
        globals.purge(now + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
        assert_eq!(globals.len(), 0);
        let again = XudpDirectAssociation::open(&dest, Some(gid), [7; 16], &globals, now)
            .await
            .unwrap();
        assert_eq!(globals.len(), 1);
        again.close(&globals, now);
    }

    #[test]
    fn global_id_rejects_cross_user_claim_while_active() {
        let map = XudpGlobalMap::new();
        let now = Instant::now();
        let gid = [0x42_u8; 8];
        map.activate(gid, [1; 16], now).unwrap();
        assert!(matches!(
            map.activate(gid, [2; 16], now),
            Err(XudpSessionError::AssociationConflict)
        ));
        // Same owner may refresh.
        map.activate(gid, [1; 16], now).unwrap();
        map.expire(gid, now);
        map.purge(now + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
        // After purge, a different user may claim the id.
        map.activate(gid, [2; 16], now).unwrap();
    }
}
