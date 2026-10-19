//! Client XUDP tunnel over one committed REALITY + Vision LINE.
//!
//! Opens VLESS Mux (`0x03`) with wire flow `xtls-rprx-vision`, then carries
//! SOCKS5 UDP ASSOCIATE traffic as XUDP frames. The LINE is fixed for the
//! association lifetime (no mid-session migration).

use std::{io, net::SocketAddr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use crate::protocol::{
    reality::{
        ClientSession,
        tls13::{ContentType, MAX_PLAINTEXT_LEN, MAX_TLS_RECORD_WIRE_LEN},
    },
    socks5::{decode_udp_datagram, encode_udp_datagram},
    vless::{
        Destination, ResponseDecodeError, UserId, VisionCommand, VisionDecoder, VisionEncoder,
        VisionMode, XudpPacket, decode_response, decode_xudp_packet, encode_vision_xudp_request,
        encode_xudp_packet, vision_udp_command_allows_port,
    },
};

use super::session::VisionTunnelError;

/// Client-side XUDP association bound to one authenticated LINE.
pub struct XudpTunnel {
    stream: TcpStream,
    session: ClientSession,
    encoder: VisionEncoder,
    decoder: VisionDecoder,
    downlink: VisionMode,
    readable: Vec<u8>,
    readable_at: usize,
    encoder_done: bool,
    /// Destination of the most recent uplink New/Keep frame (for Keep without rewrite).
    last_destination: Option<Destination>,
    association_opened: bool,
    allow_udp_443: bool,
}

impl XudpTunnel {
    /// Sends the Vision Mux/XUDP preamble and waits for the VLESS response.
    pub async fn connect(
        mut stream: TcpStream,
        mut session: ClientSession,
        user_id: UserId,
        allow_udp_443: bool,
    ) -> Result<Self, VisionTunnelError> {
        let mut request = [0_u8; 128];
        let request_len = encode_vision_xudp_request(user_id, &mut request)
            .map_err(|_| VisionTunnelError::Request)?;
        let mut encoder = VisionEncoder::new(user_id).map_err(|_| VisionTunnelError::Vision)?;
        let preamble = encoder
            .plan(0, VisionCommand::Continue, true)
            .map_err(|_| VisionTunnelError::Vision)?;
        let total = request_len
            .checked_add(preamble.wire_len())
            .filter(|n| *n <= MAX_PLAINTEXT_LEN)
            .ok_or(VisionTunnelError::Request)?;
        let mut frame = vec![0_u8; total];
        frame[..request_len].copy_from_slice(&request[..request_len]);
        encoder.assemble(&preamble, &[], &mut frame[request_len..]);
        encoder.commit(&preamble);

        let mut record = Vec::new();
        session
            .write_mut()
            .seal_into(ContentType::ApplicationData, &frame, 0, &mut record)
            .map_err(|_| VisionTunnelError::Record)?;
        stream
            .write_all(&record)
            .await
            .map_err(VisionTunnelError::Io)?;
        stream.flush().await.map_err(VisionTunnelError::Io)?;

        let mut tunnel = Self {
            stream,
            session,
            encoder,
            decoder: VisionDecoder::new(user_id),
            downlink: VisionMode::Framed,
            readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            readable_at: 0,
            encoder_done: false,
            last_destination: None,
            association_opened: false,
            allow_udp_443,
        };
        tunnel.await_response().await?;
        Ok(tunnel)
    }

    /// Relays SOCKS5 UDP datagrams on `udp` while `control` stays open.
    ///
    /// The first peer that sends a datagram becomes the only accepted peer
    /// address (typical SOCKS5 UDP ASSOCIATE cone). The TCP control connection
    /// ending tears the association down.
    pub async fn relay_socks5_udp(
        &mut self,
        udp: &UdpSocket,
        control: &mut TcpStream,
    ) -> Result<(), VisionTunnelError> {
        let mut peer: Option<SocketAddr> = None;
        let mut udp_buf = vec![0_u8; 64 * 1024];
        let mut control_buf = [0_u8; 64];
        let mut socks_out = Vec::new();
        let mut xudp_out = Vec::new();

        loop {
            tokio::select! {
                result = udp.recv_from(&mut udp_buf) => {
                    let (n, from) = result.map_err(VisionTunnelError::Io)?;
                    match peer {
                        None => peer = Some(from),
                        Some(expected) if expected != from => continue,
                        Some(_) => {}
                    }
                    let datagram = decode_udp_datagram(&udp_buf[..n])
                        .map_err(|_| VisionTunnelError::Request)?;
                    let destination = datagram.destination().clone();
                    if !vision_udp_command_allows_port(self.allow_udp_443, destination.port()) {
                        return Err(VisionTunnelError::Request);
                    }
                    self.send_xudp(&destination, datagram.payload(), &mut xudp_out)
                        .await?;
                }
                ready = self.poll_fill_readable() => {
                    ready?;
                    while let Some(packet) = self.take_xudp_packet()? {
                        let Some(destination) = packet.destination.clone().or_else(|| {
                            self.last_destination.clone()
                        }) else {
                            continue;
                        };
                        encode_udp_datagram(&destination, &packet.payload, &mut socks_out)
                            .map_err(|_| VisionTunnelError::Request)?;
                        if let Some(peer_addr) = peer {
                            udp.send_to(&socks_out, peer_addr)
                                .await
                                .map_err(VisionTunnelError::Io)?;
                        }
                    }
                }
                read = control.read(&mut control_buf) => {
                    let n = read.map_err(VisionTunnelError::Io)?;
                    if n == 0 {
                        return Ok(());
                    }
                    // Discard unexpected TCP bytes on the control channel.
                }
            }
        }
    }

    async fn send_xudp(
        &mut self,
        destination: &Destination,
        payload: &[u8],
        scratch: &mut Vec<u8>,
    ) -> Result<(), VisionTunnelError> {
        let new_association = !self.association_opened;
        let rewrite = self
            .last_destination
            .as_ref()
            .is_some_and(|last| last != destination);
        scratch.clear();
        encode_xudp_packet(
            destination,
            payload,
            new_association,
            None,
            rewrite && !new_association,
            scratch,
        )
        .map_err(|_| VisionTunnelError::Request)?;
        self.write_application(scratch).await?;
        self.association_opened = true;
        self.last_destination = Some(destination.clone());
        Ok(())
    }

    fn take_xudp_packet(&mut self) -> Result<Option<XudpPacket>, VisionTunnelError> {
        if self.readable_at >= self.readable.len() {
            return Ok(None);
        }
        let available = &self.readable[self.readable_at..];
        match decode_xudp_packet(available) {
            Ok((packet, consumed)) => {
                self.readable_at += consumed;
                if let Some(dest) = packet.destination.clone() {
                    self.last_destination = Some(dest);
                }
                if self.readable_at > 64 * 1024 {
                    self.readable.drain(..self.readable_at);
                    self.readable_at = 0;
                }
                Ok(Some(packet))
            }
            Err(crate::protocol::vless::XudpCodecError::Truncated { .. }) => Ok(None),
            Err(_) => Err(VisionTunnelError::Request),
        }
    }

    async fn await_response(&mut self) -> Result<(), VisionTunnelError> {
        let mut response_buf = Vec::new();
        loop {
            let plaintext = self.read_raw_application().await?;
            if plaintext.is_empty() {
                continue;
            }
            response_buf.extend_from_slice(&plaintext);
            match decode_response(&response_buf) {
                Ok(decoded) => {
                    let payload = decoded.payload().to_vec();
                    self.readable.clear();
                    self.readable_at = 0;
                    if !payload.is_empty() {
                        self.ingest_plaintext(&payload)?;
                    }
                    return Ok(());
                }
                Err(ResponseDecodeError::Incomplete { .. }) => continue,
                Err(_) => return Err(VisionTunnelError::Request),
            }
        }
    }

    async fn read_and_open_record(&mut self) -> Result<(), VisionTunnelError> {
        let plaintext = self.read_raw_application().await?;
        if plaintext.is_empty() {
            return Ok(());
        }
        self.ingest_plaintext(&plaintext)
    }

    async fn read_raw_application(&mut self) -> Result<Vec<u8>, VisionTunnelError> {
        loop {
            let mut header = [0_u8; 5];
            self.stream.read_exact(&mut header).await.map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    VisionTunnelError::ClosedBeforeResponse
                } else {
                    VisionTunnelError::Io(e)
                }
            })?;
            let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if body_len + 5 > MAX_TLS_RECORD_WIRE_LEN {
                return Err(VisionTunnelError::Record);
            }
            let mut body = vec![0_u8; body_len];
            self.stream
                .read_exact(&mut body)
                .await
                .map_err(VisionTunnelError::Io)?;
            match header[0] {
                20 => continue,
                23 => {
                    let mut record = Vec::with_capacity(5 + body_len);
                    record.extend_from_slice(&header);
                    record.extend_from_slice(&body);
                    let opened = self
                        .session
                        .read_mut()
                        .open_in_place(&mut record)
                        .map_err(|_| VisionTunnelError::Record)?;
                    return Ok(opened.plaintext().to_vec());
                }
                _ => return Err(VisionTunnelError::Record),
            }
        }
    }

    fn ingest_plaintext(&mut self, plaintext: &[u8]) -> Result<(), VisionTunnelError> {
        match self.downlink {
            VisionMode::Direct | VisionMode::Raw => {
                self.readable.extend_from_slice(plaintext);
                Ok(())
            }
            VisionMode::Framed => {
                let mut staged = Vec::new();
                let mode = self
                    .decoder
                    .decode_append(plaintext, &mut staged)
                    .map_err(|_| VisionTunnelError::Vision)?;
                self.readable.extend_from_slice(&staged);
                self.downlink = mode;
                if matches!(mode, VisionMode::Direct) {
                    self.encoder_done = true;
                }
                Ok(())
            }
        }
    }

    async fn poll_fill_readable(&mut self) -> Result<(), VisionTunnelError> {
        if self.readable_at < self.readable.len() {
            return Ok(());
        }
        self.read_and_open_record().await
    }

    async fn write_application(&mut self, payload: &[u8]) -> Result<(), VisionTunnelError> {
        if payload.is_empty() {
            return Ok(());
        }
        if self.encoder_done {
            return self.seal_and_send(payload).await;
        }
        let mut offset = 0;
        while offset < payload.len() {
            let want = (payload.len() - offset).min(8 * 1024);
            let planned = self.encoder.plan(want, VisionCommand::Continue, false);
            let Ok(plan) = planned else {
                self.encoder_done = true;
                return self.seal_and_send(&payload[offset..]).await;
            };
            let content = &payload[offset..offset + want];
            let mut frame = vec![0_u8; plan.wire_len()];
            self.encoder.assemble(&plan, content, &mut frame);
            self.encoder.commit(&plan);
            self.seal_and_send(&frame).await?;
            offset += want;
        }
        self.stream.flush().await.map_err(VisionTunnelError::Io)?;
        Ok(())
    }

    async fn seal_and_send(&mut self, plaintext: &[u8]) -> Result<(), VisionTunnelError> {
        let mut record = Vec::new();
        self.session
            .write_mut()
            .seal_into(ContentType::ApplicationData, plaintext, 0, &mut record)
            .map_err(|_| VisionTunnelError::Record)?;
        self.stream
            .write_all(&record)
            .await
            .map_err(VisionTunnelError::Io)?;
        Ok(())
    }
}
