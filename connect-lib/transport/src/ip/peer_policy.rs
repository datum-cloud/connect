//! Receiver-owned, host-pair packet approvals for a single authenticated peer.
//! This is deliberately not a router or a general-purpose connection tracker.
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::{Duration, Instant},
};

const MAX_FLOWS: usize = 1024;
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const ECHO_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const TCP_CLOSING_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    IcmpEcho,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub protocol: Protocol,
    pub ports: Vec<u16>,
}

#[derive(Default)]
struct Rules {
    tcp: HashSet<u16>,
    udp: HashSet<u16>,
    echo: bool,
}
impl Rules {
    fn parse(rules: Vec<Rule>) -> Result<Self, &'static str> {
        if rules.len() > 128 {
            return Err("at most 128 peer rules are allowed");
        }
        let mut result = Self::default();
        for rule in rules {
            if rule.ports.len() > 1024 || rule.ports.contains(&0) {
                return Err("peer rules require nonzero ports and at most 1024 ports per rule");
            }
            match rule.protocol {
                Protocol::IcmpEcho if rule.ports.is_empty() => result.echo = true,
                Protocol::IcmpEcho => return Err("ICMP echo rules cannot contain ports"),
                Protocol::Tcp | Protocol::Udp if rule.ports.is_empty() => {
                    return Err("TCP and UDP rules require explicit ports");
                }
                Protocol::Tcp => result.tcp.extend(rule.ports),
                Protocol::Udp => result.udp.extend(rule.ports),
            }
        }
        if result.tcp.len() + result.udp.len() > 4096 {
            return Err("at most 4096 distinct peer ports are allowed");
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct FlowKey {
    sending: bool,
    protocol: u8,
    source: u16,
    destination: u16,
}
impl FlowKey {
    fn reverse(self) -> Self {
        Self {
            sending: !self.sending,
            source: self.destination,
            destination: self.source,
            ..self
        }
    }
}
#[derive(Clone, Copy)]
enum State {
    Datagram,
    Echo,
    Syn(u32),
    SynAck {
        initial: u32,
        response: u32,
    },
    Established {
        forward_fin: bool,
        reverse_fin: bool,
    },
    Closing,
}
impl State {
    fn idle_timeout(self) -> Duration {
        match self {
            Self::Datagram => UDP_IDLE_TIMEOUT,
            Self::Echo => ECHO_IDLE_TIMEOUT,
            Self::Syn(_) | Self::SynAck { .. } => HANDSHAKE_IDLE_TIMEOUT,
            Self::Established { .. } => TCP_IDLE_TIMEOUT,
            Self::Closing => TCP_CLOSING_TIMEOUT,
        }
    }
}
struct Flow {
    state: State,
    touched: Instant,
}

/// Use a fresh policy for every session. Never share flow state across networks,
/// authenticated peers, or reconnects. Drop/clear it on revocation/disconnect.
/// Idle expiry: TCP handshake/fully closed 30s, established/half-closed TCP 24h,
/// UDP 60s, echo 10s. Both FINs shorten expiry while allowing late ACKs/retries.
pub struct PeerPolicy {
    local: IpAddr,
    remote: IpAddr,
    inbound: Rules,
    outbound: Rules,
    flows: HashMap<FlowKey, Flow>,
    last_denial: Option<&'static str>,
}
impl PeerPolicy {
    pub fn new(
        local: IpAddr,
        remote: IpAddr,
        inbound: Vec<Rule>,
        outbound: Vec<Rule>,
    ) -> Result<Self, &'static str> {
        if local == remote
            || local.is_ipv4() != remote.is_ipv4()
            || !super::unicast(local)
            || !super::unicast(remote)
        {
            return Err(
                "peer policy requires two distinct unicast hosts in the same address family",
            );
        }
        Ok(Self {
            local,
            remote,
            inbound: Rules::parse(inbound)?,
            outbound: Rules::parse(outbound)?,
            flows: HashMap::new(),
            last_denial: None,
        })
    }
    pub fn authorize_send(&mut self, packet: &[u8]) -> bool {
        self.authorize(packet, true, Instant::now())
    }
    pub fn authorize_receive(&mut self, packet: &[u8]) -> bool {
        self.authorize(packet, false, Instant::now())
    }
    pub fn clear(&mut self) {
        self.flows.clear();
        self.last_denial = None;
    }

    /// Safe diagnostic for the most recent check; never includes packet bytes.
    pub fn last_denial_reason(&self) -> Option<&'static str> {
        self.last_denial
    }
    /// Tracked flows; expired entries are collected on the next packet check.
    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }

    fn authorize(&mut self, packet: &[u8], sending: bool, now: Instant) -> bool {
        self.last_denial = None;
        let allowed = self.authorize_inner(packet, sending, now);
        if !allowed && self.last_denial.is_none() {
            self.last_denial = Some("untracked_reply");
        }
        allowed
    }

    fn authorize_inner(&mut self, packet: &[u8], sending: bool, now: Instant) -> bool {
        let Some(parsed) = parse(packet) else {
            self.last_denial = Some("malformed_packet");
            return false;
        };
        let expected = if sending {
            (self.local, self.remote)
        } else {
            (self.remote, self.local)
        };
        if (parsed.source, parsed.destination) != expected {
            self.last_denial = Some("address_policy");
            return false;
        }
        self.flows.retain(|_, flow| {
            now.saturating_duration_since(flow.touched) < flow.state.idle_timeout()
        });
        let rules = if sending {
            &self.outbound
        } else {
            &self.inbound
        };
        let key = FlowKey {
            sending,
            protocol: parsed.protocol,
            source: parsed.a,
            destination: parsed.b,
        };
        match parsed.kind {
            Kind::Tcp {
                flags,
                sequence,
                acknowledgement,
            } => {
                let syn = flags & 2 != 0;
                let ack = flags & 16 != 0;
                let rst = flags & 4 != 0;
                let fin = flags & 1 != 0;
                if syn && !ack && !rst && !fin {
                    if !rules.tcp.contains(&parsed.b) {
                        self.last_denial = Some("port_policy");
                        return false;
                    }
                    // An approved retransmitted SYN does not erase handshake state.
                    if let Some(flow) = self.flows.get_mut(&key)
                        && matches!(flow.state, State::Syn(initial) | State::SynAck { initial, .. } if initial == sequence)
                    {
                        flow.touched = now;
                        return true;
                    }
                    return self.insert(key, State::Syn(sequence), now);
                }
                let (flow_key, reverse) = if self.flows.contains_key(&key) {
                    (key, false)
                } else {
                    (key.reverse(), true)
                };
                let Some(flow) = self.flows.get_mut(&flow_key) else {
                    return false;
                };
                let allowed = match flow.state {
                    State::Syn(initial)
                        if reverse
                            && syn
                            && ack
                            && !rst
                            && !fin
                            && acknowledgement == initial.wrapping_add(1) =>
                    {
                        flow.state = State::SynAck {
                            initial,
                            response: sequence,
                        };
                        true
                    }
                    State::Syn(initial)
                        if reverse
                            && rst
                            && ack
                            && !syn
                            && acknowledgement == initial.wrapping_add(1) =>
                    {
                        true
                    }
                    State::SynAck { initial, response }
                        if reverse
                            && syn
                            && ack
                            && !rst
                            && !fin
                            && sequence == response
                            && acknowledgement == initial.wrapping_add(1) =>
                    {
                        true
                    }
                    State::SynAck { initial, response }
                        if !reverse
                            && !syn
                            && ack
                            && !rst
                            && sequence == initial.wrapping_add(1)
                            && acknowledgement == response.wrapping_add(1) =>
                    {
                        flow.state = State::Established {
                            forward_fin: false,
                            reverse_fin: false,
                        };
                        true
                    }
                    State::Established { .. } | State::Closing if !syn && (ack || rst) => true,
                    _ => false,
                };
                if allowed {
                    flow.touched = now;
                    if fin
                        && let State::Established {
                            mut forward_fin,
                            mut reverse_fin,
                        } = flow.state
                    {
                        if reverse {
                            reverse_fin = true;
                        } else {
                            forward_fin = true;
                        }
                        flow.state = if forward_fin && reverse_fin {
                            State::Closing
                        } else {
                            State::Established {
                                forward_fin,
                                reverse_fin,
                            }
                        };
                    }
                    if rst {
                        self.flows.remove(&flow_key);
                    }
                }
                allowed
            }
            Kind::Udp => {
                if let Some(flow) = self.flows.get_mut(&key) {
                    flow.touched = now;
                    return true;
                }
                if let Some(flow) = self.flows.get_mut(&key.reverse()) {
                    flow.touched = now;
                    return true;
                }
                if !rules.udp.contains(&parsed.b) {
                    self.last_denial = Some("port_policy");
                    return false;
                }
                self.insert(key, State::Datagram, now)
            }
            Kind::Echo { reply } => {
                // ICMP identifiers/sequences are not transport ports and do not
                // swap on replies. A response consumes one approved request.
                if reply {
                    self.flows
                        .remove(&FlowKey {
                            sending: !sending,
                            ..key
                        })
                        .is_some()
                } else {
                    if !rules.echo {
                        self.last_denial = Some("echo_policy");
                        return false;
                    }
                    self.insert(key, State::Echo, now)
                }
            }
        }
    }
    fn insert(&mut self, key: FlowKey, state: State, now: Instant) -> bool {
        if !self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS {
            self.last_denial = Some("flow_limit");
            return false;
        }
        self.flows.insert(
            key,
            Flow {
                state,
                touched: now,
            },
        );
        true
    }
}

enum Kind {
    Tcp {
        flags: u8,
        sequence: u32,
        acknowledgement: u32,
    },
    Udp,
    Echo {
        reply: bool,
    },
}
struct Parsed {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    a: u16,
    b: u16,
    kind: Kind,
}
fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
fn long(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn sum(bytes: &[u8]) -> u32 {
    let (chunks, remainder) = bytes.as_chunks::<2>();
    let total: u32 = chunks.iter().map(|pair| u32::from(word(pair, 0))).sum();
    total + remainder.first().map_or(0, |byte| u32::from(*byte) << 8)
}
fn valid_checksum(mut checksum: u32) -> bool {
    while checksum > 0xffff {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    checksum == 0xffff
}
fn parse(packet: &[u8]) -> Option<Parsed> {
    if packet.len() > 1500 {
        return None;
    }
    let (source, destination, protocol, offset, pseudo) = match packet.first()? >> 4 {
        4 if packet.len() >= 20
            && packet[0] == 0x45
            && usize::from(word(packet, 2)) == packet.len()
            && word(packet, 6) & 0xbfff == 0
            && packet[8] != 0
            && valid_checksum(sum(&packet[..20])) =>
        {
            let source = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?);
            let destination = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?);
            (
                IpAddr::V4(source),
                IpAddr::V4(destination),
                packet[9],
                20,
                sum(&packet[12..20]) + u32::from(packet[9]) + (packet.len() - 20) as u32,
            )
        }
        6 if packet.len() >= 40
            && usize::from(word(packet, 4)) + 40 == packet.len()
            && packet[7] != 0 =>
        {
            let source = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
            let destination = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
            (
                IpAddr::V6(source),
                IpAddr::V6(destination),
                packet[6],
                40,
                sum(&packet[8..40]) + u32::from(packet[6]) + (packet.len() - 40) as u32,
            )
        }
        _ => return None,
    };
    let payload = &packet[offset..];
    let (a, b, kind) = match protocol {
        6 if payload.len() >= 20
            && usize::from(payload[12] >> 4) * 4 >= 20
            && usize::from(payload[12] >> 4) * 4 <= payload.len()
            && valid_checksum(pseudo + sum(payload)) =>
        {
            (
                word(payload, 0),
                word(payload, 2),
                Kind::Tcp {
                    flags: payload[13],
                    sequence: long(payload, 4),
                    acknowledgement: long(payload, 8),
                },
            )
        }
        17 if payload.len() >= 8
            && usize::from(word(payload, 4)) == payload.len()
            && ((source.is_ipv4() && word(payload, 6) == 0)
                || (word(payload, 6) != 0 && valid_checksum(pseudo + sum(payload)))) =>
        {
            (word(payload, 0), word(payload, 2), Kind::Udp)
        }
        1 if source.is_ipv4()
            && payload.len() >= 8
            && payload[1] == 0
            && matches!(payload[0], 0 | 8)
            && valid_checksum(sum(payload)) =>
        {
            (
                word(payload, 4),
                word(payload, 6),
                Kind::Echo {
                    reply: payload[0] == 0,
                },
            )
        }
        58 if source.is_ipv6()
            && payload.len() >= 8
            && payload[1] == 0
            && matches!(payload[0], 128 | 129)
            && valid_checksum(pseudo + sum(payload)) =>
        {
            (
                word(payload, 4),
                word(payload, 6),
                Kind::Echo {
                    reply: payload[0] == 129,
                },
            )
        }
        _ => return None,
    };
    if matches!(kind, Kind::Tcp { .. } | Kind::Udp) && (a == 0 || b == 0) {
        return None;
    }
    Some(Parsed {
        source,
        destination,
        protocol,
        a,
        b,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hosts(v6: bool) -> (IpAddr, IpAddr) {
        if v6 {
            ("fd79::1".parse().unwrap(), "fd79::2".parse().unwrap())
        } else {
            ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap())
        }
    }
    fn rules(protocol: Protocol, ports: &[u16]) -> Vec<Rule> {
        vec![Rule {
            protocol,
            ports: ports.to_vec(),
        }]
    }
    fn checksum(mut total: u32) -> u16 {
        while total > 0xffff {
            total = (total & 0xffff) + (total >> 16);
        }
        !(total as u16)
    }
    fn packet(source: IpAddr, destination: IpAddr, protocol: u8, mut payload: Vec<u8>) -> Vec<u8> {
        let (mut ip, pseudo) = match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                let mut ip = vec![0; 20];
                ip[0] = 0x45;
                ip[8] = 64;
                ip[9] = protocol;
                ip[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
                ip[12..16].copy_from_slice(&source.octets());
                ip[16..20].copy_from_slice(&destination.octets());
                let check = checksum(sum(&ip));
                ip[10..12].copy_from_slice(&check.to_be_bytes());
                let pseudo = sum(&ip[12..20]) + u32::from(protocol) + payload.len() as u32;
                (ip, pseudo)
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                let mut ip = vec![0; 40];
                ip[0] = 0x60;
                ip[7] = 64;
                ip[6] = protocol;
                ip[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
                ip[8..24].copy_from_slice(&source.octets());
                ip[24..40].copy_from_slice(&destination.octets());
                let pseudo = sum(&ip[8..40]) + u32::from(protocol) + payload.len() as u32;
                (ip, pseudo)
            }
            _ => unreachable!(),
        };
        let position = match protocol {
            6 => 16,
            17 => 6,
            _ => 2,
        };
        let check = checksum(sum(&payload) + if protocol == 1 { 0 } else { pseudo });
        payload[position..position + 2].copy_from_slice(&check.to_be_bytes());
        ip.extend(payload);
        ip
    }
    fn udp(source: IpAddr, destination: IpAddr, a: u16, b: u16) -> Vec<u8> {
        let mut payload = vec![0; 8];
        payload[..2].copy_from_slice(&a.to_be_bytes());
        payload[2..4].copy_from_slice(&b.to_be_bytes());
        payload[5] = 8;
        packet(source, destination, 17, payload)
    }
    fn tcp(
        source: IpAddr,
        destination: IpAddr,
        a: u16,
        b: u16,
        flags: u8,
        sequence: u32,
        acknowledgement: u32,
    ) -> Vec<u8> {
        let mut payload = vec![0; 20];
        payload[..2].copy_from_slice(&a.to_be_bytes());
        payload[2..4].copy_from_slice(&b.to_be_bytes());
        payload[4..8].copy_from_slice(&sequence.to_be_bytes());
        payload[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
        payload[12] = 0x50;
        payload[13] = flags;
        packet(source, destination, 6, payload)
    }
    fn echo(
        source: IpAddr,
        destination: IpAddr,
        reply: bool,
        identifier: u16,
        sequence: u16,
    ) -> Vec<u8> {
        let mut payload = vec![0; 8];
        payload[0] = if source.is_ipv4() {
            if reply { 0 } else { 8 }
        } else if reply {
            129
        } else {
            128
        };
        payload[4..6].copy_from_slice(&identifier.to_be_bytes());
        payload[6..8].copy_from_slice(&sequence.to_be_bytes());
        packet(
            source,
            destination,
            if source.is_ipv4() { 1 } else { 58 },
            payload,
        )
    }

    #[test]
    fn default_deny_and_invalid_rules() {
        let (local, remote) = hosts(false);
        let mut policy = PeerPolicy::new(local, remote, vec![], vec![]).unwrap();
        assert!(!policy.authorize_send(&udp(local, remote, 4000, 53)));
        assert!(!policy.authorize_receive(&tcp(remote, local, 4000, 22, 2, 1, 0)));
        assert!(!policy.authorize_send(&echo(local, remote, false, 1, 1)));
        assert!(PeerPolicy::new(local, local, vec![], vec![]).is_err());
        assert!(PeerPolicy::new(local, remote, rules(Protocol::Tcp, &[]), vec![]).is_err());
        assert!(PeerPolicy::new(local, remote, rules(Protocol::Udp, &[0]), vec![]).is_err());
        assert!(PeerPolicy::new(local, remote, rules(Protocol::IcmpEcho, &[22]), vec![]).is_err());
    }

    #[test]
    fn udp_reverse_flows_never_authorize_by_source_port_alone() {
        for v6 in [false, true] {
            let (local, remote) = hosts(v6);
            let mut policy =
                PeerPolicy::new(local, remote, vec![], rules(Protocol::Udp, &[53])).unwrap();
            assert!(!policy.authorize_receive(&udp(remote, local, 53, 4000)));
            assert!(policy.authorize_send(&udp(local, remote, 4000, 53)));
            assert!(policy.authorize_receive(&udp(remote, local, 53, 4000)));
            assert!(!policy.authorize_receive(&udp(remote, local, 53, 4001)));
            assert!(!policy.authorize_receive(&udp(remote, local, 54, 4000)));
            assert!(!policy.authorize_send(&udp(local, remote, 4000, 22)));
            policy.clear();
            assert!(!policy.authorize_receive(&udp(remote, local, 53, 4000)));
        }
    }

    #[test]
    fn tcp_requires_approved_syn_and_matching_handshake_before_reverse_traffic() {
        for v6 in [false, true] {
            let (local, remote) = hosts(v6);
            let mut policy =
                PeerPolicy::new(local, remote, rules(Protocol::Tcp, &[22]), vec![]).unwrap();
            assert!(!policy.authorize_send(&tcp(local, remote, 22, 4000, 18, 50, 101)));
            assert!(!policy.authorize_receive(&tcp(remote, local, 4000, 22, 16, 100, 0)));
            assert!(policy.authorize_receive(&tcp(remote, local, 4000, 22, 2, 100, 0)));
            assert!(!policy.authorize_send(&tcp(local, remote, 22, 4000, 18, 50, 102)));
            assert!(!policy.authorize_send(&tcp(local, remote, 22, 4000, 16, 50, 101)));
            assert!(policy.authorize_send(&tcp(local, remote, 22, 4000, 18, 50, 101)));
            assert!(policy.authorize_receive(&tcp(remote, local, 4000, 22, 16, 101, 51)));
            assert!(policy.authorize_send(&tcp(local, remote, 22, 4000, 24, 51, 101)));
            assert!(!policy.authorize_send(&tcp(local, remote, 22, 4000, 2, 900, 0)));
            assert!(!policy.authorize_send(&tcp(local, remote, 22, 4001, 16, 51, 101)));
            assert!(policy.authorize_send(&tcp(local, remote, 22, 4000, 20, 51, 101)));
            assert!(!policy.authorize_receive(&tcp(remote, local, 4000, 22, 16, 101, 51)));
        }
    }

    #[test]
    fn echo_replies_require_exact_identifier_sequence_and_consume_request() {
        for v6 in [false, true] {
            let (local, remote) = hosts(v6);
            let mut policy =
                PeerPolicy::new(local, remote, vec![], rules(Protocol::IcmpEcho, &[])).unwrap();
            assert!(!policy.authorize_receive(&echo(remote, local, true, 7, 42)));
            assert!(policy.authorize_send(&echo(local, remote, false, 7, 42)));
            assert!(!policy.authorize_receive(&echo(remote, local, true, 8, 42)));
            assert!(!policy.authorize_receive(&echo(remote, local, true, 7, 43)));
            assert!(policy.authorize_receive(&echo(remote, local, true, 7, 42)));
            assert!(!policy.authorize_receive(&echo(remote, local, true, 7, 42)));
            assert!(!policy.authorize_receive(&echo(remote, local, false, 7, 42)));
        }
    }

    #[test]
    fn flow_table_is_bounded_expires_and_does_not_evict_live_approvals() {
        let (local, remote) = hosts(false);
        let mut policy =
            PeerPolicy::new(local, remote, vec![], rules(Protocol::Udp, &[53])).unwrap();
        let now = Instant::now();
        for port in 10000..10000 + MAX_FLOWS as u16 {
            assert!(policy.authorize(&udp(local, remote, port, 53), true, now));
        }
        assert!(!policy.authorize(&udp(local, remote, 20000, 53), true, now));
        assert_eq!(policy.last_denial_reason(), Some("flow_limit"));
        assert_eq!(policy.active_flows(), MAX_FLOWS);
        assert!(policy.authorize(&udp(remote, local, 53, 10000), false, now));
        assert!(!policy.authorize(
            &udp(remote, local, 53, 10000),
            false,
            now + UDP_IDLE_TIMEOUT
        ));
        assert!(policy.authorize(&udp(local, remote, 20000, 53), true, now + UDP_IDLE_TIMEOUT));
        assert_eq!(policy.flows.len(), 1);
    }

    #[test]
    fn forged_addresses_extensions_fragments_and_bad_checksums_are_rejected() {
        for v6 in [false, true] {
            let (local, remote) = hosts(v6);
            let other: IpAddr = if v6 { "fd79::3" } else { "192.0.2.3" }.parse().unwrap();
            let mut policy = PeerPolicy::new(
                local,
                remote,
                rules(Protocol::Udp, &[53]),
                rules(Protocol::Udp, &[53]),
            )
            .unwrap();
            assert!(!policy.authorize_send(&udp(other, remote, 4000, 53)));
            assert!(!policy.authorize_receive(&udp(remote, other, 4000, 53)));
            let original = udp(local, remote, 4000, 53);
            for end in 0..original.len() {
                assert!(!policy.authorize_send(&original[..end]));
            }
            let mut corrupt = original.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(!policy.authorize_send(&corrupt));
            let mut invalid = original;
            if v6 {
                invalid[6] = 44;
            } else {
                invalid[6] = 0x20;
            }
            assert!(!policy.authorize_send(&invalid));
        }
    }

    #[test]
    fn handshake_and_echo_expire_quickly_but_established_tcp_survives_idle_minutes() {
        let (local, remote) = hosts(false);
        let mut approvals = rules(Protocol::Tcp, &[22]);
        approvals.extend(rules(Protocol::IcmpEcho, &[]));
        let mut policy = PeerPolicy::new(local, remote, vec![], approvals).unwrap();
        let now = Instant::now();
        assert!(policy.authorize(&echo(local, remote, false, 1, 1), true, now));
        assert!(!policy.authorize(
            &echo(remote, local, true, 1, 1),
            false,
            now + ECHO_IDLE_TIMEOUT
        ));
        assert!(policy.authorize(&tcp(local, remote, 4000, 22, 2, 10, 0), true, now));
        assert!(!policy.authorize(
            &tcp(remote, local, 22, 4000, 18, 20, 11),
            false,
            now + HANDSHAKE_IDLE_TIMEOUT
        ));
        assert!(policy.authorize(&tcp(local, remote, 4000, 22, 2, 10, 0), true, now));
        assert!(policy.authorize(&tcp(remote, local, 22, 4000, 18, 20, 11), false, now));
        assert!(policy.authorize(&tcp(local, remote, 4000, 22, 16, 11, 21), true, now));
        let later = now + Duration::from_secs(300);
        assert!(policy.authorize(&tcp(remote, local, 22, 4000, 24, 21, 11), false, later));
        assert!(!policy.authorize(
            &tcp(remote, local, 22, 4000, 24, 21, 11),
            false,
            later + TCP_IDLE_TIMEOUT
        ));
    }

    #[test]
    fn denial_diagnostics_are_safe_categories_and_clear_after_success() {
        let (local, remote) = hosts(false);
        let mut policy =
            PeerPolicy::new(local, remote, vec![], rules(Protocol::Udp, &[53])).unwrap();
        assert!(!policy.authorize_send(&[]));
        assert_eq!(policy.last_denial_reason(), Some("malformed_packet"));
        assert!(!policy.authorize_send(&udp(remote, local, 4000, 53)));
        assert_eq!(policy.last_denial_reason(), Some("address_policy"));
        assert!(!policy.authorize_send(&udp(local, remote, 4000, 22)));
        assert_eq!(policy.last_denial_reason(), Some("port_policy"));
        assert!(!policy.authorize_receive(&echo(remote, local, true, 1, 1)));
        assert_eq!(policy.last_denial_reason(), Some("untracked_reply"));
        assert!(policy.authorize_send(&udp(local, remote, 4000, 53)));
        assert_eq!(policy.last_denial_reason(), None);
        assert_eq!(policy.active_flows(), 1);
        policy.clear();
        assert_eq!(policy.active_flows(), 0);
    }

    fn established(
        policy: &mut PeerPolicy,
        local: IpAddr,
        remote: IpAddr,
        port: u16,
        now: Instant,
    ) {
        assert!(policy.authorize(&tcp(local, remote, port, 22, 2, 10, 0), true, now));
        assert!(policy.authorize(&tcp(remote, local, 22, port, 18, 20, 11), false, now));
        assert!(policy.authorize(&tcp(local, remote, port, 22, 16, 11, 21), true, now));
    }

    #[test]
    fn half_close_allows_response_and_two_fins_expire_after_late_ack() {
        for v6 in [false, true] {
            let (local, remote) = hosts(v6);
            let mut policy =
                PeerPolicy::new(local, remote, vec![], rules(Protocol::Tcp, &[22])).unwrap();
            let now = Instant::now();
            established(&mut policy, local, remote, 4000, now);
            assert!(policy.authorize(&tcp(local, remote, 4000, 22, 17, 11, 21), true, now));
            // One FIN does not prevent the receiver streaming its response later.
            let later = now + Duration::from_secs(300);
            assert!(policy.authorize(&tcp(remote, local, 22, 4000, 24, 21, 12), false, later));
            assert!(policy.authorize(&tcp(remote, local, 22, 4000, 17, 22, 12), false, later));
            let ack_at = later + Duration::from_secs(1);
            assert!(policy.authorize(&tcp(local, remote, 4000, 22, 16, 12, 23), true, ack_at));
            // A retransmitted FIN still passes during the short closing window.
            assert!(policy.authorize(&tcp(remote, local, 22, 4000, 17, 22, 12), false, ack_at));
            assert!(!policy.authorize(
                &tcp(local, remote, 4000, 22, 16, 12, 23),
                true,
                ack_at + TCP_CLOSING_TIMEOUT
            ));
            assert_eq!(policy.active_flows(), 0);
        }
    }

    #[test]
    fn normal_tcp_closes_release_a_full_flow_table_promptly() {
        let (local, remote) = hosts(false);
        let mut policy =
            PeerPolicy::new(local, remote, vec![], rules(Protocol::Tcp, &[22])).unwrap();
        let now = Instant::now();
        for port in 10000..10000 + MAX_FLOWS as u16 {
            established(&mut policy, local, remote, port, now);
            assert!(policy.authorize(&tcp(local, remote, port, 22, 17, 11, 21), true, now));
            assert!(policy.authorize(&tcp(remote, local, 22, port, 17, 21, 12), false, now));
            assert!(policy.authorize(&tcp(local, remote, port, 22, 16, 12, 22), true, now));
        }
        assert_eq!(policy.active_flows(), MAX_FLOWS);
        assert!(!policy.authorize(&tcp(local, remote, 20000, 22, 2, 10, 0), true, now));
        assert_eq!(policy.last_denial_reason(), Some("flow_limit"));
        established(&mut policy, local, remote, 20000, now + TCP_CLOSING_TIMEOUT);
        assert_eq!(policy.active_flows(), 1);
    }
}
