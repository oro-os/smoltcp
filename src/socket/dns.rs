use core::cmp::min;
#[cfg(feature = "async")]
use core::task::Waker;

#[cfg(feature = "proto-dns-srv")]
use heapless::String;
use heapless::Vec;
use managed::ManagedSlice;

use crate::config::{DNS_MAX_NAME_SIZE, DNS_MAX_RESULT_COUNT, DNS_MAX_SERVER_COUNT};
use crate::socket::{Context, PollAt};
use crate::time::{Duration, Instant};
#[cfg(feature = "proto-dns-srv")]
use crate::wire::dns::SrvRecord as WireSrvRecord;
use crate::wire::dns::{Flags, Opcode, Packet, Question, Rcode, Record, RecordData, Repr, Type};
use crate::wire::{self, IpAddress, IpProtocol, IpRepr, UdpRepr};

#[cfg(feature = "async")]
use super::WakerRegistration;

const DNS_PORT: u16 = 53;
const MDNS_DNS_PORT: u16 = 5353;
const RETRANSMIT_DELAY: Duration = Duration::from_millis(1_000);
const MAX_RETRANSMIT_DELAY: Duration = Duration::from_millis(10_000);
const RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(10_000); // Should generally be 2-10 secs

#[cfg(feature = "proto-ipv6")]
#[allow(unused)]
const MDNS_IPV6_ADDR: IpAddress = IpAddress::Ipv6(crate::wire::Ipv6Address::new(
    0xff02, 0, 0, 0, 0, 0, 0, 0xfb,
));

#[cfg(feature = "proto-ipv4")]
#[allow(unused)]
const MDNS_IPV4_ADDR: IpAddress = IpAddress::Ipv4(crate::wire::Ipv4Address::new(224, 0, 0, 251));

/// Error returned by [`Socket::start_query`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StartQueryError {
    NoFreeSlot,
    InvalidName,
    NameTooLong,
}

impl core::fmt::Display for StartQueryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StartQueryError::NoFreeSlot => write!(f, "No free slot"),
            StartQueryError::InvalidName => write!(f, "Invalid name"),
            StartQueryError::NameTooLong => write!(f, "Name too long"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StartQueryError {}

/// Error returned by [`Socket::get_query_result`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GetQueryResultError {
    /// Query is not done yet.
    Pending,
    /// Query failed.
    Failed,
    /// SRV target exceeded the supported textual name length.
    SrvTargetTooLong,
}

impl core::fmt::Display for GetQueryResultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GetQueryResultError::Pending => write!(f, "Query is not done yet"),
            GetQueryResultError::Failed => write!(f, "Query failed"),
            GetQueryResultError::SrvTargetTooLong => write!(f, "SRV target too long"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetQueryResultError {}

/// State for an in-progress DNS query.
///
/// The only reason this struct is public is to allow the socket state
/// to be allocated externally.
#[derive(Debug)]
pub struct DnsQuery {
    state: State,

    #[cfg(feature = "async")]
    waker: WakerRegistration,
}

impl DnsQuery {
    fn set_state(&mut self, state: State) {
        self.state = state;
        #[cfg(feature = "async")]
        self.waker.wake();
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum State {
    Pending(PendingQuery),
    Completed(CompletedQuery),
    Failure(GetQueryResultError),
}

#[derive(Debug)]
struct PendingQuery {
    name: Vec<u8, DNS_MAX_NAME_SIZE>,
    type_: Type,

    port: u16, // UDP port (src for request, dst for response)
    txid: u16, // transaction ID

    timeout_at: Option<Instant>,
    retransmit_at: Instant,
    delay: Duration,

    server_idx: usize,
    mdns: MulticastDns,
}

#[derive(Debug)]
pub enum MulticastDns {
    Disabled,
    #[cfg(feature = "socket-mdns")]
    Enabled,
}

#[derive(Debug)]
struct CompletedQuery {
    results: Vec<QueryResult, DNS_MAX_RESULT_COUNT>,
}

#[cfg(feature = "proto-dns-srv")]
/// An SRV answer returned by [`Socket::get_query_result`].
pub type SrvQueryResult = WireSrvRecord<String<253>>;

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "proto-dns-srv", expect(clippy::large_enum_variant))]
/// A DNS answer returned by [`Socket::get_query_result`].
pub enum QueryResult {
    Address(IpAddress),
    #[cfg(feature = "proto-dns-srv")]
    Srv(SrvQueryResult),
}

/// A handle to an in-progress DNS query.
#[derive(Clone, Copy)]
pub struct QueryHandle(usize);

/// A Domain Name System socket.
///
/// A UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
#[derive(Debug)]
pub struct Socket<'a> {
    servers: Vec<IpAddress, DNS_MAX_SERVER_COUNT>,
    queries: ManagedSlice<'a, Option<DnsQuery>>,

    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
}

impl<'a> Socket<'a> {
    /// Create a DNS socket.
    ///
    /// Truncates the server list if `servers.len() > MAX_SERVER_COUNT`
    pub fn new<Q>(servers: &[IpAddress], queries: Q) -> Socket<'a>
    where
        Q: Into<ManagedSlice<'a, Option<DnsQuery>>>,
    {
        let truncated_servers = &servers[..min(servers.len(), DNS_MAX_SERVER_COUNT)];

        Socket {
            servers: Vec::from_slice(truncated_servers).unwrap(),
            queries: queries.into(),
            hop_limit: None,
        }
    }

    /// Update the list of DNS servers, will replace all existing servers
    ///
    /// Truncates the server list if `servers.len() > MAX_SERVER_COUNT`
    pub fn update_servers(&mut self, servers: &[IpAddress]) {
        if servers.len() > DNS_MAX_SERVER_COUNT {
            net_trace!("Max DNS Servers exceeded. Increase MAX_SERVER_COUNT");
            self.servers = Vec::from_slice(&servers[..DNS_MAX_SERVER_COUNT]).unwrap();
        } else {
            self.servers = Vec::from_slice(servers).unwrap();
        }
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    fn find_free_query(&mut self) -> Option<QueryHandle> {
        for (i, q) in self.queries.iter().enumerate() {
            if q.is_none() {
                return Some(QueryHandle(i));
            }
        }

        match &mut self.queries {
            ManagedSlice::Borrowed(_) => None,
            #[cfg(feature = "alloc")]
            ManagedSlice::Owned(queries) => {
                queries.push(None);
                let index = queries.len() - 1;
                Some(QueryHandle(index))
            }
        }
    }

    /// Start a query.
    ///
    /// `name` is specified in human-friendly format, such as `"rust-lang.org"`.
    /// It accepts names both with and without trailing dot, and they're treated
    /// the same (there's no support for DNS search path).
    pub fn start_query(
        &mut self,
        cx: &mut Context,
        name: &str,
        query_type: Type,
    ) -> Result<QueryHandle, StartQueryError> {
        let mut name = name.as_bytes();

        if name.is_empty() {
            net_trace!("invalid name: zero length");
            return Err(StartQueryError::InvalidName);
        }

        // Remove trailing dot, if any
        if name[name.len() - 1] == b'.' {
            name = &name[..name.len() - 1];
        }

        let mut raw_name: Vec<u8, DNS_MAX_NAME_SIZE> = Vec::new();

        let mut mdns = MulticastDns::Disabled;
        #[cfg(feature = "socket-mdns")]
        if name.split(|&c| c == b'.').next_back().unwrap() == b"local" {
            net_trace!("Starting a mDNS query");
            mdns = MulticastDns::Enabled;
        }

        for s in name.split(|&c| c == b'.') {
            if s.len() > 63 {
                net_trace!("invalid name: too long label");
                return Err(StartQueryError::InvalidName);
            }
            if s.is_empty() {
                net_trace!("invalid name: zero length label");
                return Err(StartQueryError::InvalidName);
            }

            // Push label
            raw_name
                .push(s.len() as u8)
                .map_err(|_| StartQueryError::NameTooLong)?;
            raw_name
                .extend_from_slice(s)
                .map_err(|_| StartQueryError::NameTooLong)?;
        }

        // Push terminator.
        raw_name
            .push(0x00)
            .map_err(|_| StartQueryError::NameTooLong)?;

        self.start_query_raw(cx, &raw_name, query_type, mdns)
    }

    /// Start a query with a raw (wire-format) DNS name.
    /// `b"\x09rust-lang\x03org\x00"`
    ///
    /// You probably want to use [`start_query`] instead.
    pub fn start_query_raw(
        &mut self,
        cx: &mut Context,
        raw_name: &[u8],
        query_type: Type,
        mdns: MulticastDns,
    ) -> Result<QueryHandle, StartQueryError> {
        let handle = self.find_free_query().ok_or(StartQueryError::NoFreeSlot)?;

        self.queries[handle.0] = Some(DnsQuery {
            state: State::Pending(PendingQuery {
                name: Vec::from_slice(raw_name).map_err(|_| StartQueryError::NameTooLong)?,
                type_: query_type,
                txid: cx.rand().rand_u16(),
                port: cx.rand().rand_source_port(),
                delay: RETRANSMIT_DELAY,
                timeout_at: None,
                retransmit_at: Instant::ZERO,
                server_idx: 0,
                mdns,
            }),
            #[cfg(feature = "async")]
            waker: WakerRegistration::new(),
        });
        Ok(handle)
    }

    /// Get the result of a query.
    ///
    /// If the query is completed, the query slot is automatically freed.
    ///
    /// # Panics
    /// Panics if the QueryHandle corresponds to a free slot.
    pub fn get_query_result(
        &mut self,
        handle: QueryHandle,
    ) -> Result<Vec<QueryResult, DNS_MAX_RESULT_COUNT>, GetQueryResultError> {
        let slot = &mut self.queries[handle.0];
        let q = slot.as_mut().unwrap();
        match &mut q.state {
            // Query is not done yet.
            State::Pending(_) => Err(GetQueryResultError::Pending),
            // Query is done
            State::Completed(q) => {
                let res = q.results.clone();
                *slot = None; // Free up the slot for recycling.
                Ok(res)
            }
            State::Failure(error) => {
                let error = *error;
                *slot = None; // Free up the slot for recycling.
                Err(error)
            }
        }
    }

    /// Cancels a query, freeing the slot.
    ///
    /// # Panics
    ///
    /// Panics if the QueryHandle corresponds to an already free slot.
    pub fn cancel_query(&mut self, handle: QueryHandle) {
        let slot = &mut self.queries[handle.0];
        if slot.is_none() {
            panic!("Canceling query in a free slot.")
        }
        *slot = None; // Free up the slot for recycling.
    }

    /// Assign a waker to a query slot
    ///
    /// The waker will be woken when the query completes, either successfully or failed.
    ///
    /// # Panics
    ///
    /// Panics if the QueryHandle corresponds to an already free slot.
    #[cfg(feature = "async")]
    pub fn register_query_waker(&mut self, handle: QueryHandle, waker: &Waker) {
        self.queries[handle.0]
            .as_mut()
            .unwrap()
            .waker
            .register(waker);
    }

    pub(crate) fn accepts(&self, ip_repr: &IpRepr, udp_repr: &UdpRepr) -> bool {
        (udp_repr.src_port == DNS_PORT
            && self
                .servers
                .iter()
                .any(|server| *server == ip_repr.src_addr()))
            || (udp_repr.src_port == MDNS_DNS_PORT)
    }

    pub(crate) fn process(
        &mut self,
        _cx: &mut Context,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        payload: &[u8],
    ) {
        debug_assert!(self.accepts(ip_repr, udp_repr));

        let size = payload.len();

        net_trace!(
            "receiving {} octets from {:?}:{}",
            size,
            ip_repr.src_addr(),
            udp_repr.dst_port
        );

        let p = match Packet::new_checked(payload) {
            Ok(x) => x,
            Err(_) => {
                net_trace!("dns packet malformed");
                return;
            }
        };
        if p.opcode() != Opcode::Query {
            net_trace!("unwanted opcode {:?}", p.opcode());
            return;
        }

        if !p.flags().contains(Flags::RESPONSE) {
            net_trace!("packet doesn't have response bit set");
            return;
        }

        if p.question_count() != 1 {
            net_trace!("bad question count {:?}", p.question_count());
            return;
        }

        // Find pending query
        for q in self.queries.iter_mut().flatten() {
            if let State::Pending(pq) = &mut q.state {
                if udp_repr.dst_port != pq.port || p.transaction_id() != pq.txid {
                    continue;
                }

                if p.rcode() == Rcode::NXDomain {
                    net_trace!("rcode NXDomain");
                    q.set_state(State::Failure(GetQueryResultError::Failed));
                    continue;
                }

                let payload = p.payload();
                let (mut payload, question) = match Question::parse(payload) {
                    Ok(x) => x,
                    Err(_) => {
                        net_trace!("question malformed");
                        return;
                    }
                };

                if question.type_ != pq.type_ {
                    net_trace!("question type mismatch");
                    return;
                }

                match eq_names(p.parse_name(question.name), p.parse_name(&pq.name)) {
                    Ok(true) => {}
                    Ok(false) => {
                        net_trace!("question name mismatch");
                        return;
                    }
                    Err(_) => {
                        net_trace!("dns question name malformed");
                        return;
                    }
                }

                let mut results = Vec::new();

                for _ in 0..p.answer_record_count() {
                    let (payload2, r) = match Record::parse(payload) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!("dns answer record malformed");
                            return;
                        }
                    };
                    payload = payload2;

                    match eq_names(p.parse_name(r.name), p.parse_name(&pq.name)) {
                        Ok(true) => {}
                        Ok(false) => {
                            net_trace!("answer name mismatch: {:?}", r);
                            continue;
                        }
                        Err(_) => {
                            net_trace!("dns answer record name malformed");
                            return;
                        }
                    }

                    match r.data {
                        #[cfg(feature = "proto-ipv4")]
                        RecordData::A(addr) => {
                            net_trace!("A: {:?}", addr);
                            if results.push(QueryResult::Address(addr.into())).is_err() {
                                net_trace!("too many results in response, ignoring {:?}", addr);
                            }
                        }
                        #[cfg(feature = "proto-ipv6")]
                        RecordData::Aaaa(addr) => {
                            net_trace!("AAAA: {:?}", addr);
                            if results.push(QueryResult::Address(addr.into())).is_err() {
                                net_trace!("too many results in response, ignoring {:?}", addr);
                            }
                        }
                        #[cfg(feature = "proto-dns-srv")]
                        RecordData::Srv(srv) => {
                            net_trace!("SRV: {:?}", srv);

                            let mut target = String::new();
                            let mut first = true;
                            for label in p.parse_name(srv.target) {
                                let label = match label {
                                    Ok(label) => label,
                                    Err(_) => {
                                        net_trace!("dns answer srv target malformed");
                                        q.set_state(State::Failure(GetQueryResultError::Failed));
                                        return;
                                    }
                                };

                                let label = match core::str::from_utf8(label) {
                                    Ok(label) => label,
                                    Err(_) => {
                                        net_trace!("dns answer srv target malformed");
                                        q.set_state(State::Failure(GetQueryResultError::Failed));
                                        return;
                                    }
                                };

                                if !first && target.push('.').is_err() {
                                    net_trace!("dns answer srv target too long");
                                    q.set_state(State::Failure(
                                        GetQueryResultError::SrvTargetTooLong,
                                    ));
                                    return;
                                }

                                if target.push_str(label).is_err() {
                                    net_trace!("dns answer srv target too long");
                                    q.set_state(State::Failure(
                                        GetQueryResultError::SrvTargetTooLong,
                                    ));
                                    return;
                                }

                                first = false;
                            }

                            let result = QueryResult::Srv(SrvQueryResult {
                                priority: srv.priority,
                                weight: srv.weight,
                                port: srv.port,
                                target,
                            });

                            if results.push(result).is_err() {
                                net_trace!("too many results in response, ignoring {:?}", srv);
                            }
                        }
                        RecordData::Cname(name) => {
                            net_trace!("CNAME: {:?}", name);

                            // When faced with a CNAME, recursive resolvers are supposed to
                            // resolve the CNAME and append the results for it.
                            //
                            // We update the query with the new name, so that we pick up the A/AAAA
                            // records for the CNAME when we parse them later.
                            // I believe it's mandatory the CNAME results MUST come *after* in the
                            // packet, so it's enough to do one linear pass over it.
                            if copy_name(&mut pq.name, p.parse_name(name)).is_err() {
                                net_trace!("dns answer cname malformed");
                                return;
                            }
                        }
                        RecordData::Other(type_, data) => {
                            net_trace!("unknown: {:?} {:?}", type_, data)
                        }
                    }
                }

                q.set_state(if results.is_empty() {
                    State::Failure(GetQueryResultError::Failed)
                } else {
                    State::Completed(CompletedQuery { results })
                });

                // If we get here, packet matched the current query, stop processing.
                return;
            }
        }

        // If we get here, packet matched with no query.
        net_trace!("no query matched");
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, (IpRepr, UdpRepr, &[u8])) -> Result<(), E>,
    {
        let hop_limit = self.hop_limit.unwrap_or(64);

        for q in self.queries.iter_mut().flatten() {
            if let State::Pending(pq) = &mut q.state {
                // As per RFC 6762 any DNS query ending in .local. MUST be sent as mdns
                // so we internally overwrite the servers for any of those queries
                // in this function.
                let servers = match pq.mdns {
                    #[cfg(feature = "socket-mdns")]
                    MulticastDns::Enabled => &[
                        #[cfg(feature = "proto-ipv6")]
                        MDNS_IPV6_ADDR,
                        #[cfg(feature = "proto-ipv4")]
                        MDNS_IPV4_ADDR,
                    ],
                    MulticastDns::Disabled => self.servers.as_slice(),
                };

                let timeout = if let Some(timeout) = pq.timeout_at {
                    timeout
                } else {
                    let v = cx.now() + RETRANSMIT_TIMEOUT;
                    pq.timeout_at = Some(v);
                    v
                };

                // Check timeout
                if timeout < cx.now() {
                    // DNS timeout
                    pq.timeout_at = Some(cx.now() + RETRANSMIT_TIMEOUT);
                    pq.retransmit_at = Instant::ZERO;
                    pq.delay = RETRANSMIT_DELAY;

                    // Try next server. We check below whether we've tried all servers.
                    pq.server_idx += 1;
                }
                // Check if we've run out of servers to try.
                if pq.server_idx >= servers.len() {
                    net_trace!("already tried all servers.");
                    q.set_state(State::Failure(GetQueryResultError::Failed));
                    continue;
                }

                // Check so the IP address is valid
                if servers[pq.server_idx].is_unspecified() {
                    net_trace!("invalid unspecified DNS server addr.");
                    q.set_state(State::Failure(GetQueryResultError::Failed));
                    continue;
                }

                if pq.retransmit_at > cx.now() {
                    // query is waiting for retransmit
                    continue;
                }

                let repr = Repr {
                    transaction_id: pq.txid,
                    flags: Flags::RECURSION_DESIRED,
                    opcode: Opcode::Query,
                    question: Question {
                        name: &pq.name,
                        type_: pq.type_,
                    },
                };

                let mut payload = [0u8; 512];
                let payload = &mut payload[..repr.buffer_len()];
                repr.emit(&mut Packet::new_unchecked(payload));

                let dst_port = match pq.mdns {
                    #[cfg(feature = "socket-mdns")]
                    MulticastDns::Enabled => MDNS_DNS_PORT,
                    MulticastDns::Disabled => DNS_PORT,
                };

                let udp_repr = UdpRepr {
                    src_port: pq.port,
                    dst_port,
                };

                let dst_addr = servers[pq.server_idx];
                let src_addr = match cx.get_source_address(&dst_addr) {
                    Some(src_addr) => src_addr,
                    None => {
                        net_trace!("no source address for destination {}", dst_addr);
                        q.set_state(State::Failure(GetQueryResultError::Failed));
                        continue;
                    }
                };

                let ip_repr = IpRepr::new(
                    src_addr,
                    dst_addr,
                    IpProtocol::Udp,
                    udp_repr.header_len() + payload.len(),
                    hop_limit,
                );

                net_trace!(
                    "sending {} octets to {} from port {}",
                    payload.len(),
                    ip_repr.dst_addr(),
                    udp_repr.src_port
                );

                emit(cx, (ip_repr, udp_repr, payload))?;

                pq.retransmit_at = cx.now() + pq.delay;
                pq.delay = MAX_RETRANSMIT_DELAY.min(pq.delay * 2);

                return Ok(());
            }
        }

        // Nothing to dispatch
        Ok(())
    }

    pub(crate) fn poll_at(&self, _cx: &Context) -> PollAt {
        self.queries
            .iter()
            .flatten()
            .filter_map(|q| match &q.state {
                State::Pending(pq) => Some(PollAt::Time(pq.retransmit_at)),
                State::Completed(_) => None,
                State::Failure(_) => None,
            })
            .min()
            .unwrap_or(PollAt::Ingress)
    }
}

fn eq_names<'a>(
    mut a: impl Iterator<Item = wire::Result<&'a [u8]>>,
    mut b: impl Iterator<Item = wire::Result<&'a [u8]>>,
) -> wire::Result<bool> {
    loop {
        match (a.next(), b.next()) {
            // Handle errors
            (Some(Err(e)), _) => return Err(e),
            (_, Some(Err(e))) => return Err(e),

            // Both finished -> equal
            (None, None) => return Ok(true),

            // One finished before the other -> not equal
            (None, _) => return Ok(false),
            (_, None) => return Ok(false),

            // Got two labels, check if they're equal
            (Some(Ok(la)), Some(Ok(lb))) => {
                if la != lb {
                    return Ok(false);
                }
            }
        }
    }
}

fn copy_name<'a, const N: usize>(
    dest: &mut Vec<u8, N>,
    name: impl Iterator<Item = wire::Result<&'a [u8]>>,
) -> Result<(), wire::Error> {
    dest.truncate(0);

    for label in name {
        let label = label?;
        dest.push(label.len() as u8).map_err(|_| wire::Error)?;
        dest.extend_from_slice(label).map_err(|_| wire::Error)?;
    }

    // Write terminator 0x00
    dest.push(0).map_err(|_| wire::Error)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use std::vec::Vec as StdVec;

    use super::*;
    use crate::phy::Medium;
    use crate::tests::setup;

    cfg_if::cfg_if! {
        if #[cfg(feature = "proto-ipv4")] {
            use crate::wire::Ipv4Address as IpvXAddress;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 1);
            const SERVER_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 53);

            const ADDRESS_QUERY_NAME: &str = "example.com";
            const ADDRESS_QUERY_TYPE: Type = Type::A;

            fn address_answer() -> StdVec<u8> {
                vec![
                    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1,
                    2, 3, 4,
                ]
            }

            fn expected_address_result() -> QueryResult {
                QueryResult::Address(IpvXAddress::new(1, 2, 3, 4).into())
            }
        } else {
            use crate::wire::Ipv6Address as IpvXAddress;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
            const SERVER_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 53);

            const ADDRESS_QUERY_NAME: &str = "example.com";
            const ADDRESS_QUERY_TYPE: Type = Type::Aaaa;

            fn address_answer() -> StdVec<u8> {
                vec![
                    0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]
            }

            fn expected_address_result() -> QueryResult {
                QueryResult::Address(IpvXAddress::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).into())
            }
        }
    }

    fn test_medium() -> Medium {
        cfg_if::cfg_if! {
            if #[cfg(feature = "medium-ip")] {
                Medium::Ip
            } else if #[cfg(feature = "medium-ethernet")] {
                Medium::Ethernet
            } else if #[cfg(feature = "medium-ieee802154")] {
                Medium::Ieee802154
            } else {
                unreachable!()
            }
        }
    }

    fn dispatch_query(socket: &mut Socket<'_>, cx: &mut Context) -> (u16, StdVec<u8>) {
        let mut emitted = None;

        assert_eq!(
            socket.dispatch(cx, |_, (_, udp_repr, payload)| {
                emitted = Some((udp_repr.src_port, payload.to_vec()));
                Ok::<_, ()>(())
            }),
            Ok(())
        );

        emitted.expect("DNS query should have been emitted")
    }

    fn build_response(query_payload: &[u8], answer: &[u8]) -> StdVec<u8> {
        let query = Packet::new_checked(query_payload).unwrap();
        let question = query.payload();

        let mut response = vec![0; 12 + question.len() + answer.len()];
        let mut packet = Packet::new_unchecked(response.as_mut_slice());
        packet.set_transaction_id(query.transaction_id());
        packet.set_flags(Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE);
        packet.set_opcode(query.opcode());
        packet.set_question_count(1);
        packet.set_answer_record_count(1);
        packet.set_authority_record_count(0);
        packet.set_additional_record_count(0);

        let payload = packet.payload_mut();
        payload[..question.len()].copy_from_slice(question);
        payload[question.len()..].copy_from_slice(answer);

        response
    }

    fn process_response(socket: &mut Socket<'_>, cx: &mut Context, dst_port: u16, payload: &[u8]) {
        let udp_repr = UdpRepr {
            src_port: DNS_PORT,
            dst_port,
        };
        let ip_repr = IpRepr::new(
            SERVER_ADDR.into(),
            LOCAL_ADDR.into(),
            IpProtocol::Udp,
            udp_repr.header_len() + payload.len(),
            64,
        );

        socket.process(cx, &ip_repr, &udp_repr, payload);
    }

    #[test]
    fn test_get_query_result_address() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);

        let handle = socket
            .start_query(cx, ADDRESS_QUERY_NAME, ADDRESS_QUERY_TYPE)
            .unwrap();
        let (query_port, query_payload) = dispatch_query(&mut socket, cx);

        let response = build_response(&query_payload, &address_answer());
        process_response(&mut socket, cx, query_port, &response);

        let expected = Vec::from_slice(&[expected_address_result()]).unwrap();
        assert_eq!(socket.get_query_result(handle), Ok(expected));
    }

    #[cfg(feature = "proto-dns-srv")]
    #[test]
    fn test_get_query_result_srv() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);

        let handle = socket
            .start_query(cx, "_sip._tcp.example.com", Type::Srv)
            .unwrap();
        let (query_port, query_payload) = dispatch_query(&mut socket, cx);

        let response = build_response(
            &query_payload,
            &[
                0xc0, 0x0c, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x12, 0x00, 0x00,
                0x00, 0x05, 0x13, 0xc4, 0x09, 0x73, 0x69, 0x70, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
                0xc0, 0x16,
            ],
        );
        process_response(&mut socket, cx, query_port, &response);

        let mut expected_target = String::new();
        expected_target.push_str("sipserver.example.com").unwrap();
        let expected = Vec::from_slice(&[QueryResult::Srv(SrvQueryResult {
            priority: 0,
            weight: 5,
            port: 5060,
            target: expected_target,
        })])
        .unwrap();
        assert_eq!(socket.get_query_result(handle), Ok(expected));
    }

    #[cfg(feature = "proto-dns-srv")]
    #[test]
    fn test_get_query_result_srv_too_long() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);

        let handle = socket
            .start_query(cx, "_sip._tcp.example.com", Type::Srv)
            .unwrap();
        let (query_port, query_payload) = dispatch_query(&mut socket, cx);

        let mut answer = vec![
            0xc0, 0x0c, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x05, 0x13, 0xc4,
        ];
        for _ in 0..5 {
            answer.push(0x3f);
            answer.extend_from_slice(&[b'a'; 63]);
        }
        answer.push(0x00);

        let rdlen = (answer.len() - 12) as u16;
        answer[10] = (rdlen >> 8) as u8;
        answer[11] = rdlen as u8;

        let response = build_response(&query_payload, &answer);
        process_response(&mut socket, cx, query_port, &response);

        assert_eq!(
            socket.get_query_result(handle),
            Err(GetQueryResultError::SrvTargetTooLong)
        );
    }
}
