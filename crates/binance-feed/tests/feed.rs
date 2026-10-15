//! The binance_feed client uses Zhida TCP, rustls and tungstenite against a
//! kernel TCP TLS WebSocket server across net_tap through Zhida's IPv4 gateway,
//! as in the live run. These tests need CAP_NET_ADMIN and /dev/net/tun, and no internet.

use std::ffi::CStr;
use std::io::{ErrorKind, Write as _};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::panic::resume_unwind;
use std::process::Command;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use binance_feed::{
    client_config, connect, socket, webpki_client_config, BookTicker, Clock, FeedError, Target,
    INGRESS_BUDGET, SOCKET_BUFFER,
};
use zhida_test_kit::{tap::TapVdev, with_eal};
use dpdk_smoltcp::smoltcp::iface::PathMtu;
use dpdk_smoltcp::smoltcp::socket::tcp::{self, State};
use dpdk_smoltcp::smoltcp::time::Instant as StackInstant;
use dpdk_smoltcp::smoltcp::wire::{EthernetAddress, Ipv4Cidr};
use dpdk_smoltcp::{
    rx_reserve, AddTcpError, Offloads, Port, PortConfig, Stack, StackConfig,
    DEFAULT_NEIGHBOR_CAPACITY,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::{Error, Message};
use zhida_buffer::PoolConfig;
use zhida_dpdk_sys::RTE_PKTMBUF_HEADROOM;

const VDEV: &CStr = c"net_tap_bnc";
const IFACE: &CStr = c"cdtap_bnc";
const RX_POOL: &CStr = c"bnc_rx";
const TX_POOL: &CStr = c"bnc_tx";
const ZHIDA_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const KERNEL_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SERVER_ADDR: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const SERVER_PORT: u16 = 9443;
const HOST: &str = "binance.test";
const PATH: &str = "/ws/btcusdt@bookTicker";
const LOCAL_PORT: u16 = 49152;
const CONNECT_LIMIT: Duration = Duration::from_secs(20);
const CLOSE_LIMIT: Duration = Duration::from_secs(10);
const READ_LIMIT: Duration = Duration::from_secs(60);
const IDLE_SLEEP: Duration = Duration::from_millis(1);
/// The TLS-only server's read timeout (see `ServerPlan::TlsOnly`).
const TLS_ONLY_READ_LIMIT: Duration = Duration::from_secs(2);

fn port_config(port_id: u16, mss_cap: Option<u16>) -> PortConfig<'static> {
    let pool = |name, count| PoolConfig {
        name,
        count,
        cache_size: 8,
        data_room_size: RTE_PKTMBUF_HEADROOM as u16 + 2048,
        socket_id: -1,
    };
    PortConfig {
        port_id,
        mtu: 1500,
        rx_descriptors: 16,
        tx_descriptors: 16,
        rx_burst: 32,
        tx_burst: 32,
        queue_socket: -1,
        rx_pool: pool(
            RX_POOL,
            u32::try_from(
                rx_reserve(16, 32, 8)
                    .checked_add(tcp::rx_mbuf_budget(&socket(mss_cap), 1500))
                    .expect("RX pool count fits usize"),
            ).unwrap(),
        ),
        tx_pool: pool(TX_POOL, 127),
        offloads: Offloads::default(),
    }
}

fn add_address(addr: Ipv4Addr, prefix: u8) {
    let cidr = format!("{addr}/{prefix}");
    let output = Command::new("ip")
        .args(["address", "add", &cidr, "dev", IFACE.to_str().expect("IFACE is ASCII")])
        .output()
        .expect("run ip address add");
    assert!(
        output.status.success(),
        "ip address add {cidr}: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

fn with_stack<T>(
    max_sockets: usize,
    paths: &[PathMtu],
    mss_cap: Option<u16>,
    body: impl FnOnce(&mut Stack, &Clock, TcpListener) -> T,
) -> T {
    with_eal(|eal| {
        let tap = TapVdev::new(VDEV, IFACE);
        // SAFETY: net_tap was just created and this EAL thread alone configures
        // and uses its Port and packets. The offload-free net_tap profile returns
        // single-segment RX buffers and frees TX buffers synchronously. The Port
        // closes before the vdev is removed, and EAL outlives both.
        let port = unsafe { Port::open(eal, port_config(tap.port_id(), mss_cap)) }
            .expect("open net_tap Port");
        add_address(KERNEL_ADDR, 24);
        add_address(SERVER_ADDR, 32);
        let listener = TcpListener::bind(SocketAddrV4::new(SERVER_ADDR, SERVER_PORT))
            .expect("bind the off-subnet TLS server");
        let config = StackConfig {
            max_udp_sockets: 0,
            ethernet: EthernetAddress([0x02, 0, 0, 0, 0, 0x01]),
            ipv4: Ipv4Cidr::new(ZHIDA_ADDR, 24),
            gateway: Some(KERNEL_ADDR),
            paths,
            random_seed: 1,
            neighbor_capacity: DEFAULT_NEIGHBOR_CAPACITY,
            segments_per_visit: 1,
            max_sockets,
            rx_staging: 32,
            tx_pending: 32,
        };
        let clock = Clock::new(Instant::now());
        let mut stack = Stack::new(port, config, StackInstant::ZERO)
            .map_err(|(_, error)| error)
            .expect("create Zhida Stack");
        let result = body(&mut stack, &clock, listener);
        stack.into_port().try_close().expect("close Port with all buffers returned");
        tap.close();
        result
    })
}

#[zhida_test_support::pinned_test]
fn capped_feed_socket_admits_on_jumbo_stack() {
    use zhida_test_kit::pair::{config, Side};
    use zhida_test_kit::ring_port::{resize, RingPort};

    with_eal(|eal| {
        let paths = [PathMtu { prefix: Ipv4Cidr::new(Side::B.ip(), 32), mtu: 1500 }];
        for (name, tcp_config, admits) in [
            ("bnc_cap", socket(Some(1460)), true),
            ("bnc_small", socket(None), false),
        ] {
            let budget = tcp::rx_mbuf_budget(&tcp_config, 9000);
            let ring = RingPort::new(name, 64, 64);
            let mut stack_config = config(Side::A);
            stack_config.paths = &paths;
            let mut port_config = ring.config();
            resize(&mut port_config, 9000, 9216);
            let reserve = rx_reserve(
                port_config.rx_descriptors,
                stack_config.rx_staging,
                port_config.rx_pool.cache_size,
            );
            port_config.rx_pool.count = u32::try_from(
                reserve.checked_add(budget).expect("RX pool count fits usize"),
            ).unwrap();
            let port = ring.open_with(eal, port_config);
            let mut stack = Stack::new(port, stack_config, StackInstant::ZERO)
                .map_err(|(_, error)| error).unwrap();
            let result = stack.add_tcp(socket(Some(1460)));
            if admits {
                let handle = result.expect("capped budget admits the feed socket");
                assert_eq!(stack.tcp(&handle).rx_frame_cap(), budget);
                assert_eq!(stack.tcp(&handle).recv_room(), SOCKET_BUFFER);
                drop(handle);
            } else {
                match result {
                    Err(AddTcpError::RxPoolTooSmall { config, required, pool }) => {
                        assert_eq!(config, socket(Some(1460)));
                        assert_eq!(pool, reserve.checked_add(budget).unwrap());
                        assert_eq!(required, reserve.checked_add(
                            tcp::rx_mbuf_budget(&socket(Some(1460)), 9000),
                        ).unwrap());
                    }
                    other => panic!("uncapped pool must reject capped socket: {other:?}"),
                }
            }
            stack.into_port().try_close().expect("close jumbo Port");
            ring.close();
        }
    });
}

fn server_config() -> (Arc<ServerConfig>, RootCertStore) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![HOST.to_owned()]).expect("generate test certificate");
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).expect("add test certificate to roots");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports rustls's safe default protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .expect("the generated certificate and key match");
    (Arc::new(config), roots)
}

enum ServerPlan {
    Tickers(Vec<String>),
    Refuse451,
    /// The client rejects the certificate. Its UnknownCA alert never reaches
    /// this server: rustls writes the alert after a failed handshake with one
    /// `write_tls`, which hands its queued records to `write_vectored`, and
    /// StackStream has only the default `write_vectored`, which writes the
    /// first record (the ChangeCipherSpec) alone. The server's handshake read
    /// ends at `TLS_ONLY_READ_LIMIT` instead.
    TlsOnly,
}

#[derive(Default)]
struct ServerSaw {
    path: String,
    host: String,
    pong: bool,
    close: bool,
    error: Option<String>,
}

fn serve(listener: TcpListener, config: Arc<ServerConfig>, plan: ServerPlan) -> ServerSaw {
    listener.set_nonblocking(true).expect("nonblocking accept");
    let deadline = Instant::now()
        .checked_add(CONNECT_LIMIT)
        .expect("accept deadline fits wall time");
    let stream = loop {
        assert!(Instant::now() < deadline, "no client within {CONNECT_LIMIT:?}");
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(IDLE_SLEEP),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => panic!("accept: {error}"),
        }
    };
    stream.set_nonblocking(false).expect("blocking TLS socket");
    let read_limit = match plan {
        ServerPlan::TlsOnly => TLS_ONLY_READ_LIMIT,
        _ => CONNECT_LIMIT,
    };
    stream.set_read_timeout(Some(read_limit)).expect("TLS read timeout");
    stream.set_write_timeout(Some(CONNECT_LIMIT)).expect("TLS write timeout");
    let conn = ServerConnection::new(config).expect("create TLS server connection");
    let tls = StreamOwned::new(conn, stream);
    let mut saw = ServerSaw::default();
    let handshake = tungstenite::accept_hdr(tls, |request: &Request, response: Response| {
        saw.path = request.uri().path().to_owned();
        saw.host = request
            .headers()
            .get("Host")
            .expect("client sends Host")
            .to_str()
            .expect("Host is ASCII")
            .to_owned();
        if matches!(plan, ServerPlan::Refuse451) {
            let response: ErrorResponse = Response::builder()
                .status(451)
                .body(Some("Service unavailable from a restricted location".to_owned()))
                .expect("valid HTTP refusal");
            Err(response)
        } else {
            Ok(response)
        }
    })
    .map_err(|error| error.to_string());
    let mut ws = match handshake {
        Ok(ws) => ws,
        Err(error) => {
            saw.error = Some(error);
            return saw;
        }
    };
    let texts = match plan {
        ServerPlan::Tickers(texts) => texts,
        ServerPlan::Refuse451 => panic!("HTTP 451 was accepted"),
        ServerPlan::TlsOnly => panic!("the client trusted an unknown certificate"),
    };
    for (index, text) in texts.into_iter().enumerate() {
        if index == 3 {
            ws.write(Message::Ping(b"keepalive".to_vec().into())).expect("send Ping");
        }
        ws.write(Message::Text(text.into())).expect("send bookTicker");
    }
    ws.flush().expect("flush bookTickers and Ping");
    loop {
        match ws.read() {
            Ok(Message::Pong(payload)) if payload.as_ref() == b"keepalive" => saw.pong = true,
            Ok(Message::Close(_)) => saw.close = true,
            Ok(_) => {}
            // Only the client's TLS close_notify gets here: rustls reports a
            // TCP EOF without it as UnexpectedEof, which panics below.
            Err(Error::ConnectionClosed) => break,
            Err(error) => panic!("server WebSocket read: {error}"),
        }
    }
    let mut tls = ws.into_inner();
    tls.conn.send_close_notify();
    tls.flush().expect("send server TLS close_notify");
    drop(tls);
    saw
}

/// After a failed connect: keeps turning the Stack (ARP and ACK answers, and
/// anything the client wrote before failing) until the server thread ended.
fn turn_until_finished(stack: &mut Stack, clock: &Clock, server: &JoinHandle<ServerSaw>) {
    let started = Instant::now();
    while !server.is_finished() {
        assert!(
            started.elapsed() < CONNECT_LIMIT,
            "server still running {CONNECT_LIMIT:?} after the client failed",
        );
        stack.turn(clock.now(), INGRESS_BUDGET).expect("turn the Stack");
        thread::sleep(IDLE_SLEEP);
    }
}

fn join(server: JoinHandle<ServerSaw>) -> ServerSaw {
    match server.join() {
        Ok(saw) => saw,
        Err(panic) => resume_unwind(panic),
    }
}

fn target() -> Target {
    Target {
        addr: SocketAddrV4::new(SERVER_ADDR, SERVER_PORT),
        host: HOST.to_owned(),
        path: PATH.to_owned(),
    }
}

fn closed_target() -> Target {
    Target {
        addr: SocketAddrV4::new(SERVER_ADDR, SERVER_PORT + 1),
        host: HOST.to_owned(),
        path: PATH.to_owned(),
    }
}

fn retry_failed_connect(stack: &mut Stack, clock: &Clock, initially_full: bool) {
    let target = closed_target();
    let tls = webpki_client_config();
    let started = Instant::now();
    let limit = Duration::from_secs(30);
    let attempt = |stack: &mut Stack, remaining| {
        match connect(stack, clock, &target, socket(None), tls.clone(), LOCAL_PORT + 1, remaining) {
            Ok(_) => panic!("a closed port opened a feed"),
            Err(error) => error,
        }
    };
    let first = attempt(stack, CONNECT_LIMIT);
    eprintln!("first retry before pumping: {first:?}");
    assert_eq!(matches!(first, FeedError::SocketsFull), initially_full, "{first:?}");
    let mut error = first;
    loop {
        match error {
            FeedError::Refused { addr } => {
                assert!(started.elapsed() < limit, "retry exceeded 30 s");
                assert_eq!(addr, target.addr);
                return;
            }
            FeedError::SocketsFull => {}
            other => panic!("retry to a closed port: {other:?}"),
        }
        let remaining = limit.checked_sub(started.elapsed()).expect("slot not freed within 30 s");
        assert!(!remaining.is_zero(), "slot not freed within 30 s");
        stack.turn(clock.now(), INGRESS_BUDGET).expect("pump the Stack between retries");
        thread::sleep(IDLE_SLEEP);
        let remaining = limit.checked_sub(started.elapsed()).expect("slot not freed within 30 s");
        error = attempt(stack, remaining.min(CONNECT_LIMIT));
    }
}

#[zhida_test_support::pinned_test]
fn refused_connect_releases_the_only_slot() {
    with_stack(1, &[], None, |stack, clock, _listener| {
        let target = closed_target();
        let error = match connect(
            stack, clock, &target, socket(None), webpki_client_config(), LOCAL_PORT, CONNECT_LIMIT,
        ) {
            Ok(_) => panic!("a closed port opened a feed"),
            Err(error) => error,
        };
        assert!(
            matches!(error, FeedError::Refused { addr } if addr == target.addr),
            "{error:?}",
        );
        retry_failed_connect(stack, clock, false);
    });
}

#[zhida_test_support::pinned_test]
fn timed_out_connect_releases_the_only_slot() {
    with_stack(1, &[], None, |stack, clock, _listener| {
        // 192.0.2.3 is unassigned in this TAP fixture; connect waits for ARP.
        let target = Target {
            addr: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 3), SERVER_PORT),
            host: HOST.to_owned(),
            path: PATH.to_owned(),
        };
        let limit = Duration::from_millis(100);
        let error = match connect(
            stack, clock, &target, socket(None), webpki_client_config(), LOCAL_PORT, limit,
        ) {
            Ok(_) => panic!("an unanswered ARP opened a feed"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                FeedError::ConnectTimeout { addr, state: State::SynSent, limit: actual }
                    if addr == target.addr && actual == limit
            ),
            "{error:?}",
        );
        // A dropped SYN-SENT socket closes without sending anything (Linux
        // tcp_close), so the very next connect gets the slot.
        retry_failed_connect(stack, clock, false);
    });
}

fn tickers() -> (Vec<String>, Vec<BookTicker>) {
    let mut texts = Vec::new();
    let mut expected = Vec::new();
    for index in 0..12u64 {
        let update_id = 400900217 + index;
        let bid_price = format!("{}.29000000", 80680 + index);
        let ask_price = format!("{}.30000000", 80680 + index);
        let bid_qty = "3.06547000";
        let ask_qty = "0.85179000";
        texts.push(format!(
            "{{\"u\":{update_id},\"s\":\"BTCUSDT\",\"b\":\"{bid_price}\",\"B\":\"{bid_qty}\",\
             \"a\":\"{ask_price}\",\"A\":\"{ask_qty}\"}}",
        ));
        expected.push(BookTicker {
            update_id,
            symbol: "BTCUSDT".to_owned(),
            bid_price,
            bid_qty: bid_qty.to_owned(),
            ask_price,
            ask_qty: ask_qty.to_owned(),
        });
    }
    (texts, expected)
}

#[zhida_test_support::pinned_test]
fn feed_reads_tickers_answers_ping_and_closes() {
    let paths = [PathMtu { prefix: Ipv4Cidr::new(SERVER_ADDR, 32), mtu: 1400 }];
    with_stack(1, &paths, Some(1360), |stack, clock, listener| {
        let (server_tls, roots) = server_config();
        let (texts, expected) = tickers();
        let server = thread::spawn(move || serve(listener, server_tls, ServerPlan::Tickers(texts)));
        let target = target();
        let mut feed = connect(
            stack, clock, &target, socket(Some(1360)), client_config(roots), LOCAL_PORT, CONNECT_LIMIT,
        )
        .expect("connect Zhida TLS WebSocket client");
        let started = Instant::now();
        let mut stop = || {
            assert!(started.elapsed() < READ_LIMIT, "tickers not received within {READ_LIMIT:?}");
            false
        };
        for ticker in expected {
            let received = feed.next(clock, &mut stop).expect("read bookTicker");
            assert_eq!(received, Some(ticker));
        }
        let state = feed.close(clock, CLOSE_LIMIT).expect("close Zhida feed");
        assert!(matches!(state, State::Closed | State::TimeWait), "TCP state {state}");
        let saw = join(server);
        assert_eq!(saw.path, PATH);
        assert_eq!(saw.host, "binance.test:9443");
        assert!(saw.pong, "server did not receive Pong(keepalive)");
        assert!(saw.close, "server did not receive the client's Close");
        assert!(saw.error.is_none(), "server failed: {:?}", saw.error);
    });
}

#[zhida_test_support::pinned_test]
fn upgrade_refused_with_http_451_reports_status_and_body() {
    with_stack(1, &[], None, |stack, clock, listener| {
        let (server_tls, roots) = server_config();
        let server = thread::spawn(move || serve(listener, server_tls, ServerPlan::Refuse451));
        let target = target();
        let error = match connect(
            stack,
            clock,
            &target,
            socket(None),
            client_config(roots),
            LOCAL_PORT,
            CONNECT_LIMIT,
        ) {
            Ok(_) => panic!("HTTP 451 opened a WebSocket"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("HTTP 451"), "{error}");
        match error {
            FeedError::Upgrade { status, body, .. } => {
                assert_eq!(status, 451);
                assert!(body.contains("restricted location"), "HTTP 451 body: {body:?}");
            }
            other => panic!("expected HTTP 451, got {other:?}"),
        }
        retry_failed_connect(stack, clock, true);
        turn_until_finished(stack, clock, &server);
        let saw = join(server);
        assert!(saw.error.is_some(), "server accepted the upgrade");
    });
}

#[zhida_test_support::pinned_test]
fn unknown_certificate_fails_tls() {
    with_stack(1, &[], None, |stack, clock, listener| {
        let (server_tls, _) = server_config();
        let server = thread::spawn(move || serve(listener, server_tls, ServerPlan::TlsOnly));
        let target = target();
        let error = match connect(
            stack,
            clock,
            &target,
            socket(None),
            webpki_client_config(),
            LOCAL_PORT,
            CONNECT_LIMIT,
        ) {
            Ok(_) => panic!("Mozilla roots trusted the self-signed certificate"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                FeedError::Tls(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            ),
            "expected UnknownIssuer, got {error:?}",
        );
        retry_failed_connect(stack, clock, true);
        turn_until_finished(stack, clock, &server);
        let saw = join(server);
        assert!(saw.error.is_some(), "server TLS handshake did not fail");
    });
}

#[test]
fn book_ticker_parses_binance_shape_and_ignores_extra_fields() {
    let text = r#"{
        "u":400900217, "s":"BTCUSDT",
        "b":"80680.29000000", "B":"3.06547000",
        "a":"80680.30000000", "A":"0.85179000", "E":123
    }"#;
    let ticker = serde_json::from_str::<BookTicker>(text).expect("parse Binance bookTicker shape");
    assert_eq!(
        ticker,
        BookTicker {
            update_id: 400900217,
            symbol: "BTCUSDT".to_owned(),
            bid_price: "80680.29000000".to_owned(),
            bid_qty: "3.06547000".to_owned(),
            ask_price: "80680.30000000".to_owned(),
            ask_qty: "0.85179000".to_owned(),
        },
    );
    assert_eq!(
        ticker.to_string(),
        "u=400900217 BTCUSDT bid 80680.29000000 x 3.06547000 ask 80680.30000000 x 0.85179000",
    );
}
