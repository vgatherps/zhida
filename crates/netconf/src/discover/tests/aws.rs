use super::*;
use crate::imds::Imds;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

struct Server {
    imds: Imds,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new(responses: Vec<(String, Vec<u8>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let imds = Imds::new(listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = thread::spawn(move || {
            for (expected, response) in responses {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if stopping.load(Ordering::SeqCst) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("accept: {e}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let request = read_request(&mut stream);
                assert_eq!(request.lines().next().unwrap(), expected);
                if expected.starts_with("GET ") {
                    assert!(request.contains("\r\nX-aws-ec2-metadata-token: secret\r\n"));
                }
                recorded.lock().unwrap().push(request);
                stream.write_all(&response).unwrap();
            }
        });
        Self {
            imds,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}
fn read_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).unwrap(), 1);
        request.push(byte[0]);
    }
    String::from_utf8(request).unwrap()
}
fn token_response(response: Vec<u8>) -> (String, Vec<u8>) {
    ("PUT /latest/api/token HTTP/1.1".into(), response)
}
fn get_response(path: &str, response: Vec<u8>) -> (String, Vec<u8>) {
    (format!("GET /latest/meta-data/{path} HTTP/1.1"), response)
}
fn response(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn metadata(device: &str, local: &str, subnet: &str, blocks: &str, public: (u16, &str)) -> Server {
    metadata_for_mac("0a:12:34:56:78:9a", device, local, subnet, blocks, public)
}
fn metadata_for_mac(
    mac: &str,
    device: &str,
    local: &str,
    subnet: &str,
    blocks: &str,
    public: (u16, &str),
) -> Server {
    let mut responses = vec![token_response(response(200, "secret"))];
    for (item, status, body) in [
        ("device-number", 200, device),
        ("local-ipv4s", 200, local),
        ("subnet-ipv4-cidr-block", 200, subnet),
        ("vpc-ipv4-cidr-blocks", 200, blocks),
        ("public-ipv4s", public.0, public.1),
    ] {
        responses.push(get_response(
            &format!("network/interfaces/macs/{mac}/{item}"),
            response(status, body),
        ));
    }
    Server::new(responses)
}

fn aws(tree: &Tree, server: &Server, addresses: &[Ipv4Cidr]) -> Result<Discovered, DiscoverError> {
    discover_aws(&tree.roots, "eth1", addresses, None, &server.imds)
}
fn ordinary(public: (u16, &str)) -> Server {
    metadata(
        "1",
        "10.0.1.23\n10.0.1.24\n",
        "10.0.1.0/24",
        "10.0.0.0/16\n192.168.0.0/16\n",
        public,
    )
}
#[test]
fn imds_put_token_then_get_with_header() {
    let path = "network/interfaces/macs/0a:12:34:56:78:9a/device-number";
    let server = Server::new(vec![
        token_response(response(200, "secret")),
        get_response(path, response(200, "1")),
    ]);
    let token = server.imds.token().unwrap();
    assert_eq!(format!("{token:?}"), "Token(..)");
    assert_eq!(server.imds.get(&token, path).unwrap().as_deref(), Some("1"));
    let requests = server.requests.lock().unwrap();
    assert!(requests[0].starts_with("PUT /latest/api/token HTTP/1.1\r\n"));
    for header in [
        "Host: 169.254.169.254\r\n",
        "X-aws-ec2-metadata-token-ttl-seconds: 60\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n",
    ] {
        assert!(requests[0].contains(header));
    }
    assert!(requests[1].starts_with(&format!("GET /latest/meta-data/{path} HTTP/1.1\r\n")));
    assert!(requests[1].contains("X-aws-ec2-metadata-token: secret\r\n"));
    drop(requests);

    let tree = Tree::new();
    let mac = "02:ab:cd:ef:01:23";
    tree.write("class/net/eth1/address", &format!("{mac}\n"));
    let server = metadata_for_mac(
        mac,
        "1",
        "10.0.1.23\n10.0.1.24\n",
        "10.0.1.0/24",
        "10.0.0.0/16",
        (200, "1.2.3.4"),
    );
    let discovered = aws(&tree, &server, &addresses()).unwrap();
    assert_eq!(discovered.config.mac, Some(mac.parse().unwrap()));
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 6);
    assert_eq!(
        requests[0].lines().next(),
        Some("PUT /latest/api/token HTTP/1.1")
    );
    for (request, item) in requests[1..].iter().zip([
        "device-number",
        "local-ipv4s",
        "subnet-ipv4-cidr-block",
        "vpc-ipv4-cidr-blocks",
        "public-ipv4s",
    ]) {
        assert_eq!(
            request.lines().next().unwrap(),
            format!("GET /latest/meta-data/network/interfaces/macs/{mac}/{item} HTTP/1.1")
        );
        assert!(request.contains("\r\nX-aws-ec2-metadata-token: secret\r\n"));
    }
}
#[test]
fn imds_401_is_token_error() {
    let server = Server::new(vec![
        token_response(response(200, "secret")),
        get_response("item", response(401, "")),
    ]);
    let token = server.imds.token().unwrap();
    assert_eq!(
        server.imds.get(&token, "item").unwrap_err().to_string(),
        "IMDS rejected the session token (401) for /latest/meta-data/item"
    );
}
#[test]
fn imds_unreachable_names_hop_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let error = Imds::new(addr).token().unwrap_err().to_string();
    assert!(error.contains("hop limit") && error.contains(&addr.to_string()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (release, held) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = read_request(&mut stream);
        assert_eq!(
            request.lines().next(),
            Some("PUT /latest/api/token HTTP/1.1")
        );
        let _ = held.recv();
        drop(stream);
    });
    let (completed, result) = mpsc::channel();
    let client = thread::spawn(move || {
        let start = Instant::now();
        let result = Imds::new(addr)
            .token()
            .map(|_| ())
            .map_err(|e| e.to_string());
        completed.send((start.elapsed(), result)).unwrap();
    });
    let outcome = result.recv_timeout(Duration::from_secs(5));
    drop(release);
    let (elapsed, result) = outcome.expect("IMDS client did not return within 5 seconds");
    server.join().unwrap();
    client.join().unwrap();
    assert!(
        elapsed < Duration::from_secs(3),
        "IMDS call took {elapsed:?}"
    );
    let error = result.unwrap_err();
    assert!(error.contains("hop limit") && error.contains(&addr.to_string()));
}
#[test]
fn imds_refuses_redirect_and_chunked() {
    for (raw, message) in [
        (
            "HTTP/1.1 301 Moved\r\nLocation: http://elsewhere/\r\n\r\n",
            "refused redirect (301)",
        ),
        (
            "HTTP/1.1 200 OK\r\ntRaNsFeR-EnCoDiNg: chunked\r\n\r\n0\r\n\r\n",
            "Transfer-Encoding",
        ),
    ] {
        let server = Server::new(vec![
            token_response(response(200, "secret")),
            get_response("item", raw.as_bytes().to_vec()),
        ]);
        let token = server.imds.token().unwrap();
        assert!(server
            .imds
            .get(&token, "item")
            .unwrap_err()
            .to_string()
            .contains(message));
    }
}
#[test]
fn aws_gateway_is_subnet_base_plus_one() {
    let tree = Tree::new();
    for (subnet, local, gateway) in [
        ("10.0.1.0/24", "10.0.1.23", "10.0.1.1"),
        ("10.0.4.0/22", "10.0.4.23", "10.0.4.1"),
    ] {
        tree.routes("");
        let server = metadata("1", local, subnet, "10.0.0.0/16", (200, "1.2.3.4"));
        assert_eq!(
            aws(&tree, &server, &[]).unwrap().config.gateway,
            Some(gateway.parse().unwrap())
        );
    }
    tree.routes("eth1 00000000 FE01000A 0003 0 0 0 00000000\n");
    let server = ordinary((200, "1.2.3.4"));
    let error = aws(&tree, &server, &addresses()).err().unwrap().to_string();
    assert!(error.contains("10.0.1.254") && error.contains("10.0.1.1"));
}
#[test]
fn aws_refuses_device_number_zero() {
    let tree = Tree::new();
    let server = metadata("0", "10.0.1.23", "10.0.1.0/24", "10.0.0.0/16", (200, ""));
    assert_eq!(
        aws(&tree, &server, &addresses()).err().unwrap().to_string(),
        "eth1 is the primary ENI (device-number 0); it carries IMDS and SSH"
    );
}
#[test]
fn aws_kernel_ip_not_in_local_ipv4s_is_error() {
    let tree = Tree::new();
    let server = ordinary((200, "1.2.3.4"));
    let error = aws(&tree, &server, &["10.0.1.25/24".parse().unwrap()])
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("10.0.1.25") && error.contains("local-ipv4s (10.0.1.23, 10.0.1.24)"));
    let server = ordinary((200, "1.2.3.4"));
    assert_eq!(
        aws(&tree, &server, &[]).unwrap().config.ipv4,
        addresses()[0]
    );
}
#[test]
fn aws_prefix_mismatch_is_error() {
    let tree = Tree::new();
    let server = ordinary((200, "1.2.3.4"));
    let error = aws(&tree, &server, &["10.0.1.23/22".parse().unwrap()])
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("10.0.1.23/22") && error.contains("10.0.1.0/24"));
}
#[test]
fn aws_vpc_blocks_become_9001_rules() {
    let tree = Tree::new();
    let server = ordinary((200, "1.2.3.4"));
    let config = aws(&tree, &server, &addresses()).unwrap().config;
    assert_eq!(config.mtu, 9001);
    assert_eq!(
        config
            .paths
            .iter()
            .map(|p| (p.prefix.to_string(), p.mtu, p.why.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("10.0.0.0/16".into(), 9001, "vpc"),
            ("192.168.0.0/16".into(), 9001, "vpc"),
            ("0.0.0.0/0".into(), 1500, "default")
        ]
    );
    let server = metadata("1", "10.0.1.23", "10.0.1.0/24", "10.0.1.0/16", (200, ""));
    assert!(aws(&tree, &server, &addresses())
        .err()
        .unwrap()
        .to_string()
        .contains("host bits"));
}
#[test]
fn default_rule_is_1500() {
    let tree = Tree::new();
    assert_eq!(
        tree.discover(&addresses(), None).unwrap().config.paths,
        vec![PathRule {
            prefix: "0.0.0.0/0".parse().unwrap(),
            mtu: 1500,
            why: "default".into()
        }]
    );
}
#[test]
fn operator_rules_survive_rediscover() {
    let tree = Tree::new();
    let server = metadata(
        "1",
        "10.0.1.23",
        "10.0.1.0/24",
        "10.0.0.0/16\n172.16.0.0/16\n",
        (200, "1.2.3.4"),
    );
    let discovered = aws(&tree, &server, &addresses()).unwrap().config;
    let mut previous = discovered.clone();
    previous.paths.insert(
        0,
        PathRule {
            prefix: "10.2.3.4/32".parse().unwrap(),
            mtu: 8500,
            why: "operator".into(),
        },
    );
    previous.paths[1].why = "peering".into();
    previous.paths[1].mtu = 8500;
    previous.paths[2].prefix = "192.168.0.0/16".parse().unwrap();
    previous.offloads = Offloads::Explicit {
        rx_checksum: false,
        tx_tcp_checksum: false,
        tx_udp_checksum: true,
    };
    previous.descriptors = 512;
    previous.rx_timestamps = true;
    previous.eal.file_prefix = "custom".into();
    if let Device::Pci(p) = &mut previous.device {
        p.devargs = "custom=1".into();
    }
    previous.mtu = 1500;
    let path = tree.dir.join("config.json");
    fs::write(&path, previous.to_json()).unwrap();
    let loaded = crate::rediscover::load_existing(&path).unwrap().unwrap();
    let mut output = Vec::new();
    crate::rediscover::write(&path, discovered, Some(&loaded), &mut output).unwrap();
    let merged = Config::load(&path).unwrap();
    assert_eq!(merged.paths[..2], previous.paths[..2]);
    assert_eq!(
        merged.paths,
        vec![
            previous.paths[0].clone(),
            previous.paths[1].clone(),
            PathRule {
                prefix: "172.16.0.0/16".parse().unwrap(),
                mtu: 9001,
                why: "vpc".into(),
            },
            PathRule {
                prefix: "0.0.0.0/0".parse().unwrap(),
                mtu: 1500,
                why: "default".into(),
            },
        ]
    );
    assert!(!merged
        .paths
        .iter()
        .any(|p| p.prefix == "192.168.0.0/16".parse().unwrap()));
    assert_eq!(merged.offloads, previous.offloads);
    assert_eq!(merged.descriptors, previous.descriptors);
    assert_eq!(merged.rx_timestamps, previous.rx_timestamps);
    assert_eq!(merged.eal, previous.eal);
    assert_eq!(merged.device, previous.device);
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "changed: mtu\nchanged: paths\n"
    );
}
#[test]
fn public_ipv4s_404_or_empty_warns() {
    let tree = Tree::new();
    for public in [(404, ""), (200, "\n  \n")] {
        let server = ordinary(public);
        let discovered = aws(&tree, &server, &addresses()).unwrap();
        assert_eq!(discovered.warnings, vec!["eth1 has no public IPv4 (IMDS public-ipv4s); internet destinations need an Elastic IP on this ENI or a NAT gateway route"]);
    }
}
#[test]
fn public_ipv4s_500_is_error() {
    let tree = Tree::new();
    let server = ordinary((500, "error"));
    assert_eq!(aws(&tree, &server, &addresses()).err().unwrap().to_string(), "IMDS answered 500 for /latest/meta-data/network/interfaces/macs/0a:12:34:56:78:9a/public-ipv4s");
}

#[test]
fn imds_response_framing_and_status_errors() {
    for (raw, message) in [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx".to_vec(),
            "Content-Length",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nx".to_vec(),
            "Content-Length",
        ),
        (b"HTTP/1.1 200 OK\r\n\r\n\xff".to_vec(), "UTF-8"),
        (b"HTTP/2 200 OK\r\n\r\n".to_vec(), "status line"),
        (b"HTTP/1.1 200 OK\r\n".to_vec(), "header terminator"),
        (response(200, &"x".repeat(65536)), "64 KiB"),
    ] {
        let server = Server::new(vec![token_response(raw)]);
        assert!(server
            .imds
            .token()
            .unwrap_err()
            .to_string()
            .contains(message));
    }
    let server = Server::new(vec![
        token_response(b"HTTP/1.0 200 OK\r\n\r\nsecret".to_vec()),
        get_response("optional", response(404, "")),
    ]);
    let token = server.imds.token().unwrap();
    assert!(server.imds.get(&token, "optional").unwrap().is_none());
    let server = Server::new(vec![token_response(response(403, ""))]);
    assert_eq!(
        server.imds.token().unwrap_err().to_string(),
        "IMDS token request answered 403"
    );
}

#[test]
fn aws_required_items_and_address_selection() {
    let tree = Tree::new();
    let values = ["1", "10.0.1.23", "10.0.1.0/24", "10.0.0.0/16"];
    for (missing, name) in [
        "device-number",
        "local-ipv4s",
        "subnet-ipv4-cidr-block",
        "vpc-ipv4-cidr-blocks",
    ]
    .iter()
    .enumerate()
    {
        let mut replies = vec![token_response(response(200, "secret"))];
        for (item, value) in [
            "device-number",
            "local-ipv4s",
            "subnet-ipv4-cidr-block",
            "vpc-ipv4-cidr-blocks",
        ]
        .iter()
        .zip(&values)
        .take(missing)
        {
            replies.push(get_response(
                &format!("network/interfaces/macs/0a:12:34:56:78:9a/{item}"),
                response(200, value),
            ));
        }
        replies.push(get_response(
            &format!("network/interfaces/macs/0a:12:34:56:78:9a/{name}"),
            response(404, ""),
        ));
        let server = Server::new(replies);
        let error = aws(&tree, &server, &addresses()).err().unwrap().to_string();
        assert!(error.contains(name) && error.contains("404"));
    }
    let addresses = [
        "10.0.1.23/24".parse().unwrap(),
        "10.0.1.24/24".parse().unwrap(),
    ];
    let server = ordinary((200, "1.2.3.4"));
    assert!(aws(&tree, &server, &addresses)
        .err()
        .unwrap()
        .to_string()
        .contains("choose one with --ipv4"));
    let server = ordinary((200, "1.2.3.4"));
    assert_eq!(
        discover_aws(
            &tree.roots,
            "eth1",
            &addresses,
            Some(addresses[1].address()),
            &server.imds
        )
        .unwrap()
        .config
        .ipv4,
        addresses[1]
    );
    tree.write("class/net/eth1/mtu", "1400\n");
    let server = ordinary((200, "1.2.3.4"));
    assert_eq!(
        aws(&tree, &server, &addresses[..1]).unwrap().config.mtu,
        1400
    );
}
