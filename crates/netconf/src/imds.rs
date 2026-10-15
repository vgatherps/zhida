use std::{
    fmt,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

pub struct Imds {
    addr: SocketAddr,
}
pub(crate) struct Token(String);
impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}
#[derive(Debug)]
pub(crate) struct ImdsError(pub(crate) String);
impl fmt::Display for ImdsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl Imds {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
    pub(crate) fn token(&self) -> Result<Token, ImdsError> {
        let path = "/latest/api/token";
        let (status, body) = self.request(
            "PUT",
            path,
            "X-aws-ec2-metadata-token-ttl-seconds: 60\r\nContent-Length: 0\r\n",
        )?;
        if status != 200 {
            return Err(ImdsError(format!("IMDS token request answered {status}")));
        }
        if body.contains(['\r', '\n']) {
            return Err(ImdsError("IMDS token contains a line break".into()));
        }
        Ok(Token(body))
    }
    pub(crate) fn get(&self, token: &Token, path: &str) -> Result<Option<String>, ImdsError> {
        if path.contains(['\r', '\n', ' ']) {
            return Err(ImdsError("invalid IMDS metadata path".into()));
        }
        let path = format!("/latest/meta-data/{path}");
        let (status, body) = self.request(
            "GET",
            &path,
            &format!("X-aws-ec2-metadata-token: {}\r\n", token.0),
        )?;
        match status {
            200 => Ok(Some(body)),
            404 => Ok(None),
            401 => Err(ImdsError(format!(
                "IMDS rejected the session token (401) for {path}"
            ))),
            _ => Err(ImdsError(format!("IMDS answered {status} for {path}"))),
        }
    }
    fn request(&self, method: &str, path: &str, headers: &str) -> Result<(u16, String), ImdsError> {
        let io_error = |e: std::io::Error| {
            if method == "PUT" {
                ImdsError(format!("IMDS token request to {}: {e}; from a container without host networking, the IMDSv2 PUT response hop limit (1 by default, 2 on AL2023) drops the reply", self.addr))
            } else {
                ImdsError(format!("IMDS GET {path}: {e}"))
            }
        };
        let timeout = Duration::from_secs(1);
        let mut stream = TcpStream::connect_timeout(&self.addr, timeout).map_err(io_error)?;
        stream.set_read_timeout(Some(timeout)).map_err(io_error)?;
        stream.set_write_timeout(Some(timeout)).map_err(io_error)?;
        stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: 169.254.169.254\r\n{headers}Connection: close\r\n\r\n").as_bytes()).map_err(io_error)?;
        let mut bytes = Vec::new();
        stream
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        let error = |message: &str| ImdsError(format!("IMDS {path}: {message}"));
        if bytes.len() > 65536 {
            return Err(error("response exceeds 64 KiB"));
        }
        let end = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| error("missing header terminator"))?;
        let headers =
            std::str::from_utf8(&bytes[..end]).map_err(|_| error("headers are not UTF-8"))?;
        let mut lines = headers.split("\r\n");
        let mut status_line = lines.next().unwrap_or_default().splitn(3, ' ');
        let version = status_line.next().unwrap_or_default();
        let code = status_line.next().unwrap_or_default();
        if version.len() != 8
            || !version.starts_with("HTTP/1.")
            || !version.as_bytes()[7].is_ascii_digit()
            || code.len() != 3
            || !code.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(error("invalid status line"));
        }
        let status: u16 = code.parse().map_err(|_| error("invalid status code"))?;
        let mut length = None;
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| error("invalid header"))?;
            if name.eq_ignore_ascii_case("Transfer-Encoding") {
                return Err(error("Transfer-Encoding refused"));
            }
            if name.eq_ignore_ascii_case("Content-Length") {
                let n = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| error("invalid Content-Length"))?;
                if length.replace(n).is_some() {
                    return Err(error("duplicate Content-Length"));
                }
            }
        }
        if (300..400).contains(&status) {
            return Err(ImdsError(format!("refused redirect ({status}) for {path}")));
        }
        let body = &bytes[end + 4..];
        if length.is_some_and(|n| n != body.len()) {
            return Err(error("body does not match Content-Length"));
        }
        // Error response bodies are not consumed by callers.
        let body = if status == 200 {
            std::str::from_utf8(body)
                .map_err(|_| error("body is not UTF-8"))?
                .to_owned()
        } else {
            String::new()
        };
        Ok((status, body))
    }
}
