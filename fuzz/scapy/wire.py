"""Ethernet/ARP/IPv4/TCP framing: frames are built with Scapy and parsed here, strictly.

Parsing follows the receiver's view smoltcp takes (src/wire/ipv4.rs check_len: IHL >= 5,
total length >= header, buffer >= total length; TCP payload = IP bytes [IHL*4, total length)),
so a mutated frame is read the way Zhida reads it. Checksum validity and option parse
errors are reported as fields, not raised, so oracles can name them.
"""

import socket
import struct
from dataclasses import dataclass

ETH_HLEN = 14
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
IP_PROTO_TCP = 6

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

OPT_EOL, OPT_NOP, OPT_MSS, OPT_WSCALE, OPT_SACK_PERM, OPT_SACK, OPT_TS = 0, 1, 2, 3, 4, 5, 8
# Fixed lengths of the option kinds Zhida may emit (RFC 9293, 7323, 2018).
OPT_LENGTHS = {OPT_MSS: 4, OPT_WSCALE: 3, OPT_SACK_PERM: 2, OPT_TS: 10}


class Malformed(Exception):
    """The frame cannot be read as Ethernet/IPv4/TCP."""


def mac_str(mac):
    return ":".join(f"{b:02x}" for b in mac)


def parse_mac(text):
    parts = text.split(":")
    if len(parts) != 6:
        raise ValueError(f"{text!r} is not a MAC address")
    return bytes(int(p, 16) for p in parts)


@dataclass(frozen=True)
class Env:
    """Addresses tap-echo hands its tester (crates/tap-echo/src/main.rs tester_env)."""
    iface: str
    zhida_mac: bytes
    tester_mac: bytes
    zhida_ip: bytes
    tester_ip: bytes
    port: int

    @classmethod
    def from_environ(cls, environ):
        return cls(iface=environ["ZHIDA_IFACE"],
                   zhida_mac=parse_mac(environ["ZHIDA_MAC"]),
                   tester_mac=parse_mac(environ["TESTER_MAC"]),
                   zhida_ip=socket.inet_aton(environ["ZHIDA_IP"]),
                   tester_ip=socket.inet_aton(environ["TESTER_IP"]),
                   port=int(environ["ECHO_PORT"]))

    @property
    def zhida_mac_str(self):
        return mac_str(self.zhida_mac)

    @property
    def tester_mac_str(self):
        return mac_str(self.tester_mac)

    @property
    def zhida_ip_str(self):
        return socket.inet_ntoa(self.zhida_ip)

    @property
    def tester_ip_str(self):
        return socket.inet_ntoa(self.tester_ip)


def checksum(data):
    """RFC 1071 Internet checksum of data (0 when data includes a correct checksum)."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tcp_checksum(src_ip, dst_ip, segment):
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, IP_PROTO_TCP, len(segment))
    return checksum(pseudo + segment)


def flag_names(flags):
    names = "FSRPAUEC"
    return "".join(names[i] for i in range(8) if flags & (1 << i)) or "-"


@dataclass(frozen=True)
class Tcp:
    src_mac: bytes
    dst_mac: bytes
    src_ip: bytes
    dst_ip: bytes
    ihl: int
    ip_total: int
    ip_flags_frag: int
    ip_checksum_ok: bool
    protocol: int
    sport: int
    dport: int
    seq: int
    ack: int
    doff: int
    flags: int
    window: int
    tcp_checksum_ok: bool
    options_raw: bytes
    options: tuple  # ((kind, value bytes), ...) when options_error is None
    options_error: str
    payload: bytes

    def option(self, kind):
        for k, value in self.options:
            if k == kind:
                return value
        return None

    @property
    def mss(self):
        v = self.option(OPT_MSS)
        return struct.unpack("!H", v)[0] if v is not None else None

    @property
    def wscale(self):
        v = self.option(OPT_WSCALE)
        return v[0] if v is not None else None

    @property
    def timestamp(self):
        v = self.option(OPT_TS)
        return struct.unpack("!II", v) if v is not None else None

    @property
    def seg_len(self):
        """Sequence space the segment occupies: payload plus SYN and FIN."""
        return len(self.payload) + bool(self.flags & SYN) + bool(self.flags & FIN)

    def describe(self):
        return (f"{flag_names(self.flags)} seq {self.seq} ack {self.ack} win {self.window} "
                f"len {len(self.payload)} {self.sport}->{self.dport}")


def parse_options(raw):
    """Strict parse: returns (((kind, value), ...), None) or ((), reason)."""
    options = []
    i = 0
    while i < len(raw):
        kind = raw[i]
        if kind == OPT_EOL:
            if any(raw[i + 1:]):
                return (), f"nonzero padding after EOL at option byte {i}"
            break
        if kind == OPT_NOP:
            i += 1
            continue
        if i + 1 >= len(raw):
            return (), f"option kind {kind} at byte {i} has no length byte"
        length = raw[i + 1]
        if length < 2 or i + length > len(raw):
            return (), f"option kind {kind} at byte {i} has length {length}"
        want = OPT_LENGTHS.get(kind)
        if want is not None and length != want:
            return (), f"option kind {kind} has length {length}, expected {want}"
        if kind == OPT_SACK and (length == 2 or (length - 2) % 8):
            return (), f"SACK option length {length} is not 2 + 8n, n >= 1"
        options.append((kind, bytes(raw[i + 2:i + length])))
        i += length
    return tuple(options), None


def smoltcp_options_ok(raw):
    """True if smoltcp's TcpOption::parse (src/wire/tcp.rs 678-746) reads every option up to
    EOL: kinds other than EOL/NOP need a length byte in 2..=remaining; MSS, window scale and
    SACK-permitted need lengths 4, 3 and 2, SACK 10 + 8n; any other kind or length (a TS
    option whose length is not 10 included) is Unknown and accepted. Bytes after EOL are
    ignored."""
    i = 0
    while i < len(raw):
        kind = raw[i]
        if kind == OPT_EOL:
            return True
        if kind == OPT_NOP:
            i += 1
            continue
        if i + 1 >= len(raw):
            return False
        length = raw[i + 1]
        if length < 2 or i + length > len(raw):
            return False
        if kind in (OPT_MSS, OPT_WSCALE, OPT_SACK_PERM) and length != OPT_LENGTHS[kind]:
            return False
        if kind == OPT_SACK and (length < 10 or (length - 2) % 8):
            return False
        i += length
    return True


IP_MF_OFFSET = 0x3FFF


def smoltcp_accepts(seg):
    """True if Zhida's smoltcp hands this parsed segment (parse_tcp already applied the
    IPv4 and TCP length checks) to its sockets: valid IPv4 and TCP checksums (software
    checksums, dpdk-smoltcp port.rs), not a fragment (src/wire/ipv4.rs 557-561, no
    fragmentation feature), and TcpRepr::parse (src/wire/tcp.rs 907-945): ports not 0, at
    most one of SYN/FIN/RST, options smoltcp_options_ok."""
    return (seg.ip_checksum_ok and seg.tcp_checksum_ok
            and not seg.ip_flags_frag & IP_MF_OFFSET
            and seg.sport != 0 and seg.dport != 0
            and bin(seg.flags & (SYN | FIN | RST)).count("1") <= 1
            and smoltcp_options_ok(seg.options_raw))


def parse_tcp(frame):
    """Ethernet/IPv4/TCP frame -> Tcp. Raises Malformed if the fields cannot be located."""
    if len(frame) < ETH_HLEN + 20:
        raise Malformed(f"{len(frame)}-byte frame is too short for IPv4")
    dst_mac, src_mac, ethertype = frame[0:6], frame[6:12], struct.unpack("!H", frame[12:14])[0]
    if ethertype != ETH_P_IP:
        raise Malformed(f"ethertype {ethertype:#06x} is not IPv4")
    ip = frame[ETH_HLEN:]
    version, ihl = ip[0] >> 4, ip[0] & 0xF
    ip_total = struct.unpack("!H", ip[2:4])[0]
    if version != 4:
        raise Malformed(f"IP version {version}")
    if ihl < 5 or ihl * 4 > len(ip):
        raise Malformed(f"IHL {ihl} with {len(ip)} IP bytes")
    if ip_total < ihl * 4 or ip_total > len(ip):
        raise Malformed(f"IP total length {ip_total} with IHL {ihl} and {len(ip)} IP bytes")
    protocol = ip[9]
    if protocol != IP_PROTO_TCP:
        raise Malformed(f"IP protocol {protocol} is not TCP")
    src_ip, dst_ip = bytes(ip[12:16]), bytes(ip[16:20])
    ip_checksum_ok = checksum(ip[:ihl * 4]) == 0
    seg = ip[ihl * 4:ip_total]
    if len(seg) < 20:
        raise Malformed(f"{len(seg)}-byte TCP segment is shorter than its header")
    sport, dport, seq, ack, off_flags, window = struct.unpack("!HHIIHH", seg[:16])
    doff = off_flags >> 12
    if doff < 5 or doff * 4 > len(seg):
        raise Malformed(f"TCP data offset {doff} with {len(seg)} segment bytes")
    options, options_error = parse_options(seg[20:doff * 4])
    return Tcp(
        src_mac=bytes(src_mac), dst_mac=bytes(dst_mac), src_ip=src_ip, dst_ip=dst_ip,
        ihl=ihl, ip_total=ip_total, ip_flags_frag=struct.unpack("!H", ip[6:8])[0],
        ip_checksum_ok=ip_checksum_ok, protocol=protocol,
        sport=sport, dport=dport, seq=seq, ack=ack, doff=doff, flags=off_flags & 0xFF,
        window=window, tcp_checksum_ok=tcp_checksum(src_ip, dst_ip, seg) == 0,
        options_raw=bytes(seg[20:doff * 4]), options=options, options_error=options_error,
        payload=bytes(seg[doff * 4:]))


@dataclass(frozen=True)
class Arp:
    eth_src: bytes
    eth_dst: bytes
    htype: int
    ptype: int
    hlen: int
    plen: int
    op: int
    sha: bytes
    spa: bytes
    tha: bytes
    tpa: bytes


def parse_arp(frame):
    if len(frame) < ETH_HLEN + 28:
        raise Malformed(f"{len(frame)}-byte frame is too short for ARP")
    if struct.unpack("!H", frame[12:14])[0] != ETH_P_ARP:
        raise Malformed("ethertype is not ARP")
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", frame[14:22])
    body = frame[22:]
    return Arp(eth_src=bytes(frame[6:12]), eth_dst=bytes(frame[0:6]), htype=htype,
               ptype=ptype, hlen=hlen, plen=plen, op=op, sha=bytes(body[0:6]),
               spa=bytes(body[6:10]), tha=bytes(body[10:16]), tpa=bytes(body[16:20]))


def ethertype(frame):
    return struct.unpack("!H", frame[12:14])[0] if len(frame) >= ETH_HLEN else None


def fix_checksums(frame):
    """Recompute the IPv4 header and TCP checksums as the receiver reads the (possibly
    mutated) header: IP over IHL*4 bytes, TCP over IP bytes [IHL*4, total length). A
    checksum field the frame does not contain stays as is."""
    out = bytearray(frame)
    ip_at = ETH_HLEN
    ihl = (out[ip_at] & 0xF) * 4
    if ihl >= 20 and ip_at + ihl <= len(out):
        out[ip_at + 10:ip_at + 12] = b"\0\0"
        out[ip_at + 10:ip_at + 12] = struct.pack("!H", checksum(bytes(out[ip_at:ip_at + ihl])))
    total = struct.unpack("!H", out[ip_at + 2:ip_at + 4])[0]
    seg_at, seg_end = ip_at + ihl, min(ip_at + total, len(out))
    if ihl >= 20 and seg_end - seg_at >= 18:
        out[seg_at + 16:seg_at + 18] = b"\0\0"
        src, dst = bytes(out[ip_at + 12:ip_at + 16]), bytes(out[ip_at + 16:ip_at + 20])
        out[seg_at + 16:seg_at + 18] = struct.pack(
            "!H", tcp_checksum(src, dst, bytes(out[seg_at:seg_end])))
    return bytes(out)


# Byte offsets of header fields inside an Ethernet/IPv4 (IHL 5)/TCP frame.
IP_AT = ETH_HLEN
TCP_AT = ETH_HLEN + 20
IP_TOS, IP_TOTAL, IP_ID, IP_FRAG, IP_TTL, IP_CSUM = 1, 2, 4, 6, 8, 10
TCP_SEQ, TCP_ACK, TCP_DOFF, TCP_FLAGS, TCP_WIN, TCP_CSUM, TCP_URP = 4, 8, 12, 13, 14, 16, 18


class Builder:
    """Builds the tester's frames with Scapy (imported lazily: unit tests of the pure
    modules do not need it)."""

    def __init__(self, env):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import ARP, Ether
        from scapy.packet import Raw
        self._Ether, self._IP, self._TCP, self._ARP, self._Raw = Ether, IP, TCP, ARP, Raw
        self.env = env
        self.ip_id = 0

    def tcp(self, sport, seq, ack, flags, window, options=(), payload=b"", urgent=0):
        """One Linux-like segment: DF set, TTL 64, IP ID counting up per frame."""
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        e = self.env
        pkt = (self._Ether(src=e.tester_mac_str, dst=e.zhida_mac_str, type=ETH_P_IP)
               / self._IP(src=e.tester_ip_str, dst=e.zhida_ip_str, ttl=64, flags="DF",
                          id=self.ip_id)
               / self._TCP(sport=sport, dport=e.port, seq=seq, ack=ack, flags=flags,
                           window=window, options=list(options), urgptr=urgent))
        if payload:
            pkt = pkt / self._Raw(load=payload)
        return bytes(pkt)

    def arp_reply(self, request):
        e = self.env
        pkt = (self._Ether(src=e.tester_mac_str, dst=mac_str(request.sha), type=ETH_P_ARP)
               / self._ARP(op=2, hwsrc=e.tester_mac_str, psrc=e.tester_ip_str,
                           hwdst=mac_str(request.sha), pdst=socket.inet_ntoa(request.spa)))
        return bytes(pkt)
