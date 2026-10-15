"""Raw frames for the unit tests, built with struct, independent of wire.Builder."""

import socket
import struct

from wire import Env, checksum, tcp_checksum

ENV = Env(iface="cdtap_echo", zhida_mac=bytes.fromhex("020000000001"),
          tester_mac=bytes.fromhex("020000000002"), zhida_ip=socket.inet_aton("192.0.2.2"),
          tester_ip=socket.inet_aton("192.0.2.1"), port=8080)
CLIENT_PORT = 40000


def tcp_frame(flags, seq, ack, window=1000, options=b"", payload=b"", src_mac=None,
              dst_mac=None, src_ip=None, dst_ip=None, sport=8080, dport=CLIENT_PORT,
              ip_options=b"", fix=True):
    """Zhida -> tester by default. `options`/`ip_options` must be 4-byte multiples."""
    src_mac = ENV.zhida_mac if src_mac is None else src_mac
    dst_mac = ENV.tester_mac if dst_mac is None else dst_mac
    src_ip = ENV.zhida_ip if src_ip is None else src_ip
    dst_ip = ENV.tester_ip if dst_ip is None else dst_ip
    doff = 5 + len(options) // 4
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, doff << 4, flags, window, 0, 0)
    seg += options + payload
    if fix:
        seg = seg[:16] + struct.pack("!H", tcp_checksum(src_ip, dst_ip, seg)) + seg[18:]
    ihl = 5 + len(ip_options) // 4
    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, ihl * 4 + len(seg), 1, 0x4000, 64, 6, 0,
                     src_ip, dst_ip) + ip_options
    if fix:
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip + seg


def arp_frame(op=1, sha=None, spa=None, tpa=None, src_mac=None):
    sha = ENV.zhida_mac if sha is None else sha
    spa = ENV.zhida_ip if spa is None else spa
    tpa = ENV.tester_ip if tpa is None else tpa
    src_mac = ENV.zhida_mac if src_mac is None else src_mac
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sha + spa + b"\0" * 6 + tpa
    return b"\xff" * 6 + src_mac + b"\x08\x06" + body
