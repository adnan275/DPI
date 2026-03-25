import struct
from dataclasses import dataclass, field
from typing import Optional


class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806


class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17


class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


@dataclass
class ParsedPacket:
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    src_port: int = 0
    dest_port: int = 0
    seq_number: int = 0
    ack_number: int = 0
    tcp_flags: int = 0
    has_udp: bool = False
    payload_length: int = 0
    payload_data: Optional[bytes] = None


class PacketParser:
    ETH_HEADER_LEN = 14
    MIN_IP_HEADER_LEN = 20
    MIN_TCP_HEADER_LEN = 20
    UDP_HEADER_LEN = 8

    @staticmethod
    def parse(raw, parsed: ParsedPacket) -> bool:
        parsed.__init__()
        parsed.timestamp_sec = raw.header.ts_sec
        parsed.timestamp_usec = raw.header.ts_usec

        data = raw.data
        length = len(data)
        offset = 0

        ok, offset = PacketParser._parse_ethernet(data, length, parsed, offset)
        if not ok:
            return False

        if parsed.ether_type == EtherType.IPv4:
            ok, offset = PacketParser._parse_ipv4(data, length, parsed, offset)
            if not ok:
                return False

            if parsed.protocol == Protocol.TCP:
                ok, offset = PacketParser._parse_tcp(data, length, parsed, offset)
                if not ok:
                    return False
            elif parsed.protocol == Protocol.UDP:
                ok, offset = PacketParser._parse_udp(data, length, parsed, offset)
                if not ok:
                    return False

        if offset < length:
            parsed.payload_length = length - offset
            parsed.payload_data = data[offset:]
        else:
            parsed.payload_length = 0
            parsed.payload_data = None

        return True

    @staticmethod
    def _parse_ethernet(data, length, parsed, offset):
        if length < PacketParser.ETH_HEADER_LEN:
            return False, offset
        parsed.dest_mac = PacketParser.mac_to_string(data[0:6])
        parsed.src_mac = PacketParser.mac_to_string(data[6:12])
        parsed.ether_type = struct.unpack_from(">H", data, 12)[0]
        return True, PacketParser.ETH_HEADER_LEN

    @staticmethod
    def _parse_ipv4(data, length, parsed, offset):
        if length < offset + PacketParser.MIN_IP_HEADER_LEN:
            return False, offset

        version_ihl = data[offset]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F

        if parsed.ip_version != 4:
            return False, offset

        ip_header_len = ihl * 4
        if ip_header_len < PacketParser.MIN_IP_HEADER_LEN or length < offset + ip_header_len:
            return False, offset

        parsed.ttl = data[offset + 8]
        parsed.protocol = data[offset + 9]

        src_raw = struct.unpack_from("I", data, offset + 12)[0]
        dst_raw = struct.unpack_from("I", data, offset + 16)[0]
        parsed.src_ip = PacketParser.ip_to_string(src_raw)
        parsed.dest_ip = PacketParser.ip_to_string(dst_raw)
        parsed.has_ip = True

        return True, offset + ip_header_len

    @staticmethod
    def _parse_tcp(data, length, parsed, offset):
        if length < offset + PacketParser.MIN_TCP_HEADER_LEN:
            return False, offset

        parsed.src_port = struct.unpack_from(">H", data, offset)[0]
        parsed.dest_port = struct.unpack_from(">H", data, offset + 2)[0]
        parsed.seq_number = struct.unpack_from(">I", data, offset + 4)[0]
        parsed.ack_number = struct.unpack_from(">I", data, offset + 8)[0]

        data_offset = (data[offset + 12] >> 4) & 0x0F
        tcp_header_len = data_offset * 4
        parsed.tcp_flags = data[offset + 13]

        if tcp_header_len < PacketParser.MIN_TCP_HEADER_LEN or length < offset + tcp_header_len:
            return False, offset

        parsed.has_tcp = True
        return True, offset + tcp_header_len

    @staticmethod
    def _parse_udp(data, length, parsed, offset):
        if length < offset + PacketParser.UDP_HEADER_LEN:
            return False, offset

        parsed.src_port = struct.unpack_from(">H", data, offset)[0]
        parsed.dest_port = struct.unpack_from(">H", data, offset + 2)[0]
        parsed.has_udp = True
        return True, offset + PacketParser.UDP_HEADER_LEN

    @staticmethod
    def mac_to_string(mac_bytes: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac_bytes)

    @staticmethod
    def ip_to_string(ip: int) -> str:
        return ".".join(str((ip >> s) & 0xFF) for s in [0, 8, 16, 24])

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, f"Unknown({protocol})")

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        parts = []
        if flags & TCPFlags.SYN:
            parts.append("SYN")
        if flags & TCPFlags.ACK:
            parts.append("ACK")
        if flags & TCPFlags.FIN:
            parts.append("FIN")
        if flags & TCPFlags.RST:
            parts.append("RST")
        if flags & TCPFlags.PSH:
            parts.append("PSH")
        if flags & TCPFlags.URG:
            parts.append("URG")
        return " ".join(parts) if parts else "none"
