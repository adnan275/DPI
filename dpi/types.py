from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional
import time


class AppType(IntEnum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22


class ConnectionState(IntEnum):
    NEW = 0
    ESTABLISHED = 1
    CLASSIFIED = 2
    BLOCKED = 3
    CLOSED = 4


class PacketAction(IntEnum):
    FORWARD = 0
    DROP = 1
    INSPECT = 2
    LOG_ONLY = 3


@dataclass
class FiveTuple:
    src_ip: int = 0
    dst_ip: int = 0
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0

    def reverse(self):
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def __hash__(self):
        h = 0
        h ^= hash(self.src_ip) + 0x9E3779B9 + (h << 6) + (h >> 2)
        h ^= hash(self.dst_ip) + 0x9E3779B9 + (h << 6) + (h >> 2)
        h ^= hash(self.src_port) + 0x9E3779B9 + (h << 6) + (h >> 2)
        h ^= hash(self.dst_port) + 0x9E3779B9 + (h << 6) + (h >> 2)
        h ^= hash(self.protocol) + 0x9E3779B9 + (h << 6) + (h >> 2)
        return h & 0xFFFFFFFFFFFFFFFF

    def __eq__(self, other):
        return (
            self.src_ip == other.src_ip
            and self.dst_ip == other.dst_ip
            and self.src_port == other.src_port
            and self.dst_port == other.dst_port
            and self.protocol == other.protocol
        )

    def to_string(self):
        def fmt(ip):
            return ".".join(str((ip >> s) & 0xFF) for s in [0, 8, 16, 24])
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return f"{fmt(self.src_ip)}:{self.src_port} -> {fmt(self.dst_ip)}:{self.dst_port} ({proto})"


@dataclass
class Connection:
    tuple: FiveTuple = field(default_factory=FiveTuple)
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    first_seen: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    action: PacketAction = PacketAction.FORWARD
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False


@dataclass
class PacketJob:
    packet_id: int = 0
    tuple: FiveTuple = field(default_factory=FiveTuple)
    data: bytes = b""
    eth_offset: int = 0
    ip_offset: int = 0
    transport_offset: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    tcp_flags: int = 0
    ts_sec: int = 0
    ts_usec: int = 0

    @property
    def payload_data(self):
        return self.data[self.payload_offset:self.payload_offset + self.payload_length]


@dataclass
class DPIStats:
    total_packets: int = 0
    total_bytes: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    active_connections: int = 0


def app_type_to_string(app: AppType) -> str:
    names = {
        AppType.UNKNOWN: "Unknown",
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.TLS: "TLS",
        AppType.QUIC: "QUIC",
        AppType.GOOGLE: "Google",
        AppType.FACEBOOK: "Facebook",
        AppType.YOUTUBE: "YouTube",
        AppType.TWITTER: "Twitter/X",
        AppType.INSTAGRAM: "Instagram",
        AppType.NETFLIX: "Netflix",
        AppType.AMAZON: "Amazon",
        AppType.MICROSOFT: "Microsoft",
        AppType.APPLE: "Apple",
        AppType.WHATSAPP: "WhatsApp",
        AppType.TELEGRAM: "Telegram",
        AppType.TIKTOK: "TikTok",
        AppType.SPOTIFY: "Spotify",
        AppType.ZOOM: "Zoom",
        AppType.DISCORD: "Discord",
        AppType.GITHUB: "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }
    return names.get(app, "Unknown")


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN
    s = sni.lower()
    if any(x in s for x in ["google", "gstatic", "googleapis", "ggpht", "gvt1"]):
        return AppType.GOOGLE
    if any(x in s for x in ["youtube", "ytimg", "youtu.be", "yt3.ggpht"]):
        return AppType.YOUTUBE
    if any(x in s for x in ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"]):
        return AppType.FACEBOOK
    if any(x in s for x in ["instagram", "cdninstagram"]):
        return AppType.INSTAGRAM
    if any(x in s for x in ["whatsapp", "wa.me"]):
        return AppType.WHATSAPP
    if any(x in s for x in ["twitter", "twimg", "x.com", "t.co"]):
        return AppType.TWITTER
    if any(x in s for x in ["netflix", "nflxvideo", "nflximg"]):
        return AppType.NETFLIX
    if any(x in s for x in ["amazon", "amazonaws", "cloudfront", "aws"]):
        return AppType.AMAZON
    if any(x in s for x in ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"]):
        return AppType.MICROSOFT
    if any(x in s for x in ["apple", "icloud", "mzstatic", "itunes"]):
        return AppType.APPLE
    if any(x in s for x in ["telegram", "t.me"]):
        return AppType.TELEGRAM
    if any(x in s for x in ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]):
        return AppType.TIKTOK
    if any(x in s for x in ["spotify", "scdn.co"]):
        return AppType.SPOTIFY
    if "zoom" in s:
        return AppType.ZOOM
    if any(x in s for x in ["discord", "discordapp"]):
        return AppType.DISCORD
    if any(x in s for x in ["github", "githubusercontent"]):
        return AppType.GITHUB
    if any(x in s for x in ["cloudflare", "cf-"]):
        return AppType.CLOUDFLARE
    return AppType.HTTPS
