import struct
from dataclasses import dataclass, field
from typing import Optional, Tuple


PCAP_MAGIC_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1

GLOBAL_HEADER_FMT = "<IHHiIII"
GLOBAL_HEADER_SIZE = struct.calcsize(GLOBAL_HEADER_FMT)

PACKET_HEADER_FMT = "<IIII"
PACKET_HEADER_SIZE = struct.calcsize(PACKET_HEADER_FMT)


@dataclass
class PcapGlobalHeader:
    magic_number: int = 0
    version_major: int = 0
    version_minor: int = 0
    thiszone: int = 0
    sigfigs: int = 0
    snaplen: int = 0
    network: int = 0


@dataclass
class PcapPacketHeader:
    ts_sec: int = 0
    ts_usec: int = 0
    incl_len: int = 0
    orig_len: int = 0


@dataclass
class RawPacket:
    header: PcapPacketHeader = field(default_factory=PcapPacketHeader)
    data: bytes = b""


class PcapReader:
    def __init__(self):
        self._file = None
        self._needs_byte_swap = False
        self._global_header = PcapGlobalHeader()

    def open(self, filename: str) -> bool:
        self.close()
        try:
            self._file = open(filename, "rb")
        except OSError as e:
            print(f"Error: Could not open file: {filename} — {e}")
            return False

        raw = self._file.read(GLOBAL_HEADER_SIZE)
        if len(raw) < GLOBAL_HEADER_SIZE:
            print("Error: Could not read PCAP global header")
            self.close()
            return False

        fields = struct.unpack(GLOBAL_HEADER_FMT, raw)
        magic = fields[0]

        if magic == PCAP_MAGIC_NATIVE:
            self._needs_byte_swap = False
        elif magic == PCAP_MAGIC_SWAPPED:
            self._needs_byte_swap = True
            fmt_be = ">IHHiIII"
            fields = struct.unpack(fmt_be, raw)
        else:
            print(f"Error: Invalid PCAP magic number: 0x{magic:08x}")
            self.close()
            return False

        self._global_header = PcapGlobalHeader(
            magic_number=fields[0],
            version_major=fields[1],
            version_minor=fields[2],
            thiszone=fields[3],
            sigfigs=fields[4],
            snaplen=fields[5],
            network=fields[6],
        )

        link = "(Ethernet)" if self._global_header.network == 1 else ""
        print(f"Opened PCAP file: {filename}")
        print(f"  Version: {self._global_header.version_major}.{self._global_header.version_minor}")
        print(f"  Snaplen: {self._global_header.snaplen} bytes")
        print(f"  Link type: {self._global_header.network} {link}")
        return True

    def close(self):
        if self._file:
            self._file.close()
            self._file = None
        self._needs_byte_swap = False

    def read_next_packet(self) -> Optional[RawPacket]:
        if not self._file:
            return None

        raw = self._file.read(PACKET_HEADER_SIZE)
        if len(raw) < PACKET_HEADER_SIZE:
            return None

        fmt = ">IIII" if self._needs_byte_swap else "<IIII"
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, raw)

        if incl_len > self._global_header.snaplen or incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}")
            return None

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            print("Error: Could not read packet data")
            return None

        return RawPacket(
            header=PcapPacketHeader(ts_sec=ts_sec, ts_usec=ts_usec, incl_len=incl_len, orig_len=orig_len),
            data=data,
        )

    def get_global_header(self) -> PcapGlobalHeader:
        return self._global_header

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
