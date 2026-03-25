#!/usr/bin/env python3
import sys
from datetime import datetime

from dpi.pcap_reader import PcapReader
from dpi.packet_parser import PacketParser, ParsedPacket, EtherType


def print_packet_summary(pkt: ParsedPacket, packet_num: int):
    ts = datetime.fromtimestamp(pkt.timestamp_sec).strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n========== Packet #{packet_num} ==========")
    print(f"Time: {ts}.{pkt.timestamp_usec:06d}")

    print("\n[Ethernet]")
    print(f"  Source MAC:      {pkt.src_mac}")
    print(f"  Destination MAC: {pkt.dest_mac}")
    etype_label = {EtherType.IPv4: " (IPv4)", EtherType.IPv6: " (IPv6)", EtherType.ARP: " (ARP)"}.get(pkt.ether_type, "")
    print(f"  EtherType:       0x{pkt.ether_type:04x}{etype_label}")

    if pkt.has_ip:
        print(f"\n[IPv{pkt.ip_version}]")
        print(f"  Source IP:      {pkt.src_ip}")
        print(f"  Destination IP: {pkt.dest_ip}")
        print(f"  Protocol:       {PacketParser.protocol_to_string(pkt.protocol)}")
        print(f"  TTL:            {pkt.ttl}")

    if pkt.has_tcp:
        print("\n[TCP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")
        print(f"  Sequence Number:  {pkt.seq_number}")
        print(f"  Ack Number:       {pkt.ack_number}")
        print(f"  Flags:            {PacketParser.tcp_flags_to_string(pkt.tcp_flags)}")

    if pkt.has_udp:
        print("\n[UDP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")

    if pkt.payload_length > 0:
        print("\n[Payload]")
        print(f"  Length: {pkt.payload_length} bytes")
        preview = pkt.payload_data[:32] if pkt.payload_data else b""
        hex_preview = " ".join(f"{b:02x}" for b in preview)
        suffix = " ..." if pkt.payload_length > 32 else ""
        print(f"  Preview: {hex_preview}{suffix}")


def print_usage(program: str):
    print(f"Usage: {program} <pcap_file> [max_packets]")
    print("\nArguments:")
    print("  pcap_file   - Path to a .pcap file captured by Wireshark")
    print("  max_packets - (Optional) Maximum number of packets to display")
    print("\nExample:")
    print(f"  {program} capture.pcap")
    print(f"  {program} capture.pcap 10")


def main():
    print("====================================")
    print("     Packet Analyzer v1.0")
    print("====================================\n")

    if len(sys.argv) < 2:
        print_usage(sys.argv[0])
        sys.exit(1)

    filename = sys.argv[1]
    max_packets = int(sys.argv[2]) if len(sys.argv) >= 3 else -1

    reader = PcapReader()
    if not reader.open(filename):
        sys.exit(1)

    print("\n--- Reading packets ---")

    packet_count = 0
    parse_errors = 0
    parsed = ParsedPacket()

    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break

        packet_count += 1
        if PacketParser.parse(raw, parsed):
            print_packet_summary(parsed, packet_count)
        else:
            print(f"Warning: Failed to parse packet #{packet_count}", file=sys.stderr)
            parse_errors += 1

        if max_packets > 0 and packet_count >= max_packets:
            print(f"\n(Stopped after {max_packets} packets)")
            break

    print("\n====================================")
    print("Summary:")
    print(f"  Total packets read:  {packet_count}")
    print(f"  Parse errors:        {parse_errors}")
    print("====================================")

    reader.close()


if __name__ == "__main__":
    main()
