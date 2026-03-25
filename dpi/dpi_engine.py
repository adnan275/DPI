import queue
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .types import (
    AppType, DPIStats, PacketAction, PacketJob, FiveTuple,
    app_type_to_string,
)
from .pcap_reader import PcapGlobalHeader, PcapPacketHeader, PcapReader
from .packet_parser import PacketParser, ParsedPacket
from .rule_manager import RuleManager
from .fast_path import FPManager
from .load_balancer import LBManager
from .connection_tracker import GlobalConnectionTable


@dataclass
class DPIConfig:
    num_load_balancers: int = 2
    fps_per_lb: int = 2
    rules_file: str = ""
    verbose: bool = False


class DPIEngine:
    PCAP_GLOBAL_HEADER_FMT = "<IHHiIII"
    PCAP_PACKET_HEADER_FMT = "<IIII"

    def __init__(self, config: DPIConfig):
        self._config = config
        self._output_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._running = False
        self._output_thread: Optional[threading.Thread] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._output_file = None
        self._output_lock = threading.Lock()
        self._stats = DPIStats()
        self._rule_manager: Optional[RuleManager] = None
        self._fp_manager: Optional[FPManager] = None
        self._lb_manager: Optional[LBManager] = None
        self._global_conn_table: Optional[GlobalConnectionTable] = None

        total_fps = config.num_load_balancers * config.fps_per_lb
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                    DPI ENGINE v1.0                            ║")
        print("║               Deep Packet Inspection System                   ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ Configuration:                                                ║")
        print(f"║   Load Balancers:    {config.num_load_balancers:>3}                                       ║")
        print(f"║   FPs per LB:        {config.fps_per_lb:>3}                                       ║")
        print(f"║   Total FP threads:  {total_fps:>3}                                       ║")
        print("╚══════════════════════════════════════════════════════════════╝")

    def initialize(self) -> bool:
        self._rule_manager = RuleManager()

        if self._config.rules_file:
            self._rule_manager.load_rules(self._config.rules_file)

        def output_cb(job: PacketJob, action: PacketAction):
            self._handle_output(job, action)

        total_fps = self._config.num_load_balancers * self._config.fps_per_lb
        self._fp_manager = FPManager(total_fps, self._rule_manager, output_cb)
        self._lb_manager = LBManager(
            self._config.num_load_balancers,
            self._config.fps_per_lb,
            self._fp_manager.get_queue_ptrs(),
        )

        self._global_conn_table = GlobalConnectionTable(total_fps)
        for i in range(total_fps):
            self._global_conn_table.register_tracker(i, self._fp_manager.get_fp(i).conn_tracker)

        print("[DPIEngine] Initialized successfully")
        return True

    def start(self):
        if self._running:
            return
        self._running = True

        self._output_thread = threading.Thread(target=self._output_thread_func, daemon=True)
        self._output_thread.start()

        self._fp_manager.start_all()
        self._lb_manager.start_all()
        print("[DPIEngine] All threads started")

    def stop(self):
        if not self._running:
            return
        self._running = False

        self._lb_manager.stop_all()
        self._fp_manager.stop_all()

        self._output_queue.put(None)
        if self._output_thread and self._output_thread.is_alive():
            self._output_thread.join()

        print("[DPIEngine] All threads stopped")

    def wait_for_completion(self):
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join()
        time.sleep(0.5)

    def process_file(self, input_file: str, output_file: str) -> bool:
        print(f"\n[DPIEngine] Processing: {input_file}")
        print(f"[DPIEngine] Output to:  {output_file}\n")

        if not self._rule_manager:
            if not self.initialize():
                return False

        try:
            self._output_file = open(output_file, "wb")
        except OSError:
            print("[DPIEngine] Error: Cannot open output file")
            return False

        self.start()

        self._reader_thread = threading.Thread(
            target=self._reader_thread_func, args=(input_file,), daemon=True
        )
        self._reader_thread.start()

        self.wait_for_completion()
        time.sleep(0.2)
        self.stop()

        if self._output_file:
            self._output_file.close()
            self._output_file = None

        print(self.generate_report())
        print(self._fp_manager.generate_classification_report())
        return True

    def _reader_thread_func(self, input_file: str):
        reader = PcapReader()
        if not reader.open(input_file):
            print("[Reader] Error: Cannot open input file")
            return

        self._write_output_header(reader.get_global_header())

        parsed = ParsedPacket()
        packet_id = 0
        print("[Reader] Starting packet processing...")

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            if not PacketParser.parse(raw, parsed):
                continue

            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue

            job = self._create_packet_job(raw, parsed, packet_id)
            packet_id += 1

            self._stats.total_packets += 1
            self._stats.total_bytes += len(raw.data)
            if parsed.has_tcp:
                self._stats.tcp_packets += 1
            elif parsed.has_udp:
                self._stats.udp_packets += 1

            lb = self._lb_manager.get_lb_for_packet(job.tuple)
            try:
                lb.get_input_queue().put_nowait(job)
            except queue.Full:
                pass

        print(f"[Reader] Finished reading {packet_id} packets")
        reader.close()

    @staticmethod
    def _parse_ip_str(ip: str) -> int:
        result = 0
        for i, part in enumerate(ip.split(".")):
            result |= int(part) << (i * 8)
        return result

    def _create_packet_job(self, raw, parsed, packet_id: int) -> PacketJob:
        job = PacketJob()
        job.packet_id = packet_id
        job.ts_sec = raw.header.ts_sec
        job.ts_usec = raw.header.ts_usec

        job.tuple = FiveTuple(
            src_ip=self._parse_ip_str(parsed.src_ip),
            dst_ip=self._parse_ip_str(parsed.dest_ip),
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol,
        )

        job.tcp_flags = parsed.tcp_flags
        job.data = raw.data
        job.eth_offset = 0
        job.ip_offset = 14

        if len(job.data) > 14:
            ip_ihl = job.data[14] & 0x0F
            ip_header_len = ip_ihl * 4
            job.transport_offset = 14 + ip_header_len

            if parsed.has_tcp and len(job.data) > job.transport_offset:
                tcp_data_offset = (job.data[job.transport_offset + 12] >> 4) & 0x0F
                job.payload_offset = job.transport_offset + tcp_data_offset * 4
            elif parsed.has_udp:
                job.payload_offset = job.transport_offset + 8

            if job.payload_offset < len(job.data):
                job.payload_length = len(job.data) - job.payload_offset

        return job

    def _output_thread_func(self):
        while self._running or not self._output_queue.empty():
            try:
                job = self._output_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if job is None:
                break
            self._write_output_packet(job)

    def _handle_output(self, job: PacketJob, action: PacketAction):
        if action == PacketAction.DROP:
            self._stats.dropped_packets += 1
            return
        self._stats.forwarded_packets += 1
        try:
            self._output_queue.put_nowait(job)
        except queue.Full:
            pass

    def _write_output_header(self, header: PcapGlobalHeader):
        with self._output_lock:
            if not self._output_file:
                return
            data = struct.pack(
                "<IHHiIII",
                header.magic_number,
                header.version_major,
                header.version_minor,
                header.thiszone,
                header.sigfigs,
                header.snaplen,
                header.network,
            )
            self._output_file.write(data)

    def _write_output_packet(self, job: PacketJob):
        with self._output_lock:
            if not self._output_file:
                return
            pkt_header = struct.pack(
                "<IIII",
                job.ts_sec,
                job.ts_usec,
                len(job.data),
                len(job.data),
            )
            self._output_file.write(pkt_header)
            self._output_file.write(job.data)

    def block_ip(self, ip: str):
        if self._rule_manager:
            self._rule_manager.block_ip(ip)

    def unblock_ip(self, ip: str):
        if self._rule_manager:
            self._rule_manager.unblock_ip(ip)

    def block_app(self, app):
        if self._rule_manager:
            if isinstance(app, str):
                for a in AppType:
                    if app_type_to_string(a) == app:
                        self._rule_manager.block_app(a)
                        return
                print(f"[DPIEngine] Unknown app: {app}")
            else:
                self._rule_manager.block_app(app)

    def unblock_app(self, app):
        if self._rule_manager:
            if isinstance(app, str):
                for a in AppType:
                    if app_type_to_string(a) == app:
                        self._rule_manager.unblock_app(a)
                        return
            else:
                self._rule_manager.unblock_app(app)

    def block_domain(self, domain: str):
        if self._rule_manager:
            self._rule_manager.block_domain(domain)

    def unblock_domain(self, domain: str):
        if self._rule_manager:
            self._rule_manager.unblock_domain(domain)

    def load_rules(self, filename: str) -> bool:
        if self._rule_manager:
            return self._rule_manager.load_rules(filename)
        return False

    def save_rules(self, filename: str) -> bool:
        if self._rule_manager:
            return self._rule_manager.save_rules(filename)
        return False

    def generate_report(self) -> str:
        s = self._stats
        lines = [
            "\n╔══════════════════════════════════════════════════════════════╗",
            "║                    DPI ENGINE STATISTICS                      ║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║ PACKET STATISTICS                                             ║",
            f"║   Total Packets:      {s.total_packets:>12}                        ║",
            f"║   Total Bytes:        {s.total_bytes:>12}                        ║",
            f"║   TCP Packets:        {s.tcp_packets:>12}                        ║",
            f"║   UDP Packets:        {s.udp_packets:>12}                        ║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║ FILTERING STATISTICS                                          ║",
            f"║   Forwarded:          {s.forwarded_packets:>12}                        ║",
            f"║   Dropped/Blocked:    {s.dropped_packets:>12}                        ║",
        ]

        if s.total_packets > 0:
            drop_rate = 100.0 * s.dropped_packets / s.total_packets
            lines.append(f"║   Drop Rate:          {drop_rate:>11.2f}%                        ║")

        if self._lb_manager:
            lb_stats = self._lb_manager.get_aggregated_stats()
            lines += [
                "╠══════════════════════════════════════════════════════════════╣",
                "║ LOAD BALANCER STATISTICS                                      ║",
                f"║   LB Received:        {lb_stats['total_received']:>12}                        ║",
                f"║   LB Dispatched:      {lb_stats['total_dispatched']:>12}                        ║",
            ]

        if self._fp_manager:
            fp_stats = self._fp_manager.get_aggregated_stats()
            lines += [
                "╠══════════════════════════════════════════════════════════════╣",
                "║ FAST PATH STATISTICS                                          ║",
                f"║   FP Processed:       {fp_stats['total_processed']:>12}                        ║",
                f"║   FP Forwarded:       {fp_stats['total_forwarded']:>12}                        ║",
                f"║   FP Dropped:         {fp_stats['total_dropped']:>12}                        ║",
                f"║   Active Connections: {fp_stats['total_connections']:>12}                        ║",
            ]

        if self._rule_manager:
            r = self._rule_manager.get_stats()
            lines += [
                "╠══════════════════════════════════════════════════════════════╣",
                "║ BLOCKING RULES                                                ║",
                f"║   Blocked IPs:        {r['blocked_ips']:>12}                        ║",
                f"║   Blocked Apps:       {r['blocked_apps']:>12}                        ║",
                f"║   Blocked Domains:    {r['blocked_domains']:>12}                        ║",
                f"║   Blocked Ports:      {r['blocked_ports']:>12}                        ║",
            ]

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)

    def get_stats(self) -> DPIStats:
        return self._stats
