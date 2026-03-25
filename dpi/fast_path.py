import queue
import threading
from typing import Callable, Dict, List, Optional

from .types import (
    AppType, Connection, ConnectionState, PacketAction, PacketJob,
    app_type_to_string, sni_to_app_type,
)
from .connection_tracker import ConnectionTracker
from .rule_manager import RuleManager
from .sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor

PacketOutputCallback = Callable[[PacketJob, PacketAction], None]


class FastPathProcessor:
    def __init__(self, fp_id: int, rule_manager: Optional[RuleManager],
                 output_callback: Optional[PacketOutputCallback]):
        self._fp_id = fp_id
        self._input_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.conn_tracker = ConnectionTracker(fp_id)
        self._rule_manager = rule_manager
        self._output_callback = output_callback
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packets_processed = 0
        self._packets_forwarded = 0
        self._packets_dropped = 0
        self._sni_extractions = 0
        self._classification_hits = 0

    def start(self):
        if self._running:
            return
        self._running = True
        t = threading.Thread(target=self._run, daemon=True)
        self._thread = t
        t.start()
        print(f"[FP{self._fp_id}] Started")

    def stop(self):
        if not self._running:
            return
        self._running = False
        self._input_queue.put(None)
        t = self._thread
        if t is not None and t.is_alive():
            t.join()
        print(f"[FP{self._fp_id}] Stopped (processed {self._packets_processed} packets)")

    def get_input_queue(self) -> queue.Queue:
        return self._input_queue

    def get_connection_tracker(self) -> ConnectionTracker:
        return self.conn_tracker

    def _run(self):
        while self._running:
            try:
                job = self._input_queue.get(timeout=0.1)
            except queue.Empty:
                self.conn_tracker.cleanup_stale(300)
                continue

            if job is None:
                break

            self._packets_processed += 1
            action = self._process_packet(job)

            if self._output_callback:
                self._output_callback(job, action)

            if action == PacketAction.DROP:
                self._packets_dropped += 1
            else:
                self._packets_forwarded += 1

    def _process_packet(self, job: PacketJob) -> PacketAction:
        conn = self.conn_tracker.get_or_create_connection(job.tuple)

        self.conn_tracker.update_connection(conn, len(job.data), True)

        if job.tuple.protocol == 6:
            self._update_tcp_state(conn, job.tcp_flags)

        if conn.state == ConnectionState.BLOCKED:
            return PacketAction.DROP

        if conn.state != ConnectionState.CLASSIFIED and job.payload_length > 0:
            self._inspect_payload(job, conn)

        return self._check_rules(job, conn)

    def _inspect_payload(self, job: PacketJob, conn: Connection):
        if job.payload_length == 0 or job.payload_offset >= len(job.data):
            return

        payload = job.data[job.payload_offset: job.payload_offset + job.payload_length]

        if self._try_extract_sni(job, conn, payload):
            return
        if self._try_extract_http_host(job, conn, payload):
            return

        if job.tuple.dst_port == 53 or job.tuple.src_port == 53:
            domain = DNSExtractor.extract_query(payload, len(payload))
            if domain:
                self.conn_tracker.classify_connection(conn, AppType.DNS, domain)
                return

        if job.tuple.dst_port == 80:
            self.conn_tracker.classify_connection(conn, AppType.HTTP, "")
        elif job.tuple.dst_port == 443:
            self.conn_tracker.classify_connection(conn, AppType.HTTPS, "")

    def _try_extract_sni(self, job: PacketJob, conn: Connection, payload: bytes) -> bool:
        if job.tuple.dst_port != 443 and job.payload_length < 50:
            return False
        sni = SNIExtractor.extract(payload, len(payload))
        if sni:
            self._sni_extractions += 1
            app = sni_to_app_type(sni)
            self.conn_tracker.classify_connection(conn, app, sni)
            if app not in (AppType.UNKNOWN, AppType.HTTPS):
                self._classification_hits += 1
            return True
        return False

    def _try_extract_http_host(self, job: PacketJob, conn: Connection, payload: bytes) -> bool:
        if job.tuple.dst_port != 80:
            return False
        host = HTTPHostExtractor.extract(payload, len(payload))
        if host:
            app = sni_to_app_type(host)
            self.conn_tracker.classify_connection(conn, app, host)
            if app not in (AppType.UNKNOWN, AppType.HTTP):
                self._classification_hits += 1
            return True
        return False

    def _check_rules(self, job: PacketJob, conn: Connection) -> PacketAction:
        if not self._rule_manager:
            return PacketAction.FORWARD

        reason = self._rule_manager.should_block(
            job.tuple.src_ip,
            job.tuple.dst_port,
            conn.app_type,
            conn.sni,
        )

        if reason:
            print(f"[FP{self._fp_id}] BLOCKED packet: {reason.reason_type} {reason.detail}")
            self.conn_tracker.block_connection(conn)
            return PacketAction.DROP

        return PacketAction.FORWARD

    def _update_tcp_state(self, conn: Connection, tcp_flags: int):
        SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04

        if tcp_flags & SYN:
            if tcp_flags & ACK:
                conn.syn_ack_seen = True
            else:
                conn.syn_seen = True

        if conn.syn_seen and conn.syn_ack_seen and (tcp_flags & ACK):
            if conn.state == ConnectionState.NEW:
                conn.state = ConnectionState.ESTABLISHED

        if tcp_flags & FIN:
            conn.fin_seen = True
        if tcp_flags & RST:
            conn.state = ConnectionState.CLOSED
        if conn.fin_seen and (tcp_flags & ACK):
            conn.state = ConnectionState.CLOSED

    def get_stats(self) -> dict:
        return {
            "packets_processed": self._packets_processed,
            "packets_forwarded": self._packets_forwarded,
            "packets_dropped": self._packets_dropped,
            "connections_tracked": self.conn_tracker.get_active_count(),
            "sni_extractions": self._sni_extractions,
            "classification_hits": self._classification_hits,
        }


class FPManager:
    def __init__(self, num_fps: int, rule_manager: Optional[RuleManager],
                 output_callback: Optional[PacketOutputCallback]):
        self._fps: List[FastPathProcessor] = [
            FastPathProcessor(i, rule_manager, output_callback) for i in range(num_fps)
        ]
        print(f"[FPManager] Created {num_fps} fast path processors")

    def start_all(self):
        for fp in self._fps:
            fp.start()

    def stop_all(self):
        for fp in self._fps:
            fp.stop()

    def get_fp(self, index: int) -> FastPathProcessor:
        return self._fps[index]

    def get_queue_ptrs(self) -> List[queue.Queue]:
        return [fp.get_input_queue() for fp in self._fps]

    def get_aggregated_stats(self) -> dict:
        totals = {"total_processed": 0, "total_forwarded": 0, "total_dropped": 0, "total_connections": 0}
        for fp in self._fps:
            s = fp.get_stats()
            totals["total_processed"] += s["packets_processed"]
            totals["total_forwarded"] += s["packets_forwarded"]
            totals["total_dropped"] += s["packets_dropped"]
            totals["total_connections"] += s["connections_tracked"]
        return totals

    def generate_classification_report(self) -> str:
        app_counts: Dict[AppType, int] = {}
        domain_counts: Dict[str, int] = {}
        total_classified: int = 0
        total_unknown: int = 0

        for fp in self._fps:
            for conn in fp.get_connection_tracker().get_all_connections():
                app: AppType = conn.app_type
                app_counts[app] = app_counts.get(app, 0) + 1
                if conn.sni:
                    domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

        for app, count in app_counts.items():
            c: int = count
            if app == AppType.UNKNOWN:
                total_unknown += c
            else:
                total_classified += c

        total: int = total_classified + total_unknown
        classified_pct = (100.0 * total_classified / total) if total > 0 else 0.0
        unknown_pct = (100.0 * total_unknown / total) if total > 0 else 0.0

        lines = [
            "\n╔══════════════════════════════════════════════════════════════╗",
            "║                 APPLICATION CLASSIFICATION REPORT             ║",
            "╠══════════════════════════════════════════════════════════════╣",
            f"║ Total Connections:    {total:>10}                           ║",
            f"║ Classified:           {total_classified:>10} ({classified_pct:.1f}%)                  ║",
            f"║ Unidentified:         {total_unknown:>10} ({unknown_pct:.1f}%)                  ║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║                    APPLICATION DISTRIBUTION                   ║",
            "╠══════════════════════════════════════════════════════════════╣",
        ]

        for app, count in sorted(app_counts.items(), key=lambda x: x[1], reverse=True):
            pct = (100.0 * count / total) if total > 0 else 0.0
            bar = "#" * min(int(pct / 5), 20)
            name = app_type_to_string(app)
            lines.append(f"║ {name:<15}{count:>8} {pct:5.1f}% {bar:<20}   ║")

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)
