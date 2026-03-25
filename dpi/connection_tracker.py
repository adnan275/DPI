import time
from typing import Callable, Dict, List, Optional

from .types import (
    AppType, Connection, ConnectionState, FiveTuple, PacketAction,
    app_type_to_string,
)


class ConnectionTracker:
    def __init__(self, fp_id: int, max_connections: int = 65536):
        self._fp_id = fp_id
        self._max_connections = max_connections
        self._connections: Dict[FiveTuple, Connection] = {}
        self._total_seen = 0
        self._classified_count = 0
        self._blocked_count = 0

    def get_or_create_connection(self, tuple_: FiveTuple) -> Connection:
        conn = self._connections.get(tuple_)
        if conn is not None:
            return conn

        if len(self._connections) >= self._max_connections:
            self._evict_oldest()

        now = time.monotonic()
        conn = Connection(tuple=tuple_, first_seen=now, last_seen=now)
        self._connections[tuple_] = conn
        self._total_seen += 1
        return conn

    def get_connection(self, tuple_: FiveTuple) -> Optional[Connection]:
        conn = self._connections.get(tuple_)
        if conn is not None:
            return conn
        return self._connections.get(tuple_.reverse())

    def update_connection(self, conn: Connection, packet_size: int, is_outbound: bool):
        conn.last_seen = time.monotonic()
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out += packet_size
        else:
            conn.packets_in += 1
            conn.bytes_in += packet_size

    def classify_connection(self, conn: Connection, app: AppType, sni: str):
        if conn.state != ConnectionState.CLASSIFIED:
            conn.app_type = app
            conn.sni = sni
            conn.state = ConnectionState.CLASSIFIED
            self._classified_count += 1

    def block_connection(self, conn: Connection):
        conn.state = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self._blocked_count += 1

    def close_connection(self, tuple_: FiveTuple):
        conn = self._connections.get(tuple_)
        if conn:
            conn.state = ConnectionState.CLOSED

    def cleanup_stale(self, timeout_seconds: float) -> int:
        now = time.monotonic()
        to_remove = [
            t for t, c in self._connections.items()
            if (now - c.last_seen) > timeout_seconds or c.state == ConnectionState.CLOSED
        ]
        for t in to_remove:
            del self._connections[t]
        return len(to_remove)

    def get_all_connections(self) -> List[Connection]:
        return list(self._connections.values())

    def get_active_count(self) -> int:
        return len(self._connections)

    def get_stats(self) -> dict:
        return {
            "active_connections": len(self._connections),
            "total_connections_seen": self._total_seen,
            "classified_connections": self._classified_count,
            "blocked_connections": self._blocked_count,
        }

    def clear(self):
        self._connections.clear()

    def for_each(self, callback: Callable[[Connection], None]):
        for conn in self._connections.values():
            callback(conn)

    def _evict_oldest(self):
        if not self._connections:
            return
        oldest_key = min(self._connections, key=lambda t: self._connections[t].last_seen)
        del self._connections[oldest_key]


class GlobalConnectionTable:
    def __init__(self, num_fps: int):
        self._trackers: List[Optional[ConnectionTracker]] = [None] * num_fps

    def register_tracker(self, fp_id: int, tracker: ConnectionTracker):
        if fp_id < len(self._trackers):
            self._trackers[fp_id] = tracker

    def get_global_stats(self) -> dict:
        total_active = 0
        total_seen = 0
        app_distribution: Dict[AppType, int] = {}
        domain_counts: Dict[str, int] = {}

        for tracker in self._trackers:
            if tracker is None:
                continue
            stats = tracker.get_stats()
            total_active += stats["active_connections"]
            total_seen += stats["total_connections_seen"]

            def collect(conn: Connection):
                app_distribution[conn.app_type] = app_distribution.get(conn.app_type, 0) + 1
                if conn.sni:
                    domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

            tracker.for_each(collect)

        sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        return {
            "total_active_connections": total_active,
            "total_connections_seen": total_seen,
            "app_distribution": app_distribution,
            "top_domains": sorted_domains,
        }

    def generate_report(self) -> str:
        stats = self.get_global_stats()
        lines = [
            "\n╔══════════════════════════════════════════════════════════════╗",
            "║               CONNECTION STATISTICS REPORT                    ║",
            "╠══════════════════════════════════════════════════════════════╣",
            f"║ Active Connections:     {stats['total_active_connections']:>10}                          ║",
            f"║ Total Connections Seen: {stats['total_connections_seen']:>10}                          ║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║                    APPLICATION BREAKDOWN                      ║",
            "╠══════════════════════════════════════════════════════════════╣",
        ]

        dist = stats["app_distribution"]
        total = sum(dist.values())
        sorted_apps = sorted(dist.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = (100.0 * count / total) if total > 0 else 0.0
            name = app_type_to_string(app)
            lines.append(f"║ {name:<20}{count:>10} ({pct:5.1f}%)           ║")

        if stats["top_domains"]:
            lines += [
                "╠══════════════════════════════════════════════════════════════╣",
                "║                      TOP DOMAINS                             ║",
                "╠══════════════════════════════════════════════════════════════╣",
            ]
            for domain, count in stats["top_domains"]:
                if len(domain) > 35:
                    domain = domain[:32] + "..."
                lines.append(f"║ {domain:<40}{count:>10}           ║")

        lines.append("╚══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)
