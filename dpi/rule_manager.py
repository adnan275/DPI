import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from .types import AppType, app_type_to_string


@dataclass
class BlockReason:
    reason_type: str = ""
    detail: str = ""


class RuleManager:
    def __init__(self):
        self._blocked_ips: Set[int] = set()
        self._blocked_apps: Set[AppType] = set()
        self._blocked_domains: Set[str] = set()
        self._domain_patterns: List[str] = []
        self._blocked_ports: Set[int] = set()

        self._ip_lock = threading.Lock()
        self._app_lock = threading.Lock()
        self._domain_lock = threading.Lock()
        self._port_lock = threading.Lock()

    @staticmethod
    def _parse_ip(ip: str) -> int:
        result = 0
        shift = 0
        for octet_str in ip.split("."):
            result |= int(octet_str) << shift
            shift += 8
        return result

    @staticmethod
    def _ip_to_string(ip: int) -> str:
        return ".".join(str((ip >> s) & 0xFF) for s in [0, 8, 16, 24])

    def block_ip(self, ip):
        if isinstance(ip, str):
            ip = self._parse_ip(ip)
        with self._ip_lock:
            self._blocked_ips.add(ip)
        print(f"[RuleManager] Blocked IP: {self._ip_to_string(ip)}")

    def unblock_ip(self, ip):
        if isinstance(ip, str):
            ip = self._parse_ip(ip)
        with self._ip_lock:
            self._blocked_ips.discard(ip)
        print(f"[RuleManager] Unblocked IP: {self._ip_to_string(ip)}")

    def is_ip_blocked(self, ip: int) -> bool:
        with self._ip_lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self) -> List[str]:
        with self._ip_lock:
            return [self._ip_to_string(ip) for ip in self._blocked_ips]

    def block_app(self, app: AppType):
        with self._app_lock:
            self._blocked_apps.add(app)
        print(f"[RuleManager] Blocked app: {app_type_to_string(app)}")

    def unblock_app(self, app: AppType):
        with self._app_lock:
            self._blocked_apps.discard(app)
        print(f"[RuleManager] Unblocked app: {app_type_to_string(app)}")

    def is_app_blocked(self, app: AppType) -> bool:
        with self._app_lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> List[AppType]:
        with self._app_lock:
            return list(self._blocked_apps)

    def block_domain(self, domain: str):
        with self._domain_lock:
            if "*" in domain:
                self._domain_patterns.append(domain)
            else:
                self._blocked_domains.add(domain)
        print(f"[RuleManager] Blocked domain: {domain}")

    def unblock_domain(self, domain: str):
        with self._domain_lock:
            if "*" in domain:
                if domain in self._domain_patterns:
                    self._domain_patterns.remove(domain)
            else:
                self._blocked_domains.discard(domain)
        print(f"[RuleManager] Unblocked domain: {domain}")

    @staticmethod
    def _domain_matches_pattern(domain: str, pattern: str) -> bool:
        if len(pattern) >= 2 and pattern[0] == "*" and pattern[1] == ".":
            suffix = pattern[1:]
            if domain.endswith(suffix):
                return True
            if domain == pattern[2:]:
                return True
        return False

    def is_domain_blocked(self, domain: str) -> bool:
        lower = domain.lower()
        with self._domain_lock:
            if lower in self._blocked_domains:
                return True
            for pattern in self._domain_patterns:
                if self._domain_matches_pattern(lower, pattern.lower()):
                    return True
        return False

    def get_blocked_domains(self) -> List[str]:
        with self._domain_lock:
            return list(self._blocked_domains) + list(self._domain_patterns)

    def block_port(self, port: int):
        with self._port_lock:
            self._blocked_ports.add(port)
        print(f"[RuleManager] Blocked port: {port}")

    def unblock_port(self, port: int):
        with self._port_lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._port_lock:
            return port in self._blocked_ports

    def should_block(self, src_ip: int, dst_port: int, app: AppType, domain: str) -> Optional[BlockReason]:
        if self.is_ip_blocked(src_ip):
            return BlockReason("IP", self._ip_to_string(src_ip))
        if self.is_port_blocked(dst_port):
            return BlockReason("PORT", str(dst_port))
        if self.is_app_blocked(app):
            return BlockReason("APP", app_type_to_string(app))
        if domain and self.is_domain_blocked(domain):
            return BlockReason("DOMAIN", domain)
        return None

    def save_rules(self, filename: str) -> bool:
        try:
            with open(filename, "w") as f:
                f.write("[BLOCKED_IPS]\n")
                for ip in self.get_blocked_ips():
                    f.write(ip + "\n")
                f.write("\n[BLOCKED_APPS]\n")
                for app in self.get_blocked_apps():
                    f.write(app_type_to_string(app) + "\n")
                f.write("\n[BLOCKED_DOMAINS]\n")
                for domain in self.get_blocked_domains():
                    f.write(domain + "\n")
                f.write("\n[BLOCKED_PORTS]\n")
                with self._port_lock:
                    for port in self._blocked_ports:
                        f.write(str(port) + "\n")
            print(f"[RuleManager] Rules saved to: {filename}")
            return True
        except OSError:
            return False

    def load_rules(self, filename: str) -> bool:
        try:
            with open(filename) as f:
                section = ""
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("["):
                        section = line
                        continue
                    if section == "[BLOCKED_IPS]":
                        self.block_ip(line)
                    elif section == "[BLOCKED_APPS]":
                        for app in AppType:
                            if app_type_to_string(app) == line:
                                self.block_app(app)
                                break
                    elif section == "[BLOCKED_DOMAINS]":
                        self.block_domain(line)
                    elif section == "[BLOCKED_PORTS]":
                        self.block_port(int(line))
            print(f"[RuleManager] Rules loaded from: {filename}")
            return True
        except OSError:
            return False

    def clear_all(self):
        with self._ip_lock:
            self._blocked_ips.clear()
        with self._app_lock:
            self._blocked_apps.clear()
        with self._domain_lock:
            self._blocked_domains.clear()
            self._domain_patterns.clear()
        with self._port_lock:
            self._blocked_ports.clear()
        print("[RuleManager] All rules cleared")

    def get_stats(self) -> dict:
        with self._domain_lock:
            domains = len(self._blocked_domains) + len(self._domain_patterns)
        return {
            "blocked_ips": len(self._blocked_ips),
            "blocked_apps": len(self._blocked_apps),
            "blocked_domains": domains,
            "blocked_ports": len(self._blocked_ports),
        }
