# -*- coding: utf-8 -*-
"""扫描编排。

流程：网段展开 -> 并发存活探测（ICMP + TCP）-> 读 ARP 表补 MAC
      -> 在线设备端口扫描 -> 主机名解析（NetBIOS + 反向 DNS）-> 厂商识别
"""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from . import oui, winapi

# 存活探测用：数量少、覆盖率高，任一端口通即判定在线
PROBE_PORTS: Sequence[int] = (80, 445, 135, 22, 502, 3389)

# 在线设备的端口详情扫描（不含存活探测用的 PROBE_PORTS，结果会合并展示）
FULL_PORTS: Sequence[int] = (
    21, 22, 23, 25, 53, 80, 88, 102, 110, 111, 135, 139, 143, 389, 443, 445,
    502, 515, 548, 554, 587, 631, 902, 1883, 1900, 3306, 3389, 4040, 4862,
    4863, 5094, 5432, 5900, 6379, 8080, 8443, 9100, 10000, 44818,
)

# NetBIOS NBSTAT 查询报文：向 137 端口发一次即可拿到 Windows 设备名
_NBSTAT_QUERY = (
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20"
    + b"CK" + b"AA" * 15
    + b"\x00\x00\x21\x00\x01"
)

MODES = {
    "fast": {"tcp_probe": False, "ports": False, "names": False, "timeout": 600},
    "standard": {"tcp_probe": True, "ports": True, "names": True, "timeout": 700},
    "deep": {"tcp_probe": True, "ports": True, "names": True, "timeout": 1200},
}


@dataclass
class Discovered:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    ports: str = ""
    rtt: Optional[int] = None
    online: bool = True


def parse_targets(text: str) -> List[str]:
    """把用户输入的网段文本展开成 IP 列表。

    支持：192.168.1.0/24、192.168.1（视为 /24）、192.168.1.10-192.168.1.50、
          单个 IP，多个目标用逗号、空格、分号或换行分隔。
    """
    ips: List[str] = []
    seen = set()
    for token in re.split(r"[,\s;]+", (text or "").strip()):
        if not token:
            continue
        try:
            if "-" in token and "/" not in token:
                start_raw, end_raw = token.split("-", 1)
                start = ipaddress.IPv4Address(start_raw)
                if re.fullmatch(r"\d{1,3}", end_raw):
                    end = ipaddress.IPv4Address(
                        ".".join(start_raw.split(".")[:3] + [end_raw])
                    )
                else:
                    end = ipaddress.IPv4Address(end_raw)
                if int(end) < int(start):
                    start, end = end, start
                candidates = [
                    str(ipaddress.IPv4Address(addr))
                    for addr in range(int(start), int(end) + 1)
                ]
            else:
                if "/" not in token:
                    parts = token.split(".")
                    if len(parts) == 3:
                        token = token + ".0/24"
                    elif len(parts) == 4:
                        token = token + "/32"
                network = ipaddress.ip_network(token, strict=False)
                candidates = [str(host) for host in network.hosts()]
                if not candidates:  # /32 或 /31
                    candidates = [str(addr) for addr in network]
        except ValueError:
            continue
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                ips.append(candidate)
    return ips


def suggest_subnets() -> List[str]:
    """根据本机网卡自动推荐网段。"""
    suggestions = []
    for ip, mask in winapi.get_local_ipv4():
        try:
            network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except ValueError:
            continue
        if network.prefixlen >= 30:
            continue
        text = str(network)
        if text not in suggestions:
            suggestions.append(text)
    return suggestions


# 网卡描述里出现这些关键词，视为虚拟网卡
VIRTUAL_KEYWORDS = (
    "vmware", "virtualbox", "hyper-v", "vethernet", "tap-", "virtual",
    "loopback", "qemu", "parallels",
)


def list_adapters() -> List[Dict]:
    """本机网卡明细：ip / mask / 子网 / 描述 / 是否虚拟。"""
    adapters = []
    for ip, mask, desc, _if_type in winapi.get_adapters():
        try:
            network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            subnet = str(network)
        except ValueError:
            subnet = ""
        lowered = desc.lower()
        adapters.append(
            {
                "ip": ip,
                "mask": mask,
                "subnet": subnet,
                "desc": desc,
                "virtual": any(word in lowered for word in VIRTUAL_KEYWORDS),
            }
        )
    return adapters


def analyze_targets(targets_text: str) -> Dict:
    """扫描前分析：目标 IP 与本机网卡的直连情况、虚拟网卡撞车提醒。"""
    ips = parse_targets(targets_text)
    adapters = list_adapters()
    networks = []
    for adapter in adapters:
        if not adapter["subnet"]:
            continue
        networks.append((ipaddress.ip_network(adapter["subnet"]), adapter))
    direct = 0
    for ip in ips:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if any(addr in network for network, _ in networks):
            direct += 1
    virtual_match = []
    for network, adapter in networks:
        if not adapter["virtual"] or not ips:
            continue
        if all(ipaddress.IPv4Address(ip) in network for ip in ips):
            virtual_match.append(adapter)
    return {
        "total": len(ips),
        "direct": direct,
        "adapters": adapters,
        "virtual_match": virtual_match,
    }


def _nbstat(ip: str, timeout: float = 0.4) -> str:
    """通过 UDP 137 端口的 NBSTAT 查询取 NetBIOS 设备名。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(_NBSTAT_QUERY, (ip, 137))
        data, _ = sock.recvfrom(2048)
    except OSError:
        return ""
    finally:
        sock.close()

    # DNS 头 12 字节 + 问题段 38 字节 = 附加记录起始于 50
    offset = 50
    if len(data) < offset + 12:
        return ""
    try:
        rdlength = struct.unpack(">H", data[offset + 8: offset + 10])[0]
    except struct.error:
        return ""
    rdata = data[offset + 12: offset + 12 + rdlength]
    if len(rdata) < 19:
        return ""
    count = rdata[0]
    best = ""
    for index in range(count):
        chunk = rdata[1 + index * 18: 1 + (index + 1) * 18]
        if len(chunk) < 16:
            break
        name = chunk[:15].decode("ascii", "ignore").strip()
        name_type = chunk[15]
        if not name:
            continue
        # 0x00 工作站名，0x20 服务器服务名
        if name_type == 0x20:
            return name
        if name_type == 0x00 and not best:
            best = name
    return best


def _reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except OSError:
        return ""
    return "" if not host or host == ip else host


class Scanner:
    def __init__(
        self,
        progress: Optional[Callable[[int, int, str], None]] = None,
        cancel: Optional[threading.Event] = None,
    ) -> None:
        self.progress = progress or (lambda done, total, text: None)
        self.cancel = cancel or threading.Event()

    # ------------------------------------------------------------------ 内部

    def _report(self, done: int, total: int, text: str) -> None:
        self.progress(done, total, text)

    def _probe_alive(self, ip: str, tcp_probe: bool, timeout_ms: int) -> Optional[int]:
        """返回 RTT(ms) 表示 ICMP 通；0 表示 TCP 通但 ICMP 不通；None 表示离线。"""
        rtt = winapi.icmp_ping(ip, timeout_ms)
        if rtt is not None:
            return rtt
        if not tcp_probe:
            return None
        tcp_timeout = max(0.15, timeout_ms / 1000.0)
        for port in PROBE_PORTS:
            if self.cancel.is_set():
                return None
            if winapi.tcp_connect(ip, port, tcp_timeout):
                return 0
        return None

    def _scan_ports(self, ips: Sequence[str], concurrency: int, timeout_ms: int) -> Dict[str, List[int]]:
        result: Dict[str, List[int]] = {ip: [] for ip in ips}
        if not ips:
            return result
        tcp_timeout = max(0.15, timeout_ms / 1000.0)
        jobs = [(ip, port) for ip in ips for port in FULL_PORTS]
        done = 0
        total = len(jobs)
        with ThreadPoolExecutor(max_workers=min(concurrency, max(8, len(jobs)))) as pool:
            futures = {
                pool.submit(winapi.tcp_connect, ip, port, tcp_timeout): (ip, port)
                for ip, port in jobs
            }
            for future in as_completed(futures):
                if self.cancel.is_set():
                    break
                ip, port = futures[future]
                done += 1
                try:
                    if future.result():
                        result[ip].append(port)
                except Exception:  # noqa: BLE001
                    pass
                if done % 40 == 0:
                    self._report(done, total, f"端口扫描 {done}/{total}")
        for ip in result:
            result[ip].sort()
        self._report(total, total, "端口扫描完成")
        return result

    def _resolve_names(self, ips: Sequence[str], concurrency: int = 64) -> Dict[str, str]:
        result: Dict[str, str] = {}
        total = len(ips)
        done = 0
        with ThreadPoolExecutor(max_workers=min(concurrency, max(4, total))) as pool:
            futures = {pool.submit(self._resolve_one, ip): ip for ip in ips}
            for future in as_completed(futures):
                if self.cancel.is_set():
                    break
                ip = futures[future]
                done += 1
                try:
                    result[ip] = future.result()
                except Exception:  # noqa: BLE001
                    result[ip] = ""
                self._report(done, total, f"解析主机名 {done}/{total}")
        return result

    @staticmethod
    def _resolve_one(ip: str) -> str:
        return _nbstat(ip) or _reverse_dns(ip)

    # ------------------------------------------------------------------ 主流程

    def scan(
        self,
        targets: str,
        mode: str = "standard",
        concurrency: int = 256,
        timeout_ms: Optional[int] = None,
    ) -> List[Discovered]:
        config = MODES.get(mode, MODES["standard"])
        if timeout_ms is None:
            timeout_ms = config["timeout"]

        ips = parse_targets(targets)
        total = len(ips)
        if not total:
            return []

        started = time.time()

        # 阶段 1：并发存活探测。发包本身会触发系统的 ARP 解析
        alive: Dict[str, Optional[int]] = {}
        done = 0
        with ThreadPoolExecutor(max_workers=min(concurrency, max(8, total))) as pool:
            futures = {
                pool.submit(self._probe_alive, ip, config["tcp_probe"], timeout_ms): ip
                for ip in ips
            }
            for future in as_completed(futures):
                if self.cancel.is_set():
                    break
                ip = futures[future]
                done += 1
                try:
                    rtt = future.result()
                except Exception:  # noqa: BLE001
                    rtt = None
                if rtt is not None:
                    alive[ip] = rtt
                if done % 16 == 0 or done == total:
                    self._report(done, total, f"存活探测 {done}/{total}，已发现 {len(alive)} 台")

        if self.cancel.is_set() and not alive:
            return []

        # 阶段 2：读 ARP 表，拿到 IP -> MAC
        self._report(total, total, "读取 ARP 表")
        arp_table = winapi.get_arp_table()

        online_ips = sorted(alive, key=lambda value: ipaddress.IPv4Address(value))

        # ARP 表里有记录但探测没回应的设备，也视为在线（可能被防火墙挡了探测包）
        target_set = set(ips)
        for ip, mac in arp_table.items():
            if ip in target_set and ip not in alive and mac:
                alive[ip] = None
        online_ips = sorted(alive, key=lambda value: ipaddress.IPv4Address(value))

        ports_map: Dict[str, List[int]] = {}
        if config["ports"] and online_ips:
            ports_map = self._scan_ports(online_ips, concurrency, min(timeout_ms, 400))

        names: Dict[str, str] = {}
        if config["names"] and online_ips:
            names = self._resolve_names(online_ips)

        devices: List[Discovered] = []
        for ip in online_ips:
            mac = arp_table.get(ip, "")
            ports = ports_map.get(ip, [])
            devices.append(
                Discovered(
                    ip=ip,
                    mac=mac,
                    hostname=names.get(ip, ""),
                    vendor=oui.lookup_vendor(mac),
                    ports=", ".join(str(port) for port in ports),
                    rtt=alive.get(ip),
                )
            )

        elapsed = time.time() - started
        self._report(
            total,
            total,
            f"完成：{len(devices)} 台在线，用时 {elapsed:.1f} 秒",
        )
        return devices
