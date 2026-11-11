# -*- coding: utf-8 -*-
"""Windows 原生网络 API 封装。

全部通过 ctypes 直接调用系统 DLL，不依赖 Npcap/WinPcap，也不需要管理员权限。
    GetIpAddrTable  -> 读取本机网卡 IP 与子网掩码，用于自动识别网段
    GetIpNetTable2  -> 读取 ARP 邻居表，拿到 IP -> MAC 映射（主力方案）
    arp -a          -> 兜底方案，API 不可用时解析命令输出
    IcmpSendEcho    -> 发送 ICMP 回显请求，走 icmp.dll，不需要 raw socket
"""

from __future__ import annotations

import ctypes
import re
import socket
import struct
import subprocess
import threading
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple

AF_INET = 2
ERROR_NOT_FOUND = 1168
ERROR_BUFFER_OVERFLOW = 111

# NL_NEIGHBOR_STATE 中代表"确实学到了 MAC 地址"的状态
NUD_PROBE = 2
NUD_DELAY = 3
NUD_STALE = 4
NUD_REACHABLE = 5
NUD_PERMANENT = 6
GOOD_ARP_STATES = {NUD_PROBE, NUD_DELAY, NUD_STALE, NUD_REACHABLE, NUD_PERMANENT}

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)


def dword_to_ip(value: int) -> str:
    """系统 API 返回的 DWORD 在内存中本就是网络字节序，按小端解包即可还原。"""
    return socket.inet_ntoa(struct.pack("<I", value & 0xFFFFFFFF))


def ip_to_dword(ip: str) -> int:
    return struct.unpack("<I", socket.inet_aton(ip))[0]


# --------------------------------------------------------------- 本机网卡 ----


class MIB_IPADDRROW(ctypes.Structure):
    _fields_ = [
        ("dwAddr", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("dwMask", wintypes.DWORD),
        ("dwBCastAddr", wintypes.DWORD),
        ("dwReasmSize", wintypes.DWORD),
        ("unused1", wintypes.WORD),
        ("wType", wintypes.WORD),
    ]


class MIB_IPADDRTABLE(ctypes.Structure):
    _fields_ = [("dwNumEntries", wintypes.DWORD), ("table", MIB_IPADDRROW * 1)]


iphlpapi.GetIpAddrTable.argtypes = [
    ctypes.POINTER(MIB_IPADDRTABLE),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
]
iphlpapi.GetIpAddrTable.restype = wintypes.DWORD


def get_local_ipv4() -> List[Tuple[str, str]]:
    """返回 [(ip, mask), ...]，已剔除回环地址和未配置地址。"""
    size = wintypes.DWORD(0)
    iphlpapi.GetIpAddrTable(None, ctypes.byref(size), True)
    if size.value == 0:
        return []
    buf = ctypes.create_string_buffer(size.value)
    ptr = ctypes.cast(buf, ctypes.POINTER(MIB_IPADDRTABLE))
    if iphlpapi.GetIpAddrTable(ptr, ctypes.byref(size), True) != 0:
        return []
    count = ptr.contents.dwNumEntries
    if count <= 0:
        return []
    rows = (MIB_IPADDRROW * count).from_buffer(buf, 4)
    result = []
    for row in rows:
        ip = dword_to_ip(row.dwAddr)
        mask = dword_to_ip(row.dwMask)
        if ip.startswith("127.") or ip == "0.0.0.0" or mask == "0.0.0.0":
            continue
        result.append((ip, mask))
    return result


# ----------------------------------------------------------------- ARP 表 ----


class MIB_IPNET_ROW2(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_ubyte * 28),  # SOCKADDR_INET
        ("InterfaceIndex", wintypes.DWORD),
        ("InterfaceLuid", ctypes.c_uint64),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PhysicalAddressLength", wintypes.DWORD),
        ("State", ctypes.c_int32),
        ("Flags", wintypes.DWORD),
        ("ReachabilityTime", wintypes.DWORD),
    ]


class MIB_IPNET_TABLE2(ctypes.Structure):
    _fields_ = [("NumEntries", wintypes.DWORD), ("Table", MIB_IPNET_ROW2 * 1)]


iphlpapi.GetIpNetTable2.argtypes = [wintypes.USHORT, ctypes.POINTER(ctypes.c_void_p)]
iphlpapi.GetIpNetTable2.restype = wintypes.DWORD
iphlpapi.FreeMibTable.argtypes = [ctypes.c_void_p]


def _arp_via_api() -> Dict[str, str]:
    ptr = ctypes.c_void_p(0)
    ret = iphlpapi.GetIpNetTable2(AF_INET, ctypes.byref(ptr))
    if ret not in (0, ERROR_NOT_FOUND) or not ptr.value:
        return {}
    result: Dict[str, str] = {}
    try:
        head = ctypes.cast(ptr, ctypes.POINTER(MIB_IPNET_TABLE2)).contents
        count = head.NumEntries
        if count <= 0:
            return {}
        # Table 数组紧跟在 NumEntries 之后，因行结构按 8 字节对齐，偏移量为 8
        rows = ctypes.cast(ctypes.byref(head, 8), ctypes.POINTER(MIB_IPNET_ROW2 * count)).contents
        for row in rows:
            if row.State not in GOOD_ARP_STATES or row.PhysicalAddressLength < 6:
                continue
            mac_bytes = bytes(row.PhysicalAddress[:6])
            if mac_bytes in (b"\x00\x00\x00\x00\x00\x00", b"\xff\xff\xff\xff\xff\xff"):
                continue
            if mac_bytes[0] & 0x01:  # 组播/广播不是真实设备
                continue
            result[socket.inet_ntoa(bytes(row.Address[4:8]))] = ":".join(
                f"{b:02X}" for b in mac_bytes
            )
    finally:
        iphlpapi.FreeMibTable(ptr)
    return result


_ARP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2})\s+(\S+)"
)


def _arp_via_command() -> Dict[str, str]:
    try:
        cp = subprocess.run(
            ["arp", "-a"], capture_output=True, timeout=20, creationflags=_NO_WINDOW
        )
        raw = cp.stdout
        text = raw.decode("utf-8", "ignore") or raw.decode("mbcs", "ignore")
    except Exception:
        return {}
    result = {}
    for ip, mac, kind in _ARP_RE.findall(text):
        if "无效" in kind or "invalid" in kind.lower():
            continue
        mac = mac.replace("-", ":").upper()
        if mac == "FF:FF:FF:FF:FF:FF":
            continue
        result[ip] = mac
    return result


def get_arp_table() -> Dict[str, str]:
    """返回 {ip: MAC}。先走系统 API，拿不到再解析 arp -a，两者结果合并。"""
    table = _arp_via_api()
    if not table:
        table = _arp_via_command()
    else:
        for ip, mac in _arp_via_command().items():
            table.setdefault(ip, mac)
    return table


# ------------------------------------------------------------------- ICMP ----


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", wintypes.DWORD),
        ("Status", wintypes.DWORD),
        ("RoundTripTime", wintypes.DWORD),
        ("DataSize", wintypes.WORD),
        ("Reserved", wintypes.WORD),
        ("Data", ctypes.c_void_p),
        ("Options", ctypes.c_ubyte * 16),
    ]


try:
    _icmp = ctypes.WinDLL("icmp", use_last_error=True)
except OSError:  # pragma: no cover - 极老系统可能没有 icmp.dll
    _icmp = None

_icmp_available = _icmp is not None
_icmp_local = threading.local()

if _icmp is not None:
    _icmp.IcmpCreateFile.argtypes = []
    _icmp.IcmpCreateFile.restype = wintypes.HANDLE
    _icmp.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    _icmp.IcmpCloseHandle.restype = wintypes.BOOL
    _icmp.IcmpSendEcho.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_char_p,
        wintypes.WORD,
        ctypes.c_void_p,
        ctypes.c_char_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _icmp.IcmpSendEcho.restype = wintypes.DWORD


def _icmp_handle():
    """每个线程独立持有句柄，避免多线程争用同一个 IcmpHandle。"""
    handle = getattr(_icmp_local, "handle", None)
    if handle is None and _icmp is not None:
        handle = _icmp.IcmpCreateFile()
        _icmp_local.handle = handle
    return handle


def _ping_via_command(ip: str, timeout_ms: int) -> Optional[int]:
    try:
        cp = subprocess.run(
            ["ping", "-n", "1", "-w", str(max(200, timeout_ms)), ip],
            capture_output=True,
            timeout=max(2, timeout_ms / 1000 + 3),
            creationflags=_NO_WINDOW,
        )
        text = cp.stdout.decode("mbcs", "ignore")
    except Exception:
        return None
    if "ttl=" not in text.lower():
        return None
    match = re.search(r"(?:时间|time)[=<]\s*(\d+)\s*ms", text, re.I)
    return int(match.group(1)) if match else 1


def icmp_ping(ip: str, timeout_ms: int = 800) -> Optional[int]:
    """返回往返耗时(ms)，不通返回 None。"""
    global _icmp_available
    if _icmp_available and _icmp is not None:
        handle = _icmp_handle()
        if handle and int(handle) != -1:
            payload = b"lannote"
            reply = ctypes.create_string_buffer(
                ctypes.sizeof(ICMP_ECHO_REPLY) + len(payload) + 16
            )
            sent = _icmp.IcmpSendEcho(
                handle,
                ip_to_dword(ip),
                payload,
                len(payload),
                None,
                reply,
                ctypes.sizeof(reply),
                timeout_ms,
            )
            if sent > 0:
                echo = ctypes.cast(reply, ctypes.POINTER(ICMP_ECHO_REPLY)).contents
                if echo.Status == 0:
                    return int(echo.RoundTripTime)
            return None
        _icmp_available = False
    return _ping_via_command(ip, timeout_ms)


# ------------------------------------------------------------- TCP 探测 ----


def tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return False
    try:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- 网卡信息 ----


class IP_ADDRESS_STRING(ctypes.Structure):
    _fields_ = [("buffer", ctypes.c_char * 16)]


class IP_ADDR_STRING(ctypes.Structure):
    _fields_ = [
        ("Next", ctypes.c_void_p),
        ("IpAddress", IP_ADDRESS_STRING),
        ("IpMask", IP_ADDRESS_STRING),
        ("Context", wintypes.DWORD),
    ]


class IP_ADAPTER_INFO(ctypes.Structure):
    _fields_ = [
        ("Next", ctypes.c_void_p),
        ("ComboIndex", wintypes.DWORD),
        ("AdapterName", ctypes.c_char * 260),
        ("Description", ctypes.c_char * 132),
        ("AddressLength", wintypes.DWORD),
        ("Address", ctypes.c_ubyte * 8),
        ("Index", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("DhcpEnabled", wintypes.DWORD),
        ("CurrentIpAddress", ctypes.c_void_p),
        ("IpAddressList", IP_ADDR_STRING),
        ("GatewayList", IP_ADDR_STRING),
        ("DhcpServer", IP_ADDR_STRING),
        ("HaveWins", wintypes.BOOL),
        ("LeaseObtained", ctypes.c_uint64),
        ("LeaseExpires", ctypes.c_uint64),
        ("PrimaryWinsServer", IP_ADDR_STRING),
        ("SecondaryWinsServer", IP_ADDR_STRING),
    ]


iphlpapi.GetAdaptersInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG)]
iphlpapi.GetAdaptersInfo.restype = wintypes.DWORD


def get_adapters() -> List[Tuple[str, str, str, int]]:
    """返回 [(ip, mask, 网卡描述, 接口类型), ...]，异常时退化为纯地址表。"""
    fallback = [(ip, mask, "", 0) for ip, mask in get_local_ipv4()]
    try:
        size = wintypes.ULONG(0)
        # 第一次调用预期返回 ERROR_BUFFER_OVERFLOW(111) 并带出所需缓冲区大小
        ret = iphlpapi.GetAdaptersInfo(None, ctypes.byref(size))
        if ret not in (0, ERROR_BUFFER_OVERFLOW) or size.value == 0:
            return fallback
        buf = ctypes.create_string_buffer(size.value)
        if iphlpapi.GetAdaptersInfo(buf, ctypes.byref(size)) != 0:
            return fallback
        result = []
        node = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO))
        while node:
            info = node.contents
            description = info.Description.decode("mbcs", "ignore")
            addr_node = info.IpAddressList
            while True:
                ip = addr_node.IpAddress.buffer.decode("ascii", "ignore")
                mask = addr_node.IpMask.buffer.decode("ascii", "ignore")
                if ip and ip not in ("0.0.0.0", "127.0.0.1"):
                    result.append((ip, mask, description, info.Type))
                if not addr_node.Next:
                    break
                addr_node = ctypes.cast(
                    addr_node.Next, ctypes.POINTER(IP_ADDR_STRING)
                ).contents
            if not info.Next:
                break
            node = ctypes.cast(info.Next, ctypes.POINTER(IP_ADAPTER_INFO))
        return result if result else fallback
    except Exception:  # noqa: BLE001 - 结构异常时绝不能影响主流程
        return fallback
