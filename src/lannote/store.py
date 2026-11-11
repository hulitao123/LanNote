# -*- coding: utf-8 -*-
"""设备台账持久化。

SQLite 单文件，设备以 MAC 地址作为唯一身份：路由器重新分配 IP 后，
备注、自定义内容依然跟着这台设备走。取不到 MAC 时（跨网段等）降级按 IP 记。
"""

from __future__ import annotations

import csv
import os
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    key         TEXT PRIMARY KEY,
    mac         TEXT DEFAULT '',
    ip          TEXT DEFAULT '',
    hostname    TEXT DEFAULT '',
    vendor      TEXT DEFAULT '',
    ports       TEXT DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    first_seen  TEXT DEFAULT '',
    last_seen   TEXT DEFAULT '',
    last_online TEXT DEFAULT '',
    online      INTEGER NOT NULL DEFAULT 0,
    rtt         INTEGER,
    seen_count  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_online ON devices(online);
"""

COLUMNS = (
    "key", "mac", "ip", "hostname", "vendor", "ports", "note",
    "first_seen", "last_seen", "last_online", "online", "rtt", "seen_count",
)

CSV_HEADER = ("状态", "IP 地址", "MAC 地址", "厂商", "主机名", "开放端口", "备注", "首次发现", "最后在线")


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _writable(directory: str) -> bool:
    try:
        with tempfile.NamedTemporaryFile("w", dir=directory, delete=True):
            return True
    except OSError:
        return False


def default_db_path() -> str:
    """优先放在程序所在目录（U 盘随身带），不可写时退回用户配置目录。"""
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
    if _writable(base):
        return os.path.join(base, "LanNote.db")
    fallback = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "LanNote")
    os.makedirs(fallback, exist_ok=True)
    return os.path.join(fallback, "LanNote.db")


@dataclass
class Device:
    key: str
    mac: str = ""
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    ports: str = ""
    note: str = ""
    first_seen: str = ""
    last_seen: str = ""
    last_online: str = ""
    online: int = 0
    rtt: Optional[int] = None
    seen_count: int = 0

    @property
    def display_name(self) -> str:
        return self.note or self.hostname or self.vendor or self.ip

    @staticmethod
    def make_key(mac: str, ip: str) -> str:
        return (mac or "").upper().replace("-", ":") or f"ip:{ip}"


class Store:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or default_db_path()
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------------ 查询

    def all_devices(self) -> List[Device]:
        rows = self.conn.execute(
            "SELECT * FROM devices ORDER BY online DESC, "
            "CAST((substr(ip,1,instr(ip,'.')-1)) AS INTEGER)*16777216 + "
            "CAST(substr(ip, instr(ip,'.')+1) AS INTEGER)"
        ).fetchall()
        return [self._row_to_device(row) for row in rows]

    def get(self, key: str) -> Optional[Device]:
        row = self.conn.execute("SELECT * FROM devices WHERE key=?", (key,)).fetchone()
        return self._row_to_device(row) if row else None

    @staticmethod
    def _row_to_device(row: sqlite3.Row) -> Device:
        return Device(
            key=row["key"],
            mac=row["mac"] or "",
            ip=row["ip"] or "",
            hostname=row["hostname"] or "",
            vendor=row["vendor"] or "",
            ports=row["ports"] or "",
            note=row["note"] or "",
            first_seen=row["first_seen"] or "",
            last_seen=row["last_seen"] or "",
            last_online=row["last_online"] or "",
            online=int(row["online"] or 0),
            rtt=row["rtt"],
            seen_count=int(row["seen_count"] or 0),
        )

    # ------------------------------------------------------------------ 写入

    def upsert_scan(self, devices: Iterable) -> List[str]:
        """合并一次扫描结果：刷新发现字段，保留用户备注。返回本次命中的 key 列表。"""
        now = now_text()
        keys: List[str] = []
        for item in devices:
            key = Device.make_key(getattr(item, "mac", ""), getattr(item, "ip", ""))
            keys.append(key)
            existing = self.get(key)
            self.conn.execute(
                """
                INSERT INTO devices (key, mac, ip, hostname, vendor, ports, note,
                                     first_seen, last_seen, last_online, online, rtt, seen_count)
                VALUES (?,?,?,?,?,?,'',?,?,?,1,?,1)
                ON CONFLICT(key) DO UPDATE SET
                    ip=excluded.ip,
                    hostname=excluded.hostname,
                    vendor=excluded.vendor,
                    ports=excluded.ports,
                    last_seen=excluded.last_seen,
                    last_online=excluded.last_online,
                    online=1,
                    rtt=excluded.rtt,
                    seen_count=devices.seen_count+1
                """,
                (
                    key,
                    (getattr(item, "mac", "") or "").upper(),
                    getattr(item, "ip", ""),
                    getattr(item, "hostname", "") or "",
                    getattr(item, "vendor", "") or "",
                    getattr(item, "ports", "") or "",
                    now if not existing else (existing.first_seen or now),
                    now,
                    now,
                    getattr(item, "rtt", None),
                ),
            )
        self.conn.commit()
        return keys

    def mark_offline_except(self, keys: Iterable[str]) -> None:
        keep = list(keys)
        if keep:
            placeholders = ",".join("?" * len(keep))
            self.conn.execute(
                f"UPDATE devices SET online=0 WHERE key NOT IN ({placeholders})", keep
            )
        else:
            self.conn.execute("UPDATE devices SET online=0")
        self.conn.commit()

    def set_note(self, key: str, note: str) -> None:
        self.conn.execute("UPDATE devices SET note=? WHERE key=?", (note or "", key))
        self.conn.commit()

    def delete(self, key: str) -> None:
        self.conn.execute("DELETE FROM devices WHERE key=?", (key,))
        self.conn.commit()

    def clear_all(self) -> None:
        self.conn.execute("DELETE FROM devices")
        self.conn.commit()

    # ------------------------------------------------------------------ 导出

    def export_csv(self, path: str, devices: Iterable[Device]) -> int:
        count = 0
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(CSV_HEADER)
            for device in devices:
                writer.writerow(
                    [
                        "在线" if device.online else "离线",
                        device.ip,
                        device.mac,
                        device.vendor,
                        device.hostname,
                        device.ports,
                        device.note,
                        device.first_seen,
                        device.last_online,
                    ]
                )
                count += 1
        return count

    def import_notes_from_csv(self, path: str) -> int:
        """按 MAC 或 IP 回填备注，用于台账迁移。"""
        updated = 0
        with open(path, "r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                mac = (row.get("MAC 地址") or "").strip().upper()
                ip = (row.get("IP 地址") or "").strip()
                note = (row.get("备注") or "").strip()
                if not note:
                    continue
                key = Device.make_key(mac, ip)
                if self.get(key):
                    self.set_note(key, note)
                    updated += 1
        return updated
