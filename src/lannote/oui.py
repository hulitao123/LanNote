# -*- coding: utf-8 -*-
"""MAC 厂商（OUI）离线识别。

数据文件为纯文本，每行 "十六进制前缀\t厂商名"，前缀长度 6/8/10 位十六进制字符，
查询时按最长前缀匹配。文件随 exe 一起打包，现场断网也能识别。
"""

from __future__ import annotations

import os
import sys
from typing import Dict, Optional

# 数据文件里查不到时才用到的兜底条目，只收录高置信度前缀
_FALLBACK: Dict[str, str] = {
    "000C29": "VMware",
    "005056": "VMware",
    "000569": "VMware",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
}

_PREFIX_LENGTHS = (10, 8, 6)


def _candidate_paths() -> list:
    """依次查找：exe 同目录、PyInstaller 临时目录、源码目录。"""
    found = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        found.append(os.path.join(meipass, "data", "oui.txt"))
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else None
    if base:
        found.append(os.path.join(base, "data", "oui.txt"))
        found.append(os.path.join(base, "oui.txt"))
    here = os.path.dirname(os.path.abspath(__file__))
    found.append(os.path.join(here, "..", "..", "data", "oui.txt"))
    return found


class OuiDb:
    def __init__(self) -> None:
        self._map: Dict[str, str] = {}
        self.loaded = False
        self.source = ""

    def load(self) -> bool:
        if self.loaded:
            return bool(self._map)
        self.loaded = True
        for path in _candidate_paths():
            path = os.path.normpath(path)
            if not os.path.isfile(path):
                continue
            try:
                count = 0
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    for line in handle:
                        if "\t" not in line:
                            continue
                        prefix, vendor = line.rstrip("\r\n").split("\t", 1)
                        prefix = prefix.strip().upper().replace(":", "").replace("-", "")
                        vendor = vendor.strip()
                        if not prefix or not vendor:
                            continue
                        self._map[prefix] = vendor
                        count += 1
                if count:
                    self.source = path
                    return True
            except OSError:
                continue
        return False

    def lookup(self, mac: Optional[str]) -> str:
        if not mac:
            return ""
        self.load()
        hexstr = mac.replace(":", "").replace("-", "").replace(".", "").upper()
        if len(hexstr) < 6:
            return ""
        for length in _PREFIX_LENGTHS:
            if len(hexstr) < length:
                continue
            vendor = self._map.get(hexstr[:length])
            if vendor:
                return vendor
        return _FALLBACK.get(hexstr[:6], "")

    @property
    def size(self) -> int:
        return len(self._map)


_db = OuiDb()


def lookup_vendor(mac: Optional[str]) -> str:
    return _db.lookup(mac)


def db_size() -> int:
    _db.load()
    return _db.size
