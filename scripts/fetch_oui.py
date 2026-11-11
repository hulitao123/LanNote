# -*- coding: utf-8 -*-
"""下载 MAC 厂商库并生成 data/oui.txt（打包时内置，现场可离线识别）。

依次尝试多个数据源，任一成功即可。生成格式为 "十六进制前缀\t厂商名"。
"""

from __future__ import annotations

import csv
import io
import os
import ssl
import sys
import urllib.request

SOURCES = [
    ("manuf", "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf"),
    ("manuf", "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"),
    ("manuf", "https://cdn.jsdelivr.net/gh/wireshark/wireshark@master/manuf"),
    ("ieee", "https://standards-oui.ieee.org/oui/oui.csv"),
]

TIMEOUT = 60


def _download(url: str) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(url, headers={"User-Agent": "LanNote/1.0"})
    with urllib.request.urlopen(request, timeout=TIMEOUT, context=ctx) as response:
        raw = response.read()
    return raw.decode("utf-8", errors="ignore")


def parse_manuf(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t") if "\t" in line else line.split(None, 1)
        if len(parts) < 2:
            continue
        prefix = parts[0].strip().upper().replace(":", "").replace("-", "").replace(".", "")
        name = parts[1].strip()
        if len(parts) > 2 and not name:
            name = parts[2].strip()
        if not prefix or not name:
            continue
        try:
            int(prefix, 16)
        except ValueError:
            continue
        out[prefix] = name
    return out


def parse_ieee(text: str) -> dict:
    out = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if len(row) < 3:
            continue
        prefix = row[1].strip().upper().replace(":", "").replace("-", "")
        name = row[2].strip()
        if len(prefix) != 6 or not name:
            continue
        try:
            int(prefix, 16)
        except ValueError:
            continue
        out[prefix] = name
    return out


def main() -> int:
    target = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "oui.txt")
    for kind, url in SOURCES:
        try:
            print(f"尝试 {url}", flush=True)
            text = _download(url)
            data = parse_manuf(text) if kind == "manuf" else parse_ieee(text)
            if len(data) < 1000:
                print(f"  数据过少（{len(data)} 条），换下一个源", flush=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8", newline="\n") as handle:
                for prefix in sorted(data):
                    handle.write(f"{prefix}\t{data[prefix]}\n")
            print(f"成功写入 {target}，共 {len(data)} 条", flush=True)
            return 0
        except Exception as exc:  # noqa: BLE001
            print(f"  失败：{exc}", flush=True)
    print("全部数据源均失败，将只使用内置兜底厂商表", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
