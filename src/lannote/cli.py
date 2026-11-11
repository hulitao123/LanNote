# -*- coding: utf-8 -*-
"""命令行入口，用于验证扫描内核。正式使用请运行打包后的 exe。"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Optional, Sequence

from . import oui, scanner, winapi


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="LanNote 局域网扫描（命令行验证用）")
    parser.add_argument("targets", nargs="?", default="", help="网段，例如 192.168.1.0/24")
    parser.add_argument("--mode", choices=sorted(scanner.MODES), default="standard")
    parser.add_argument("--concurrency", type=int, default=256)
    parser.add_argument("--timeout", type=int, default=0, help="超时(毫秒)，0 表示用模式默认值")
    parser.add_argument("--list-subnets", action="store_true", help="只列出本机网段建议")
    parser.add_argument("--adapters", action="store_true", help="列出本机网卡明细")
    args = parser.parse_args(argv)

    if args.adapters:
        for adapter in scanner.list_adapters():
            mark = " [虚拟]" if adapter["virtual"] else ""
            print(f"{adapter['ip']:<16} {adapter['mask']:<16} {adapter['subnet']:<20} {adapter['desc']}{mark}")
        return 0

    if args.list_subnets:
        for item in scanner.suggest_subnets():
            print(item)
        return 0

    print(f"本机网卡：{winapi.get_local_ipv4()}")
    targets = args.targets or ",".join(scanner.suggest_subnets())
    ips = scanner.parse_targets(targets)
    print(f"目标网段：{targets}（{len(ips)} 个地址）")
    if not ips:
        print("没有可扫描的地址，请手动指定网段")
        return 1

    last = [""]

    def report(done: int, total: int, text: str) -> None:
        if text != last[0]:
            last[0] = text
            print(f"\r  {text:<70}", end="", flush=True)

    engine = scanner.Scanner(progress=report)
    started = time.time()
    devices = engine.scan(
        targets,
        mode=args.mode,
        concurrency=args.concurrency,
        timeout_ms=args.timeout or None,
    )
    print("\r" + " " * 78 + "\r", end="")

    print(f"{'IP':<16}{'MAC':<20}{'厂商':<28}{'主机名':<22}开放端口")
    print("-" * 110)
    for device in devices:
        print(
            f"{device.ip:<16}{device.mac or '-':<20}{(device.vendor or '-')[:26]:<28}"
            f"{(device.hostname or '-')[:20]:<22}{device.ports}"
        )
    print("-" * 110)
    print(
        f"共 {len(devices)} 台在线，用时 {time.time() - started:.1f} 秒，"
        f"OUI 库 {oui.db_size()} 条"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
