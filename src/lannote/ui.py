# -*- coding: utf-8 -*-
"""LanNote 图形界面。"""

from __future__ import annotations

import ctypes
import json
import os
import queue
import threading
import tkinter as tk
import ipaddress
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Dict, List, Optional

from . import oui, scanner, store
from .scanner import Discovered, Scanner
from .store import Device, Store

COLUMNS = ("status", "ip", "mac", "vendor", "hostname", "ports", "note")
HEADERS = {
    "status": "状态",
    "ip": "IP 地址",
    "mac": "MAC 地址",
    "vendor": "厂商",
    "hostname": "主机名",
    "ports": "开放端口",
    "note": "备注（双击编辑）",
}
WIDTHS = {
    "status": 52,
    "ip": 110,
    "mac": 148,
    "vendor": 148,
    "hostname": 150,
    "ports": 150,
    "note": 240,
}

FONT = ("Microsoft YaHei UI", 9)


def config_path() -> str:
    return os.path.join(os.path.dirname(store.default_db_path()), "LanNote.json")


def load_config() -> dict:
    try:
        with open(config_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(data: dict) -> None:
    try:
        with open(config_path(), "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
    except OSError:
        pass


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("LanNote · 现场 IP 扫描台账")
        root.geometry("1100x660")
        root.minsize(860, 480)

        self.store = Store()
        self.devices: List[Device] = []
        self.iid_to_key: Dict[str, str] = {}
        self.sort_col = "ip"
        self.sort_desc = False
        self.scanning = False
        self.cancel_event = threading.Event()
        self.msg_queue: queue.Queue = queue.Queue()
        self.scan_thread: Optional[threading.Thread] = None

        config = load_config()
        self._build_menu()
        self._build_toolbar(config)
        self._build_filterbar()
        self._build_table()
        self._build_statusbar()

        self.filter_text.trace_add("write", lambda *_: self.populate())
        self.only_online.trace_add("write", lambda *_: self.populate())
        self.only_unnoted.trace_add("write", lambda *_: self.populate())
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.reload_from_store()
        self.root.after(120, self._poll)

    # ------------------------------------------------------------------ 布局

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="导出 CSV…", command=self.export_csv)
        file_menu.add_command(label="导入备注（CSV）…", command=self.import_notes)
        file_menu.add_separator()
        file_menu.add_command(label="清空台账…", command=self.clear_all)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.on_close)
        menubar.add_cascade(label="文件", menu=file_menu)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)
        self.root.config(menu=menubar)

    def _build_toolbar(self, config: dict) -> None:
        bar = ttk.Frame(self.root, padding=(10, 8, 10, 4))
        bar.pack(fill="x")

        ttk.Label(bar, text="扫描网段：").pack(side="left")
        self.target_var = tk.StringVar(
            value=config.get("last_targets") or ", ".join(scanner.suggest_subnets())
        )
        combo = ttk.Combobox(bar, textvariable=self.target_var, width=32, font=FONT)
        subnets = scanner.suggest_subnets()
        combo["values"] = subnets + [value for value in (config.get("history") or []) if value not in subnets]
        combo.pack(side="left", padx=(2, 10))

        ttk.Label(bar, text="模式：").pack(side="left")
        self.mode_var = tk.StringVar(value=config.get("last_mode") or "标准")
        mode_box = ttk.Combobox(
            bar, textvariable=self.mode_var, width=8, state="readonly",
            values=("快速", "标准", "深度"),
        )
        mode_box.pack(side="left", padx=(2, 10))

        ttk.Label(bar, text="并发：").pack(side="left")
        self.conc_var = tk.StringVar(value=str(config.get("concurrency", 256)))
        ttk.Combobox(
            bar, textvariable=self.conc_var, width=6, state="readonly",
            values=("64", "128", "256", "512"),
        ).pack(side="left", padx=(2, 12))

        self.scan_button = ttk.Button(bar, text="开始扫描", command=self.start_scan)
        self.scan_button.pack(side="left")

        ttk.Button(bar, text="本机网卡", command=self.show_adapters).pack(
            side="left", padx=(8, 0)
        )

        self.progress = ttk.Progressbar(bar, mode="determinate", length=180)
        self.progress.pack(side="left", padx=(12, 0), fill="x", expand=True)

        self.progress_text = tk.StringVar(value="就绪")
        ttk.Label(bar, textvariable=self.progress_text, width=34, anchor="e").pack(
            side="left", padx=(8, 0)
        )

    def _build_filterbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(10, 2, 10, 6))
        bar.pack(fill="x")

        ttk.Label(bar, text="筛选：").pack(side="left")
        self.filter_text = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.filter_text, width=34, font=FONT)
        entry.pack(side="left", padx=(2, 12))
        entry.insert(0, "")
        entry.bind("<Escape>", lambda *_: self.filter_text.set(""))

        self.only_online = tk.BooleanVar(value=False)
        self.only_unnoted = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="仅在线", variable=self.only_online).pack(side="left", padx=(0, 8))
        ttk.Checkbutton(bar, text="未备注", variable=self.only_unnoted).pack(side="left", padx=(0, 12))

        ttk.Button(bar, text="导出 CSV", command=self.export_csv).pack(side="right")
        ttk.Button(bar, text="刷新", command=self.reload_from_store).pack(side="right", padx=(0, 8))

    def _build_table(self) -> None:
        frame = ttk.Frame(self.root, padding=(10, 0, 10, 0))
        frame.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(frame, columns=COLUMNS, show="headings", selectmode="extended")
        for col in COLUMNS:
            self.tree.heading(
                col,
                text=HEADERS[col],
                command=lambda c=col: self.sort_by(c),
            )
            anchor = "center" if col == "status" else "w"
            stretch = col in ("note", "hostname", "vendor")
            self.tree.column(col, width=WIDTHS[col], anchor=anchor, stretch=stretch)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        style = ttk.Style(self.root)
        style.configure("Treeview", rowheight=26, font=FONT)
        style.configure("Treeview.Heading", font=(FONT[0], 9, "bold"))
        self.tree.tag_configure("online", foreground="#1a7f37")
        self.tree.tag_configure("offline", foreground="#9a9a9a")

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self.on_right_click)
        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="编辑备注…", command=self.edit_selected_note)
        self.menu.add_command(label="复制 IP", command=lambda: self.copy_selected("ip"))
        self.menu.add_command(label="复制 MAC", command=lambda: self.copy_selected("mac"))
        self.menu.add_command(label="复制备注", command=lambda: self.copy_selected("note"))
        self.menu.add_separator()
        self.menu.add_command(label="删除该记录…", command=self.delete_selected)

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(10, 4, 10, 8))
        bar.pack(fill="x")
        self.status_var = tk.StringVar()
        ttk.Label(bar, textvariable=self.status_var, font=FONT).pack(side="left")

    # ------------------------------------------------------------------ 数据

    def reload_from_store(self) -> None:
        self.devices = self.store.all_devices()
        self.populate()

    def visible_devices(self) -> List[Device]:
        text = self.filter_text.get().strip().lower()
        result = []
        for device in self.devices:
            if self.only_online.get() and not device.online:
                continue
            if self.only_unnoted.get() and not device.note.strip():
                continue
            if text:
                haystack = f"{device.ip} {device.mac} {device.vendor} {device.hostname} {device.note}".lower()
                if text not in haystack:
                    continue
            result.append(device)
        return result

    @staticmethod
    def _ip_sort_key(device: Device):
        try:
            return (0, int(ipaddress.IPv4Address(device.ip or "0.0.0.0")))
        except ValueError:
            return (1, device.ip)

    def sort_by(self, col: str) -> None:
        if self.sort_col == col:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_col = col
            self.sort_desc = False
        reverse = self.sort_desc
        if col == "ip":
            self.devices.sort(key=self._ip_sort_key, reverse=reverse)
        else:
            getter = {
                "status": lambda d: d.online,
                "mac": lambda d: d.mac,
                "vendor": lambda d: d.vendor,
                "hostname": lambda d: d.hostname.lower(),
                "ports": lambda d: d.ports,
                "note": lambda d: d.note.lower(),
            }.get(col, lambda d: "")
            self.devices.sort(key=getter, reverse=reverse)
        for heading_col in COLUMNS:
            base = HEADERS[heading_col]
            self.tree.heading(heading_col, text=("↓ " if (heading_col == col and self.sort_desc)
                                                 else "↑ " if heading_col == col else "") + base)
        self.populate()

    def populate(self) -> None:
        selected = {self.iid_to_key.get(item) for item in self.tree.selection()}
        self.tree.delete(*self.tree.get_children())
        self.iid_to_key.clear()
        for device in self.visible_devices():
            values = (
                "在线" if device.online else "离线",
                device.ip,
                device.mac or "—",
                device.vendor or "",
                device.hostname or "",
                device.ports or "",
                device.note or "",
            )
            iid = self.tree.insert("", "end", values=values,
                                   tags=("online" if device.online else "offline",))
            self.iid_to_key[iid] = device.key
        restore = [item for item, key in self.iid_to_key.items() if key in selected]
        if restore:
            self.tree.selection_set(restore)
        self.update_status()

    def update_status(self) -> None:
        total = len(self.devices)
        online = sum(1 for device in self.devices if device.online)
        unnoted = sum(1 for device in self.devices if device.online and not device.note.strip())
        self.status_var.set(
            f"台账共 {total} 台 · 在线 {online} 台 · 未备注 {unnoted} 台    "
            f"OUI 厂商库 {oui.db_size()} 条    数据文件：{self.store.path}"
        )

    # ------------------------------------------------------------------ 扫描

    def confirm_targets(self, targets: str) -> bool:
        """扫描前防呆：目标网段与本机网卡的直连情况、虚拟网卡撞车提醒。"""
        try:
            info = scanner.analyze_targets(targets)
        except Exception:  # noqa: BLE001 - 分析失败绝不阻塞扫描
            return True
        if not info["total"]:
            return True
        subnets = ", ".join(
            f"{adapter['subnet'] or adapter['ip']}"
            + ("（虚拟）" if adapter["virtual"] else "")
            for adapter in info["adapters"]
        )
        if info["direct"] == 0:
            return messagebox.askyesno(
                "网段不直连",
                "本机没有任何网卡与目标网段直连，扫描包将经网关转发：\n"
                "· 多数设备可能扫不到\n· 拿不到 MAC 地址\n\n"
                f"本机网卡网段：{subnets}\n\n仍要继续扫描吗？",
            )
        if info["virtual_match"]:
            names = "\n".join(
                f"· {adapter['ip']}  {adapter['desc']}" for adapter in info["virtual_match"]
            )
            return messagebox.askyesno(
                "虚拟网卡同网段",
                "目标网段与本机虚拟网卡同网段：\n"
                f"{names}\n\n"
                "如果你要扫的是现场网络，请确认网段没有输错"
                "（虚拟网卡可能抢先收包导致扫到的是虚拟网络）。\n\n仍要继续吗？",
            )
        return True

    def show_adapters(self) -> None:
        adapters = scanner.list_adapters()
        if not adapters:
            messagebox.showinfo("本机网卡", "未读取到本机 IPv4 网卡信息。")
            return
        lines = []
        for adapter in adapters:
            mark = "［虚拟网卡］" if adapter["virtual"] else ""
            subnet = adapter["subnet"] or "未知网段"
            lines.append(
                f"IP {adapter['ip']}\n掩码 {adapter['mask']} · 网段 {subnet}\n"
                f"{adapter['desc'] or '未知网卡'} {mark}"
            )
        messagebox.showinfo(
            "本机网卡",
            "\n\n".join(lines) + "\n\n提示：扫描网段应与某块网卡的网段一致，"
            "否则设备 MAC 取不到。",
        )

    def start_scan(self) -> None:
        if self.scanning:
            self.cancel_event.set()
            self.progress_text.set("正在停止…")
            self.scan_button.config(text="开始扫描")
            return
        targets = self.target_var.get().strip()
        ips = scanner.parse_targets(targets)
        if not ips:
            messagebox.showwarning(
                "网段无效",
                "无法识别扫描目标。\n示例：192.168.1.0/24 或 192.168.1 或 192.168.1.10-50\n"
                "多个网段用逗号或空格分隔。",
            )
            return
        if len(ips) > 4096 and not messagebox.askyesno(
            "目标较大", f"共 {len(ips)} 个地址，扫描可能耗时较长，继续吗？"
        ):
            return
        if not self.confirm_targets(targets):
            return

        mode_name = {"快速": "fast", "标准": "standard", "深度": "deep"}.get(
            self.mode_var.get(), "standard"
        )
        try:
            concurrency = max(16, min(1024, int(self.conc_var.get())))
        except ValueError:
            concurrency = 256

        self._remember_targets(targets)
        self.scanning = True
        self.cancel_event = threading.Event()
        self.scan_button.config(text="停止")
        self.progress.config(mode="determinate", value=0, maximum=len(ips))
        self.progress_text.set("准备扫描…")

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(targets, mode_name, concurrency),
            daemon=True,
        )
        self.scan_thread.start()

    def _remember_targets(self, targets: str) -> None:
        config = load_config()
        history = [targets] + [value for value in (config.get("history") or []) if value != targets]
        config["history"] = history[:8]
        config["last_targets"] = targets
        config["last_mode"] = self.mode_var.get()
        config["concurrency"] = self.conc_var.get()
        save_config(config)

    def _scan_worker(self, targets: str, mode: str, concurrency: int) -> None:
        def progress(done: int, total: int, text: str) -> None:
            self.msg_queue.put(("progress", (done, total, text)))

        engine = Scanner(progress=progress, cancel=self.cancel_event)
        try:
            found = engine.scan(targets, mode=mode, concurrency=concurrency)
            if not self.cancel_event.is_set():
                keys = self.store.upsert_scan(found)
                self.store.mark_offline_except(keys)
                self.msg_queue.put(("done", len(found)))
            else:
                self.msg_queue.put(("cancelled", None))
        except Exception as exc:  # noqa: BLE001
            self.msg_queue.put(("error", str(exc)))

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "progress":
                    done, total, text = payload
                    if total:
                        self.progress.config(maximum=total, value=min(done, total))
                    self.progress_text.set(text)
                elif kind == "done":
                    self._finish_scan(f"扫描完成，发现 {payload} 台在线设备")
                elif kind == "cancelled":
                    self._finish_scan("扫描已停止")
                elif kind == "error":
                    self._finish_scan(f"扫描出错：{payload}")
                    messagebox.showerror("扫描出错", payload)
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _finish_scan(self, text: str) -> None:
        self.scanning = False
        self.scan_button.config(text="开始扫描")
        self.progress_text.set(text)
        self.reload_from_store()

    # ------------------------------------------------------------------ 编辑

    def selected_device(self) -> Optional[Device]:
        selection = self.tree.selection()
        if not selection:
            return None
        key = self.iid_to_key.get(selection[0])
        if not key:
            return None
        for device in self.devices:
            if device.key == key:
                return device
        return None

    def on_double_click(self, event) -> None:
        if self.tree.identify_region(event.x, event.y) != "cell":
            return
        if self.tree.identify_column(event.x) == f"#{COLUMNS.index('note') + 1}":
            self.edit_selected_note()

    def on_right_click(self, event) -> None:
        item = self.tree.identify_row(event.y)
        if item:
            if item not in self.tree.selection():
                self.tree.selection_set(item)
            self.menu.tk_popup(event.x_root, event.y_root)

    def edit_selected_note(self) -> None:
        device = self.selected_device()
        if not device:
            return
        title = f"备注 · {device.ip}"
        if device.mac:
            title += f"（{device.mac}）"
        note = simpledialog.askstring(
            title,
            f"设备：{device.vendor or device.hostname or '未知设备'}\n输入备注：",
            initialvalue=device.note,
            parent=self.root,
        )
        if note is None:
            return
        note = note.strip()
        self.store.set_note(device.key, note)
        device.note = note
        self.populate()

    def copy_selected(self, field: str) -> None:
        device = self.selected_device()
        if not device:
            return
        value = {"ip": device.ip, "mac": device.mac, "note": device.note}.get(field, "")
        if value:
            self.root.clipboard_clear()
            self.root.clipboard_append(value)

    def delete_selected(self) -> None:
        device = self.selected_device()
        if not device:
            return
        if not messagebox.askyesno("删除记录", f"确定从台账中删除 {device.ip} 的记录吗？"):
            return
        self.store.delete(device.key)
        self.reload_from_store()

    # ------------------------------------------------------------------ 文件

    def export_csv(self) -> None:
        devices = self.visible_devices()
        if not devices:
            messagebox.showinfo("导出", "当前没有可导出的行。")
            return
        path = filedialog.asksaveasfilename(
            title="导出扫描结果",
            defaultextension=".csv",
            filetypes=(("CSV 文件", "*.csv"), ("所有文件", "*.*")),
            initialfile=f"LanNote_{__import__('datetime').datetime.now():%Y%m%d_%H%M}.csv",
        )
        if not path:
            return
        try:
            count = self.store.export_csv(path, devices)
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        messagebox.showinfo("导出完成", f"已导出 {count} 行到：\n{path}")

    def import_notes(self) -> None:
        path = filedialog.askopenfilename(
            title="导入备注（按 MAC 或 IP 匹配回填）",
            filetypes=(("CSV 文件", "*.csv"), ("所有文件", "*.*")),
        )
        if not path:
            return
        try:
            count = self.store.import_notes_from_csv(path)
        except (OSError, KeyError) as exc:
            messagebox.showerror("导入失败", str(exc))
            return
        self.reload_from_store()
        messagebox.showinfo("导入完成", f"成功回填 {count} 条备注。")

    def clear_all(self) -> None:
        if messagebox.askyesno(
            "清空台账", "将删除所有设备记录与备注（不可恢复），确定吗？"
        ):
            self.store.clear_all()
            self.reload_from_store()

    def show_about(self) -> None:
        messagebox.showinfo(
            "关于 LanNote",
            "LanNote v1.0\n现场局域网 IP / MAC 扫描与备注台账\n\n"
            "免管理员权限 · 免 Npcap 驱动 · 数据存于本机 SQLite\n"
            "扫描原理：并发探测 → 读取系统 ARP 表 → 按 MAC 绑定备注",
        )

    def on_close(self) -> None:
        self.cancel_event.set()
        self.store.close()
        self.root.destroy()


def run() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001
        pass
    root = tk.Tk()
    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except tk.TclError:
        pass
    App(root)
    root.mainloop()
