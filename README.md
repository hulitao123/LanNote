# LanNote · 现场 IP 扫描台账

一个小巧的 Windows 局域网扫描工具：扫出网段内所有在线设备的 **IP、MAC 地址、厂商、主机名、开放端口**，并支持给每台设备 **绑定备注**，备注长期保存在本地台账里——下次再来扫，认得每一台设备。

参考 [trickdaddy24/LanScan](https://github.com/trickdaddy24/LanScan) 的思路重写为 Windows 桌面单文件版。

## 下载

直接下载编译好的单文件程序（无需安装 Python）：

**https://github.com/hulitao123/LanNote/releases/latest**

## 特点

- **免管理员权限、免 Npcap/WinPcap 驱动**：直接调用 Windows 系统 API（`GetIpNetTable2` 读 ARP 表、`icmp.dll` 发 ICMP），双击就能用
- **持久台账**：设备以 MAC 地址为唯一身份，改 IP 换 DHCP 都不丢备注；取不到 MAC 时自动按 IP 记录
- **离线识别厂商**：内置约 4 万条 OUI 厂商库，现场断网也能认出 Siemens、华为、海康等
- **单文件绿色版**：一个 exe，放 U 盘即插即用；台账 `LanNote.db` 就在 exe 旁边，拷走即备份
- **三种扫描模式**：快速（纯 ICMP，秒级）/ 标准（ICMP + TCP 探测 + 端口 + 主机名，默认）/ 深度（更长超时，适合网络状况差的现场）

## 使用

1. 双击 `LanNote.exe`，网段已自动识别（也可手改，如 `192.168.1.0/24`、`192.168.1`、`10.1.1.10-50`，多网段用逗号分隔）
2. 点 **开始扫描**，结果实时显示进度
3. **双击"备注"列**给设备写备注（如"车间发酵罐 A"），自动保存
4. 顶部筛选框可按 IP/MAC/厂商/备注过滤；"仅在线""未备注"一键筛选
5. **导出 CSV**（带 BOM，Excel 直接打开不乱码）；文件菜单里还能从旧 CSV 回填备注

### 命令行模式（可选）

```
LanNote.exe --cli 192.168.1.0/24 --mode standard
```

## 文件说明

| 文件 | 作用 |
|---|---|
| `LanNote.exe` | 主程序 |
| `LanNote.db` | 设备台账（SQLite），删掉即重置 |
| `LanNote.json` | 记住上次网段、模式、并发设置 |

> 若 exe 所在目录不可写（如 Program Files），数据自动改存 `%APPDATA%\LanNote\`。

## 现场提示

- 个别杀毒软件可能对未签名的 PyInstaller exe 报警，添加信任即可
- 扫描只发常规探测包（ICMP + 少量 TCP 连接），对网络无破坏性，但请遵守现场管理规定
- 设备禁 ping 且禁常见端口时，只要它在 ARP 表里（和你在同一网段且近期活跃）仍会被列出

## 从源码构建

```bash
python -m venv .venv
.venv\Scripts\activate
pip install pyinstaller
python scripts/fetch_oui.py        # 更新厂商库（可选）
pyinstaller --onefile --noconsole --name LanNote --paths src ^
  --add-data "data/oui.txt;data" launch.py
```

## 源码结构

```
src/lannote/
  winapi.py    Windows API 封装（网段识别 / ARP 表 / ICMP / TCP 探测）
  scanner.py   扫描编排（网段展开、存活探测、主机名解析）
  oui.py       MAC 厂商离线识别
  store.py     SQLite 台账（按 MAC 绑定备注、CSV 导入导出）
  ui.py        tkinter 界面
  cli.py       命令行验证入口
scripts/fetch_oui.py   下载并转换 IEEE/Wireshark 厂商库
```
