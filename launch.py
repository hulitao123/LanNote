# -*- coding: utf-8 -*-
"""LanNote 启动脚本（源码运行与 PyInstaller 打包共用入口）。"""

import os
import sys

if not getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from lannote import cli
from lannote.ui import run

if __name__ == "__main__":
    if "--cli" in sys.argv:
        args = [item for item in sys.argv[1:] if item != "--cli"]
        sys.exit(cli.main(args))
    run()
