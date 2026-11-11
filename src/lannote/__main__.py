# -*- coding: utf-8 -*-
"""模块入口：python -m lannote"""

import sys

from .ui import run

if __name__ == "__main__":
    sys.exit(run() or 0)
