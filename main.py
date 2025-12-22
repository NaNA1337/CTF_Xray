#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CTF-XRay 主程序入口
CTF专用AI辅助分析工具
"""

import sys
from PySide6.QtWidgets import QApplication
from ctf_gui import CTFXRayMainWindow

def main():
    app = QApplication(sys.argv)
    window = CTFXRayMainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()