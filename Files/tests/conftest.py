import os
import sys

# 让 tests/ 下的用例直接 import 上层的 converters / health / scrip
FILES_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if FILES_DIR not in sys.path:
    sys.path.insert(0, FILES_DIR)
