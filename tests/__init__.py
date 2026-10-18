# Tests package initialization
import os
import sys

# Ensure both repository root and subdirectories are in sys.path for test discovery
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
SUB_DIR = os.path.join(ROOT_DIR, "NeuralPhish")

for p in [ROOT_DIR, SUB_DIR]:
    if os.path.exists(p) and p not in sys.path:
        sys.path.insert(0, p)
