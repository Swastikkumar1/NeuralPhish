# Tests package initialization
import os
import sys

# Ensure NeuralPhish package directory is in sys.path for test discovery
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
APP_DIR = os.path.join(PROJECT_ROOT, "NeuralPhish")

if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)
