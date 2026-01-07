# Configuration settings
import os

# Worker counts for parallel processing
NMAP_WORKERS = 10
HTTP_WORKERS = 20

# Timeout settings (seconds)
NMAP_TIMEOUT = 60
HTTP_TIMEOUT = 15

# Upload/Results directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

# Ensure directories exist
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
