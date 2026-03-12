import os
import json

def load_config():
    config_path = os.getenv("CONFIG_PATH", "models/config.json")
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"MAX_LEN": 250, "OPTIMAL_THRESHOLD": 0.5}

APP_CONFIG = load_config()
MAX_LEN = APP_CONFIG.get("MAX_LEN", 250)
THRESHOLD = APP_CONFIG.get("OPTIMAL_THRESHOLD", 0.5)

TRANCO_FILE_PATH = os.getenv("TRANCO_PATH", "data/top-1m-Tranco-list.csv")