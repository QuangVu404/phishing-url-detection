import os
import json

# Lấy cấu hình từ file models/config.json nếu có, hoặc dùng mặc định
def load_config():
    config_path = os.getenv("CONFIG_PATH", "models/config_20260224_165928.json")
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"MAX_LEN": 500, "OPTIMAL_THRESHOLD": 0.5}

APP_CONFIG = load_config()
MAX_LEN = APP_CONFIG.get("MAX_LEN", 500)
THRESHOLD = APP_CONFIG.get("OPTIMAL_THRESHOLD", 0.5)