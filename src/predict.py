import os
import pandas as pd

from src.preprocessor.clean_url import clean_url
from src.preprocessor.unshorten_url import unshorten_url

from src.features.caculate_url_entropy import calculate_entropy
from src.features.sanitize_url import sanitize_url

from src.inference.model_loader import get_model
from src.inference.tokenizer_loader import get_tokenizer
from src.inference.config import MAX_LEN, THRESHOLD
from tensorflow.keras.preprocessing.sequence import pad_sequences

"""
Pipeline xử lý dự đoán:
1. Unshorten URL:  Giải mã link rút gọn (nếu có).
2. Entropy Check:  Tính độ hỗn loạn của URL để phát hiện chuỗi ngẫu nhiên.
3. Clean URL:      Chuyển chữ thường, xóa protocol (http/https) và www.
4. Whitelist:      Nếu URL sạch chính xác 100% nằm trong Top Tranco -> Bỏ qua AI, trả về LEGIT.
5. Sanitize URL:   Masking các tham số nhạy cảm theo bộ Rule bảo toàn ngữ nghĩa.
6. Model Predict:  Biến URL thành chuỗi số (Tokenize/Pad) và đưa vào model.
7. Heuristic:      Cân chỉnh xác suất: 
                   - Giảm 40% rủi ro nếu thuộc main_domain uy tín (và không nằm trong Blacklist Subdomain).
                   - Cộng thêm 10% rủi ro nếu Entropy cực cao (> 5.0).
"""

model = get_model()
tokenizer = get_tokenizer()

GLOBAL_TRUSTED_DOMAINS = {'kaggle.com', 'google.com', 'github.com', 'microsoft.com', 'apple.com'}
ABUSED_SUBDOMAINS = {
    'sites.google.com', 'docs.google.com', 'github.io', 
    'netlify.app', 'herokuapp.com', 'storage.googleapis.com',
    'firebaseapp.com', 'web.app'
}

Tranco_FILE_PATH = 'data/top-1m-Tranco-list.csv'
if os.path.exists(Tranco_FILE_PATH):
    try:
        df_tranco = pd.read_csv(Tranco_FILE_PATH, header=None)
        top_domains = df_tranco[1].astype(str).str.lower().tolist()
        GLOBAL_TRUSTED_DOMAINS.update(top_domains)
        print(f"[*] Đã tải {len(GLOBAL_TRUSTED_DOMAINS)} domains vào Whitelist.")
    except Exception as e:
        print(f"[!] Lỗi khi load Tranco list: {e}")
else:
    print("[!] Không tìm thấy file Tranco list, sử dụng Whitelist mặc định.")

def predict_phishing(raw_url):
    url = unshorten_url(str(raw_url))
    entropy_score = calculate_entropy(str(url))
    
    url_clean = clean_url(url).rstrip('/')
    
    if url_clean in GLOBAL_TRUSTED_DOMAINS:
        return {
            "url": raw_url,
            "final_url": url if url != raw_url else None,
            "probability": 0.00,
            "prediction": "LEGIT",
            "threshold_used": THRESHOLD
        }

    domain = url_clean.split('/')[0]
    main_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
    
    url_masked = sanitize_url(url_clean)
    seq = tokenizer.texts_to_sequences([url_masked])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')
    prob = float(model.predict(padded, verbose=0).flatten()[0])

    is_trusted_domain = (main_domain in GLOBAL_TRUSTED_DOMAINS)
    is_abused_subdomain = any(domain.endswith(s) for s in ABUSED_SUBDOMAINS)
    
    if is_trusted_domain and not is_abused_subdomain:
        prob = prob * 0.6
    elif entropy_score > 5.0:
        prob = min(1.0, prob + 0.1)
    
    label = 'PHISHING' if prob > THRESHOLD else 'LEGIT'
    
    return {
        "url": raw_url,
        "final_url": url if url != raw_url else None,
        "probability": round(prob, 4),
        "prediction": label,
        "threshold_used": THRESHOLD
    }