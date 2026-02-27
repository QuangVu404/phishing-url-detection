import pandas as pd
import os
from src.preprocessing import clean_url, sanitize_url, unshorten_url
from src.model_loader import get_model
from src.tokenizer_loader import get_tokenizer
from src.caculate_entropy import calculate_entropy
from src.config import MAX_LEN, THRESHOLD
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Lấy model & tokenizer
model = get_model()
tokenizer = get_tokenizer()

# KHỞI TẠO DANH SÁCH TRẮNG
Tranco_FILE_PATH = 'data/top-1m-Tranco-list.csv' 
GLOBAL_TRUSTED_DOMAINS = set(['kaggle.com', 'google.com', 'github.com', 'microsoft.com', 'apple.com'])
try:
    if os.path.exists(Tranco_FILE_PATH):
        df_tranco = pd.read_csv(Tranco_FILE_PATH, header=None)
        
        # Domain nằm ở cột thứ 2 trong file
        top_domains = df_tranco[1].astype(str).str.lower().tolist()
        
        GLOBAL_TRUSTED_DOMAINS.update(top_domains[:])
        print(f"Đã tải {len(GLOBAL_TRUSTED_DOMAINS)} domains vào Danh sách Trắng.")
    else:
        print("Không tìm thấy file Tranco. Dùng danh sách trắng mặc định.")
except Exception as e:
    print(f"Lỗi khi tải file Tranco: {e}. Dùng danh sách trắng mặc định.")

def predict_phishing(raw_url):
    """
    Dự đoán 1 URL là Phishing hay Legit, tích hợp Masking, Entropy và Whitelist.
    """
    # Giải mã link rút gọn
    url = unshorten_url(str(raw_url))
    
    # Tính Entropy trên URL GỐC
    entropy_score = calculate_entropy(str(url))
    
    # Tiền xử lý
    url_clean = clean_url(url)
    url_clean = url_clean.rstrip('/')
    
    if url_clean in GLOBAL_TRUSTED_DOMAINS:
        return {
            "url": raw_url,
            "final_url": url if url != raw_url else None,
            "probability": 0.00,
            "prediction": "LEGIT",
            "threshold_used": 0.5
        }
    
    # Rút trích Domain gốc để kiểm tra Whitelist
    domain = url_clean.split('/')[0]
    main_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
    
    # Masking để chống nhiễu OOV
    url_masked = sanitize_url(url_clean)
    
    # Tokenize + Pad
    seq = tokenizer.texts_to_sequences([url_masked])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')
    
    prob = float(model.predict(padded, verbose=0).flatten()[0])
    threshold = THRESHOLD
    
    # Giảm 40% rủi ro nếu là domain uy tín và Cộng thêm rủi ro nếu mã quá hỗn loạn
    if main_domain in GLOBAL_TRUSTED_DOMAINS or domain in GLOBAL_TRUSTED_DOMAINS:
        prob = prob * 0.6
    if entropy_score > 4.5:
        prob = min(1.0, prob + 0.1)
    
    label = 'PHISHING' if prob > threshold else 'LEGIT'
    
    return {
        "url": raw_url,
        "final_url": url if url != raw_url else None,
        "probability": round(prob, 4),
        "prediction": label,
        "threshold_used": THRESHOLD
    }