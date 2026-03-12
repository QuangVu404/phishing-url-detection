import os
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences

from src.preprocessor.clean_url import clean_url
from src.preprocessor.unshorten_url import unshorten_url
from src.features.calculate_url_entropy import calculate_entropy
from src.features.sanitize_url import sanitize_url
from src.inference.model_loader import get_model
from src.inference.tokenizer_loader import get_tokenizer
from src.inference.config import MAX_LEN, THRESHOLD, TRANCO_FILE_PATH

"""
Pipeline xử lý dự đoán:
1. Validate:      Kiểm tra URL đầu vào hợp lệ.
2. Unshorten URL: Giải mã link rút gọn (timeout=3s, fallback về URL gốc).
3. Clean URL:     Chuyển chữ thường, xóa protocol và www, rstrip('/').
4. Whitelist:     Nếu main_domain nằm trong Top Tranco → Bỏ qua AI, trả về LEGIT.
                  (check main_domain, không phải url_clean — tránh miss URL có path)
5. Sanitize URL:  Masking các tham số nhạy cảm bảo toàn ngữ nghĩa.
6. Model Predict: Tokenize/Pad → ResNet1D-SE predict.
7. Heuristic:     Cân chỉnh xác suất:
                  - Giảm 40% nếu main_domain uy tín và không nằm trong Blacklist Subdomain.
                  - Cộng thêm 10% nếu entropy domain cực cao (> 4.5).

QUAN TRỌNG — Lazy Singleton Pattern:
    Các biến _model, _tokenizer, _trusted_domains KHÔNG được load khi import module.
    Chúng chỉ load lần đầu tiên khi predict_phishing() được gọi.

    Trong FastAPI, gọi init_resources() ở lifespan để pre-warm trước khi nhận request:

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            init_resources()
            yield
"""

_model = None
_tokenizer = None
_trusted_domains: frozenset = None

ABUSED_SUBDOMAINS = frozenset({
    "sites.google.com", "docs.google.com", "github.io",
    "netlify.app", "herokuapp.com", "storage.googleapis.com",
    "firebaseapp.com", "web.app",
})


def _load_trusted_domains() -> frozenset:
    """
    Load Tranco top-1M + default whitelist.
    Trả về frozenset để đảm bảo immutable và thread-safe sau khi load.
    """
    base = {
        "kaggle.com", "google.com", "github.com",
        "microsoft.com", "apple.com",
    }
    if os.path.exists(TRANCO_FILE_PATH):
        try:
            df = pd.read_csv(TRANCO_FILE_PATH, header=None)
            base.update(df[1].astype(str).str.lower().tolist())
            print(f"[*] Đã tải {len(base):,} domains vào Whitelist.")
        except Exception as e:
            print(f"[!] Lỗi khi load Tranco list: {e}")
    else:
        print("[!] Không tìm thấy file Tranco list, sử dụng Whitelist mặc định.")
    return frozenset(base)


def init_resources():
    """
    Pre-warm tất cả resources (model, tokenizer, trusted domains).
    Gọi 1 lần trong FastAPI lifespan hoặc khi khởi động server.
    """
    global _model, _tokenizer, _trusted_domains
    _model           = get_model()
    _tokenizer       = get_tokenizer()
    _trusted_domains = _load_trusted_domains()


def _get_resources():
    """
    Lazy init — tự động load nếu chưa init.
    Dùng trong unit test hoặc standalone script (không cần gọi init_resources trước).
    """
    global _model, _tokenizer, _trusted_domains
    if _model is None:
        _model = get_model()
    if _tokenizer is None:
        _tokenizer = get_tokenizer()
    if _trusted_domains is None:
        _trusted_domains = _load_trusted_domains()
    return _model, _tokenizer, _trusted_domains


def predict_phishing(raw_url: str) -> dict:
    """
    Dự đoán URL có phải phishing không.

    Args:
        raw_url: URL gốc (có hoặc không có protocol).

    Returns:
        {
            "url":            URL gốc,
            "resolved_url":   URL sau unshorten (None nếu không đổi),
            "masked_url":     URL sau sanitize để debug (None nếu whitelist hit),
            "entropy":        Entropy của domain (None nếu whitelist hit),
            "probability":    Xác suất phishing sau heuristic [0.0, 1.0],
            "prediction":     "PHISHING" hoặc "LEGIT",
            "threshold_used": Ngưỡng phân loại đang dùng,
        }

    Raises:
        ValueError: Nếu URL quá ngắn hoặc không hợp lệ sau clean.
    """
    raw_url = str(raw_url).strip()
    if len(raw_url) < 4:
        raise ValueError(f"URL quá ngắn hoặc rỗng: {repr(raw_url)}")

    model, tokenizer, trusted_domains = _get_resources()

    resolved = unshorten_url(raw_url)

    url_clean = clean_url(resolved).rstrip("/")
    if not url_clean:
        raise ValueError(f"URL không hợp lệ sau clean: {repr(raw_url)}")

    domain      = url_clean.split("/")[0]
    main_domain = ".".join(domain.split(".")[-2:]) if "." in domain else domain

    is_abused = any(domain.endswith(s) for s in ABUSED_SUBDOMAINS)
    if main_domain in trusted_domains and not is_abused:
        return {
            "url":            raw_url,
            "resolved_url":   resolved if resolved != raw_url else None,
            "masked_url":     None,
            "entropy":        None,
            "probability":    0.00,
            "prediction":     "LEGIT",
            "threshold_used": THRESHOLD,
        }

    domain_entropy = calculate_entropy(domain)

    url_masked = sanitize_url(url_clean)
    seq        = tokenizer.texts_to_sequences([url_masked])
    padded     = pad_sequences(seq, maxlen=MAX_LEN, padding="post", truncating="post")
    prob       = float(model.predict(padded, verbose=0).flatten()[0])

    is_trusted_main     = main_domain in trusted_domains
    is_abused_subdomain = any(domain.endswith(s) for s in ABUSED_SUBDOMAINS)

    if is_trusted_main and not is_abused_subdomain:
        prob = prob * 0.6
    elif domain_entropy > 4.5:
        prob = min(1.0, prob + 0.1)

    label = "PHISHING" if prob > THRESHOLD else "LEGIT"

    return {
        "url":            raw_url,
        "resolved_url":   resolved if resolved != raw_url else None,
        "masked_url":     url_masked,
        "entropy":        round(domain_entropy, 4),
        "probability":    round(prob, 4),
        "prediction":     label,
        "threshold_used": THRESHOLD,
    }