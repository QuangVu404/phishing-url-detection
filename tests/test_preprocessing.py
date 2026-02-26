from src.preprocessing import clean_url, sanitize_url

def test_clean_url():
    # Kiểm tra chuyển chữ thường và xóa giao thức
    assert clean_url("https://www.Google.com/Login") == "google.com/login"
    assert clean_url("http://PAYPAL.com/") == "paypal.com/"
    assert clean_url("www.github.com") == "github.com"

def test_sanitize_url():
    # Kiểm tra hàm tạo mặt nạ (Masking)
    assert sanitize_url("192.168.1.1/admin") == "<IP_ADDRESS>/admin"
    assert "<HEX_ID>" in sanitize_url("example.com/a8b9cdef1234567890/verify")