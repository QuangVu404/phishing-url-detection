from unittest.mock import patch, MagicMock
from src.predict import predict_phishing

# Dùng Mock để test logic mà KHÔNG CẦN load model nặng lên RAM
@patch('src.predict.get_model')
@patch('src.predict.get_tokenizer')
def test_predict_phishing_logic(mock_get_tokenizer, mock_get_model):
    # Giả lập mô hình trả về xác suất 0.95 (Phishing)
    mock_model = MagicMock()
    mock_model.predict.return_value = [[0.95]]
    mock_get_model.return_value = mock_model
    
    result = predict_phishing("http://secure-update-paypal.com.vn-verify.info")
    
    assert result['url'] == "http://secure-update-paypal.com.vn-verify.info"
    assert result['prediction'] == "PHISHING"
    assert result['probability'] == 0.95