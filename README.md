AI Phishing Shield: Phishing URL Detection System
Hệ thống phát hiện URL độc hại dựa trên Deep Learning (CNN), được triển khai dưới dạng API (FastAPI/Docker) và tích hợp Chrome Extension để bảo vệ người dùng trong thời gian thực.

1. Tổng quan dự án
Dự án xây dựng một quy trình hoàn chỉnh (End-to-End Pipeline) từ xử lý dữ liệu, huấn luyện mô hình đến triển khai thực tế. Hệ thống sử dụng mạng nơ-ron cuộn 1 chiều (1D-CNN) ở cấp độ ký tự (Character-level) để nhận diện các đặc điểm bất thường trong cấu trúc URL mà không cần bóc tách thủ công các đặc trưng (Feature Engineering).

2. Kiến trúc mô hình (Model Architecture)
Mô hình được thiết kế để xử lý dữ liệu dạng chuỗi ký tự, bao gồm các lớp chính:

Character Tokenization: Chuyển đổi URL thành chuỗi số dựa trên bộ từ điển ký tự.

Embedding Layer: Biểu diễn các ký tự trong không gian vectơ thấp chiều.

1D Convolutional Layers: Trích xuất các đặc trưng cục bộ (n-grams) từ chuỗi URL.

Global MaxPooling: Giữ lại các đặc trưng quan trọng nhất từ các bộ lọc.

Fully Connected Layers: Phân loại dựa trên các đặc trưng đã trích xuất.

Sigmoid Output: Trả về xác suất (Probability) để phân loại nhị phân (Legitimate/Phishing).

3. Quy trình xử lý dữ liệu (Data Pipeline)
Dữ liệu được xử lý qua các bước nghiêm ngặt để đảm bảo độ chính xác:

Cleaning: Chuẩn hóa URL (lowercase), loại bỏ trùng lặp.

Sanitization: Sử dụng Regex để gắn nhãn các thành phần nhạy cảm như IP, Token, ID hoặc các chuỗi Hex dài.

Vectorization: Padding chuỗi về độ dài cố định (500 ký tự) để đưa vào mô hình.

4. Hướng dẫn cài đặt và sử dụng
Triển khai cục bộ (Local Deployment)
Cài đặt thư viện:

Bash
pip install -r requirements.txt
Khởi chạy Server:

Bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
API Docs: Truy cập http://localhost:8000/docs để kiểm thử qua Swagger UI.

Triển khai với Docker
Bash
docker build -t phishing-detector .
docker run -p 8000:7860 phishing-detector
5. Cấu trúc API (API Usage)
Endpoint: POST /predict

Request Body:

JSON
{ "url": "http://example-malicious-site.com" }
Response:

JSON
{
  "url": "http://example-malicious-site.com",
  "prediction": "PHISHING",
  "probability": 0.985
}
6. Công nghệ sử dụng
Ngôn ngữ: Python.

Deep Learning: TensorFlow / Keras.

Backend: FastAPI.

DevOps: Docker, Hugging Face Spaces.

Frontend: JavaScript (Chrome Extension API).