FROM python:3.10-slim

WORKDIR /workspace

# Copy requirements và cài đặt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ mã nguồn
COPY . .

# Expose port 8000
EXPOSE 8000

# Chạy server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]