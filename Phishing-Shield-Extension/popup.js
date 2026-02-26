document.getElementById('scan-btn').addEventListener('click', async () => {
    const btn = document.getElementById('scan-btn');
    const resultBox = document.getElementById('result-box');
    const loadingUI = document.getElementById('loading');
    
    const statusTitle = document.getElementById('status-title');
    const urlScanned = document.getElementById('url-scanned');
    const probText = document.getElementById('prob-text');
    const aiMessage = document.getElementById('ai-message');

    // Reset UI
    btn.disabled = true;
    resultBox.classList.add('hidden');
    loadingUI.classList.remove('hidden');

    try {
        // 1. Lấy URL của Tab đang hiển thị
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        let currentUrl = tab.url;

        // Bỏ qua các trang nội bộ của Chrome
        if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://')) {
            throw new Error("Không thể quét trang hệ thống.");
        }

        urlScanned.innerText = currentUrl;

        // 2. Gọi API đến FastAPI Server
        const API_URL = 'https://quangvu404-phishing-shield-api.hf.space/predict';
        
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl })
        });

        if (!response.ok) throw new Error("Server AI phản hồi lỗi.");
        
        const data = await response.json();
        
        // 3. Xử lý hiển thị kết quả
        loadingUI.classList.add('hidden');
        resultBox.classList.remove('hidden');

        const riskPercent = (data.probability * 100).toFixed(2);
        probText.innerText = `Xác suất lừa đảo: ${riskPercent}%`;

        if (data.prediction === "PHISHING") {
            resultBox.className = "status-danger";
            statusTitle.innerText = "🚨 PHÁT HIỆN LỪA ĐẢO!";
            aiMessage.innerText = "Hệ thống AI nhận diện cấu trúc bất thường trong đường link này. Tuyệt đối không nhập tài khoản hay mật khẩu.";
        } else {
            resultBox.className = "status-safe";
            statusTitle.innerText = "✅ TRANG WEB AN TOÀN";
            aiMessage.innerText = "Đường link có cấu trúc an toàn, chưa phát hiện dấu hiệu giả mạo.";
        }

    } catch (error) {
        loadingUI.classList.add('hidden');
        resultBox.classList.remove('hidden');
        resultBox.className = "status-danger";
        
        statusTitle.innerText = "⚠️ LỖI KẾT NỐI";
        urlScanned.innerText = "";
        probText.innerText = "Không thể kết nối đến Máy chủ AI";
        aiMessage.innerText = error.message === "Failed to fetch" 
            ? "Hãy đảm bảo Backend FastAPI (uvicorn) đang chạy ở cổng 8000." 
            : error.message;
    } finally {
        btn.disabled = false;
        btn.innerText = "🔄 Quét Lại";
    }
});