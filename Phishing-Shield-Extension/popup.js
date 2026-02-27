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
        // 1. Get the URL of the active Tab
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        let currentUrl = tab.url;

        // Skip internal browser system pages
        if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://')) {
            throw new Error("Cannot scan system pages.");
        }

        urlScanned.innerText = currentUrl;

        // 2. Call the API to FastAPI Server on Hugging Face
        const API_URL = 'https://quangvu404-phishing-shield-api.hf.space/predict';
        
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl })
        });

        if (!response.ok) throw new Error("AI Server returned an error.");
        
        const data = await response.json();
        
        // 3. Handle result display
        loadingUI.classList.add('hidden');
        resultBox.classList.remove('hidden');

        if (data.final_url && data.final_url !== currentUrl) {
            urlScanned.innerHTML = `
                <span style="color: #888; text-decoration: line-through; font-size: 0.9em;">${currentUrl}</span>
                <br>
                <span style="color: #ff4757;">👉 Destination:</span> <strong>${data.final_url}</strong>
            `;
        } else {
            urlScanned.innerText = currentUrl;
        }

        const riskPercent = (data.probability * 100).toFixed(2);
        probText.innerText = `Phishing Probability: ${riskPercent}%`;

        if (data.prediction === "PHISHING") {
            resultBox.className = "status-danger";
            statusTitle.innerText = "🚨 PHISHING DETECTED!";
            aiMessage.innerText = "The AI system identified an unusual structure in this link. Do NOT enter any accounts or passwords.";
        } else {
            resultBox.className = "status-safe";
            statusTitle.innerText = "✅ SAFE WEBSITE";
            aiMessage.innerText = "The link structure appears safe, and no signs of phishing were detected.";
        }

    } catch (error) {
        loadingUI.classList.add('hidden');
        resultBox.classList.remove('hidden');
        resultBox.className = "status-danger";
        
        statusTitle.innerText = "⚠️ CONNECTION ERROR";
        urlScanned.innerText = "";
        probText.innerText = "Could not connect to AI Server";
        aiMessage.innerText = error.message === "Failed to fetch" 
            ? "Please ensure the FastAPI Backend is running correctly." 
            : error.message;
    } finally {
        btn.disabled = false;
        btn.innerText = "🔄 Scan Again";
    }
});