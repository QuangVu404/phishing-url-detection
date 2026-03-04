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

    let currentUrl = "";

    try {
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab || !tab.url) {
             throw new Error("System and local pages cannot be scanned.");
        }
        
        currentUrl = tab.url;

        if (
            currentUrl.startsWith('chrome://') ||
            currentUrl.startsWith('edge://') ||
            currentUrl.startsWith('about:') ||
            currentUrl.startsWith('file://') ||
            currentUrl.startsWith('chrome-extension://')
        ) {
            throw new Error("System and local pages cannot be scanned.");
        }

        urlScanned.innerText = currentUrl;

        const API_URL = 'https://quangvu404-phishing-shield-api.hf.space/predict';

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000);

        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) throw new Error("AI Server returned an error.");

        const data = await response.json();

        if (data.error === true) {
            throw new Error(data.message);
        }

        loadingUI.classList.add('hidden');
        resultBox.classList.remove('hidden');

        const riskPercent = (data.probability * 100).toFixed(2);
        probText.innerText = `Phishing Probability: ${riskPercent}%`;

        resultBox.classList.remove('status-safe', 'status-danger');

        if (data.prediction === "PHISHING") {
            resultBox.classList.add('status-danger');
            statusTitle.innerText = "🚨 PHISHING DETECTED!";
            aiMessage.innerText = "The AI system identified an unusual structure in this link. Do NOT enter any accounts or passwords.";
        } else {
            resultBox.classList.add('status-safe');
            statusTitle.innerText = "✅ SAFE WEBSITE";
            aiMessage.innerText = "The link structure appears safe, and no signs of phishing were detected.";
        }

    } catch (error) {
        loadingUI.classList.add('hidden');
        resultBox.classList.remove('hidden');

        resultBox.classList.remove('status-safe', 'status-danger');
        resultBox.classList.add('status-danger');

        if (error.message.includes("System")) {
            statusTitle.innerText = "⚠️ SCAN SKIPPED";
            probText.innerText = "System Page Detected";
        } else {
            statusTitle.innerText = "⚠️ SCAN ERROR";
            probText.innerText = "Could not complete the scan";
        }

        urlScanned.innerText = currentUrl || "Unknown URL";

        if (error.name === "AbortError") {
            aiMessage.innerText = "Request timed out. The AI Server is taking too long to respond.";
        } else if (error.message === "Failed to fetch") {
            aiMessage.innerText = "Unable to connect to the AI Server. Please ensure the backend is running.";
        } else {
            aiMessage.innerText = error.message;
        }

    } finally {
        btn.disabled = false;
        btn.innerText = "🔄 Scan Again";
    }
});