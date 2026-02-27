chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "scanPhishingLink",
        title: "Scan this link with AI Phishing Shield",
        contexts: ["link"]
    });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === "scanPhishingLink") {
        const targetUrl = info.linkUrl;
        let finalUrl = targetUrl;

        chrome.notifications.create("scanning", {
            type: "basic",
            iconUrl: "icon.png",
            title: "AI Phishing Shield",
            message: `Analyzing: ${targetUrl}\nPlease wait while the AI extracts features...`
        });

        try {
            try {
                const redirectCheck = await fetch(targetUrl);
                finalUrl = redirectCheck.url;
            } catch (fetchError) {
                console.log("CORS block, using original URL", fetchError);
            }

            const API_URL = 'https://quangvu404-phishing-shield-api.hf.space/predict';
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: finalUrl }) 
            });

            if (!response.ok) throw new Error("Failed to connect to the AI Server");

            const data = await response.json();
            const riskPercent = (data.probability * 100).toFixed(2);
            
            let resultMessage = "";
            let notificationTitle = "";

            if (data.prediction === "PHISHING") {
                notificationTitle = "🚨 PHISHING DETECTED!";
                resultMessage = `Phishing Probability: ${riskPercent}%\nDO NOT CLICK THIS LINK!`;
            } else {
                notificationTitle = "✅ SAFE LINK";
                resultMessage = `Phishing Probability: ${riskPercent}%\nThe link structure appears safe.`;
            }

            if (finalUrl !== targetUrl) {
                resultMessage += `\nRedirects to: ${finalUrl}`;
            } else {
                resultMessage += `\nScanned link: ${finalUrl}`;
            }

            chrome.notifications.clear("scanning");
            chrome.notifications.create({
                type: "basic",
                iconUrl: "icon.png", 
                title: notificationTitle,
                message: resultMessage
            });

        } catch (error) {
            chrome.notifications.clear("scanning");
            chrome.notifications.create({
                type: "basic",
                iconUrl: "icon.png",
                title: "⚠️ SCAN ERROR",
                message: "Unable to connect to the AI system at this time."
            });
        }
    }
});