document.addEventListener("DOMContentLoaded", () => {
    const checkBtn = document.getElementById("checkBtn");
    const resultDiv = document.getElementById("result"); // Renamed to avoid conflict with `result` text
    const accuracyEl = document.getElementById("accuracy");
    const logoIcon = document.getElementById("logoIcon");

    checkBtn.addEventListener("click", () => {
        // Disable button and add scanning class to logo
        checkBtn.disabled = true;
        logoIcon.classList.add('scanning');

        resultDiv.innerHTML = `
            <div class="loader"></div>
            <p style="margin-top: 10px;">Scanning for threats...</p>
        `;
        accuracyEl.innerText = ""; // Clear accuracy during scan

        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            const url = tabs[0].url;

            // ✅ Skip trusted URLs - keep this for immediate feedback
            const trustedSites = ["google.com", "chat.openai.com", "openai.com", "wikipedia.org", "github.com", "stackoverflow.com"]; // Added more common trusted sites
            const isTrusted = trustedSites.some(site => url.includes(site));
            if (isTrusted) {
                resultDiv.innerHTML = `
                    <p class="safe">✅ Trusted Site!</p>
                    <p style="font-size:13px; color:#aaa;">${url}</p>
                `;
                accuracyEl.innerHTML = `Model skipped for trusted source <span class="info-icon" title="This indicates how often the model correctly predicts phishing or legitimate websites based on its training data.">ⓘ</span>`;
                checkBtn.disabled = false;
                logoIcon.classList.remove('scanning');
                return;
            }

            // ✅ Fetch prediction
            fetch("http://localhost:5000/predict", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: url })
            })
            .then((response) => {
                const contentType = response.headers.get("content-type");
                if (!response.ok || !contentType || !contentType.includes("application/json")) {
                    throw new Error("Invalid JSON response or server error.");
                }
                return response.json();
            })
            .then((data) => {
                const probability = data.proba; // Probability of being phishing
                const confidence = (probability * 100).toFixed(2);

                let statusText = '';
                let statusClass = '';
                let barColor = '';
                let iconHtml = '';

                if (probability >= 0.9) {
                    statusText = "🚨 Very High Risk!";
                    statusClass = 'phishing';
                    barColor = '#ff4b5c'; // Red
                    iconHtml = '&#x1F6A8;'; // Alarm icon
                } else if (probability >= 0.6) {
                    statusText = "⚠️ High Risk";
                    statusClass = 'warning';
                    barColor = '#ffa500'; // Orange
                    iconHtml = '&#x26A0;&#xFE0F;'; // Warning sign
                } else if (probability >= 0.3) { // Added a mid-range for "potentially suspicious"
                    statusText = "🧐 Potentially Suspicious";
                    statusClass = 'warning';
                    barColor = '#FFD700'; // Gold
                    iconHtml = '&#x1F914;'; // Thinking face
                } else {
                    statusText = "✅ Likely Safe";
                    statusClass = 'safe';
                    barColor = '#00c853'; // Green
                    iconHtml = '&#x1F60A;'; // Smiling face
                }

                resultDiv.innerHTML = `
                    <div class="result-content">
                        <p><strong class="${statusClass}">${iconHtml} ${statusText}</strong></p>
                        <div class="progress-container">
                            <div class="progress-bar" style="width:${confidence}%; background:${barColor};">
                                ${confidence}%
                            </div>
                        </div>
                        <p style="font-size:13px; color:#aaa; margin-top:10px;">Phishing Likelihood</p>
                        ${data.reasons && data.reasons.length > 0 ? `
                            <details style="margin-top: 15px; width: 90%; background: rgba(0,0,0,0.2); padding: 8px; border-radius: 5px; cursor: pointer;">
                                <summary style="font-size: 13px; font-weight: bold; color: #ffcb05;">Why this result?</summary>
                                <ul style="list-style-type: disc; padding-left: 20px; font-size: 12px; margin-top: 5px; color: #ccc;">
                                    ${data.reasons.map(reason => `<li>${reason}</li>`).join('')}
                                </ul>
                            </details>
                        ` : ''}
                        <p class="learn-more" id="learnMoreLink">Learn more about phishing</p>
                    </div>
                `;

                // Add event listener for "Learn More" link
                document.getElementById('learnMoreLink').addEventListener('click', () => {
                    chrome.tabs.create({ url: 'https://www.google.com/search?q=what+is+phishing+attack' }); // Or a custom educational page
                });

            })
            .catch((err) => {
                console.error("Prediction Error:", err);
                resultDiv.innerHTML = `
                    <p class="phishing">❌ Scan Failed!</p>
                    <p style="font-size:12px; color:#aaa;">Could not connect to the PhishGuard server. Please ensure it is running.</p>
                `;
            })
            .finally(() => {
                checkBtn.disabled = false; // Re-enable button
                logoIcon.classList.remove('scanning'); // Remove scanning animation
            });

            // ✅ Fetch model accuracy safely (moved outside main fetch to run concurrently)
            fetch("http://localhost:5000/model-info")
                .then((res) => {
                    const contentType = res.headers.get("content-type");
                    if (!res.ok || !contentType || !contentType.includes("application/json")) {
                        throw new Error("Model-info did not return JSON.");
                    }
                    return res.json();
                })
                .then((data) => {
                    accuracyEl.innerHTML = `Model Accuracy: <strong style="color: #ffcb05;">${data.accuracy}%</strong> <span class="info-icon" title="This indicates how often the model correctly predicts phishing or legitimate websites based on its training data.">ⓘ</span>`;
                })
                .catch((err) => {
                    console.error("Accuracy Fetch Error:", err);
                    accuracyEl.innerHTML = `⚠️ Failed to fetch accuracy. <span class="info-icon" title="This indicates how often the model correctly predicts phishing or legitimate websites based on its training data.">ⓘ</span>`;
                });
        });
    });
});