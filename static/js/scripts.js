document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const checkButton = document.getElementById('checkButton');
    const resultContainer = document.getElementById('resultContainer');
    const resultContent = document.getElementById('resultContent');
    const analysisDetails = document.getElementById('analysisDetails');
    const loading = document.getElementById('loading');

    checkButton.addEventListener('click', analyzeURL);
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            analyzeURL();
        }
    });

    async function analyzeURL() {
        const url = urlInput.value.trim();

        if (!url) {
            showError('Please enter a URL');
            return;
        }

        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            showError('URL must start with http:// or https://');
            return;
        }

        loading.style.display = 'flex';
        resultContainer.style.display = 'none';

        try {
            const response = await fetch('/check_url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();

            if (response.ok) {
                displayResult(data);
            } else {
                showError(data.message || 'An error occurred during analysis');
            }
        } catch (error) {
            showError('Failed to connect to the server');
        } finally {
            loading.style.display = 'none';
        }
    }

    function displayResult(data) {
        resultContainer.style.display = 'block';
        const isSafe = data.status === 'safe';
        const confidence = (data.confidence * 100).toFixed(1);

        resultContent.innerHTML = `
            <div class="result-item ${isSafe ? 'safe' : 'dangerous'}">
                <h3>
                    <i class="fas ${isSafe ? 'fa-shield-check' : 'fa-shield-exclamation'}"></i>
                    ${isSafe ? 'Safe URL Detected' : 'Potentially Malicious URL'}
                </h3>
                <p>Confidence Level: ${confidence}%</p>
                <div class="confidence-meter">
                    <div class="confidence-value" style="width: ${confidence}%"></div>
                </div>
                <p>Analyzed URL: ${urlInput.value}</p>
            </div>
        `;

        // Display analysis details
        if (data.analysis) {
            const warnings = data.analysis.split('Warning:').filter(w => w.trim());
            analysisDetails.innerHTML = `
                <h3>Security Analysis Details</h3>
                ${warnings.map(warning => `
                    <div class="warning-item">
                        <i class="fas fa-exclamation-triangle"></i>
                        ${warning.trim()}
                    </div>
                `).join('')}
            `;
        }
    }

    function showError(message) {
        resultContainer.style.display = 'block';
        resultContent.innerHTML = `
            <div class="result-item dangerous">
                <h3>
                    <i class="fas fa-exclamation-circle"></i>
                    Error
                </h3>
                <p>${message}</p>
            </div>
        `;
        analysisDetails.innerHTML = '';
    }
});