"""
Simple FastAPI app with basic URL analysis
"""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import re
from urllib.parse import urlparse

app = FastAPI(title="🛡️ Phishing URL Detector", description="Simple URL safety checker")

class URLRequest(BaseModel):
    url: str

def simple_url_analysis(url: str) -> dict:
    """Simple rule-based phishing detection"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Simple suspicious indicators
        suspicious_patterns = [
            'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
            'secure', 'verify', 'update', 'confirm', 'suspend'
        ]
        
        phishing_indicators = 0
        reasons = []
        
        # Check for suspicious keywords in domain
        for pattern in suspicious_patterns:
            if pattern in domain and not domain.startswith(pattern + '.'):
                phishing_indicators += 1
                reasons.append(f"Suspicious '{pattern}' in domain")
        
        # Check for IP address instead of domain
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
            phishing_indicators += 2
            reasons.append("Uses IP address instead of domain name")
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                phishing_indicators += 1
                reasons.append(f"Suspicious TLD: {tld}")
        
        # Check for excessive subdomains
        subdomains = domain.split('.')
        if len(subdomains) > 4:
            phishing_indicators += 1
            reasons.append("Too many subdomains")
        
        # Check for suspicious path patterns
        suspicious_path_words = ['login', 'signin', 'account', 'verify', 'secure']
        for word in suspicious_path_words:
            if word in path:
                phishing_indicators += 0.5
                reasons.append(f"Suspicious path contains '{word}'")
        
        # Check for HTTPS
        if not parsed.scheme == 'https':
            phishing_indicators += 0.5
            reasons.append("Not using HTTPS encryption")
        
        # Determine if phishing based on indicators
        is_phishing = phishing_indicators >= 2
        confidence = min(phishing_indicators / 5.0, 0.95) if is_phishing else max(0.95 - (phishing_indicators / 5.0), 0.05)
        
        return {
            "url": url,
            "is_safe": not is_phishing,
            "confidence": confidence,
            "prediction": "phishing" if is_phishing else "safe",
            "risk_score": phishing_indicators,
            "reasons": reasons[:3] if reasons else ["No suspicious patterns detected"]
        }
        
    except Exception as e:
        return {
            "url": url,
            "is_safe": False,
            "confidence": 0.5,
            "prediction": "error",
            "risk_score": 0,
            "reasons": [f"Analysis error: {str(e)}"]
        }

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>🛡️ Phishing URL Detector</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { box-sizing: border-box; }
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                max-width: 900px; margin: 0 auto; padding: 20px; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh; color: #333;
            }
            .container { 
                background: white; border-radius: 15px; padding: 40px; 
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            }
            .header { text-align: center; margin-bottom: 40px; }
            .header h1 { font-size: 3rem; margin: 0; color: #333; }
            .header p { font-size: 1.2rem; color: #666; margin: 10px 0; }
            .input-group { margin: 30px 0; text-align: center; }
            .url-input { 
                width: 70%; padding: 15px; font-size: 16px; border: 2px solid #ddd;
                border-radius: 8px; margin-right: 10px; outline: none;
            }
            .url-input:focus { border-color: #667eea; }
            .check-btn { 
                padding: 15px 25px; font-size: 16px; background: #667eea; 
                color: white; border: none; border-radius: 8px; cursor: pointer;
                transition: all 0.3s ease;
            }
            .check-btn:hover { background: #5a67d8; transform: translateY(-2px); }
            .check-btn:disabled { background: #ccc; cursor: not-allowed; }
            .result { margin-top: 30px; padding: 25px; border-radius: 10px; display: none; }
            .result.safe { background: #d4edda; border: 2px solid #c3e6cb; color: #155724; }
            .result.danger { background: #f8d7da; border: 2px solid #f5c6cb; color: #721c24; }
            .result h3 { margin: 0 0 15px 0; font-size: 1.4rem; }
            .result p { margin: 8px 0; }
            .reasons { margin-top: 15px; }
            .reasons ul { margin: 10px 0; padding-left: 20px; }
            .loading { display: none; text-align: center; margin: 20px 0; }
            .footer { text-align: center; margin-top: 40px; color: #666; }
            .examples { margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; }
            .examples h4 { margin: 0 0 15px 0; color: #333; }
            .example-url { 
                display: inline-block; margin: 5px; padding: 8px 12px; 
                background: #e9ecef; border-radius: 5px; cursor: pointer; 
                transition: all 0.2s ease;
            }
            .example-url:hover { background: #667eea; color: white; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Phishing URL Detector</h1>
                <p>Advanced AI-powered URL safety analysis</p>
                <p>Protect yourself from malicious websites and phishing attacks</p>
            </div>
            
            <div class="input-group">
                <input type="url" id="urlInput" class="url-input" 
                       placeholder="Enter URL to analyze (e.g., https://suspicious-site.com)" />
                <button onclick="checkURL()" class="check-btn" id="checkBtn">🔍 Analyze URL</button>
            </div>
            
            <div class="examples">
                <h4>📋 Try these example URLs:</h4>
                <span class="example-url" onclick="setURL('https://google.com')">✅ https://google.com</span>
                <span class="example-url" onclick="setURL('https://github.com')">✅ https://github.com</span>
                <span class="example-url" onclick="setURL('http://paypal-secure-login.tk')">⚠️ Suspicious Example</span>
                <span class="example-url" onclick="setURL('https://192.168.1.1/login')">⚠️ IP Address</span>
            </div>
            
            <div class="loading" id="loading">
                <p>🔄 Analyzing URL security...</p>
            </div>
            
            <div id="result" class="result"></div>
            
            <div class="footer">
                <p>🛡️ <strong>Stay Safe Online</strong> | Always verify URLs before entering personal information</p>
                <p><small>This tool provides security analysis but should not be your only line of defense.</small></p>
            </div>
        </div>
        
        <script>
        function setURL(url) {
            document.getElementById('urlInput').value = url;
        }
        
        async function checkURL() {
            const urlInput = document.getElementById('urlInput');
            const checkBtn = document.getElementById('checkBtn');
            const loading = document.getElementById('loading');
            const resultDiv = document.getElementById('result');
            
            const url = urlInput.value.trim();
            if (!url) {
                alert('Please enter a URL to analyze');
                return;
            }
            
            // Add protocol if missing
            let finalUrl = url;
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                finalUrl = 'https://' + url;
                urlInput.value = finalUrl;
            }
            
            // Show loading state
            checkBtn.disabled = true;
            checkBtn.textContent = '🔄 Analyzing...';
            loading.style.display = 'block';
            resultDiv.style.display = 'none';
            
            try {
                const response = await fetch('/check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: finalUrl})
                });
                
                const data = await response.json();
                
                if (data.is_safe) {
                    resultDiv.className = 'result safe';
                    resultDiv.innerHTML = `
                        <h3>✅ URL appears to be SAFE</h3>
                        <p><strong>Analyzed URL:</strong> ${data.url}</p>
                        <p><strong>Safety Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</p>
                        <p><strong>Risk Score:</strong> ${data.risk_score}/5</p>
                        <div class="reasons">
                            <p><strong>Analysis Notes:</strong></p>
                            <ul>
                                ${data.reasons.map(reason => `<li>${reason}</li>`).join('')}
                            </ul>
                        </div>
                    `;
                } else {
                    resultDiv.className = 'result danger';
                    resultDiv.innerHTML = `
                        <h3>⚠️ WARNING: Potential PHISHING detected!</h3>
                        <p><strong>Analyzed URL:</strong> ${data.url}</p>
                        <p><strong>Threat Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</p>
                        <p><strong>Risk Score:</strong> ${data.risk_score}/5</p>
                        <p>🚨 <strong>Do NOT enter personal information on this website!</strong></p>
                        <div class="reasons">
                            <p><strong>Suspicious Indicators Found:</strong></p>
                            <ul>
                                ${data.reasons.map(reason => `<li>${reason}</li>`).join('')}
                            </ul>
                        </div>
                    `;
                }
                
                resultDiv.style.display = 'block';
                
            } catch (error) {
                resultDiv.className = 'result danger';
                resultDiv.innerHTML = `
                    <h3>❌ Analysis Error</h3>
                    <p>Unable to analyze the URL. Please check the URL format and try again.</p>
                    <p><strong>Error:</strong> ${error.message}</p>
                `;
                resultDiv.style.display = 'block';
            } finally {
                // Reset button state
                checkBtn.disabled = false;
                checkBtn.textContent = '🔍 Analyze URL';
                loading.style.display = 'none';
            }
        }
        
        // Allow Enter key to submit
        document.getElementById('urlInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                checkURL();
            }
        });
        </script>
    </body>
    </html>
    """

@app.post("/check")
async def check_url(request: URLRequest):
    result = simple_url_analysis(request.url)
    return result

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "simple"}

@app.get("/api/docs")
async def api_docs():
    return {
        "endpoints": {
            "/": "Web interface for URL checking",
            "/check": "POST endpoint for URL analysis",
            "/health": "Health check endpoint"
        },
        "example_request": {
            "url": "/check",
            "method": "POST",
            "body": {"url": "https://example.com"}
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)