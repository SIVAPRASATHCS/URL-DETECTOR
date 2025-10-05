# Simple FastAPI deployment version
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import pickle
import os
from enhanced_feature_extractor import EnhancedFeatureExtraction

app = FastAPI(title="Phishing URL Detector", description="AI-powered URL safety checker")

# Load model
try:
    with open('pickle/advanced_model.pkl', 'rb') as f:
        model = pickle.load(f)
    feature_extractor = EnhancedFeatureExtraction()
except:
    model = None
    feature_extractor = None

class URLRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>🛡️ Phishing URL Detector</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .container { text-align: center; }
            .input-group { margin: 20px 0; }
            input[type="url"] { width: 60%; padding: 10px; font-size: 16px; }
            button { padding: 10px 20px; font-size: 16px; background: #007bff; color: white; border: none; cursor: pointer; }
            .result { margin-top: 20px; padding: 20px; border-radius: 5px; }
            .safe { background: #d4edda; border: 1px solid #c3e6cb; }
            .danger { background: #f8d7da; border: 1px solid #f5c6cb; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Phishing URL Detector</h1>
            <p>Check if a URL is safe or potentially malicious</p>
            <div class="input-group">
                <input type="url" id="urlInput" placeholder="Enter URL to check (e.g., https://example.com)" />
                <button onclick="checkURL()">Check URL</button>
            </div>
            <div id="result"></div>
        </div>
        
        <script>
        async function checkURL() {
            const url = document.getElementById('urlInput').value;
            if (!url) {
                alert('Please enter a URL');
                return;
            }
            
            try {
                const response = await fetch('/check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                
                const data = await response.json();
                const resultDiv = document.getElementById('result');
                
                if (data.is_safe) {
                    resultDiv.innerHTML = `
                        <div class="result safe">
                            <h3>✅ URL appears to be SAFE</h3>
                            <p>Confidence: ${(data.confidence * 100).toFixed(1)}%</p>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `
                        <div class="result danger">
                            <h3>⚠️ WARNING: Potential PHISHING detected!</h3>
                            <p>Threat Level: ${(data.confidence * 100).toFixed(1)}%</p>
                            <p>🚨 Do not enter personal information on this website!</p>
                        </div>
                    `;
                }
            } catch (error) {
                document.getElementById('result').innerHTML = 
                    '<div class="result">Error checking URL. Please try again.</div>';
            }
        }
        </script>
    </body>
    </html>
    """

@app.post("/check")
async def check_url(request: URLRequest):
    if not model or not feature_extractor:
        raise HTTPException(status_code=500, detail="Model not loaded")
    
    try:
        # Extract features
        features = feature_extractor.extract_features(request.url)
        
        # Make prediction
        prediction = model.predict([features])[0]
        probability = model.predict_proba([features])[0]
        
        return {
            "url": request.url,
            "is_safe": prediction == 0,
            "confidence": float(max(probability)),
            "prediction": "safe" if prediction == 0 else "phishing"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing URL: {str(e)}")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "model_loaded": model is not None}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))