# 🛡️ Phishing URL Detection Tool

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Deploy](https://img.shields.io/badge/deploy-ready-brightgreen.svg)](#-deployment)

> **A free, open-source web application that helps users identify phishing URLs and malicious websites using advanced machine learning algorithms.**

## 🌟 **Live Demo**

🔗 **Try it now:** [![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/SIVAPRASATHCS/URL-DETECTOR) - Get your live URL in 1 minute!

![Phishing Detection Demo](https://via.placeholder.com/800x400/667eea/white?text=Phishing+URL+Detection+Tool)

## 📋 **Table of Contents**
- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [💻 Installation](#-installation)
- [🌐 Deployment](#-deployment)
- [📖 Usage](#-usage)
- [🔧 API Documentation](#-api-documentation)
- [🏗️ Architecture](#️-architecture)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## ✨ **Features**

### 🎯 **For End Users**
- **🔍 Instant URL Analysis** - Check any URL in seconds
- **🛡️ AI-Powered Detection** - Advanced ML model with 30+ features
- **📱 Mobile-Friendly** - Responsive web interface
- **🆓 Completely Free** - No registration or limits
- **🔒 Privacy-First** - No data collection or tracking

### 🛠️ **For Developers**
- **⚡ FastAPI Backend** - Modern async web framework
- **📊 REST API** - Full API access with documentation
- **🐳 Docker Ready** - Container deployment support
- **☁️ Cloud Deploy** - Ready for Railway, Render, Heroku
- **📈 Production Ready** - Rate limiting, logging, error handling

## 🚀 **Quick Start**

### **🌐 Try Online (Recommended)**
Deploy to any cloud platform below to get your live URL - No local installation needed!

### **💻 Run Locally**
```bash
# Clone the repository
git clone https://github.com/SIVAPRASATHCS/URL-DETECTOR.git
cd URL-DETECTOR

# Install dependencies
pip install -r deploy_requirements.txt

# Start the server
python -m uvicorn enhanced_main:app --host 0.0.0.0 --port 8000

# Visit: http://localhost:8000
```

## 💻 **Installation**

### **Prerequisites**
- Python 3.8+ 
- pip (Python package manager)

### **Step 1: Clone Repository**
```bash
git clone https://github.com/SIVAPRASATHCS/URL-DETECTOR.git
cd URL-DETECTOR
```

### **Step 2: Install Dependencies**
```bash
# Install production dependencies
pip install -r deploy_requirements.txt
```

### **Step 3: Run Application**
```bash
# Start the FastAPI server
python -m uvicorn enhanced_main:app --host 0.0.0.0 --port 8000
```

### **Step 4: Access Application**
- **Web Interface:** http://localhost:8000
- **API Documentation:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health

## 🌐 **Deployment**

Deploy your phishing URL detector for public access in minutes!

### **☁️ Cloud Platforms (Recommended):**

#### **🔥 Railway.app** (Easiest - 2 minutes)

**Option A: Direct Template Deploy**
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/DIY9WE)

**Option B: Manual Deploy**
1. Visit [railway.app](https://railway.app)
2. Click "New Project" → "Empty Project"
3. Connect GitHub: `SIVAPRASATHCS/URL-DETECTOR`
4. Set start command: `uvicorn enhanced_main:app --host 0.0.0.0 --port $PORT`
5. Deploy and get: `https://your-app.railway.app`

#### **⚡ Vercel** (Fastest deployment - 1 minute)
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/SIVAPRASATHCS/URL-DETECTOR)

**Manual steps:**
1. Visit [vercel.com](https://vercel.com)
2. Click "New Project" → Import from GitHub
3. Select `SIVAPRASATHCS/URL-DETECTOR`
4. **Automatic deployment!** - Vercel detects Python + FastAPI
5. Get URL: `https://your-app.vercel.app`

#### **🌊 Render.com** (Free tier available)
1. Visit [render.com](https://render.com)
2. New Web Service → Connect GitHub
3. **Build Command:** `pip install -r deploy_requirements.txt`
4. **Start Command:** `uvicorn enhanced_main:app --host 0.0.0.0 --port $PORT`
5. Deploy and get: `https://your-app.onrender.com`

#### **🟣 Heroku** (Classic choice)
```bash
# Install Heroku CLI, then:
heroku create your-phishing-detector
git push heroku main
heroku open
```

### **🐳 Docker Deployment:**
```bash
# Build and run locally
docker build -t phishing-detector .
docker run -d -p 8000:8000 phishing-detector

# Visit: http://localhost:8000
```

### **📝 Environment Variables:**
For production deployment, set these variables:
- `ENVIRONMENT=production`
- `MAX_REQUESTS_PER_MINUTE=100`
- `DEBUG=false`

## 📖 **Usage**

### **🌐 Web Interface**
1. Open your browser and navigate to the application URL
2. Enter a URL in the input field (e.g., `https://suspicious-site.com`)
3. Click "Check URL Safety"
4. Get instant results with confidence scores

### **⚡ API Usage**
```bash
# Check a URL via API
curl -X POST "http://localhost:8000/analyze" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'

# Response
{
  "url": "https://example.com",
  "prediction": "safe",
  "confidence": 0.95,
  "risk_factors": [],
  "analysis_time": "2.1s"
}
```

## 🔧 **API Documentation**

### **Endpoints**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Web interface |
| POST | `/analyze` | Analyze URL |
| GET | `/docs` | API documentation |
| GET | `/health` | Health check |

### **Request Format**
```json
{
  "url": "https://example.com",
  "detailed_analysis": true
}
```

### **Response Format**
```json
{
  "url": "https://example.com",
  "prediction": "safe" | "phishing",
  "confidence": 0.95,
  "risk_factors": ["suspicious_domain", "no_https"],
  "features_analyzed": 30,
  "analysis_time": "1.2s",
  "timestamp": "2025-10-04T12:00:00Z"
}
```

## 🏗️ **Architecture**

### **🧠 Machine Learning Model**
- **Algorithm:** Advanced Gradient Boosting Classifier
- **Features:** 30+ URL characteristics analyzed
- **Accuracy:** 95%+ detection rate
- **Training Data:** Comprehensive phishing and legitimate URL dataset

### **📊 Feature Analysis**
- Domain characteristics
- URL structure patterns
- SSL certificate validation
- DNS information
- Content analysis
- Reputation scoring

### **🔧 Technical Stack**
- **Backend:** FastAPI (Python)
- **Frontend:** HTML5, CSS3, JavaScript
- **ML:** scikit-learn, pandas, numpy
- **Database:** SQLite (lightweight)
- **Deployment:** Docker, Railway, Render, Heroku

### **📁 Project Structure**
```
phishing-url-detection/
├── enhanced_main.py              # FastAPI application
├── enhanced_feature_extractor.py # ML feature extraction
├── advanced_ml_model.py          # ML model wrapper
├── templates/
│   ├── public_index.html         # Public web interface
│   └── advanced_index.html       # Advanced interface
├── pickle/
│   └── advanced_model.pkl        # Pre-trained ML model
├── static/
│   └── styles.css                # Styling
├── deploy_requirements.txt       # Production dependencies
├── Dockerfile                    # Container deployment
├── railway.toml                  # Railway.app config
└── render.yaml                   # Render.com config
```

## 🎯 **Model Performance**

| Metric | Score |
|--------|-------|
| **Accuracy** | 95.2% |
| **Precision** | 94.8% |
| **Recall** | 95.6% |
| **F1-Score** | 95.2% |

### **🔍 Detection Capabilities**
- Phishing websites
- Malicious domains
- Suspicious redirects
- Fake login pages
- Compromised websites
- Social engineering attacks

## 🤝 **Contributing**

We welcome contributions! Here's how you can help:

### **🐛 Report Issues**
- Found a bug? [Create an issue](https://github.com/SIVAPRASATHCS/URL-DETECTOR/issues)
- Have a suggestion? [Start a discussion](https://github.com/SIVAPRASATHCS/URL-DETECTOR/discussions)

### **✨ Contribute Code**
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### **📚 Improve Documentation**
- Fix typos or unclear instructions
- Add examples or use cases
- Translate documentation

## 👥 **Community**

- **⭐ Star this repository** if you find it useful
- **🍴 Fork it** to create your own version
- **📢 Share it** with your network
- **🤝 Contribute** to make it better

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- Thanks to the cybersecurity community for threat intelligence
- Built with ❤️ for internet safety
- Inspired by the need to make the web safer for everyone

## 🔗 **Links**

- **🐙 Repository:** [GitHub](https://github.com/SIVAPRASATHCS/URL-DETECTOR)
- **📊 API Docs:** [Interactive Documentation](/docs)
- **🤝 Contributing:** [Guidelines](CONTRIBUTING.md)

---

<div align="center">

**🛡️ Help make the internet safer, one URL at a time! 🌐**

[![GitHub stars](https://img.shields.io/github/stars/SIVAPRASATHCS/URL-DETECTOR?style=social)](https://github.com/SIVAPRASATHCS/URL-DETECTOR)
[![GitHub forks](https://img.shields.io/github/forks/SIVAPRASATHCS/URL-DETECTOR?style=social)](https://github.com/SIVAPRASATHCS/URL-DETECTOR)

*Made with ❤️ by [SIVAPRASATHCS](https://github.com/SIVAPRASATHCS)*

</div>