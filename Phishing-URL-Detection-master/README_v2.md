# 🛡️ PhishGuard - Advanced Phishing URL Detection System

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-green.svg)
![Security](https://img.shields.io/badge/security-phishing%20detection-red.svg)

**PhishGuard** is a state-of-the-art phishing URL detection system powered by machine learning and real-time threat intelligence. This upgraded version features a modern FastAPI backend, React frontend, advanced feature extraction, and comprehensive security analysis.

## 🚀 New Features (v2.0)

### ✨ **Major Upgrades**
- **Modern FastAPI Backend**: Async support, automatic documentation, better performance
- **React-based Frontend**: Beautiful, responsive UI with real-time updates
- **Enhanced Feature Extraction**: 30+ advanced security features + real-time threat intelligence
- **Database Integration**: SQLite/PostgreSQL support with scan history and statistics
- **REST API**: Comprehensive API with batch processing and detailed analytics
- **Docker Support**: Easy deployment with Docker and Docker Compose
- **Real-time Analysis**: Live SSL certificate, DNS, and WHOIS analysis
- **Advanced Security**: Rate limiting, input validation, and security headers

### 🔧 **Technical Improvements**
- Async/await support for better performance
- Comprehensive error handling and logging
- Input validation with Pydantic models
- Background task processing
- Caching support (Redis)
- Health checks and monitoring
- Comprehensive test suite

## 📁 Project Structure

```
PhishGuard/
├── main.py                          # FastAPI application
├── enhanced_feature_extractor.py    # Advanced feature extraction
├── database.py                      # Database management
├── models.py                        # Pydantic models
├── config.py                        # Configuration settings
├── test_api.py                      # Test suite
├── requirements_updated.txt         # Updated dependencies
├── Dockerfile                       # Docker configuration
├── docker-compose.yml              # Multi-service deployment
├── pickle/
│   └── model.pkl                   # ML model
├── templates/
│   └── enhanced_index.html         # React frontend
├── static/
│   └── styles.css                  # CSS styles
└── README_v2.md                    # This file
```

## 🏃 Quick Start

### Method 1: Direct Python (Recommended for development)

1. **Clone and setup**:
```bash
cd Phishing-URL-Detection-master
```

2. **Install dependencies**:
```bash
pip install -r requirements_updated.txt
```

3. **Run the application**:
```bash
python main.py
```

4. **Access the application**:
   - Web Interface: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Alternative docs: http://localhost:8000/redoc

### Method 2: Docker (Recommended for production)

1. **Using Docker**:
```bash
docker build -t phishguard .
docker run -p 8000:8000 phishguard
```

2. **Using Docker Compose** (includes database and Redis):
```bash
docker-compose up -d
```

## 🔥 API Usage Examples

### Single URL Analysis
```bash
curl -X POST "http://localhost:8000/api/v1/analyze" \
     -H "Content-Type: application/json" \
     -d '{
       "url": "https://suspicious-site.com",
       "include_features": true,
       "check_real_time": true
     }'
```

### Batch Analysis
```bash
curl -X POST "http://localhost:8000/api/v1/batch-analyze" \
     -H "Content-Type: application/json" \
     -d '{
       "urls": [
         "https://google.com",
         "https://suspicious-site.com",
         "https://amazon.com"
       ],
       "include_features": false
     }'
```

### Get Statistics
```bash
curl "http://localhost:8000/api/v1/stats"
```

### Get Scan History
```bash
curl "http://localhost:8000/api/v1/history?limit=10"
```

## 🧠 Enhanced Features

### Advanced Feature Extraction
- **Traditional Features**: 30 classic phishing detection features
- **SSL Analysis**: Certificate validation, expiry, issuer analysis
- **DNS Intelligence**: Real-time DNS reputation checking
- **WHOIS Analysis**: Domain age, registration details
- **Content Analysis**: JavaScript behavior, form handlers
- **Threat Intelligence**: Pattern matching against known threats

### Real-time Security Analysis
- Live SSL certificate validation
- DNS reputation scoring
- Domain age and registration analysis
- Suspicious pattern detection
- Unicode/punycode analysis

### Performance & Scalability
- Async processing for better performance
- Background task execution
- Redis caching support
- Database connection pooling
- Rate limiting and DDoS protection

## 📊 Monitoring & Analytics

### Built-in Dashboards
- Real-time scan statistics
- Threat detection trends
- Performance metrics
- API usage analytics

### Health Monitoring
```bash
# Check system health
curl http://localhost:8000/health

# Response includes:
{
  "status": "healthy",
  "timestamp": "2025-10-02T...",
  "model_loaded": true,
  "database_connected": true,
  "version": "2.0.0"
}
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest test_api.py -v

# Run with coverage
pytest test_api.py --cov=. --cov-report=html
```

### Test Coverage
- API endpoint testing
- Feature extraction validation
- Database operations
- Performance benchmarks
- Security validation

## 🔒 Security Features

### Input Validation
- URL format validation
- Request size limits
- SQL injection prevention
- XSS protection

### Rate Limiting
- Per-IP request limiting
- API key-based quotas
- DDoS protection

### Security Headers
- CORS configuration
- HTTPS enforcement
- Security headers (HSTS, CSP, etc.)

## 🚀 Deployment Options

### 1. Development Server
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Production with Gunicorn
```bash
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker
```

### 3. Docker Production
```bash
docker-compose -f docker-compose.yml up -d
```

### 4. Kubernetes (Advanced)
```yaml
# kubernetes-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phishguard-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: phishguard-api
  template:
    metadata:
      labels:
        app: phishguard-api
    spec:
      containers:
      - name: api
        image: phishguard:latest
        ports:
        - containerPort: 8000
```

## 🌐 API Documentation

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Web interface |
| GET | `/health` | Health check |
| GET | `/docs` | API documentation |
| POST | `/api/v1/analyze` | Single URL analysis |
| POST | `/api/v1/batch-analyze` | Batch URL analysis |
| GET | `/api/v1/stats` | System statistics |
| GET | `/api/v1/history` | Scan history |

### Response Models

All API responses follow consistent JSON schemas with proper error handling:

```json
{
  "url": "https://example.com",
  "is_phishing": false,
  "confidence": 0.95,
  "risk_score": 0.1,
  "risk_level": "low",
  "analysis_time": 1.23,
  "timestamp": "2025-10-02T12:00:00Z",
  "threat_intel": {
    "domain_reputation": {...},
    "ssl_analysis": {...},
    "suspicious_patterns": {...}
  }
}
```

## 🔧 Configuration

### Environment Variables
```bash
# Application settings
ENVIRONMENT=production
DEBUG=false
HOST=0.0.0.0
PORT=8000

# Database
DATABASE_URL=sqlite:///./phishing_detection.db
# or PostgreSQL: postgresql://user:pass@localhost/dbname

# Redis (optional)
REDIS_URL=redis://localhost:6379

# Security
SECRET_KEY=your-secret-key-here
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600

# External APIs (optional)
VIRUSTOTAL_API_KEY=your-vt-key
GOOGLE_SAFE_BROWSING_API_KEY=your-gsb-key
```

### Custom Configuration
Create a `.env` file with your settings:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## 📈 Performance Benchmarks

### Typical Performance Metrics
- **Single URL Analysis**: ~1-3 seconds
- **Batch Processing**: ~0.5 seconds per URL
- **Memory Usage**: ~100-200MB base
- **Concurrent Users**: 100+ simultaneous connections
- **Throughput**: 1000+ requests per minute

### Optimization Tips
1. Enable Redis caching for better performance
2. Use batch processing for multiple URLs
3. Disable real-time checks for faster analysis
4. Deploy with multiple workers in production

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and add tests
4. Run the test suite: `pytest`
5. Submit a pull request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements_updated.txt
pip install -r requirements-dev.txt  # If available

# Run in development mode
uvicorn main:app --reload

# Run tests
pytest -v
```

## 📝 Changelog

### v2.0.0 (Current)
- ✅ FastAPI backend with async support
- ✅ React frontend with modern UI
- ✅ Enhanced feature extraction (30+ features)
- ✅ Real-time threat intelligence
- ✅ Database integration (SQLite/PostgreSQL)
- ✅ REST API with comprehensive documentation
- ✅ Docker and Docker Compose support
- ✅ Comprehensive testing suite
- ✅ Security improvements and rate limiting

### v1.0.0 (Original)
- Basic Flask application
- Simple ML model
- 30 traditional phishing features
- Basic web interface

## 🛡️ Security Notice

This tool is for educational and legitimate security purposes only. Always:
- Respect website terms of service
- Use responsibly and ethically
- Report actual phishing sites to appropriate authorities
- Keep the system updated with latest security patches

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Original project contributors
- Security research community
- Open source libraries and frameworks
- FastAPI and React communities

## 📞 Support

- 📚 [Documentation](http://localhost:8000/docs)
- 🐛 [Issue Tracker](https://github.com/your-repo/issues)
- 💬 [Discussions](https://github.com/your-repo/discussions)
- 📧 Email: security@yourproject.com

---

**⚠️ Disclaimer**: This tool is for educational and research purposes. Use responsibly and in compliance with applicable laws and terms of service.