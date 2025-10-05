# Enterprise Database Schema
# Advanced database structure for production use

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    api_key VARCHAR(64) UNIQUE,
    plan_type VARCHAR(20) DEFAULT 'free', -- free, pro, enterprise
    requests_count INTEGER DEFAULT 0,
    requests_limit INTEGER DEFAULT 1000,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE url_analyses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    url_hash VARCHAR(64) UNIQUE,
    original_url TEXT NOT NULL,
    domain VARCHAR(255),
    is_phishing BOOLEAN,
    confidence_score FLOAT,
    risk_score INTEGER,
    analysis_data JSONB, -- Store detailed analysis results
    analysis_time_ms INTEGER,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE threat_intelligence (
    id SERIAL PRIMARY KEY,
    url_pattern VARCHAR(500),
    threat_type VARCHAR(50), -- phishing, malware, spam, etc.
    severity VARCHAR(20), -- low, medium, high, critical
    source VARCHAR(100), -- PhishTank, OpenPhish, custom, etc.
    confidence FLOAT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB
);

CREATE TABLE user_feedback (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    url_analysis_id INTEGER REFERENCES url_analyses(id),
    is_correct BOOLEAN,
    feedback_type VARCHAR(20), -- false_positive, false_negative, correct
    user_comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE api_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    endpoint VARCHAR(100),
    method VARCHAR(10),
    status_code INTEGER,
    response_time_ms INTEGER,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE analytics_daily (
    date DATE PRIMARY KEY,
    total_requests INTEGER DEFAULT 0,
    unique_users INTEGER DEFAULT 0,
    threats_detected INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    avg_response_time FLOAT DEFAULT 0,
    top_threats JSONB
);

-- Indexes for performance
CREATE INDEX idx_url_analyses_user_id ON url_analyses(user_id);
CREATE INDEX idx_url_analyses_created_at ON url_analyses(created_at);
CREATE INDEX idx_url_analyses_domain ON url_analyses(domain);
CREATE INDEX idx_threat_intelligence_pattern ON threat_intelligence USING gin(url_pattern gin_trgm_ops);
CREATE INDEX idx_api_requests_user_id ON api_requests(user_id);
CREATE INDEX idx_api_requests_created_at ON api_requests(created_at);