import streamlit as st
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import re
import requests
from datetime import datetime
import os

# Page configuration
st.set_page_config(
    page_title="🛡️ Phishing URL Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
.main-header {
    font-size: 3rem;
    color: #1f77b4;
    text-align: center;
    margin-bottom: 2rem;
}
.sub-header {
    font-size: 1.2rem;
    color: #666;
    text-align: center;
    margin-bottom: 3rem;
}
.result-safe {
    background-color: #d4edda;
    border: 1px solid #c3e6cb;
    border-radius: 0.5rem;
    padding: 1rem;
    margin: 1rem 0;
}
.result-danger {
    background-color: #f8d7da;
    border: 1px solid #f5c6cb;
    border-radius: 0.5rem;
    padding: 1rem;
    margin: 1rem 0;
}
.feature-box {
    background-color: #f8f9fa;
    border-radius: 0.5rem;
    padding: 1rem;
    margin: 0.5rem 0;
}
</style>
""", unsafe_allow_html=True)

class FeatureExtractor:
    def __init__(self):
        pass
    
    def extract_features(self, url):
        """Extract features from URL"""
        try:
            features = []
            
            # Basic URL properties
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # 1. URL Length
            features.append(len(url))
            
            # 2. Number of dots in URL
            features.append(url.count('.'))
            
            # 3. Number of hyphens in URL
            features.append(url.count('-'))
            
            # 4. Number of underscores in URL
            features.append(url.count('_'))
            
            # 5. Number of slashes in URL
            features.append(url.count('/'))
            
            # 6. Number of question marks in URL
            features.append(url.count('?'))
            
            # 7. Number of equal signs in URL
            features.append(url.count('='))
            
            # 8. Number of @ signs in URL
            features.append(url.count('@'))
            
            # 9. Number of ampersands in URL
            features.append(url.count('&'))
            
            # 10. Number of exclamation marks in URL
            features.append(url.count('!'))
            
            # 11. Number of spaces in URL
            features.append(url.count(' '))
            
            # 12. Number of tildes in URL
            features.append(url.count('~'))
            
            # 13. Number of commas in URL
            features.append(url.count(','))
            
            # 14. Number of plus signs in URL
            features.append(url.count('+'))
            
            # 15. Number of asterisks in URL
            features.append(url.count('*'))
            
            # 16. Number of hash signs in URL
            features.append(url.count('#'))
            
            # 17. Number of dollar signs in URL
            features.append(url.count('$'))
            
            # 18. Number of percent signs in URL
            features.append(url.count('%'))
            
            # 19. Has HTTPS
            features.append(1 if parsed_url.scheme == 'https' else 0)
            
            # 20. Domain length
            features.append(len(domain))
            
            # 21. Has IP address instead of domain
            ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            features.append(1 if ip_pattern.match(domain) else 0)
            
            # 22. Number of subdomains
            subdomains = domain.split('.')
            features.append(len(subdomains) - 2 if len(subdomains) > 2 else 0)
            
            # 23. Path length
            features.append(len(path))
            
            # 24. Query length
            query = parsed_url.query
            features.append(len(query))
            
            # 25. Fragment length
            fragment = parsed_url.fragment
            features.append(len(fragment))
            
            # 26-30. Suspicious keywords (common in phishing URLs)
            suspicious_keywords = ['secure', 'account', 'update', 'confirm', 'verify']
            for keyword in suspicious_keywords:
                features.append(1 if keyword in url.lower() else 0)
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            st.error(f"Error extracting features: {e}")
            return None

@st.cache_data
def load_model():
    """Load the trained model"""
    try:
        model_path = os.path.join(os.path.dirname(__file__), 'pickle', 'advanced_model.pkl')
        if not os.path.exists(model_path):
            # Try alternative path
            model_path = 'pickle/advanced_model.pkl'
        
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        return model
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None

def analyze_url(url, model, feature_extractor):
    """Analyze URL for phishing"""
    try:
        # Extract features
        features = feature_extractor.extract_features(url)
        if features is None:
            return None, None, None
        
        # Make prediction
        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0]
        
        return prediction, probability, features
        
    except Exception as e:
        st.error(f"Error analyzing URL: {e}")
        return None, None, None

def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ Phishing URL Detector</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Protect yourself from malicious websites with AI-powered URL analysis</p>', unsafe_allow_html=True)
    
    # Load model
    model = load_model()
    if model is None:
        st.error("❌ Failed to load the ML model. Please check the model file.")
        return
    
    feature_extractor = FeatureExtractor()
    
    # Sidebar
    with st.sidebar:
        st.header("📊 About This Tool")
        st.write("""
        This tool uses machine learning to detect potentially dangerous phishing URLs.
        
        **How it works:**
        1. Enter a URL in the input field
        2. AI analyzes 30+ features of the URL
        3. Get instant results with confidence scores
        
        **Features analyzed:**
        - URL structure and length
        - Domain characteristics
        - Suspicious keywords
        - Security indicators
        """)
        
        st.header("⚠️ Disclaimer")
        st.warning("""
        This tool provides security analysis but should not be your only line of defense. 
        Always exercise caution when clicking links from unknown sources.
        """)
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔍 URL Analysis")
        
        # URL input
        url_input = st.text_input(
            "Enter URL to analyze:",
            placeholder="https://example.com",
            help="Enter the complete URL including http:// or https://"
        )
        
        # Analysis button
        if st.button("🔍 Analyze URL", type="primary"):
            if not url_input:
                st.error("Please enter a URL to analyze.")
                return
            
            # Validate URL format
            if not url_input.startswith(('http://', 'https://')):
                url_input = 'http://' + url_input
            
            with st.spinner("🔄 Analyzing URL..."):
                prediction, probability, features = analyze_url(url_input, model, feature_extractor)
                
                if prediction is not None:
                    # Display results
                    if prediction == 0:  # Safe
                        st.markdown(f"""
                        <div class="result-safe">
                            <h3>✅ URL appears to be SAFE</h3>
                            <p><strong>Analyzed URL:</strong> {url_input}</p>
                            <p><strong>Confidence:</strong> {probability[0]*100:.1f}% safe</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.success("This URL appears to be legitimate based on our analysis.")
                        
                    else:  # Phishing
                        st.markdown(f"""
                        <div class="result-danger">
                            <h3>⚠️ WARNING: Potential PHISHING URL detected!</h3>
                            <p><strong>Analyzed URL:</strong> {url_input}</p>
                            <p><strong>Threat Level:</strong> {probability[1]*100:.1f}% likely to be phishing</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.error("🚨 This URL shows characteristics of a phishing website. DO NOT enter personal information!")
                        
                        # Safety recommendations
                        with st.expander("🛡️ Safety Recommendations"):
                            st.write("""
                            **If you suspect this URL is phishing:**
                            - Do not click on it or enter personal information
                            - Verify the sender if it came via email/message
                            - Check for typos in the domain name
                            - Look for security indicators (HTTPS, padlock icon)
                            - When in doubt, navigate to the official website directly
                            """)
                
                else:
                    st.error("Failed to analyze the URL. Please try again.")
    
    with col2:
        st.subheader("📈 Recent Analysis")
        
        # Display some sample analysis for demo
        if url_input and prediction is not None:
            st.markdown('<div class="feature-box">', unsafe_allow_html=True)
            st.write("**Analysis Details:**")
            
            parsed = urlparse(url_input)
            
            st.write(f"• **URL Length:** {len(url_input)} characters")
            st.write(f"• **Domain:** {parsed.netloc}")
            st.write(f"• **Protocol:** {parsed.scheme.upper()}")
            st.write(f"• **Has HTTPS:** {'✅' if parsed.scheme == 'https' else '❌'}")
            st.write(f"• **Subdomains:** {len(parsed.netloc.split('.')) - 2}")
            
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Tips section
        st.subheader("💡 Security Tips")
        with st.expander("How to spot phishing URLs"):
            st.write("""
            **Red flags to watch for:**
            - Suspicious domains (typos, extra characters)
            - Lack of HTTPS encryption
            - Shortened URLs that hide the real destination
            - Urgent language demanding immediate action
            - Requests for sensitive information via email
            
            **Best practices:**
            - Always check the URL before clicking
            - Type website addresses directly in your browser
            - Use bookmarks for important sites
            - Keep your browser updated
            - Enable two-factor authentication
            """)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; margin-top: 2rem;'>
        <p>🛡️ <strong>Phishing URL Detector</strong> | Powered by Machine Learning | 
        <a href='https://github.com/SIVAPRASATHCS/URL_DETECTOR' target='_blank'>View on GitHub</a></p>
        <p><small>Made with ❤️ using Streamlit | Last updated: {}</small></p>
    </div>
    """.format(datetime.now().strftime("%B %Y")), unsafe_allow_html=True)

if __name__ == "__main__":
    main()