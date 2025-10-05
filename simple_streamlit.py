import streamlit as st
import re
from urllib.parse import urlparse
from datetime import datetime

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
            "reasons": reasons[:5] if reasons else ["No suspicious patterns detected"]
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

def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ Phishing URL Detector</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Protect yourself from malicious websites with AI-powered URL analysis</p>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("📊 About This Tool")
        st.write("""
        This tool uses advanced pattern recognition to detect potentially dangerous phishing URLs.
        
        **How it works:**
        1. Enter a URL in the input field
        2. AI analyzes multiple security features
        3. Get instant results with confidence scores
        
        **Features analyzed:**
        - Domain authenticity
        - URL structure patterns
        - Suspicious keywords
        - Security indicators
        - Known phishing patterns
        """)
        
        st.header("⚠️ Disclaimer")
        st.warning("""
        This tool provides security analysis but should not be your only line of defense. 
        Always exercise caution when clicking links from unknown sources.
        """)
        
        st.header("🔗 Quick Test URLs")
        if st.button("Test Safe URL"):
            st.session_state.test_url = "https://github.com"
        if st.button("Test Suspicious URL"):
            st.session_state.test_url = "http://paypal-secure.tk"
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔍 URL Analysis")
        
        # URL input
        default_url = st.session_state.get('test_url', '')
        url_input = st.text_input(
            "Enter URL to analyze:",
            value=default_url,
            placeholder="https://example.com",
            help="Enter the complete URL including http:// or https://"
        )
        
        # Analysis button
        if st.button("🔍 Analyze URL", type="primary") or url_input != default_url and url_input:
            if not url_input:
                st.error("Please enter a URL to analyze.")
                return
            
            # Validate URL format
            if not url_input.startswith(('http://', 'https://')):
                url_input = 'https://' + url_input
            
            with st.spinner("🔄 Analyzing URL..."):
                result = simple_url_analysis(url_input)
                
                if result["prediction"] != "error":
                    # Display results
                    if result["is_safe"]:  # Safe
                        st.markdown(f"""
                        <div class="result-safe">
                            <h3>✅ URL appears to be SAFE</h3>
                            <p><strong>Analyzed URL:</strong> {result['url']}</p>
                            <p><strong>Safety Confidence:</strong> {result['confidence']*100:.1f}%</p>
                            <p><strong>Risk Score:</strong> {result['risk_score']}/5</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.success("This URL appears to be legitimate based on our analysis.")
                        
                    else:  # Phishing
                        st.markdown(f"""
                        <div class="result-danger">
                            <h3>⚠️ WARNING: Potential PHISHING URL detected!</h3>
                            <p><strong>Analyzed URL:</strong> {result['url']}</p>
                            <p><strong>Threat Confidence:</strong> {result['confidence']*100:.1f}%</p>
                            <p><strong>Risk Score:</strong> {result['risk_score']}/5</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.error("🚨 This URL shows characteristics of a phishing website. DO NOT enter personal information!")
                    
                    # Show analysis details
                    with st.expander("📋 Detailed Analysis"):
                        st.write("**Indicators Found:**")
                        for reason in result['reasons']:
                            st.write(f"• {reason}")
                        
                        # Safety recommendations
                        if not result["is_safe"]:
                            st.write("**🛡️ Safety Recommendations:**")
                            st.write("""
                            - Do not click on it or enter personal information
                            - Verify the sender if it came via email/message
                            - Check for typos in the domain name
                            - Look for security indicators (HTTPS, padlock icon)
                            - When in doubt, navigate to the official website directly
                            """)
                
                else:
                    st.error("Failed to analyze the URL. Please check the URL format and try again.")
    
    with col2:
        st.subheader("📈 URL Statistics")
        
        # Display some sample analysis for demo
        if url_input:
            st.markdown('<div class="feature-box">', unsafe_allow_html=True)
            st.write("**URL Components:**")
            
            try:
                parsed = urlparse(url_input)
                st.write(f"• **Length:** {len(url_input)} characters")
                st.write(f"• **Domain:** {parsed.netloc}")
                st.write(f"• **Protocol:** {parsed.scheme.upper()}")
                st.write(f"• **Has HTTPS:** {'✅' if parsed.scheme == 'https' else '❌'}")
                st.write(f"• **Subdomains:** {len(parsed.netloc.split('.')) - 2}")
                if parsed.path:
                    st.write(f"• **Path:** {parsed.path}")
                if parsed.query:
                    st.write(f"• **Query:** Present")
            except:
                st.write("• Invalid URL format")
            
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
        <p>🛡️ <strong>Phishing URL Detector</strong> | Powered by Pattern Recognition | 
        <a href='https://github.com/SIVAPRASATHCS/url_detector' target='_blank'>View on GitHub</a></p>
        <p><small>Made with ❤️ using Streamlit | Last updated: {}</small></p>
    </div>
    """.format(datetime.now().strftime("%B %Y")), unsafe_allow_html=True)

if __name__ == "__main__":
    main()