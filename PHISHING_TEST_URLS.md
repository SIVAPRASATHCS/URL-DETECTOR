# 🎯 Phishing URL Test Cases for SecureURL Guardian

## 🚨 **IMPORTANT DISCLAIMER**
**These are simulated phishing URLs for TESTING PURPOSES ONLY. Do NOT visit these URLs or use them maliciously. They are designed to test the detection system's capabilities.**

---

## 📝 **Test URLs That Will Trigger Phishing Detection**

### 🔴 **High-Risk URLs (Risk Score 70-100)**

#### **Brand Impersonation - Banking**
```
https://paypal-secure-verification.tk
https://amazon-account-suspended.ml
https://microsoft-office365-login.ga
https://apple-id-verification.cf
https://google-account-security.gq
```

#### **Cryptocurrency Scams**
```
https://bitcoin-wallet-recovery.pw
https://ethereum-exchange-bonus.top
https://crypto-trading-urgent.click
```

#### **Banking Phishing**
```
https://bank-account-verify-now.tk
https://secure-banking-login.ml
https://finance-credit-approval.ga
```

#### **Social Media Impersonation**
```
https://facebook-security-alert.cf
https://instagram-verification.gq
https://twitter-account-locked.pw
```

### 🟡 **Medium-Risk URLs (Risk Score 30-69)**

#### **URL Shorteners (Suspicious)**
```
https://bit.ly/suspicious-link
https://tinyurl.com/phishing-test
https://t.co/malicious-redirect
```

#### **Long Suspicious URLs**
```
https://legitimate-looking-domain.com/very/long/path/with/many/segments/and/parameters?verify=account&urgent=true&suspend=false&secure=login
```

#### **Typosquatting Examples**
```
https://gooogle.com
https://amazom.com
https://payp4l.com
https://micr0soft.com
```

### 🟢 **Low-Risk URLs (Should show as Safe)**
```
https://google.com
https://github.com
https://stackoverflow.com
https://microsoft.com
https://amazon.com
```

---

## 🧪 **Testing Instructions**

### **Step 1: Test High-Risk URLs**
1. Copy any URL from the **High-Risk** section
2. Paste it into the analysis field
3. **Expected Result**: Risk Score 70-100, marked as "POTENTIALLY DANGEROUS"
4. Enable "Deep Scan" for more detailed analysis
5. Generate PDF report to see comprehensive analysis

### **Step 2: Test Medium-Risk URLs**
1. Copy any URL from the **Medium-Risk** section  
2. **Expected Result**: Risk Score 30-69, marked as "MEDIUM RISK"
3. Should show specific threat indicators

### **Step 3: Test Safe URLs**
1. Copy any URL from the **Low-Risk** section
2. **Expected Result**: Risk Score 0-29, marked as "SAFE"

### **Step 4: Test Detection Features**

#### **Brand Impersonation Detection**
- Try: `https://paypal-secure-verification.tk`
- **Should detect**: "Potential phishing threat: paypal"
- **Risk factors**: "Contains phishing-related keyword: paypal"

#### **Suspicious TLD Detection**  
- Try: `https://legitimate-site.tk`
- **Should detect**: "High-risk TLD: .tk"

#### **URL Length Detection**
- Try the very long URL from medium-risk section
- **Should detect**: "Unusually long URL"

#### **IP Address Detection**
- Try: `http://192.168.1.1/login`
- **Should detect**: "Direct IP address usage"

---

## 🔍 **What Each Detection Catches**

### **High-Risk Indicators (Major Points)**
- ✅ **Suspicious TLDs**: .tk, .ml, .ga, .cf, .gq, .pw, .top, .click
- ✅ **Brand Keywords**: paypal, amazon, google, microsoft, apple, facebook
- ✅ **Security Keywords**: secure, verify, update, confirm, suspend, urgent
- ✅ **Banking Terms**: bank, finance, credit, loan, investment
- ✅ **Crypto Terms**: bitcoin, ethereum, crypto, wallet, exchange

### **Medium-Risk Indicators**
- ✅ **URL Shorteners**: bit.ly, tinyurl.com, t.co, ow.ly
- ✅ **Long URLs**: Over 150 characters
- ✅ **Complex Subdomains**: More than 3 subdomains
- ✅ **Suspicious Encoding**: Multiple % encodings

### **Technical Analysis (Deep Scan)**
- ✅ **SSL Certificate**: Validity and issuer check
- ✅ **Content Analysis**: Forms, JavaScript, social engineering
- ✅ **Network Analysis**: Response time, security headers

---

## 📊 **Expected Test Results**

### **High-Risk URL Example**
```
URL: https://paypal-secure-verification.tk
Risk Score: 85/100
Risk Level: High
Threats Detected:
- Potential phishing threat: paypal
- High-risk TLD: .tk
- Contains security-related keyword: secure
- Contains security-related keyword: verification
```

### **Medium-Risk URL Example**
```
URL: https://bit.ly/suspicious-link  
Risk Score: 45/100
Risk Level: Medium
Threats Detected:
- URL shortener detected
```

### **Safe URL Example**
```
URL: https://google.com
Risk Score: 5/100
Risk Level: Low
Safety Indicators:
- Known legitimate domain
- Uses HTTPS encryption
```

---

## 🎯 **Advanced Testing Scenarios**

### **Test Report Generation**
1. Analyze a high-risk URL
2. Enable "Generate PDF Report" 
3. Download the detailed report
4. Verify it contains technical details and recommendations

### **Test Mobile Interface**
1. Open application on mobile browser
2. Test touch-friendly interface
3. Verify responsive design works properly

### **Test Dashboard**
1. Navigate to `/dashboard`
2. View recent analyses
3. Check real-time statistics

---

## ⚠️ **Safety Reminders**

- **Never visit these test URLs in a real browser**
- **These are for testing the detection system only**
- **Do not use these URLs for actual phishing attempts**
- **Report any real phishing URLs to appropriate authorities**

---

**🛡️ Happy Testing! Your SecureURL Guardian should now properly detect various types of phishing attempts.**