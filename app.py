import streamlit as st
import pandas as pd
import joblib
import re
import math
from urllib.parse import urlparse
from collections import Counter

# ========================================
# Feature Extraction Function (Same as Colab)
# ========================================
def extract_features(url):
    """
    Extract handcrafted features from a URL for phishing detection.
    Identical to the training function for consistency.
    """
    features = {}
    
    try:
        # Parse the URL
        parsed = urlparse(url)
        hostname = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # 1. URL Length Features
        features['url_length'] = len(url)
        features['hostname_length'] = len(hostname)
        features['path_length'] = len(path)
        
        # 2. Count Special Characters
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        features['num_percent'] = url.count('%')
        
        # 3. Count Digits
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['digit_ratio'] = sum(c.isdigit() for c in url) / max(len(url), 1)
        
        # 4. Special Character Ratio
        special_chars = len(re.findall(r'[^a-zA-Z0-9]', url))
        features['special_char_ratio'] = special_chars / max(len(url), 1)
        
        # 5. Number of Subdomains
        if hostname:
            subdomains = hostname.split('.')
            features['num_subdomains'] = max(len(subdomains) - 2, 0)
        else:
            features['num_subdomains'] = 0
        
        # 6. HTTPS Check
        features['is_https'] = 1 if parsed.scheme == 'https' else 0
        
        # 7. IP Address Detection
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['has_ip_address'] = 1 if re.search(ip_pattern, hostname) else 0
        
        # 8. Suspicious TLD Check
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
        features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0
        
        # 9. Query Parameters Count
        features['num_query_params'] = len(query.split('&')) if query else 0
        
        # 10. Shannon Entropy of Hostname
        if hostname:
            entropy = 0
            for count in Counter(hostname).values():
                probability = count / len(hostname)
                entropy -= probability * math.log2(probability)
            features['hostname_entropy'] = entropy
        else:
            features['hostname_entropy'] = 0
        
        # 11. Suspicious Keywords
        suspicious_keywords = ['login', 'signin', 'bank', 'account', 'update', 
                              'verify', 'secure', 'password', 'confirm', 'admin']
        features['has_suspicious_keyword'] = 1 if any(kw in url.lower() for kw in suspicious_keywords) else 0
        
        # 12. Abnormal URL Features
        features['abnormal_url'] = 1 if hostname and hostname not in url else 0
        
        # 13. Double Slash in Path
        features['double_slash_redirecting'] = 1 if '//' in path else 0
        
    except Exception as e:
        st.error(f"Error parsing URL: {e}")
        features = {
            'url_length': 0, 'hostname_length': 0, 'path_length': 0,
            'num_dots': 0, 'num_hyphens': 0, 'num_underscores': 0,
            'num_slashes': 0, 'num_question_marks': 0, 'num_equals': 0,
            'num_at': 0, 'num_ampersands': 0, 'num_percent': 0,
            'num_digits': 0, 'digit_ratio': 0, 'special_char_ratio': 0,
            'num_subdomains': 0, 'is_https': 0, 'has_ip_address': 0,
            'suspicious_tld': 0, 'num_query_params': 0, 'hostname_entropy': 0,
            'has_suspicious_keyword': 0, 'abnormal_url': 0, 'double_slash_redirecting': 0
        }
    
    return features

# ========================================
# Load Model and Feature Columns
# ========================================
@st.cache_resource
def load_model_and_features():
    try:
        model = joblib.load('phishing_detector_model.pkl')
        feature_columns = joblib.load('feature_columns.pkl')
        try:
            model_info = joblib.load('model_info.pkl')
        except:
            model_info = None
        return model, feature_columns, model_info
    except FileNotFoundError as e:
        st.error(f"❌ Model files not found! Please ensure the following files are in the same directory as app.py:")
        st.error("  - phishing_detector_model.pkl")
        st.error("  - feature_columns.pkl")
        st.stop()

# ========================================
# Streamlit UI
# ========================================
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔒",
    layout="centered"
)

# Load model
model, feature_columns, model_info = load_model_and_features()

# Title and Description
st.title("🔒 Phishing URL Detector")
st.markdown("### Detect malicious URLs using Machine Learning")

if model_info:
    st.info(f"**Model:** {model_info['model_name']} with {model_info['n_features']} features")

st.markdown("---")

# URL Input
st.subheader("Enter URL to Check")
url_input = st.text_input(
    "URL:",
    placeholder="https://example.com",
    help="Enter a complete URL including http:// or https://"
)

# Check URL Button
if st.button("🔍 Check URL", type="primary", use_container_width=True):
    if url_input.strip():
        with st.spinner("Analyzing URL..."):
            # Extract features
            features = extract_features(url_input)
            
            # Create DataFrame with correct column order
            features_df = pd.DataFrame([features])
            features_df = features_df[feature_columns]  # Ensure correct order
            
            # Make prediction
            prediction = model.predict(features_df)[0]
            prediction_proba = model.predict_proba(features_df)[0]

            print(prediction_proba)
            
            # Display results
            st.markdown("---")
            st.subheader("🔍 Analysis Result")
            
            if prediction == 1:
                # Phishing URL
                st.error("⚠️ **PHISHING URL DETECTED**")
                st.warning(f"This URL is likely malicious with {prediction_proba[1]*100:.1f}% confidence.")
                st.markdown("**⚠️ Warning:** Do not enter any personal information on this website!")
            else:
                # Legitimate URL
                st.success("✅ **LEGITIMATE URL**")
                st.info(f"This URL appears to be safe with {prediction_proba[0]*100:.1f}% confidence.")
                st.markdown("**Note:** Always exercise caution when entering sensitive information online.")
            
            # Optional: Show extracted features
            with st.expander("📊 View Extracted Features"):
                # Convert features to a nice display format
                features_display = pd.DataFrame({
                    'Feature': features.keys(),
                    'Value': features.values()
                })
                st.dataframe(features_display, use_container_width=True, hide_index=True)
    else:
        st.warning("⚠️ Please enter a URL to check.")

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: gray; font-size: 14px;'>
        <p>🎓 Machine Learning Project | Phishing Detection System</p>
        <p>Built with Random Forest & Handcrafted URL Features</p>
    </div>
    """,
    unsafe_allow_html=True
)

# Sidebar with information
with st.sidebar:
    st.header("ℹ️ About")
    st.markdown("""
    This tool analyzes URLs using machine learning to detect potential phishing attempts.
    
    **Features Analyzed:**
    - URL structure and length
    - Special characters and patterns
    - Domain characteristics
    - Suspicious keywords
    - Entropy analysis
    - And more...
    
    **How to Use:**
    1. Enter a complete URL
    2. Click "Check URL"
    3. Review the result
    """)
    
    st.markdown("---")
    st.subheader("🧪 Test Examples")
    st.code("https://www.google.com", language="text")
    st.code("http://secure-login-verify.tk", language="text")
    st.code("http://192.168.1.1/admin", language="text")