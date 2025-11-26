# 🔒 Phishing URL Detector

Machine Learning-based phishing URL detection system using Random Forest and handcrafted features.

## 📋 Overview

This project detects phishing URLs by analyzing 24 handcrafted features extracted from URL structure.


## 🚀 Installation & Setup

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Step 1: Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector
```

### Step 2: Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`

## 📝 Usage

1. Enter a URL in the text input field
2. Click "Check URL" button
3. View the prediction result:
   - ✅ **Legitimate**: URL appears safe
   - ⚠️ **Phishing**: URL is potentially malicious
4. Expand "View Extracted Features" to see detailed analysis

## 🧪 Example URLs to Test

**Legitimate:**
- `https://www.google.com`
- `https://www.github.com`
- `https://www.python.org`

**Suspicious (for testing):**
- `http://secure-login-verify.tk`
- `http://paypal-account-update.ml`
- `http://192.168.1.1/admin`

## 📁 Project structure
phishing-detector/
├── app.py                          # Streamlit web application
├── training_notebook.py        # Model training code (Colab)
├── phishing_detector_model.pkl     # Trained Random Forest model
├── feature_columns.pkl             # Feature order for prediction
├── model_info.pkl                  # Model metadata
├── requirements.txt                # Python dependencies
└── README.md                       # Project documentation

## 🔍 Features Analyzed

The model analyzes 24 different URL characteristics:

### Length Metrics
- URL length, hostname length, path length

### Character Counts
- Dots, hyphens, underscores, slashes, special characters

### Security Indicators
- HTTPS usage, IP address detection

### Structural Analysis
- Number of subdomains, query parameters

### Pattern Detection
- Suspicious TLD, suspicious keywords, entropy analysis

## 🎓 Model Training

The model was trained using Google Colab. See `training_notebook.ipynb` for complete training code.

### Dataset
- **Source**: HuggingFace - shawhin/phishing-site-classification
- **Size**: 11,000+ labeled URLs
- **Split**: 80% training, 20% testing
- **Classes**: Phishing (1), Legitimate (0)

### Training Process
1. Load dataset from HuggingFace
2. Extract 24 handcrafted features
3. Train Random Forest (100 trees) and XGBoost
4. Evaluate on test set
5. Select best performing model
6. Save model for deployment

