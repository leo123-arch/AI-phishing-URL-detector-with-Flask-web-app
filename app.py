from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import re

app = Flask(__name__)
model = joblib.load('phishing_model.pkl')

feature_cols = ['url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdirs',
                 'num_params', 'suspicious_words', 'special_char_count', 'digits_count', 'entropy']

def shannon_entropy(s):
    import math
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs) if s else 0

def extract_features(url):
    has_https_flag = 1 if url.startswith('https') else 0
    # Strip the scheme before measuring everything else, to match how the
    # training data's benign URLs were represented (bare domains, no scheme)
    stripped = re.sub(r'^https?://', '', url)

    return {
        'url_length': len(stripped),
        'num_dots': stripped.count('.'),
        'has_https': has_https_flag,
        'has_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', stripped) else 0,
        'num_subdirs': stripped.count('/'),
        'num_params': stripped.count('?') + stripped.count('&'),
        'suspicious_words': sum(1 for w in ['login','verify','secure','account','update','bank'] if w in stripped.lower()),
        'special_char_count': sum(stripped.count(c) for c in '-_%@=~'),
        'digits_count': sum(c.isdigit() for c in stripped),
        'entropy': shannon_entropy(stripped),
    }
def explain(features):
    reasons = []
    if features['has_ip']:
        reasons.append("Uses an IP address instead of a domain name")
    if not features['has_https']:
        reasons.append("Does not use HTTPS")
    if features['num_dots'] >= 4:
        reasons.append("Unusually high number of subdomains")
    if features['suspicious_words'] > 0:
        reasons.append("Contains suspicious keywords (login/verify/secure/etc.)")
    if features['url_length'] > 75:
        reasons.append("Unusually long URL")
    if features['special_char_count'] > 5:
        reasons.append("High number of special characters")
    if features['entropy'] > 4.2:
        reasons.append("High randomness in URL characters")
    return reasons if reasons else ["No strong red-flag patterns detected"]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    url = request.json.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    features = extract_features(url)
    X = pd.DataFrame([features])[feature_cols]
    prediction = int(model.predict(X)[0])
    proba = model.predict_proba(X)[0][prediction]

    return jsonify({
        'url': url,
        'is_phishing': bool(prediction),
        'confidence': round(float(proba) * 100, 1),
        'reasons': explain(features),
        'features': features
    })

if __name__ == '__main__':
    app.run(debug=True)