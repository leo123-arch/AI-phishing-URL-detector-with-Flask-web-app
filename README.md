# AI Phishing URL Detector

An AI-powered web app that detects phishing URLs using a Random Forest classifier, with real-time explanations for why a URL was flagged.

## What it does
Paste any URL and get an instant prediction (safe/phishing) with a confidence score and the specific risk factors that triggered the result — not just a black-box yes/no.

## Dataset
- Source: [Phishing URLs Dataset with Extracted Features](https://www.kaggle.com/datasets/victusadi/phishing-urls-dataset-with-extracted-features) (Kaggle)
- 160,064 URLs, 12 engineered features per URL
- Note: dataset was heavily imbalanced (159,244 phishing vs. 820 benign) — handled using stratified train/test split and `class_weight='balanced'`

## Model
- Algorithm: Random Forest Classifier (scikit-learn)
- Features used: URL length, dot count, HTTPS presence, IP address presence, subdirectory count, parameter count, suspicious keyword count, special character count, digit count, Shannon entropy
- Performance: [PASTE YOUR precision/recall/f1 NUMBERS HERE]

## A real bug I found and fixed
Initial testing showed the model misclassifying obviously safe sites (e.g., google.com) as phishing with 100% confidence. Investigation revealed a train/serve mismatch: the training dataset's benign URLs were stored without a URL scheme (e.g. `google.com`), while my live feature extraction was computing features on full URLs (e.g. `https://google.com`), inflating length/subdirectory counts. Fixed by normalizing URLs (stripping the scheme before feature extraction) consistently across training and live inference.

## Tech Stack
Python, scikit-learn, pandas, Flask, HTML/CSS/JS

## How to run locally
\`\`\`bash
pip install flask pandas scikit-learn joblib
python app.py
\`\`\`
Then open http://127.0.0.1:5000

## Limitations
- Trained on a dataset with only 820 benign examples — a larger, more balanced dataset would likely improve real-world robustness
- Feature-based detection can miss phishing URLs that don't match known structural patterns (e.g., convincing look-alike domains with no other red flags)
