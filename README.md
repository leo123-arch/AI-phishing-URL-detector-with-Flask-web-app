# AI Phishing URL Detector

A full-stack security web app that detects phishing URLs using machine learning, with user accounts and persistent scan history.

## Features
- User registration and login (Flask-Login, hashed passwords)
- Real-time URL risk scoring via a Random Forest classifier
- Feature-level explanations for every verdict (not just a black-box score)
- Per-user scan history and stats dashboard
- Downloadable CSV scan reports
- Responsive UI

## Tech Stack
- **Backend:** Python, Flask, Flask-Login, Flask-SQLAlchemy
- **ML:** scikit-learn (Random Forest), pandas
- **Database:** SQLite
- **Frontend:** HTML, CSS, JavaScript (Jinja2 templating)

## Dataset
[Phishing URLs Dataset with Extracted Features](https://www.kaggle.com/datasets/victusadi/phishing-urls-dataset-with-extracted-features) — 160,064 URLs, 12 engineered features. Note: dataset was heavily imbalanced (159,244 phishing vs. 820 benign); handled with stratified train/test split and `class_weight='balanced'`.

## A real bug I found and fixed
Initial testing showed the model misclassifying safe sites (e.g. google.com) as phishing with 100% confidence. Root cause: the training dataset's benign URLs were stored without a URL scheme, while live feature extraction computed features on full URLs, inflating length/subdirectory counts. Fixed by normalizing URLs (stripping the scheme) consistently across training and inference.

## How to Run Locally
\`\`\`bash
pip install flask flask-login flask-sqlalchemy werkzeug pandas scikit-learn joblib
python app.py
\`\`\`
Visit http://127.0.0.1:5000, register an account, and start scanning.

## Limitations
- Trained on only 820 benign examples — a larger, more balanced dataset would improve real-world robustness
- Feature-based detection can miss phishing URLs with no obvious structural red flags
- SECRET_KEY should be set via environment variable in production, not hardcoded
