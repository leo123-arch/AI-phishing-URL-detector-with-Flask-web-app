from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import joblib, pandas as pd, re, math

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-to-something-random-later'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

model = joblib.load('phishing_model.pkl')
feature_cols = ['url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdirs',
                 'num_params', 'suspicious_words', 'special_char_count', 'digits_count', 'entropy']


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    is_phishing = db.Column(db.Boolean, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('That username is already taken.')
            return redirect(url_for('register'))
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('home'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password.')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def shannon_entropy(s):
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
        'suspicious_words': sum(1 for w in ['login', 'verify', 'secure', 'account', 'update', 'bank'] if w in stripped.lower()),
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
@login_required
def home():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
@login_required
def check_url():
    url = request.json.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    features = extract_features(url)
    X = pd.DataFrame([features])[feature_cols]
    prediction = int(model.predict(X)[0])
    proba = model.predict_proba(X)[0][prediction]
    confidence = round(float(proba) * 100, 1)

    # Log this scan against the logged-in user
    scan = Scan(
        user_id=current_user.id,
        url=url,
        is_phishing=bool(prediction),
        confidence=confidence
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({
        'url': url,
        'is_phishing': bool(prediction),
        'confidence': confidence,
        'reasons': explain(features),
        'features': features
    })


@app.route('/dashboard')
@login_required
def dashboard():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).all()
    total = len(scans)
    flagged = sum(1 for s in scans if s.is_phishing)
    safe = total - flagged
    flagged_pct = round((flagged / total) * 100, 1) if total > 0 else 0

    return render_template('dashboard.html',
                            scans=scans, total=total, flagged=flagged,
                            safe=safe, flagged_pct=flagged_pct)


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)