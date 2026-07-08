from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import pandas as pd

# Use only the numeric features (drop url and tld for now — tld is text, needs encoding, skip it to save time)
feature_cols = ['url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdirs',
                 'num_params', 'suspicious_words', 'special_char_count', 'digits_count', 'entropy']

df = pd.read_csv('phishing_features.csv')  # rename to match your downloaded file


X = df[feature_cols]
y = df['label']

# stratify=y ensures both train and test sets keep the same 99.5%/0.5% ratio
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# class_weight='balanced' tells the model to penalize mistakes on the minority class (benign) more heavily
model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)

predictions = model.predict(X_test)
print(classification_report(y_test, predictions))
print(confusion_matrix(y_test, predictions))

joblib.dump(model, 'phishing_model.pkl')

importances = pd.Series(model.feature_importances_, index=feature_cols).sort_values(ascending=False)
print(importances)

print(df['url'].duplicated().sum())
print(df.duplicated(subset=feature_cols).sum())
test_urls = pd.DataFrame([
    {'url_length': 22, 'num_dots': 2, 'has_https': 1, 'has_ip': 0, 'num_subdirs': 1,
     'num_params': 0, 'suspicious_words': 0, 'special_char_count': 0, 'digits_count': 0, 'entropy': 3.5},
    {'url_length': 95, 'num_dots': 5, 'has_https': 0, 'has_ip': 1, 'num_subdirs': 4,
     'num_params': 3, 'suspicious_words': 2, 'special_char_count': 8, 'digits_count': 10, 'entropy': 4.8},
])
print(model.predict(test_urls[feature_cols]))
joblib.dump(model, 'phishing_model.pkl')
print("Model saved")