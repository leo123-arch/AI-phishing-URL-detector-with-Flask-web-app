import pandas as pd
from app import extract_features  # reuse your actual function

df = pd.read_csv('phishing_features.csv')

feature_cols = ['url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdirs',
                 'num_params', 'suspicious_words', 'special_char_count', 'digits_count', 'entropy']

print("=== Average features for BENIGN (label=0) rows in training data ===")
print(df[df['label'] == 0][feature_cols].mean())

print("\n=== Average features for PHISHING (label=1) rows in training data ===")
print(df[df['label'] == 1][feature_cols].mean())

print("\n=== What our live function computes for google.com ===")
print(extract_features("https://www.google.com"))