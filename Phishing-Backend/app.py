from flask import Flask, request, jsonify
import joblib
import numpy as np
from utils import extract_features # Ensure this is updated with all 33 features
from flask_cors import CORS
from urllib.parse import urlparse
import re

app = Flask(__name__)
CORS(app)

# --- Global Variables for Model and Scaler ---
model = None
scaler = None
MODEL_ACCURACY = 0.0

# --- Load the trained model and scaler ---
try:
    model = joblib.load('phishing_model.pkl')
    scaler = joblib.load('phishing_scaler.pkl')
    print("✅ Model and Scaler loaded successfully!")
    # Update this with the actual accuracy from your training script's last run
    MODEL_ACCURACY = 99.71 # REMEMBER TO REPLACE THIS WITH YOUR ACTUAL ACCURACY
except FileNotFoundError:
    print("❌ Error: 'phishing_model.pkl' or 'phishing_scaler.pkl' not found.")
    print("Please ensure you have run 'phishing_model_training.py' to train and save the model/scaler.")
except Exception as e:
    print(f"❌ An error occurred while loading the model or scaler: {e}")

# --- Trusted domains to bypass model ---
trusted_domains = {
    "google.com", "gmail.com", "openai.com", "facebook.com",
    "youtube.com", "linkedin.com", "amazon.com", "microsoft.com",
    "apple.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "reddit.com", "twitter.com", "instagram.com", "netflix.com", # Corrected "redit.com" to "reddit.com"
    "discord.com", "medium.com", "dev.to", "developer.mozilla.org",
    "docs.python.org", "w3schools.com"
}

# --- Helper function to extract domain from URL ---
def get_domain(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except:
        return ""

# --- Feature Mapping for get_prediction_reasons ---
# This map MUST match the order and number of features returned by utils.extract_features
feature_map = [
    "url_length",                      # 0: len(url)
    "num_hyphens",                     # 1: url.count('-')
    "has_at_symbol",                   # 2: url.count('@')
    "num_double_slashes",              # 3: url.count('//')
    "uses_https",                      # 4: 1 if parsed.scheme == 'https' else 0
    "num_dots_in_hostname",            # 5: hostname.count('.')
    "is_ip_address_in_hostname",       # 6: is_ip_address
    "is_suspicious_tld",               # 7: 1 if tld in SUSPICIOUS_TLDS else 0
    "num_subdomains",                  # 8: len(subdomain_parts)
    "is_shortened_url",                # 9: is_shortened
    "domain_entropy",                  # 10: calculate_entropy(ext.domain)
    "main_domain_length",              # 11: len(ext.domain)
    "path_length",                     # 12: len(path)
    "query_length",                    # 13: len(query)
    # Keyword features (16 of them, starting from index 14)
    "keyword_login",                   # 14
    "keyword_secure",                  # 15
    "keyword_bank",                    # 16
    "keyword_update",                  # 17
    "keyword_verify",                  # 18
    "keyword_account",                 # 19
    "keyword_webscr",                  # 20
    "keyword_confirm",                 # 21
    "keyword_signin",                  # 22
    "keyword_password",                # 23
    "keyword_free",                    # 24
    "keyword_gift",                    # 25
    "keyword_award",                   # 26
    "keyword_alert",                   # 27
    "keyword_error",                   # 28
    "keyword_invoice",                 # 29
    "num_digits_in_url",               # 30: sum(char.isdigit() for char in full_url_lower)
    "num_unusual_special_chars_in_url",# 31: sum(not c.isalnum()...)
    "url_path_depth"                   # 32: path.count('/')
]

def get_prediction_reasons(url, features_list, proba):
    reasons = []
    
    # Map features_list to a dictionary for easier access by name
    features_dict = {feature_map[i]: features_list[i] for i in range(len(features_list))}

    # --- Reasons for Phishing Risk (higher proba) ---
    if proba >= 0.55: # Start giving specific reasons if probability is moderately high
        # Security/Trust Indicators
        if features_dict["uses_https"] == 0:
            reasons.append("The site does NOT use HTTPS (not secure).")
        if features_dict["is_ip_address_in_hostname"] == 1:
            reasons.append("IP address used in URL instead of a legitimate domain name.")
        if features_dict["is_suspicious_tld"] == 1:
            reasons.append("Uses a Top-Level Domain (TLD) frequently associated with phishing.")
        if features_dict["is_shortened_url"] == 1:
            reasons.append("The URL is shortened, which can conceal the true destination.")

        # Obfuscation/Complexity
        if features_dict["url_length"] > 75: # Example threshold
            reasons.append("Very long URL, often used to hide malicious parts.")
        if features_dict["num_hyphens"] > 3: # Example threshold
            reasons.append("Excessive hyphens in the domain/URL, a common phishing tactic.")
        if features_dict["has_at_symbol"] == 1:
            reasons.append("URL contains an '@' symbol, which can be used to mislead.")
        if features_dict["num_double_slashes"] > 1:
            reasons.append("Unusual number of double slashes, often a sign of obfuscation.")
        if features_dict["num_subdomains"] > 3: # Example threshold
            reasons.append("Many subdomains used, potentially to hide the true domain.")
        if features_dict["domain_entropy"] > 3.5: # Example threshold, might need tuning based on your data
            reasons.append("The domain name appears unusually random or machine-generated.")
        if features_dict["num_digits_in_url"] > 10: # Example threshold
            reasons.append("Contains an unusual number of digits in the URL (e.g., in the domain).")
        if features_dict["num_unusual_special_chars_in_url"] > 2: # Example threshold
            reasons.append("Presence of unusual special characters in the URL.")
        if features_dict["url_path_depth"] > 5:
            reasons.append("The URL path is very deep, which can be suspicious.")


        # Keyword Presence (if relevant and proba is high)
        phishing_keywords_found = [
            kw for kw_idx, kw in enumerate(feature_map[14:30]) # Keywords start from index 14
            if features_dict[kw] == 1
        ]
        if phishing_keywords_found:
            reasons.append(f"Contains suspicious keywords like: {', '.join([k.replace('keyword_','') for k in phishing_keywords_found])}.")

    # --- Reasons for "Looks Safe" (lower proba) ---
    if proba < 0.45: # Give safe reasons if probability is low
        if features_dict["uses_https"] == 1:
            reasons.append("The site uses HTTPS, indicating a secure connection.")
        if features_dict["is_ip_address_in_hostname"] == 0:
            reasons.append("Uses a standard domain name (not an IP address).")
        if features_dict["is_suspicious_tld"] == 0:
            reasons.append("Uses a common and trusted Top-Level Domain (TLD).")
        if features_dict["is_shortened_url"] == 0:
            reasons.append("The URL is not shortened, showing the full destination.")
        if features_dict["url_length"] <= 75 and features_dict["url_length"] > 10:
             reasons.append("URL length appears normal.")
        if features_dict["num_hyphens"] <= 3:
             reasons.append("Normal number of hyphens in the URL.")

    # --- General Fallback Reasons ---
    if not reasons: # If no specific reasons were added
        if proba >= 0.5:
            reasons.append("Model detected general suspicious patterns.")
        else: # proba < 0.5
            reasons.append("URL structure appears legitimate.")

    return reasons


@app.route('/predict', methods=['POST'])
def predict():
    if model is None or scaler is None:
        return jsonify({"error": "Model or scaler not loaded. Server not ready."}), 500

    data = request.get_json()
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    domain = get_domain(url)
    
    proba = 0.0
    phishing_status = 0
    message = "Looks Safe"
    reasons = []

    # Check against trusted domains first for immediate feedback
    if domain in trusted_domains:
        proba = 0.01
        message = "Trusted Domain"
        reasons.append(f"Domain '{domain}' is in the trusted list.")
    else:
        try:
            # Extract features using your enhanced utils.extract_features
            features_list = extract_features(url)
            
            # --- IMPORTANT VALIDATION ---
            # Ensure the number of features matches what the model expects
            expected_features_count = len(feature_map) # Should be 33
            if len(features_list) != expected_features_count:
                print(f"Mismatch: utils.extract_features returned {len(features_list)} features, but {expected_features_count} were expected.")
                return jsonify({'error': f'Feature extraction mismatch. Expected {expected_features_count}, got {len(features_list)}. Please check utils.py and feature_map.'}), 500
            # --- END VALIDATION ---

            features_array = np.array(features_list).reshape(1, -1)
            
            # Scale the features using the loaded scaler
            scaled_features = scaler.transform(features_array)
            
            proba = model.predict_proba(scaled_features)[0][1]
            phishing_status = int(proba >= 0.5)

            if phishing_status == 1:
                message = "Phishing Risk"
            else:
                message = "Looks Safe"
            
            reasons = get_prediction_reasons(url, features_list, proba)

        except Exception as e:
            print(f"Error during feature extraction or prediction for URL {url}: {e}")
            return jsonify({'error': f'Failed to process URL: {str(e)}'}), 500

    result = {
        'url': url,
        'phishing': phishing_status,
        'proba': round(proba, 4),
        'message': message,
        'reasons': reasons
    }

    return jsonify(result)

# Endpoint to provide model information (e.g., accuracy)
@app.route('/model-info', methods=['GET'])
def model_info():
    if model is None:
        return jsonify({"error": "Model not loaded."}), 500
    return jsonify({
        "accuracy": MODEL_ACCURACY,
        "model_type": "GradientBoostingClassifier",
        "status": "ready" if model else "not_loaded"
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)