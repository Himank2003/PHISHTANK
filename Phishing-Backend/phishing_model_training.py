import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay, accuracy_score
from sklearn.preprocessing import StandardScaler # Import StandardScaler
from utils import extract_features  # Ensure this exists and is enhanced as discussed previously

# Load dataset
df = pd.read_csv('phishing_site_urls.csv')
df['features'] = df['URL'].apply(extract_features)

# Convert list of features into a 2D numpy array
X = np.vstack(df['features'].values)
y = df['Label'].map({'bad': 1, 'good': 0}).values

# --- MODIFIED: Train-test split to keep track of original indices ---
# Get the original indices of the DataFrame
original_indices = df.index.values

# Perform the split on X, y, and the original_indices
X_train, X_test, y_train, y_test, train_indices, test_indices = train_test_split(
    X, y, original_indices, test_size=0.2, random_state=42
)

# --- Feature Scaling ---
# Initialize and fit the StandardScaler on the training data
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
# Transform the test data using the *fitted* scaler
X_test_scaled = scaler.transform(X_test)

# Train the Gradient Boosting Classifier on the SCALED training data
print("Training Gradient Boosting Classifier...")
model = GradientBoostingClassifier(n_estimators=200, learning_rate=0.1, max_depth=5, random_state=42)
model.fit(X_train_scaled, y_train)
print("Training complete.")

# Predict & Evaluate on the SCALED test data
y_pred = model.predict(X_test_scaled)
y_proba = model.predict_proba(X_test_scaled)[:, 1] # Probability of being the positive class (phishing)

# --- Accuracy and classification report ---
print("\n--- Model Evaluation ---")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Calculate overall accuracy
calculated_accuracy = round(accuracy_score(y_test, y_pred) * 100, 2)
print(f"\nOverall Model Accuracy: {calculated_accuracy}%")
print("NOTE: Please use this accuracy value to update 'MODEL_ACCURACY' in your app.py file.")


# Log confidence scores with predictions
# --- FIX APPLIED HERE: Use test_indices to get original URLs ---
df_results = pd.DataFrame({
    'URL': df.loc[test_indices, 'URL'].reset_index(drop=True), # Use the actual original indices for the test set
    'Actual': y_test,
    'Predicted': y_pred,
    'Confidence (Phishing %)': (y_proba * 100).round(2)
})
print("\nSample Predictions with Confidence (Test Set):")
print(df_results.head(10))

# --- Confusion Matrix ---
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Good", "Phishing"])
disp.plot(cmap="Blues")
plt.title("Phishing Site Detection - Confusion Matrix")
plt.show()

# --- Save model and scaler ---
joblib.dump(model, 'phishing_model.pkl')
joblib.dump(scaler, 'phishing_scaler.pkl') # Save the scaler
print("\n✅ Model and Scaler trained and saved as 'phishing_model.pkl' and 'phishing_scaler.pkl'")