import pandas as pd

# Load phishing dataset (previous cleaned one)
df_phishing = pd.read_csv('./phishing_site_urls.csv')

# Load Tranco legit sites (top 500)
df_legit = pd.read_csv('./tranco_ZW3ZG.csv')
legit_urls = "https://" + df_legit.iloc[:500, 1].astype(str).str.strip()

# Format legit dataset
df_legit_clean = pd.DataFrame({
    "URL": legit_urls,
    "Label": "good"
})

# Merge both datasets
df_merged = pd.concat([df_phishing, df_legit_clean], ignore_index=True)

# Save the final file used for training
df_merged.to_csv('./phishing_site_urls.csv', index=False)

print("✅ Merged dataset saved as phishing_site_urls.csv")
