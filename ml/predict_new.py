import pandas as pd
import numpy as np
import joblib
import json
import sys

# Load model, label mapping, feature names
model = joblib.load('random_forest_full.pkl')
with open('label_mapping.json', 'r') as f:
    label_map = json.load(f)
# Reverse mapping: integer -> label name
reverse_label_map = {v: k for k, v in label_map.items()}

with open('feature_names.txt', 'r') as f:
    required_features = [line.strip() for line in f]

def predict_csv(csv_path):
    # Load CSV
    df = pd.read_csv(csv_path, low_memory=False)
    
    # Clean column names (strip spaces)
    df.columns = df.columns.str.strip()
    
    # Replace infinite values with NaN
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Drop rows with any NaN (or fill if preferred)
    df = df.dropna()
    
    # Ensure all required features exist; fill missing with 0
    for col in required_features:
        if col not in df.columns:
            df[col] = 0
    # Reorder columns to match training order
    df = df[required_features]
    
    # Predict
    predictions = model.predict(df)
    
    # Convert to labels
    predicted_labels = [reverse_label_map[p] for p in predictions]
    
    # Add to dataframe
    df['predicted_label'] = predicted_labels
    
    # Show alerts (non‑BENIGN)
    alerts = df[df['predicted_label'] != 'BENIGN']
    print(f"Found {len(alerts)} alerts")
    if len(alerts) > 0:
        print(alerts[['predicted_label']].head(10))
    
    return df

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python predict_new.py <csv_file>")
        sys.exit(1)
    predict_csv(sys.argv[1])