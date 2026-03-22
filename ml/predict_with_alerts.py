import pandas as pd
import numpy as np
import joblib
import json
import sys
import time
import os

# Load model and files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'random_forest_full.pkl')
model = joblib.load(MODEL_PATH)

LABEL_MAPPING_PATH = os.path.join(BASE_DIR, 'models', 'label_mapping.json')
with open(LABEL_MAPPING_PATH, 'r') as f:
    label_map = json.load(f)
reverse_label_map = {v: k for k, v in label_map.items()}

FEATURES_PATH = os.path.join(BASE_DIR, 'models', 'feature_names.txt')
with open(FEATURES_PATH, 'r') as f:
    required_features = [line.strip() for line in f]


def predict_and_alert(csv_path, alerts_file='alerts.json'):
    print(f"Loading {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()
    print(f"Loaded {len(df)} rows, {len(df.columns)} columns")

    # Auto-detect IP columns
    src_ip_col = next(
        (c for c in df.columns if 'source' in c.lower() and 'ip' in c.lower()), None
    )
    dst_ip_col = next(
        (c for c in df.columns if 'dest' in c.lower() and 'ip' in c.lower()), None
    )
    proto_col = next((c for c in df.columns if 'protocol' in c.lower()), None)

    # Create IP dataframe with SAME INDEX
    ip_df = pd.DataFrame(index=df.index)

    ip_df['Source IP'] = df[src_ip_col] if src_ip_col else 'unknown'
    ip_df['Destination IP'] = df[dst_ip_col] if dst_ip_col else 'unknown'
    ip_df['Protocol'] = df[proto_col] if proto_col else 'unknown'

    # Handle infinite and missing values
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    print(f"After cleaning: {len(df)} rows")

    # NO NEED for ip_df = ip_df.loc[df.index] since index already matches original df, and after dropna df.index subset matches

    # Features: exclude IP columns (and any other non-feature columns like Label)
    ip_cols = ['Source IP', 'Destination IP', 'Protocol']
    feature_cols = [c for c in df.columns if c not in ip_cols and c != 'Label']
    df_feat = df[feature_cols]

    # Ensure all required features exist; add missing with 0
    for col in required_features:
        if col not in df_feat.columns:
            df_feat[col] = 0
    df_feat = df_feat[required_features]

    # Batch prediction with alerts
    batch_size = 1000 if len(df_feat) > 1000 else len(df_feat)
    total_alerts = 0

    open(alerts_file, "w").close()

    for i in range(0, len(df_feat), batch_size):
        batch = df_feat.iloc[i:i + batch_size]

        preds = model.predict(batch)

        alerts = []

        for j, p in enumerate(preds):
            if p != 0:
                alert = {
                    "time": time.time(),
                    "predicted_label": reverse_label_map[p],
                    "src_ip": ip_df.iloc[i + j]['Source IP'],
                    "dst_ip": ip_df.iloc[i + j]['Destination IP'],
                    "protocol": ip_df.iloc[i + j]['Protocol'],
                }
                alerts.append(alert)

        total_alerts += len(alerts)

        # append to file
        with open(alerts_file, "a") as f:
            for alert in alerts:
                f.write(json.dumps(alert) + "\n")

        print(f"Processed rows {i} to {min(i + batch_size, len(df_feat))}")

        time.sleep(2)  # simulate live traffic

    print(f"Total alerts generated: {total_alerts}")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python predict_with_alerts.py <csv_file>")
        sys.exit(1)
    predict_and_alert(sys.argv[1])
