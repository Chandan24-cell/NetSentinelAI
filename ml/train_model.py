import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load the merged CSV (adjust path if needed)
df = pd.read_csv('merged_cve_dataset.csv')
print(f"Loaded {len(df)} rows, {df.shape[1]} columns")