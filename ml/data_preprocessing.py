import pandas as pd
import glob
import os

# Set the path to your MachineLearningCVE folder
folder_path = "MachineLearningCVE"

# Find all CSV files in the folder
files = glob.glob(f"{folder_path}/*.csv")

print(f"Found {len(files)} CSV files in {folder_path}")
print("="*50)

# Print all file names
for f in files:
    print(f"  - {os.path.basename(f)}")
print("="*50)

# Load all CSV files
df_list = []
for i, file in enumerate(files, 1):
    filename = os.path.basename(file)
    print(f"\n[{i}/{len(files)}] Loading {filename}...")
    
    try:
        df = pd.read_csv(file, low_memory=False)
        df_list.append(df)
        print(f"  ✓ Loaded {len(df):,} rows, {len(df.columns)} columns")
    except Exception as e:
        print(f"  ✗ Error: {e}")

# Merge all dataframes
if df_list:
    print("\n" + "="*50)
    print("Merging all files...")
    data = pd.concat(df_list, ignore_index=True)
    
    print("\n✅ MERGE COMPLETE!")
    print("="*50)
    print(f"Total rows: {data.shape[0]:,}")
    print(f"Total columns: {data.shape[1]}")
    print(f"\nDataset Info:")
    print(f"  - Memory usage: {data.memory_usage(deep=True).sum() / (1024**3):.2f} GB")
    print(f"  - Missing values: {data.isnull().sum().sum():,}")
    
    # Show first few rows
    print(f"\nFirst 3 rows:")
    print(data.head(3))
    
    # Show basic statistics
    print(f"\nDataset description:")
    print(f"  - Unique values per column:")
    for col in data.columns[:5]:
        print(f"    * {col}: {data[col].nunique():,} unique values")
    
    # Save merged dataset
    output_file = "merged_cve_dataset.csv"
    print(f"\n💾 Saving merged dataset to {output_file}...")
    data.to_csv(output_file, index=False)
    
    # Show file size
    file_size = os.path.getsize(output_file) / (1024*1024)
    print(f"✅ Saved! File size: {file_size:.2f} MB")
else:
    print("\n❌ No files were successfully loaded!")
