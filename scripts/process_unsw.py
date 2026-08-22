"""
Inspection and Conversion Pipeline for UNSW-NB15 using Standard Library csv and numpy.
"""

from pathlib import Path
import csv
from collections import Counter
import numpy as np

# Locate files
paths_to_check = [
    Path(".."),
    Path("."),
    Path("data/unsw"),
    Path("data"),
]

train_csv = None
test_csv = None
features_csv = None

for p in paths_to_check:
    if (p / "UNSW_NB15_training-set.csv").exists():
        train_csv = p / "UNSW_NB15_training-set.csv"
    if (p / "UNSW_NB15_testing-set.csv").exists():
        test_csv = p / "UNSW_NB15_testing-set.csv"
    if (p / "NUSW-NB15_features(in).csv").exists():
        features_csv = p / "NUSW-NB15_features(in).csv"

print(f"Found train: {train_csv}")
print(f"Found test: {test_csv}")
print(f"Found features: {features_csv}")

def inspect_csv(file_path):
    print(f"\n==========================================")
    print(f"Inspecting: {file_path}")
    with open(file_path, mode="r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader)
        print(f"Column count: {len(header)}")
        print(f"Columns: {header}")
        
        attack_cats = Counter()
        labels = Counter()
        row_count = 0
        
        attack_cat_idx = header.index("attack_cat") if "attack_cat" in header else -1
        label_idx = header.index("label") if "label" in header else -1
        
        first_few_rows = []
        for row in reader:
            row_count += 1
            if attack_cat_idx != -1:
                attack_cats[row[attack_cat_idx].strip()] += 1
            if label_idx != -1:
                labels[row[label_idx].strip()] += 1
            if row_count <= 3:
                first_few_rows.append(row)
                
    print(f"Total Rows: {row_count}")
    print(f"Attack Categories: {dict(attack_cats)}")
    print(f"Binary Labels: {dict(labels)}")
    return header, row_count, attack_cats, labels

if __name__ == "__main__":
    if features_csv:
        print("\n--- Features CSV ---")
        with open(features_csv, mode="r", encoding="utf-8", errors="ignore") as f:
            for i in range(15):
                line = f.readline()
                if not line:
                    break
                print(line.strip())
                
    if train_csv:
        inspect_csv(train_csv)
    if test_csv:
        inspect_csv(test_csv)
