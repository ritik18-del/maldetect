import argparse
import csv
import os
import sys
from typing import List

import numpy as np

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.features.extractor import extract_features_from_bytes


def iter_files(dir_path: str) -> List[str]:
    for root, _dirs, files in os.walk(dir_path):
        for name in files:
            yield os.path.join(root, name)


def main():
    parser = argparse.ArgumentParser(description="Extract dataset features to CSV")
    parser.add_argument("--benign", required=True, help="Directory of benign samples")
    parser.add_argument("--malware", required=True, help="Directory of malware samples")
    parser.add_argument("--out", required=True, help="Output CSV path")
    args = parser.parse_args()

    rows = []
    header = None

    for label_dir, label in ((args.benign, 0), (args.malware, 1)):
        for path in iter_files(label_dir):
            try:
                with open(path, 'rb') as f:
                    b = f.read()
                features, feature_names = extract_features_from_bytes(b)
                if header is None:
                    header = feature_names + ["label"]
                row = list(map(float, features.tolist())) + [label]
                rows.append(row)
            except Exception:
                continue

    if header is None:
        print("No data extracted; check directories.")
        return

    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.out, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()


