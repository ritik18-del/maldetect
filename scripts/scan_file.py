import argparse
import os
import sys

import numpy as np

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.features.extractor import extract_features_from_bytes
from app.models.infer import ensure_model_and_predict_proba


def main():
    parser = argparse.ArgumentParser(description="Scan a file with MalDetect model")
    parser.add_argument("path", help="Path to file to scan")
    args = parser.parse_args()

    with open(args.path, "rb") as f:
        file_bytes = f.read()
    features, _ = extract_features_from_bytes(file_bytes)
    proba_mal, model_info = ensure_model_and_predict_proba(features)
    label = "malicious" if proba_mal >= 0.5 else "benign"
    print(f"Prediction: {label}")
    print(f"Confidence (malicious): {proba_mal:.4f}")
    print(f"Model: {model_info}")


if __name__ == "__main__":
    main()


