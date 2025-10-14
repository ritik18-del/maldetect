import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ..features.extractor import extract_features_from_bytes, get_feature_vector_length


DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
SAMPLES_DIR = os.path.join(DATA_DIR, "samples")
BENIGN_DIR = os.path.join(SAMPLES_DIR, "benign")
MALWARE_DIR = os.path.join(SAMPLES_DIR, "malware")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
MODEL_PATH = os.path.join(PROCESSED_DIR, "model.joblib")  # legacy default

# Map algorithm keys to (constructor, default filename)
ALGORITHMS: Dict[str, Tuple[object, str]] = {
    "rf": (lambda: RandomForestClassifier(n_estimators=300, max_depth=None, n_jobs=-1, random_state=42), "model_rf.joblib"),
    "dt": (lambda: DecisionTreeClassifier(random_state=42), "model_dt.joblib"),
    "svm": (lambda: SVC(kernel="rbf", probability=True, C=2.0, gamma="scale", random_state=42), "model_svm.joblib"),
    "nb": (lambda: GaussianNB(), "model_nb.joblib"),
    "mlp": (lambda: MLPClassifier(hidden_layer_sizes=(128, 64), activation="relu", max_iter=200, random_state=42), "model_mlp.joblib"),
}


@dataclass
class TrainResult:
    report: str
    model_path: str
    algo: str = "rf"


def _load_dataset_from_csv(csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(csv_path)
    if "label" not in df.columns:
        raise ValueError("CSV must include a 'label' column with 0/1 labels")
    y = df["label"].astype(int).values
    X = df.drop(columns=["label"]).values.astype(np.float32)
    return X, y


def _load_dataset_from_samples() -> Tuple[np.ndarray, np.ndarray]:
    X_list = []
    y_list = []
    for label_dir, label in ((BENIGN_DIR, 0), (MALWARE_DIR, 1)):
        if not os.path.isdir(label_dir):
            continue
        for root, _dirs, files in os.walk(label_dir):
            for name in files:
                path = os.path.join(root, name)
                try:
                    with open(path, "rb") as f:
                        file_bytes = f.read()
                    features, _ = extract_features_from_bytes(file_bytes)
                    X_list.append(features)
                    y_list.append(label)
                except Exception:
                    # Skip unreadable files
                    continue
    if not X_list:
        # synthetic fallback for demo
        n_features = get_feature_vector_length()
        X = np.random.rand(200, n_features).astype(np.float32)
        y = (X[:, 0] + X[:, 1] * 0.5 > 0.75).astype(int)
        return X, y
    X = np.stack(X_list)
    y = np.array(y_list, dtype=int)
    return X, y


def _train_one_algo(X, y, algo_key: str) -> TrainResult:
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    make_model, filename = ALGORITHMS[algo_key]
    model = make_model()

    # simple split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y if len(np.unique(y)) > 1 else None
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, digits=4)

    out_path = os.path.join(PROCESSED_DIR, filename)
    joblib.dump(model, out_path)
    return TrainResult(report=report, model_path=out_path, algo=algo_key)


def train_model(csv_path: Optional[str] = None, algo: Optional[str] = None, train_all: bool = False) -> List[TrainResult]:
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    if csv_path:
        X, y = _load_dataset_from_csv(csv_path)
    else:
        X, y = _load_dataset_from_samples()

    results: List[TrainResult] = []
    if train_all:
        for key in ALGORITHMS.keys():
            results.append(_train_one_algo(X, y, key))
        return results

    algo_key = algo or "rf"
    if algo_key not in ALGORITHMS:
        raise ValueError(f"Unknown algo '{algo_key}'. Choose one of: {list(ALGORITHMS.keys())}")
    results.append(_train_one_algo(X, y, algo_key))
    return results


