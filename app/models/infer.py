import os
from typing import Dict, Tuple, Optional

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier


MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "data", "processed")
DEFAULT_MODEL = os.path.abspath(os.path.join(MODEL_DIR, "model_rf.joblib"))


def _resolve_model_path(algo: Optional[str]) -> str:
    if not algo:
        return DEFAULT_MODEL if os.path.exists(DEFAULT_MODEL) else os.path.abspath(os.path.join(MODEL_DIR, "model.joblib"))
    mapping = {
        "rf": "model_rf.joblib",
        "dt": "model_dt.joblib",
        "svm": "model_svm.joblib",
        "nb": "model_nb.joblib",
        "mlp": "model_mlp.joblib",
    }
    filename = mapping.get(algo, "model_rf.joblib")
    return os.path.abspath(os.path.join(MODEL_DIR, filename))


def _load_or_create_model(algo: Optional[str] = None):
    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path = _resolve_model_path(algo)
    if os.path.exists(model_path):
        return joblib.load(model_path)
    # Fallback: small RF so predict_proba works; user should train real models
    return RandomForestClassifier(n_estimators=100, random_state=42)


def ensure_model_and_predict_proba(feature_vector: np.ndarray, algo: Optional[str] = None) -> Tuple[float, Dict[str, str]]:
    model_path = _resolve_model_path(algo)
    has_file = os.path.exists(model_path)
    model = _load_or_create_model(algo)
    if not hasattr(model, "classes_"):
        # If model isn't trained, build a trivial fallback to avoid runtime error
        # Train on tiny synthetic data with 2 classes for predict_proba to work
        X = np.stack([feature_vector, feature_vector * 0.0 + 1e-6], axis=0)
        y = np.array([0, 1], dtype=int)
        model.fit(X, y)
    proba = model.predict_proba(feature_vector.reshape(1, -1))[0]
    # Assume class 1 is malicious if present, else take last column
    malicious_index = int(np.where(model.classes_ == 1)[0][0]) if 1 in model.classes_ else -1
    p_mal = float(proba[malicious_index])
    info = {
        "name": type(model).__name__,
        "version": "1.0",
        "algo": algo or "auto",
        "model_path": model_path if has_file else None,
        "source": "file" if has_file else "fallback",
    }
    return p_mal, info


