import io
import json
import os
import tempfile
import hashlib
from typing import Tuple

from flask import Flask, jsonify, render_template, request

from .features.extractor import (
    extract_features_from_bytes,
    get_feature_vector_length,
)
from .models.infer import ensure_model_and_predict_proba


app = Flask(__name__, static_folder="static", template_folder="templates")


@app.get("/api/health")
def health() -> Tuple[str, int]:
    return jsonify({"status": "ok"}), 200


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    uploaded = request.files["file"]
    if uploaded.filename == "":
        return jsonify({"error": "No file selected"}), 400

    file_bytes = uploaded.read()
    if not file_bytes:
        return jsonify({"error": "Empty file"}), 400

    try:
        feature_vector, feature_names = extract_features_from_bytes(file_bytes)
        algo = request.form.get("algo") or request.args.get("algo")
        proba_malicious, model_info = ensure_model_and_predict_proba(feature_vector, algo=algo)
        label = "malicious" if proba_malicious >= 0.5 else "benign"
        # Basic stats from feature vector indices
        entropy = float(feature_vector[256])
        strings_mean_len = float(feature_vector[257])
        strings_std_len = float(feature_vector[258])
        strings_count = float(feature_vector[259])
        file_size = float(feature_vector[260])
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        response = {
            "label": label,
            "confidence_malicious": float(proba_malicious),
            "model": model_info,
            "feature_vector_length": get_feature_vector_length(),
            "algo": model_info.get("algo"),
            "stats": {
                "sha256": sha256,
                "file_size": file_size,
                "entropy": entropy,
                "strings_mean_len": strings_mean_len,
                "strings_std_len": strings_std_len,
                "strings_count": strings_count,
            },
        }
        return jsonify(response), 200
    except Exception as exc:  # meaningful handling at boundary
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    # Dev server (use waitress for production)
    app.run(host="0.0.0.0", port=5000, debug=True)


