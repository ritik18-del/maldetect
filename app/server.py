import io
import json
import os
import tempfile
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Tuple

from flask import Flask, jsonify, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

from app.features.extractor import (
    extract_features_from_bytes,
    get_feature_vector_length,
)
from app.models.infer import ensure_model_and_predict_proba
from app.models.database import (
    db, ScanRecord, ModelPerformance, init_database,
    save_scan_record, get_recent_scans, get_scan_statistics
)


app = Flask(__name__, static_folder="static", template_folder="templates")

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///maldetect.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Initialize database
init_database(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
        threshold = float(request.form.get("threshold") or request.args.get("threshold") or 0.5)
        proba_malicious, model_info = ensure_model_and_predict_proba(feature_vector, algo=algo)
        label = "malicious" if proba_malicious >= threshold else "benign"
        
        # Basic stats from feature vector indices
        entropy = float(feature_vector[256])
        strings_mean_len = float(feature_vector[257])
        strings_std_len = float(feature_vector[258])
        strings_count = float(feature_vector[259])
        file_size = float(feature_vector[260])
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        
        # Save to database
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
        scan_record = save_scan_record(
            filename=uploaded.filename,
            file_size=int(file_size),
            sha256=sha256,
            label=label,
            confidence=float(proba_malicious),
            algorithm=model_info.get("algo", "auto"),
            entropy=entropy,
            strings_count=int(strings_count),
            strings_mean_len=strings_mean_len,
            strings_std_len=strings_std_len,
            user_ip=user_ip
        )
        
        logger.info(f"File scanned: {uploaded.filename} - {label} ({proba_malicious:.2f})")
        
        response = {
            "label": label,
            "confidence_malicious": float(proba_malicious),
            "model": model_info,
            "feature_vector_length": get_feature_vector_length(),
            "algo": model_info.get("algo"),
            "scan_id": scan_record.id,
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
        logger.error(f"Scan error: {str(exc)}")
        return jsonify({"error": str(exc)}), 500


@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.get("/bulk-scan")
def bulk_scan_page():
    return render_template("bulk-scan.html")


# Pages: History, Reports, API Docs
@app.get("/history")
def history_page():
    return render_template("history.html")


@app.get("/reports")
def reports_page():
    return render_template("reports.html")


@app.get("/api/docs")
def api_docs_page():
    return render_template("api-docs.html")


@app.get("/api/dashboard/stats")
def dashboard_stats():
    try:
        statistics = get_scan_statistics()
        recent_scans = [scan.to_dict() for scan in get_recent_scans(limit=20)]
        
        # Mock model performance data (in real implementation, load from database)
        model_performance = [
            {"algorithm": "rf", "accuracy": 0.95, "precision": 0.94, "recall": 0.96, "f1_score": 0.95},
            {"algorithm": "svm", "accuracy": 0.92, "precision": 0.91, "recall": 0.93, "f1_score": 0.92},
            {"algorithm": "mlp", "accuracy": 0.89, "precision": 0.88, "recall": 0.90, "f1_score": 0.89},
            {"algorithm": "nb", "accuracy": 0.87, "precision": 0.86, "recall": 0.88, "f1_score": 0.87},
            {"algorithm": "dt", "accuracy": 0.85, "precision": 0.84, "recall": 0.86, "f1_score": 0.85},
        ]
        
        return jsonify({
            "statistics": statistics,
            "recent_scans": recent_scans,
            "model_performance": model_performance
        }), 200
    except Exception as exc:
        logger.error(f"Dashboard stats error: {str(exc)}")
        return jsonify({"error": str(exc)}), 500


@app.get("/api/scans")
def get_scans():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        
        scans = ScanRecord.query.order_by(ScanRecord.scan_timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            "scans": [scan.to_dict() for scan in scans.items],
            "total": scans.total,
            "pages": scans.pages,
            "current_page": page,
            "per_page": per_page
        }), 200
    except Exception as exc:
        logger.error(f"Get scans error: {str(exc)}")
        return jsonify({"error": str(exc)}), 500


@app.get("/api/scans/<int:scan_id>")
def get_scan_details(scan_id):
    try:
        scan = ScanRecord.query.get_or_404(scan_id)
        return jsonify(scan.to_dict()), 200
    except Exception as exc:
        logger.error(f"Get scan details error: {str(exc)}")
        return jsonify({"error": str(exc)}), 500


@app.post("/api/bulk-scan")
def bulk_scan():
    try:
        if "files" not in request.files:
            return jsonify({"error": "No files uploaded"}), 400
        
        files = request.files.getlist("files")
        if not files or all(f.filename == "" for f in files):
            return jsonify({"error": "No files selected"}), 400
        
        algo = request.form.get("algo") or "auto"
        results = []
        
        for file in files:
            if file.filename == "":
                continue
                
            try:
                file_bytes = file.read()
                if not file_bytes:
                    continue
                    
                feature_vector, _ = extract_features_from_bytes(file_bytes)
                proba_malicious, model_info = ensure_model_and_predict_proba(feature_vector, algo=algo)
                label = "malicious" if proba_malicious >= 0.5 else "benign"
                
                results.append({
                    "filename": file.filename,
                    "label": label,
                    "confidence_malicious": float(proba_malicious),
                    "algorithm": model_info.get("algo", "auto")
                })
                
                logger.info(f"Bulk scan: {file.filename} - {label} ({proba_malicious:.2f})")
                
            except Exception as e:
                results.append({
                    "filename": file.filename,
                    "error": str(e)
                })
        
        return jsonify({
            "results": results,
            "total_scanned": len(results)
        }), 200
        
    except Exception as exc:
        logger.error(f"Bulk scan error: {str(exc)}")
        return jsonify({"error": str(exc)}), 500


@app.get("/api/export/scans")
def export_scans():
    try:
        format_type = request.args.get('format', 'csv').lower()
        limit = int(request.args.get('limit', 1000))
        
        scans = ScanRecord.query.order_by(ScanRecord.scan_timestamp.desc()).limit(limit).all()
        
        if format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'ID', 'Filename', 'File Size', 'SHA256', 'Label', 'Confidence',
                'Algorithm', 'Entropy', 'Strings Count', 'Strings Mean Length',
                'Strings Std Length', 'Scan Timestamp', 'User IP'
            ])
            
            # Write data
            for scan in scans:
                writer.writerow([
                    scan.id, scan.filename, scan.file_size, scan.sha256,
                    scan.label, scan.confidence, scan.algorithm, scan.entropy,
                    scan.strings_count, scan.strings_mean_len, scan.strings_std_len,
                    scan.scan_timestamp.isoformat() if scan.scan_timestamp else None,
                    scan.user_ip
                ])
            
            output.seek(0)
            return output.getvalue(), 200, {
                'Content-Type': 'text/csv',
                'Content-Disposition': f'attachment; filename=maldetect-scans-{datetime.now().strftime("%Y%m%d")}.csv'
            }
        
        elif format_type == 'json':
            return jsonify({
                "scans": [scan.to_dict() for scan in scans],
                "export_timestamp": datetime.utcnow().isoformat(),
                "total_records": len(scans)
            }), 200
        
        else:
            return jsonify({"error": "Unsupported format. Use 'csv' or 'json'"}), 400
            
    except Exception as exc:
        logger.error(f"Export scans error: {str(exc)}")
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    # Dev server (use waitress for production)
    app.run(host="0.0.0.0", port=5000, debug=True)


