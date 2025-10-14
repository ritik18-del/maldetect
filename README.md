MalDetect - Malware Detection System

Overview
MalDetect is a simple end-to-end malware detection system that demonstrates a typical workflow:
- Dataset preparation (static features only in this starter)
- Model training with scikit-learn (RandomForest)
- Model persistence and inference utilities
- Flask backend for file upload and scan endpoints
- Minimal HTML/CSS/JS UI for scanning files and viewing prediction/confidence

This starter focuses on static analysis (no execution) via byte-level features. You can extend it with richer static features (e.g., PE headers) and dynamic/sandbox features later.

Project Structure
```
maldetect/
  app/
    server.py                 # Flask app
    features/
      extractor.py            # Static feature extraction from arbitrary files
    models/
      train.py                # Training pipeline
      infer.py                # Inference utilities (loads saved model)
    templates/
      index.html              # Basic UI
    static/
      css/styles.css
      js/main.js
  data/
    samples/
      benign/                # Put benign sample files here
      malware/               # Put malware sample files here
    processed/               # Derived datasets/features
  scripts/
    train_model.py           # CLI to train and save a model
    scan_file.py             # CLI to scan a local file using the saved model
    extract_dataset.py       # CLI to extract features + CSV from samples
  requirements.txt
  README.md
```

Setup
1) Python environment (Windows PowerShell):
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

2) Optional: Place sample data
- Put benign files under `data/samples/benign/` and malware samples under `data/samples/malware/`.
- You may also use your own dataset and convert it into features with `scripts/extract_dataset.py`.

Training a Model
Algorithms supported: rf (RandomForest), dt (DecisionTree), svm (RBF SVM), nb (GaussianNB), mlp (NeuralNet).

Option A: Train from samples in `data/samples/` (will extract features automatically):
```
python scripts/train_model.py --from-samples --algo rf
# Or train ALL algorithms and save each:
python scripts/train_model.py --from-samples --all
```

Option B: Train from an existing CSV of features (label column name: `label`):
```
python scripts/train_model.py --from-csv path\to\features.csv --algo svm
```

If no data is available, the script falls back to a synthetic dataset (useful for demo only).

Running the App
```
venv\Scripts\activate
python -m waitress --listen=0.0.0.0:5000 app.server:app
# Or for development with Flask's server:
python app/server.py
```
Then open `http://localhost:5000/` and upload a file to scan.
You can select the model in the dropdown (Auto uses the best-available trained model path e.g., `model_rf.joblib`).

CLI Scanning
After training a model:
```
python scripts/scan_file.py path\to\file.exe
```

Notes & Next Steps
- Current features are byte-histogram + entropy + string statistics; they are file-agnostic and safe on any file type. Accuracy depends heavily on dataset quality and feature richness.
- Consider adding richer static features (e.g., PE header fields for Windows executables) and dynamic features from sandboxing (API calls, process behavior).
- Add logging, authentication, database (scan history), and integrations (e.g., VirusTotal) as needed.

Security Disclaimer
Never execute untrusted binaries on your host. This starter performs static analysis only (reads bytes and metadata). For dynamic analysis, use sandboxed environments.

