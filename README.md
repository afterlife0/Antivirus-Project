# Advanced Multi-Algorithm Antivirus Software & ML Training Pipeline

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
  - [Antivirus Application](#antivirus-application)
  - [ML Training Pipeline](#ml-training-pipeline)
- [Directory Structure](#directory-structure)
- [Key Features](#key-features)
- [Getting Started](#getting-started)
- [Usage Guide](#usage-guide)
- [Development Workflow](#development-workflow)
- [Security Practices](#security-practices)
- [Contribution Guidelines](#contribution-guidelines)
- [License](#license)
- [Contact](#contact)
- [Acknowledgements](#acknowledgements)
- [Project Status](#project-status)
- [For Developers](#for-developers)

---

## Project Overview

This repository provides a **professional-grade, modular antivirus system** featuring a modern PySide6 user interface and a robust machine learning training pipeline for malware detection.

- The **Antivirus Application** uses ensemble machine learning, signature, and YARA rule-based detection to provide real-time protection, quarantine, reporting, and threat intelligence.
- The **ML Training Pipeline** enables advanced, memory-efficient, numerical-only training and optimization of detection models, using the EMBER2018 dataset and supporting independent model development, tuning, and evaluation.

---

## Architecture

### Antivirus Application

- **Frontend (PySide6):** Modern, themable UI for scanning, quarantine, settings, and reporting.
- **Detection Engine:** Hybrid approach using ML ensemble, signature matching, and YARA rules.
- **Threat Intelligence:** External API integration for real-time malware information and rule/model updates.
- **Core Services:** File management, quarantine handling, configuration, notifications, and logging.
- **Extensibility:** Modular design allows easy addition of new detection modules, intelligence feeds, or UI features.

### ML Training Pipeline

- **Data Loader:** Efficiently loads EMBER2018 parquet files in chunks.
- **Preprocessor:** Separates numerical/string columns, handles NA/outliers, balances data.
- **Model Trainer:** Orchestrates training for Random Forest, SVM, DNN, XGBoost, LightGBM on processed data.
- **Independent Models:** Each model is trained, tuned, and saved independently for deployment to the antivirus.
- **Reporting & Visualization:** Generates metrics, charts, and reports to guide production model selection.
- **Strict Modularity:** Each file/class serves a single, well-documented purpose.

---

## Directory Structure

```
antivirus_project/
├── main.py
├── src/
│   ├── ui/
│   │   ├── main_window.py
│   │   ├── scan_window.py
│   │   ├── quarantine_window.py
│   │   ├── settings_window.py
│   │   ├── model_status_window.py
│   │   ├── dialogs/
│   │   └── widgets/
│   ├── core/
│   │   ├── app_config.py
│   │   ├── scanner_engine.py
│   │   ├── file_manager.py
│   │   ├── threat_database.py
│   │   └── model_manager.py
│   ├── detection/
│   │   ├── ml_detector.py
│   │   ├── models/
│   │   ├── ensemble/
│   │   ├── signature_detector.py
│   │   ├── yara_detector.py
│   │   ├── feature_extractor.py
│   │   └── classification_engine.py
│   ├── intelligence/
│   │   ├── threat_intel_client.py
│   │   └── feeds/
│   ├── notification/
│   │   └── notifier.py
│   ├── utils/
│   │   ├── theme_manager.py
│   │   ├── crypto_utils.py
│   │   ├── file_utils.py
│   │   ├── model_utils.py
│   │   ├── encoding_utils.py
│   │   └── helpers.py
│   └── resources/
│       ├── themes/
│       ├── icons/
│       └── sounds/
├── models/           # Production ML models (trained using ml_training_pipeline)
├── signatures/       # Signature database for fast detection
├── yara_rules/       # YARA rules for advanced detection
├── quarantine/       # Quarantined threat files
├── logs/
├── config/
├── requirements.txt

ml_training_pipeline/
├── data/
│   └── ember2018_parquet/
│       ├── train.parquet
│       └── test.parquet
├── data_loader.py              # DataLoader class - memory-efficient loading
├── preprocessor.py             # DataPreprocessor class - preprocessing & arg parsing
├── trainer.py                  # ModelTrainer class - independent training coordinator
├── svm.py                      # SVMModel class - SVM with hyperparameter tuning
├── random_forest.py            # RandomForestModel class - Random Forest with tuning
├── dnn.py                      # DNNModel class - Deep Neural Network with tuning
├── xgboost.py                  # XGBoostModel class - XGBoost with tuning
├── lightgbm.py                 # LightGBMModel class - LightGBM with tuning
├── outputs/
│   ├── models/
│   ├── reports/
│   ├── processed_data/
│   ├── visualizations/
│   ├── hyperparameter_results/
│   └── logs/
└── requirements.txt
```

---

## Key Features

### Antivirus Application

- **Ensemble ML Detection:** Five model ensemble with weighted voting for robust and accurate classification.
- **Signature & YARA Detection:** Fast, customizable, and updatable threat identification.
- **Real-Time Protection:** Background scanning, system tray notifications, and responsive UI.
- **Quarantine & Recovery:** Secure file isolation, recovery, and deletion.
- **Configurable Scans:** Quick, full, custom, and memory scan modes.
- **Comprehensive Reporting:** Scan history, threat details, and exportable reports.
- **Theming & Accessibility:** Light/dark themes, scalable UI, screen reader support.
- **Extensible & Modular:** Add new detection methods, intelligence sources, or UI features with ease.

### ML Training Pipeline

- **Memory-Efficient Data Loading:** Handles large parquet datasets in chunks, supporting multi-core.
- **Configurable Preprocessing:** Split numeric/string, handle missing/outliers, balance with SMOTE, robust scaling.
- **Independent Model Training:** Train/tune SVM, Random Forest, DNN, XGBoost, LightGBM on numerical features only.
- **Comprehensive Evaluation:** Accuracy, log loss, AUC, precision, recall, F1, confusion matrix.
- **Automated Reporting:** Generates reports and visualizations for every run.
- **Deployment Ready:** Exports production-ready models for use in the antivirus app.

---

## Getting Started

### Prerequisites

- **Python 3.11+**
- **Antivirus Requirements**:
  - PySide6, scikit-learn, xgboost, lightgbm, tensorflow, pandas, numpy, yara-python, joblib, requests, pyinstaller
- **ML Training Pipeline Requirements**:
  - pandas, numpy, scikit-learn, tensorflow, keras, xgboost, lightgbm, pyarrow, joblib, matplotlib, seaborn, plotly, click, argparse, tqdm, psutil, imbalanced-learn, chardet, pickle, json, yaml, opencv-python

Install all dependencies:
```sh
pip install -r requirements.txt
```
For ML training pipeline, use its separate requirements file if needed:
```sh
pip install -r ml_training_pipeline/requirements.txt
```

---

## Usage Guide

### To Train or Update Detection Models

1. **Preprocess Data:**
   ```sh
   cd ml_training_pipeline
   python preprocessor.py \
     --subset-size 100000 \
     --use-preprocessing True \
     --use-balancing True \
     --balancing-method smote \
     --missing-strategy smart \
     --chunk-size 10000 \
     --output-dir outputs/processed_data \
     --report-level comprehensive \
     --random-seed 42 \
     --memory-limit 8.0 \
     --n-cores -1 \
     --feature-scaling robust \
     --outlier-handling True
   ```

2. **Train Models:**
   ```sh
   python trainer.py \
     --processed-data-dir outputs/processed_data \
     --subset-size 100000 \
     --n-cores -1 \
     --max-memory 16.0 \
     --batch-size 1000 \
     --random-seed 42 \
     --output-dir outputs \
     --models-to-train all \
     --cross-validation True \
     --cv-folds 5 \
     --use-hyperparameter True \
     --hyperparameter-method grid \
     --hyperparameter-cv 3 \
     --hyperparameter-scoring f1_weighted \
     --hyperparameter-timeout 60 \
     --early-stopping True \
     --save-models True \
     --save-hyperparameter-results True \
     --generate-report True \
     --create-visualizations True \
     --verbose 1
   ```
3. **Deploy Models:**
   - Copy/export the best trained models from `ml_training_pipeline/outputs/models/` to `antivirus_project/models/`.

### To Run the Antivirus Application

```sh
cd antivirus_project
python main.py
```

---

## Reports & Outputs

- **Processed Data:** `ml_training_pipeline/outputs/processed_data/`
- **Trained Models:** `ml_training_pipeline/outputs/models/` → `antivirus_project/models/`
- **Reports:** `ml_training_pipeline/outputs/reports/`
- **Visualizations:** `ml_training_pipeline/outputs/visualizations/`
- **Logs:** `logs/` (for both training and antivirus runtime)
- **Quarantine:** `quarantine/` (isolated files)

---

## Development Workflow

- **Strict Directory Structure:** All files must remain in their assigned folders.
- **Single Responsibility:** Each file/class does one thing, with clear documentation.
- **Connection Documentation:** Every file lists its dependencies.
- **Compliance Verification:** Imports, classes, and links are checked after each PR/commit.
- **Encoding Safety:** All file/text operations use UTF-8.
- **PySide6 Only:** No other GUI libraries allowed.
- **Testing:** All new code must be tested (see `tests/`).

---

## Security Practices

- **Encoding-Safe File Operations:** All file/text I/O is UTF-8.
- **Secure Quarantine/Deletion:** Cryptographic and secure deletion methods used.
- **Input Validation:** All external data is validated before use.
- **No Sensitive Data Logging:** Application does not log sensitive information.

---

## Contribution Guidelines

- Follow the [AI Development Instructions](.github/instructions/instructions.instructions.md).
- All new files/classes must be documented and connected.
- Run compliance and integration checks after every change.
- Fix/improve existing code before adding new files/features.
- Use meaningful names and document all public methods.
- Submit pull requests with detailed descriptions and test results.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contact

- Website: [https://antivirus.example.com](https://antivirus.example.com)
- Support: [support@example.com](mailto:support@example.com)

---

## Acknowledgements

- [PySide6 (Qt for Python)](https://pyside6.qt.io/)
- [scikit-learn](https://scikit-learn.org/)
- [XGBoost](https://xgboost.readthedocs.io/)
- [LightGBM](https://lightgbm.readthedocs.io/)
- [TensorFlow](https://www.tensorflow.org/)
- [YARA-Python](https://github.com/VirusTotal/yara-python)
- [NumPy](https://numpy.org/)
- [Pandas](https://pandas.pydata.org/)

---

## Project Status

- [x] Core infrastructure (AppConfig, ThemeManager, MainWindow)
- [x] ML ensemble detection (Random Forest, SVM, DNN, XGBoost, LightGBM)
- [x] Signature and YARA detection
- [x] Quarantine and scan history
- [x] Theming and accessibility
- [x] Model training pipeline (numerical-only, modular, production export)
- [ ] Threat intelligence integration (in progress)
- [ ] Advanced reporting and external API integrations (planned)

---

## For Developers

- See [comprehensive_workspace_analysis.txt](comprehensive_workspace_analysis.txt) for a full inventory of classes, methods, and architecture.
- Follow the absolute workflow pipeline and compliance checklist for all contributions.

---
