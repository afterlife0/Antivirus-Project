# EMBER2018 Antivirus ML Training Pipeline

## Overview

This project implements a robust, memory-efficient machine learning pipeline for malware detection using the EMBER2018 dataset. The pipeline is designed for **NUMERICAL-ONLY TRAINING**, strict modularity, and comprehensive hyperparameter tuning, with detailed reporting and visualizations.

- **Memory-efficient data loading** from parquet files
- **Configurable preprocessing** with string/numerical column separation
- **Independent model training** for SVM, Random Forest, DNN, XGBoost, and LightGBM
- **Comprehensive evaluation metrics** and hyperparameter optimization
- **Detailed reports** and performance visualizations
- **Strict file/class naming and import/export consistency**

---

## Directory Structure

```
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

## Workflow Pipeline

1. **Data Loading**  
   Use [`DataLoader`](data_loader.py) to load EMBER2018 parquet files efficiently.

2. **Preprocessing**  
   Use [`DataPreprocessor`](preprocessor.py) to separate numerical/string columns, handle missing values, balance data, and save processed datasets.

3. **Model Training**  
   Use [`ModelTrainer`](trainer.py) to coordinate training for all models using only numerical data.  
   Models: [`SVMModel`](svm.py), [`RandomForestModel`](random_forest.py), [`DNNModel`](dnn.py), [`XGBoostModel`](xgboost.py), [`LightGBMModel`](lightgbm.py)

4. **Hyperparameter Tuning**  
   All models support configurable hyperparameter optimization (`--use-hyperparameter`).

5. **Reporting & Visualization**  
   Detailed reports and performance charts are generated in `outputs/reports/` and `outputs/visualizations/`.

---

## Usage

### 1. Install Requirements

```sh
pip install -r requirements.txt
```

### 2. Data Preprocessing

```sh
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

### 3. Model Training

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

---

## Reports & Outputs

- **Processed Data:** `outputs/processed_data/`
- **Trained Models:** `outputs/models/`
- **Reports:** `outputs/reports/`
- **Visualizations:** `outputs/visualizations/`
- **Hyperparameter Results:** `outputs/hyperparameter_results/`
- **Logs:** `outputs/logs/`

---

## Core Principles

- **Memory Efficiency:** Chunked loading, multi-core support, minimal RAM usage
- **Numerical-Only Training:** All models train exclusively on numerical features
- **Hyperparameter Tuning:** Configurable, supports grid/random/bayesian search
- **Comprehensive Metrics:** Accuracy, Log Loss, AUC, Precision, Recall, F1, Confusion Matrix
- **Strict Modularity:** Each file/class serves a single, unique purpose
- **Robustness:** Extensive error handling and reproducibility

---

## File Dependency Map

- [`data_loader.py`](data_loader.py): No dependencies. Used by [`preprocessor.py`](preprocessor.py).
- [`preprocessor.py`](preprocessor.py): Depends on [`data_loader.py`](data_loader.py). Saves processed data.
- [`trainer.py`](trainer.py): Imports all model files. Loads only processed numerical data.
- Model files ([`svm.py`](svm.py), [`random_forest.py`](random_forest.py), [`dnn.py`](dnn.py), [`xgboost.py`](xgboost.py), [`lightgbm.py`](lightgbm.py)): No dependencies. Imported by [`trainer.py`](trainer.py).

---

## Requirements

See [`requirements.txt`](requirements.txt) for all dependencies, including:
- pandas, numpy, scikit-learn, tensorflow, keras, xgboost, lightgbm, pyarrow, joblib, matplotlib, seaborn, plotly, click, argparse, tqdm, psutil, imbalanced-learn, chardet, pickle, json, yaml, opencv-python, pillow, scipy, optuna, hyperopt, scikit-optimize

---

## Compliance

- **Strict file/class naming and import/export consistency**
- **No redundant functions or duplicate code**
- **No direct dependency of trainer.py on preprocessor.py or data_loader.py**
- **All models are independent and robust**
- **Workspace integrity and compliance enforced**

---

## Project Goal

Create a robust, memory-efficient ML model training pipeline for antivirus detection using EMBER2018, with numerical-only training, independent training coordinator, configurable hyperparameter tuning, comprehensive metrics, detailed reporting, and strict modularity.

---
