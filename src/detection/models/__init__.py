"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Detection Models Package Initialization

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (package initialization)

Connected Components (files that import from this module):
- All individual ML detector modules
- src.detection.ml_detector
- src.detection.ensemble.voting_classifier

Integration Points:
- Enables detection models package recognition by Python
- Provides package-level initialization for ML detector modules
- Establishes ML models module structure

Verification Checklist:
□ Package initialization established
□ Import path resolution enabled for ML detectors
□ Individual model access configured
□ No circular dependencies
"""

# Package initialization for detection models module
__version__ = "1.0.0"
__author__ = "AntivirusLab"
__description__ = "ML detection models package for Advanced Multi-Algorithm Antivirus"

# Models package-level imports
# Note: These will be uncommented as modules become available
# from .random_forest_detector import RandomForestDetector
# from .svm_detector import SVMDetector
# from .dnn_detector import DNNDetector
# from .xgboost_detector import XGBoostDetector
# from .lightgbm_detector import LightGBMDetector
