"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Ensemble Detection Package Initialization

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (package initialization)

Connected Components (files that import from this module):
- src.detection.ml_detector
- src.detection.classification_engine
- All individual ML detector modules

Integration Points:
- Enables ensemble detection package recognition by Python
- Provides package-level initialization for ensemble modules
- Establishes ensemble detection module structure

Verification Checklist:
□ Package initialization established
□ Import path resolution enabled for ensemble modules
□ Voting classifier and confidence calculator access configured
□ No circular dependencies
"""

# Package initialization for ensemble detection module
__version__ = "1.0.0"
__author__ = "AntivirusLab"
__description__ = "Ensemble detection algorithms package for Advanced Multi-Algorithm Antivirus"

# Ensemble package-level imports
# Note: These will be uncommented as modules become available
# from .voting_classifier import EnsembleVotingClassifier
# from .confidence_calculator import ConfidenceCalculator
