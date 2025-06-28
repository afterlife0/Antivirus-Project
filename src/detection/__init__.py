"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Detection Package Initialization

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (package initialization)

Connected Components (files that import from this module):
- All detection modules
- src.core.scanner_engine
- src.core.classification_engine

Integration Points:
- Enables detection package recognition by Python
- Provides package-level initialization for detection modules
- Establishes detection module structure

Verification Checklist:
□ Package initialization established
□ Import path resolution enabled for detection modules
□ Subpackage access configured for models and ensemble
□ No circular dependencies
"""

# Package initialization for detection module
__version__ = "1.0.0"
__author__ = "AntivirusLab"
__description__ = "Detection algorithms package for Advanced Multi-Algorithm Antivirus"

# Detection package-level imports
# Note: These will be uncommented as modules become available
# from .ml_detector import MLEnsembleDetector
# from .signature_detector import SignatureDetector
# from .yara_detector import YaraDetector
# from .classification_engine import ClassificationEngine
# from .feature_extractor import FeatureExtractor
