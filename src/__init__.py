"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Source Package Initialization

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (package initialization)

Connected Components (files that import from this module):
- main.py (imports from src package)
- ALL src subpackages

Integration Points:
- Enables src package recognition by Python
- Provides package-level initialization
- Establishes base package structure

Verification Checklist:
□ Package initialization established
□ Import path resolution enabled
□ Subpackage access configured
□ No circular dependencies
"""

# Package initialization for src module
__version__ = "1.0.0"
__author__ = "AntivirusLab"
__description__ = "Advanced Multi-Algorithm Antivirus Software"

# Package-level imports for convenience
# Note: These will be uncommented as modules become available
# from .core.app_config import AppConfig
# from .utils.theme_manager import ThemeManager
# from .utils.encoding_utils import EncodingHandler
# from .ui.main_window import MainWindow