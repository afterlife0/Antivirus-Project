"""
Advanced Multi-Algorithm Antivirus Software
==========================================
UI Components Package Initialization

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (package initialization)

Connected Components (files that import from this module):
- main.py (imports UI components)
- ALL UI module files

Integration Points:
- Enables UI package recognition
- Provides UI component access
- Manages UI module dependencies
- Establishes PySide6 UI framework

Verification Checklist:
✓ UI package initialization established
✓ UI component access enabled
✓ PySide6 framework integration configured
✓ Window management system enabled
✓ Conditional imports for unavailable modules
✓ Proper error handling implemented
"""

# UI components package initialization
__version__ = "1.0.0"
__description__ = "PySide6 UI components for Advanced Multi-Algorithm Antivirus"
__author__ = "afterlife0"

# Import available UI components with error handling
__all__ = []

try:
    from .main_window import MainWindow
    __all__.append('MainWindow')
except ImportError as e:
    print(f"Warning: MainWindow not available: {e}")
    MainWindow = None

try:
    from .scan_window import ScanWindow
    __all__.append('ScanWindow')
except ImportError as e:
    print(f"Warning: ScanWindow not available: {e}")
    ScanWindow = None

# Future UI components - will be uncommented as they become available
try:
    from .quarantine_window import QuarantineWindow
    __all__.append('QuarantineWindow')
except ImportError:
    QuarantineWindow = None

try:
    from .settings_window import SettingsWindow
    __all__.append('SettingsWindow')
except ImportError:
    SettingsWindow = None

try:
    from .model_status_window import ModelStatusWindow
    __all__.append('ModelStatusWindow')
except ImportError:
    ModelStatusWindow = None

# Dialog components
try:
    from .dialogs import (
        ThreatDetailsDialog,
        ScanOptionsDialog, 
        ModelConfigDialog
    )
    __all__.extend(['ThreatDetailsDialog', 'ScanOptionsDialog', 'ModelConfigDialog'])
except ImportError:
    ThreatDetailsDialog = None
    ScanOptionsDialog = None
    ModelConfigDialog = None

# Widget components
try:
    from .widgets import (
        ScanProgressWidget,
        ThreatListWidget,
        NotificationWidget,
        ModelMetricsWidget
    )
    __all__.extend(['ScanProgressWidget', 'ThreatListWidget', 'NotificationWidget', 'ModelMetricsWidget'])
except ImportError:
    ScanProgressWidget = None
    ThreatListWidget = None
    NotificationWidget = None
    ModelMetricsWidget = None

# Package utility functions
def get_available_components():
    """Return list of available UI components."""
    available = []
    components = {
        'MainWindow': MainWindow,
        'ScanWindow': ScanWindow,
        'QuarantineWindow': QuarantineWindow,
        'SettingsWindow': SettingsWindow,
        'ModelStatusWindow': ModelStatusWindow,
        'ThreatDetailsDialog': ThreatDetailsDialog,
        'ScanOptionsDialog': ScanOptionsDialog,
        'ModelConfigDialog': ModelConfigDialog,
        'ScanProgressWidget': ScanProgressWidget,
        'ThreatListWidget': ThreatListWidget,
        'NotificationWidget': NotificationWidget,
        'ModelMetricsWidget': ModelMetricsWidget
    }
    
    for name, component in components.items():
        if component is not None:
            available.append(name)
    
    return available

def verify_ui_components():
    """Verify UI component availability and return status."""
    available_components = get_available_components()
    total_components = 12  # Total planned components
    
    status = {
        'available': len(available_components),
        'total': total_components,
        'percentage': (len(available_components) / total_components) * 100,
        'components': available_components,
        'missing': []
    }
    
    all_components = [
        'MainWindow', 'ScanWindow', 'QuarantineWindow', 'SettingsWindow',
        'ModelStatusWindow', 'ThreatDetailsDialog', 'ScanOptionsDialog',
        'ModelConfigDialog', 'ScanProgressWidget', 'ThreatListWidget',
        'NotificationWidget', 'ModelMetricsWidget'
    ]
    
    for component in all_components:
        if component not in available_components:
            status['missing'].append(component)
    
    return status

# Factory functions for safe component creation
def create_main_window(*args, **kwargs):
    """Safely create MainWindow instance."""
    if MainWindow is None:
        raise ImportError("MainWindow is not available")
    return MainWindow(*args, **kwargs)

def create_scan_window(*args, **kwargs):
    """Safely create ScanWindow instance."""
    if ScanWindow is None:
        raise ImportError("ScanWindow is not available")
    return ScanWindow(*args, **kwargs)

def create_quarantine_window(*args, **kwargs):
    """Safely create QuarantineWindow instance."""
    if QuarantineWindow is None:
        raise ImportError("QuarantineWindow is not available")
    return QuarantineWindow(*args, **kwargs)

def create_settings_window(*args, **kwargs):
    """Safely create SettingsWindow instance."""
    if SettingsWindow is None:
        raise ImportError("SettingsWindow is not available")
    return SettingsWindow(*args, **kwargs)

def create_model_status_window(*args, **kwargs):
    """Safely create ModelStatusWindow instance."""
    if ModelStatusWindow is None:
        raise ImportError("ModelStatusWindow is not available")
    return ModelStatusWindow(*args, **kwargs)

# Component validation
def validate_component_imports():
    """Validate all UI component imports and log status."""
    import logging
    logger = logging.getLogger(__name__)
    
    status = verify_ui_components()
    
    logger.info(f"UI Components Status: {status['available']}/{status['total']} available ({status['percentage']:.1f}%)")
    
    if status['available'] > 0:
        logger.info(f"Available components: {', '.join(status['components'])}")
    
    if status['missing']:
        logger.warning(f"Missing components: {', '.join(status['missing'])}")
    
    return status

# Initialize logging and validate components on import
if __name__ != "__main__":
    try:
        validate_component_imports()
    except Exception as validation_error:
        print(f"UI component validation error: {validation_error}")

# Export factory functions for safe usage
__all__.extend([
    'create_main_window',
    'create_scan_window', 
    'create_quarantine_window',
    'create_settings_window',
    'create_model_status_window',
    'get_available_components',
    'verify_ui_components',
    'validate_component_imports'
])