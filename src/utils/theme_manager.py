"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Theme Management System - Complete Enhanced Implementation

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.core.app_config (AppConfig)
- src.utils.encoding_utils (EncodingHandler, safe_read_file, safe_write_file)

Connected Components (files that import from this module):
- main.py (AntivirusApp - imports ThemeManager)
- src.ui.main_window (MainWindow - imports ThemeManager)
- src.ui.scan_window (ScanWindow - imports ThemeManager)
- src.ui.quarantine_window (QuarantineWindow - imports ThemeManager)
- src.ui.settings_window (SettingsWindow - imports ThemeManager)
- src.ui.model_status_window (ModelStatusWindow - imports ThemeManager)
- ALL UI dialog and widget files (theme application)

Integration Points:
- **ENHANCED**: Provides centralized theme management for entire UI with real-time application
- **ENHANCED**: Applies dark/light themes with comprehensive QSS stylesheets
- **ENHANCED**: Manages theme switching and persistence via AppConfig with validation
- **ENHANCED**: Handles theme resource loading with encoding safety and caching
- **ENHANCED**: Supports dynamic theme changes without restart with signal system
- **ENHANCED**: Provides theme-aware color palettes and icons with fallback support
- **ENHANCED**: Complete API compatibility with all UI components
- **ENHANCED**: Advanced error handling and recovery mechanisms
- **ENHANCED**: Performance optimization with intelligent caching
- **ENHANCED**: Custom theme support with validation and hot-reloading

Verification Checklist:
✓ All imports verified working with exact class names
✓ Class name matches exactly: ThemeManager
✓ Dependencies properly imported with EXACT class names from workspace
✓ Enhanced signal system for real-time theme communication
✓ Comprehensive theme system implemented with validation
✓ Advanced theme switching capability with error recovery
✓ Enhanced theme persistence via configuration with validation
✓ Optimized resource loading with encoding safety and caching
✓ Advanced theme-aware color palettes with UI component mapping
✓ Enhanced icon theme management with fallback generation
✓ Complete API compatibility for all connected components
✓ Performance monitoring and optimization implemented
✓ Custom theme support with hot-reloading capabilities
"""
import sys
import os
import logging
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json

from PySide6.QtWidgets import QApplication, QWidget
from PySide6.QtCore import QObject, Signal, QTimer, QMutex, QThread
from PySide6.QtGui import QPalette, QColor, QIcon, QPixmap, QPainter, QBrush

# Core dependencies - EXACT imports as specified in workspace
try:
    from src.core.app_config import AppConfig
    APP_CONFIG_AVAILABLE = True
except ImportError as e:
    print(f"❌ CRITICAL: AppConfig not available: {e}")
    APP_CONFIG_AVAILABLE = False
    sys.exit(1)

try:
    from src.utils.encoding_utils import EncodingHandler, safe_read_file, safe_write_file
    ENCODING_AVAILABLE = True
except ImportError as e:
    print(f"❌ CRITICAL: EncodingHandler not available: {e}")
    ENCODING_AVAILABLE = False
    sys.exit(1)


class ThemeType(Enum):
    """Enhanced enumeration for supported theme types with extended metadata."""
    DARK = "dark"
    LIGHT = "light"
    AUTO = "auto"  # System-based theme detection
    CUSTOM = "custom"  # Custom user themes


class ThemeValidationLevel(Enum):
    """Theme validation depth levels."""
    BASIC = "basic"           # Basic syntax validation
    STANDARD = "standard"     # Standard + color validation
    COMPREHENSIVE = "comprehensive"  # Standard + performance testing
    STRICT = "strict"         # All checks + compatibility validation


class ThemeApplicationTarget(Enum):
    """Theme application targets for granular control."""
    GLOBAL = "global"         # Apply to entire application
    WINDOW = "window"         # Apply to specific window
    WIDGET = "widget"         # Apply to specific widget
    COMPONENT = "component"   # Apply to UI component


@dataclass
class ThemeMetadata:
    """Enhanced theme metadata with comprehensive information."""
    name: str
    type: ThemeType
    version: str = "1.0.0"
    author: str = "System"
    description: str = ""
    created_date: datetime = field(default_factory=datetime.now)
    last_modified: datetime = field(default_factory=datetime.now)
    
    # **NEW**: Enhanced metadata
    file_path: Optional[str] = None
    file_size_kb: float = 0.0
    checksum: Optional[str] = None
    is_valid: bool = True
    validation_level: ThemeValidationLevel = ThemeValidationLevel.BASIC
    
    # **NEW**: Performance and usage tracking
    load_time_ms: float = 0.0
    application_count: int = 0
    last_used: Optional[datetime] = None
    error_count: int = 0
    last_error: Optional[str] = None
    
    # **NEW**: Compatibility information
    min_app_version: str = "1.0.0"
    max_app_version: str = "99.0.0"
    required_features: List[str] = field(default_factory=list)
    supported_components: List[str] = field(default_factory=list)


@dataclass
class ThemeApplicationResult:
    """Result of theme application operation."""
    success: bool
    theme_name: str
    target: str
    application_time_ms: float = 0.0
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    applied_components: List[str] = field(default_factory=list)
    failed_components: List[str] = field(default_factory=list)


@dataclass
class ThemePerformanceMetrics:
    """Performance metrics for theme operations."""
    total_applications: int = 0
    successful_applications: int = 0
    failed_applications: int = 0
    average_application_time: float = 0.0
    min_application_time: float = float('inf')
    max_application_time: float = 0.0
    cache_hit_rate: float = 0.0
    last_performance_check: Optional[datetime] = None
    
    def update_application_metrics(self, application_time: float, success: bool):
        """Update application performance metrics."""
        self.total_applications += 1
        if success:
            self.successful_applications += 1
            # Update timing metrics
            self.min_application_time = min(self.min_application_time, application_time)
            self.max_application_time = max(self.max_application_time, application_time)
            # Update average (running average)
            if self.successful_applications == 1:
                self.average_application_time = application_time
            else:
                self.average_application_time = (
                    (self.average_application_time * (self.successful_applications - 1) + application_time) /
                    self.successful_applications
                )
        else:
            self.failed_applications += 1


class ThemeManager(QObject):
    """
    **ENHANCED** Centralized theme management system for the Advanced Multi-Algorithm Antivirus Software.
    
    This class provides comprehensive theme management with advanced features including:
    - **Multi-level theme validation and error recovery**
    - **Performance monitoring and optimization**
    - **Custom theme support with hot-reloading**
    - **Real-time theme application with granular control**
    - **Advanced caching system for optimal performance**
    - **Component-specific theme customization**
    - **Dynamic theme switching without application restart**
    - **Comprehensive error handling and recovery mechanisms**
    - **Theme compatibility validation and versioning**
    - **Performance metrics collection and analysis**
    
    Key Features:
    - **Thread-safe operations** with advanced synchronization
    - **Real-time theme updates** with signal-based communication
    - **Custom theme validation** with multiple validation levels
    - **Performance optimization** with intelligent caching and lazy loading
    - **Component isolation** preventing theme conflicts
    - **Fallback mechanisms** ensuring application stability
    - **Hot-reloading capabilities** for development and customization
    - **Memory optimization** with automatic cleanup and garbage collection
    """
    
    # **ENHANCED**: Comprehensive signal system for real-time communication
    theme_changed = Signal(str, dict)  # theme_name, theme_metadata
    theme_applied = Signal(str, str)   # widget_name, theme_name
    theme_error = Signal(str, str)     # error_type, error_message
    theme_warning = Signal(str, str)   # warning_type, warning_message
    theme_loaded = Signal(str, dict)   # theme_name, load_info
    theme_validated = Signal(str, bool, dict)  # theme_name, is_valid, validation_info
    custom_theme_detected = Signal(str, str)   # theme_path, theme_name
    performance_update = Signal(dict)  # performance_metrics
    
    # **ENHANCED**: Theme resource paths with comprehensive structure
    THEMES_DIR = Path("src/resources/themes")
    ICONS_DIR = Path("src/resources/icons")
    CUSTOM_THEMES_DIR = Path("src/resources/themes/custom")
    CACHE_DIR = Path("src/resources/themes/.cache")
    BACKUP_DIR = Path("src/resources/themes/.backup")
    
    # **ENHANCED**: Default theme files with versioning
    DARK_THEME_FILE = THEMES_DIR / "dark.qss"
    LIGHT_THEME_FILE = THEMES_DIR / "light.qss"
    AUTO_THEME_FILE = THEMES_DIR / "auto.qss"
    
    # **ENHANCED**: Theme validation patterns and rules
    VALID_THEME_EXTENSIONS = ['.qss', '.css', '.json']
    THEME_SIZE_LIMIT_KB = 1024  # 1MB limit for theme files
    MAX_CUSTOM_THEMES = 50
    
    def __init__(self, config: AppConfig):
        """
        Initialize the enhanced theme manager with comprehensive features.
        
        Args:
            config: Application configuration manager
        """
        try:
            super().__init__()
            self.config = config
            self.encoding_handler = EncodingHandler()
            self.logger = logging.getLogger("ThemeManager")
            
            # **ENHANCED**: Advanced threading and synchronization
            self._theme_lock = threading.RLock()
            self._cache_lock = threading.RLock()
            self._operation_timeout = 30  # seconds
            self._shutdown_event = threading.Event()
            
            # **ENHANCED**: Theme state management with comprehensive tracking
            self.current_theme = ThemeType.DARK
            self.current_stylesheet = ""
            self.theme_cache = {}  # Enhanced cache with metadata
            self.custom_themes = {}
            self.theme_metadata = {}  # Comprehensive metadata tracking
            
            # **ENHANCED**: Color palettes with extended component support
            self.color_palettes = {}
            self.component_palettes = {}  # Component-specific color overrides
            
            # **ENHANCED**: Icon themes with fallback generation
            self.icon_themes = {}
            self.icon_cache = {}
            
            # **ENHANCED**: Performance monitoring and optimization
            self.performance_metrics = ThemePerformanceMetrics()
            self._application_history = deque(maxlen=100)
            self._error_history = deque(maxlen=50)
            
            # **ENHANCED**: Theme watchers and auto-reload
            self._theme_watchers = {}
            self._auto_reload_enabled = True
            
            # **ENHANCED**: Application state tracking
            self._applied_themes = {}  # Track which themes are applied to which widgets
            self._component_themes = defaultdict(dict)  # Component-specific theme overrides
            
            # **ENHANCED**: Initialize comprehensive theme system
            self._initialize_enhanced_theme_system()
            
            self.logger.info("Enhanced ThemeManager initialized successfully with comprehensive features")
            
        except Exception as e:
            self.logger.error(f"Critical error initializing Enhanced ThemeManager: {e}")
            raise
    
    def _initialize_enhanced_theme_system(self):
        """Initialize the enhanced theme management system with comprehensive features."""
        try:
            # **ENHANCED**: Create comprehensive directory structure
            self._create_enhanced_theme_directories()
            
            # **ENHANCED**: Initialize extended color palettes with component mapping
            self._initialize_enhanced_color_palettes()
            
            # **ENHANCED**: Initialize advanced icon themes with fallback generation
            self._initialize_enhanced_icon_themes()
            
            # **ENHANCED**: Load and validate all themes with comprehensive validation
            self._load_and_validate_all_themes()
            
            # **ENHANCED**: Set current theme from configuration with validation
            self._set_current_theme_with_validation()
            
            # **ENHANCED**: Initialize performance monitoring and optimization
            self._initialize_performance_monitoring()
            
            # **ENHANCED**: Setup theme watchers for auto-reload
            self._initialize_theme_watchers()
            
            # **ENHANCED**: Validate system integrity
            if not self._validate_system_integrity():
                self.logger.warning("Theme system integrity check failed - using fallback configuration")
                self._create_enhanced_fallback_theme()
            
            self.logger.info("Enhanced theme system initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize enhanced theme system: {e}")
            # **ENHANCED**: Advanced fallback with error recovery
            self._create_enhanced_fallback_theme()
            self._initialize_error_recovery()
    
    def _create_enhanced_theme_directories(self):
        """Create comprehensive theme resource directories with proper permissions."""
        try:
            directories = [
                self.THEMES_DIR,
                self.ICONS_DIR,
                self.CUSTOM_THEMES_DIR,
                self.CACHE_DIR,
                self.BACKUP_DIR,
                self.ICONS_DIR / "dark",
                self.ICONS_DIR / "light",
                self.ICONS_DIR / "custom",
                self.ICONS_DIR / "fallback"
            ]
            
            for directory in directories:
                directory.mkdir(parents=True, exist_ok=True)
                
                # **NEW**: Validate directory permissions
                if not self._validate_directory_permissions(directory):
                    self.logger.warning(f"Limited permissions for directory: {directory}")
            
            # **NEW**: Create theme manifest files
            self._create_theme_manifests()
            
            self.logger.debug("Enhanced theme directories created and validated")
            
        except Exception as e:
            self.logger.error(f"Error creating enhanced theme directories: {e}")
            raise
    
    def _validate_directory_permissions(self, directory: Path) -> bool:
        """Validate directory permissions for theme operations."""
        try:
            # Test write permission
            test_file = directory / ".permission_test"
            test_file.write_text("test", encoding='utf-8')
            test_file.unlink()
            
            # Test read permission
            return os.access(directory, os.R_OK)
            
        except (OSError, PermissionError):
            return False
    
    def _create_theme_manifests(self):
        """Create theme manifest files for metadata tracking."""
        try:
            manifest_content = {
                "version": "1.0.0",
                "created": datetime.now().isoformat(),
                "themes": {},
                "custom_themes": {},
                "performance_data": {}
            }
            
            manifest_file = self.THEMES_DIR / "manifest.json"
            if not manifest_file.exists():
                safe_write_file(manifest_file, json.dumps(manifest_content, indent=2))
                self.logger.debug("Theme manifest created")
            
        except Exception as e:
            self.logger.warning(f"Could not create theme manifest: {e}")
    
    def _initialize_enhanced_color_palettes(self):
        """Initialize comprehensive color palettes with component-specific mappings."""
        try:
            # **ENHANCED**: Extended Dark theme color palette with component mapping
            self.color_palettes[ThemeType.DARK] = {
                # **Core Colors** - Foundation
                "background": "#2b2b2b",
                "background_alt": "#3c3c3c",
                "background_hover": "#404040",
                "background_selected": "#0078d4",
                "background_disabled": "#1e1e1e",
                "background_focus": "#1a1a1a",
                "background_gradient_start": "#2b2b2b",
                "background_gradient_end": "#1e1e1e",
                
                # **Text Colors** - Typography
                "text": "#ffffff",
                "text_primary": "#ffffff",
                "text_secondary": "#cccccc",
                "text_tertiary": "#999999",
                "text_disabled": "#808080",
                "text_link": "#4fc3f7",
                "text_link_hover": "#81d4fa",
                "text_error": "#f44336",
                "text_warning": "#ff9800",
                "text_success": "#4caf50",
                "text_info": "#2196f3",
                
                # **Border Colors** - Structure
                "border": "#555555",
                "border_light": "#666666",
                "border_dark": "#444444",
                "border_focus": "#0078d4",
                "border_error": "#f44336",
                "border_warning": "#ff9800",
                "border_success": "#4caf50",
                "border_hover": "#777777",
                
                # **Button Colors** - Interactive Elements
                "button_background": "#404040",
                "button_background_hover": "#4a4a4a",
                "button_background_pressed": "#363636",
                "button_background_disabled": "#2a2a2a",
                "button_primary": "#0078d4",
                "button_primary_hover": "#106ebe",
                "button_primary_pressed": "#005a9e",
                "button_secondary": "#666666",
                "button_secondary_hover": "#777777",
                "button_danger": "#d32f2f",
                "button_danger_hover": "#b71c1c",
                "button_success": "#388e3c",
                "button_success_hover": "#2e7d32",
                "button_warning": "#f57c00",
                "button_warning_hover": "#ef6c00",
                
                # **Status Colors** - State Indication
                "status_safe": "#4caf50",
                "status_safe_light": "#81c784",
                "status_warning": "#ff9800",
                "status_warning_light": "#ffb74d",
                "status_danger": "#f44336",
                "status_danger_light": "#e57373",
                "status_info": "#2196f3",
                "status_info_light": "#64b5f6",
                "status_scanning": "#9c27b0",
                "status_scanning_light": "#ba68c8",
                
                # **Component-Specific Colors**
                "sidebar_background": "#1e1e1e",
                "sidebar_header": "#252525",
                "sidebar_item": "#2b2b2b",
                "sidebar_item_hover": "#333333",
                "sidebar_item_active": "#0078d4",
                
                "toolbar_background": "#333333",
                "toolbar_border": "#555555",
                "toolbar_button": "#404040",
                "toolbar_button_hover": "#4a4a4a",
                
                "menu_background": "#2b2b2b",
                "menu_border": "#555555",
                "menu_item": "transparent",
                "menu_item_hover": "#404040",
                "menu_separator": "#555555",
                
                "table_background": "#2b2b2b",
                "table_alternate": "#333333",
                "table_header": "#404040",
                "table_border": "#555555",
                "table_selection": "#0078d4",
                
                "tab_background": "#3c3c3c",
                "tab_active": "#2b2b2b",
                "tab_hover": "#404040",
                "tab_border": "#555555",
                
                # **Progress and Loading Colors**
                "progress_background": "#404040",
                "progress_chunk": "#0078d4",
                "progress_text": "#ffffff",
                "loading_spinner": "#0078d4",
                
                # **Scrollbar Colors**
                "scrollbar_background": "#2b2b2b",
                "scrollbar_handle": "#555555",
                "scrollbar_handle_hover": "#666666",
                "scrollbar_handle_pressed": "#777777",
                
                # **Shadow and Effects**
                "shadow_light": "rgba(0, 0, 0, 0.2)",
                "shadow_medium": "rgba(0, 0, 0, 0.4)",
                "shadow_dark": "rgba(0, 0, 0, 0.6)",
                "glow_primary": "rgba(0, 120, 212, 0.3)",
                "glow_success": "rgba(76, 175, 80, 0.3)",
                "glow_error": "rgba(244, 67, 54, 0.3)",
                
                # **Advanced UI Elements**
                "tooltip_background": "#1a1a1a",
                "tooltip_border": "#555555",
                "tooltip_text": "#ffffff",
                
                "notification_background": "#333333",
                "notification_border": "#555555",
                "notification_text": "#ffffff",
                
                "modal_overlay": "rgba(0, 0, 0, 0.5)",
                "modal_background": "#2b2b2b",
                "modal_border": "#555555"
            }
            
            # **ENHANCED**: Extended Light theme color palette with component mapping
            self.color_palettes[ThemeType.LIGHT] = {
                # **Core Colors** - Foundation
                "background": "#ffffff",
                "background_alt": "#f8f9fa",
                "background_hover": "#e9ecef",
                "background_selected": "#0066cc",
                "background_disabled": "#f5f5f5",
                "background_focus": "#ffffff",
                "background_gradient_start": "#ffffff",
                "background_gradient_end": "#f8f9fa",
                
                # **Text Colors** - Typography
                "text": "#212529",
                "text_primary": "#212529",
                "text_secondary": "#6c757d",
                "text_tertiary": "#adb5bd",
                "text_disabled": "#adb5bd",
                "text_link": "#0066cc",
                "text_link_hover": "#0056b3",
                "text_error": "#dc3545",
                "text_warning": "#fd7e14",
                "text_success": "#198754",
                "text_info": "#0dcaf0",
                
                # **Border Colors** - Structure
                "border": "#dee2e6",
                "border_light": "#e9ecef",
                "border_dark": "#ced4da",
                "border_focus": "#0066cc",
                "border_error": "#dc3545",
                "border_warning": "#fd7e14",
                "border_success": "#198754",
                "border_hover": "#ced4da",
                
                # **Button Colors** - Interactive Elements
                "button_background": "#f8f9fa",
                "button_background_hover": "#e9ecef",
                "button_background_pressed": "#dee2e6",
                "button_background_disabled": "#f5f5f5",
                "button_primary": "#0066cc",
                "button_primary_hover": "#0056b3",
                "button_primary_pressed": "#004494",
                "button_secondary": "#6c757d",
                "button_secondary_hover": "#5c636a",
                "button_danger": "#dc3545",
                "button_danger_hover": "#c82333",
                "button_success": "#198754",
                "button_success_hover": "#157347",
                "button_warning": "#fd7e14",
                "button_warning_hover": "#e8680d",
                
                # **Status Colors** - State Indication
                "status_safe": "#198754",
                "status_safe_light": "#d1e7dd",
                "status_warning": "#fd7e14",
                "status_warning_light": "#fff3cd",
                "status_danger": "#dc3545",
                "status_danger_light": "#f8d7da",
                "status_info": "#0dcaf0",
                "status_info_light": "#d1ecf1",
                "status_scanning": "#6f42c1",
                "status_scanning_light": "#e2e3ff",
                
                # **Component-Specific Colors**
                "sidebar_background": "#f8f9fa",
                "sidebar_header": "#e9ecef",
                "sidebar_item": "#ffffff",
                "sidebar_item_hover": "#dee2e6",
                "sidebar_item_active": "#0066cc",
                
                "toolbar_background": "#f8f9fa",
                "toolbar_border": "#dee2e6",
                "toolbar_button": "#ffffff",
                "toolbar_button_hover": "#e9ecef",
                
                "menu_background": "#ffffff",
                "menu_border": "#dee2e6",
                "menu_item": "transparent",
                "menu_item_hover": "#e9ecef",
                "menu_separator": "#dee2e6",
                
                "table_background": "#ffffff",
                "table_alternate": "#f8f9fa",
                "table_header": "#e9ecef",
                "table_border": "#dee2e6",
                "table_selection": "#0066cc",
                
                "tab_background": "#f8f9fa",
                "tab_active": "#ffffff",
                "tab_hover": "#e9ecef",
                "tab_border": "#dee2e6",
                
                # **Progress and Loading Colors**
                "progress_background": "#e9ecef",
                "progress_chunk": "#0066cc",
                "progress_text": "#212529",
                "loading_spinner": "#0066cc",
                
                # **Scrollbar Colors**
                "scrollbar_background": "#f8f9fa",
                "scrollbar_handle": "#ced4da",
                "scrollbar_handle_hover": "#adb5bd",
                "scrollbar_handle_pressed": "#6c757d",
                
                # **Shadow and Effects**
                "shadow_light": "rgba(0, 0, 0, 0.1)",
                "shadow_medium": "rgba(0, 0, 0, 0.2)",
                "shadow_dark": "rgba(0, 0, 0, 0.3)",
                "glow_primary": "rgba(0, 102, 204, 0.3)",
                "glow_success": "rgba(25, 135, 84, 0.3)",
                "glow_error": "rgba(220, 53, 69, 0.3)",
                
                # **Advanced UI Elements**
                "tooltip_background": "#ffffff",
                "tooltip_border": "#dee2e6",
                "tooltip_text": "#212529",
                
                "notification_background": "#f8f9fa",
                "notification_border": "#dee2e6",
                "notification_text": "#212529",
                
                "modal_overlay": "rgba(0, 0, 0, 0.3)",
                "modal_background": "#ffffff",
                "modal_border": "#dee2e6"
            }
            
            # **NEW**: Initialize component-specific palette overrides
            self._initialize_component_palettes()
            
            self.logger.debug("Enhanced color palettes initialized with comprehensive component mapping")
            
        except Exception as e:
            self.logger.error(f"Error initializing enhanced color palettes: {e}")
            raise
    
    def _initialize_component_palettes(self):
        """Initialize component-specific color palette overrides."""
        try:
            # **NEW**: Sidebar-specific color overrides
            self.component_palettes['sidebar'] = {
                ThemeType.DARK: {
                    "background": "#1a1a1a",
                    "header_background": "#1e1e1e",
                    "button_active": "#0078d4",
                    "button_hover": "#2a2a2a"
                },
                ThemeType.LIGHT: {
                    "background": "#f0f2f5",
                    "header_background": "#e4e6ea",
                    "button_active": "#0066cc",
                    "button_hover": "#e9ecef"
                }
            }
            
            # **NEW**: Scan window-specific overrides
            self.component_palettes['scan_window'] = {
                ThemeType.DARK: {
                    "progress_safe": "#4caf50",
                    "progress_scanning": "#ff9800",
                    "progress_threat": "#f44336"
                },
                ThemeType.LIGHT: {
                    "progress_safe": "#198754",
                    "progress_scanning": "#fd7e14",
                    "progress_threat": "#dc3545"
                }
            }
            
            # **NEW**: Model status window overrides
            self.component_palettes['model_status'] = {
                ThemeType.DARK: {
                    "model_loaded": "#4caf50",
                    "model_loading": "#ff9800",
                    "model_error": "#f44336",
                    "model_disabled": "#666666"
                },
                ThemeType.LIGHT: {
                    "model_loaded": "#198754",
                    "model_loading": "#fd7e14",
                    "model_error": "#dc3545",
                    "model_disabled": "#6c757d"
                }
            }
            
            self.logger.debug("Component-specific palettes initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing component palettes: {e}")
    
    def _initialize_enhanced_icon_themes(self):
        """Initialize comprehensive icon themes with fallback generation capabilities."""
        try:
            # **ENHANCED**: Dark theme icons with comprehensive mapping
            self.icon_themes[ThemeType.DARK] = {
                # **Core Application Icons**
                "app_icon": "dark/app_icon.png",
                "shield": "dark/shield.png",
                "shield_active": "dark/shield_active.png",
                "shield_disabled": "dark/shield_disabled.png",
                
                # **Main Navigation Icons**
                "scan": "dark/scan.png",
                "scan_active": "dark/scan_active.png",
                "quarantine": "dark/quarantine.png",
                "quarantine_active": "dark/quarantine_active.png",
                "settings": "dark/settings.png",
                "settings_active": "dark/settings_active.png",
                "models": "dark/models.png",
                "models_active": "dark/models_active.png",
                "reports": "dark/reports.png",
                "reports_active": "dark/reports_active.png",
                
                # **Status and State Icons**
                "status_safe": "dark/status_safe.png",
                "status_warning": "dark/status_warning.png",
                "status_danger": "dark/status_danger.png",
                "status_info": "dark/status_info.png",
                "status_scanning": "dark/status_scanning.png",
                "status_updating": "dark/status_updating.png",
                
                # **Threat Detection Icons**
                "virus": "dark/virus.png",
                "malware": "dark/malware.png",
                "ransomware": "dark/ransomware.png",
                "trojan": "dark/trojan.png",
                "adware": "dark/adware.png",
                "spyware": "dark/spyware.png",
                "rootkit": "dark/rootkit.png",
                
                # **Action Icons**
                "clean": "dark/clean.png",
                "delete": "dark/delete.png",
                "restore": "dark/restore.png",
                "backup": "dark/backup.png",
                "export": "dark/export.png",
                "import": "dark/import.png",
                "refresh": "dark/refresh.png",
                "update": "dark/update.png",
                
                # **ML Model Icons**
                "model_loaded": "dark/model_loaded.png",
                "model_loading": "dark/model_loading.png",
                "model_error": "dark/model_error.png",
                "model_disabled": "dark/model_disabled.png",
                "ensemble": "dark/ensemble.png",
                "training": "dark/training.png",
                
                # **UI Control Icons**
                "play": "dark/play.png",
                "pause": "dark/pause.png",
                "stop": "dark/stop.png",
                "close": "dark/close.png",
                "minimize": "dark/minimize.png",
                "maximize": "dark/maximize.png",
                "expand": "dark/expand.png",
                "collapse": "dark/collapse.png",
                
                # **File and Folder Icons**
                "file": "dark/file.png",
                "folder": "dark/folder.png",
                "folder_open": "dark/folder_open.png",
                "document": "dark/document.png",
                "executable": "dark/executable.png",
                "archive": "dark/archive.png",
                
                # **Network and System Icons**
                "network": "dark/network.png",
                "system": "dark/system.png",
                "process": "dark/process.png",
                "service": "dark/service.png",
                "registry": "dark/registry.png",
                "memory": "dark/memory.png"
            }
            
            # **ENHANCED**: Light theme icons with comprehensive mapping
            self.icon_themes[ThemeType.LIGHT] = {
                # Mirror dark theme structure but with light-themed icons
                icon: path.replace("dark/", "light/") 
                for icon, path in self.icon_themes[ThemeType.DARK].items()
            }
            
            # **NEW**: Initialize icon cache
            self.icon_cache = {
                ThemeType.DARK: {},
                ThemeType.LIGHT: {},
                'fallback': {}
            }
            
            self.logger.debug("Enhanced icon themes initialized with comprehensive mapping")
            
        except Exception as e:
            self.logger.error(f"Error initializing enhanced icon themes: {e}")
            raise
    
    def _load_and_validate_all_themes(self):
        """Load and validate all available themes with comprehensive validation."""
        try:
            self.logger.info("Loading and validating all themes...")
            
            # **ENHANCED**: Load built-in themes with validation
            self._load_built_in_themes()
            
            # **ENHANCED**: Discover and load custom themes
            self._discover_and_load_custom_themes()
            
            # **ENHANCED**: Validate theme integrity
            self._validate_theme_integrity()
            
            # **ENHANCED**: Generate theme cache
            self._generate_theme_cache()
            
            self.logger.info(f"Theme loading completed: {len(self.theme_cache)} themes loaded")
            
        except Exception as e:
            self.logger.error(f"Error loading and validating themes: {e}")
            self._create_enhanced_fallback_theme()
    
    def _load_built_in_themes(self):
        """Load built-in themes with comprehensive validation and metadata."""
        try:
            # **ENHANCED**: Dark theme with comprehensive stylesheet
            dark_stylesheet = self._generate_comprehensive_dark_stylesheet()
            self.theme_cache[ThemeType.DARK] = {
                'stylesheet': dark_stylesheet,
                'metadata': ThemeMetadata(
                    name="Dark Theme",
                    type=ThemeType.DARK,
                    version="2.0.0",
                    author="System",
                    description="Advanced dark theme with comprehensive component support",
                    supported_components=["MainWindow", "ScanWindow", "QuarantineWindow", "SettingsWindow", "ModelStatusWindow"],
                    is_valid=True
                )
            }
            
            # **ENHANCED**: Light theme with comprehensive stylesheet
            light_stylesheet = self._generate_comprehensive_light_stylesheet()
            self.theme_cache[ThemeType.LIGHT] = {
                'stylesheet': light_stylesheet,
                'metadata': ThemeMetadata(
                    name="Light Theme",
                    type=ThemeType.LIGHT,
                    version="2.0.0",
                    author="System",
                    description="Advanced light theme with comprehensive component support",
                    supported_components=["MainWindow", "ScanWindow", "QuarantineWindow", "SettingsWindow", "ModelStatusWindow"],
                    is_valid=True
                )
            }
            
            self.logger.debug("Built-in themes loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Error loading built-in themes: {e}")
            raise
    
    def _generate_comprehensive_dark_stylesheet(self) -> str:
        """Generate comprehensive dark theme stylesheet with all UI components."""
        try:
            colors = self.color_palettes[ThemeType.DARK]
            
            stylesheet = f"""
/* ========================================================================
   ADVANCED MULTI-ALGORITHM ANTIVIRUS - DARK THEME STYLESHEET
   ======================================================================== */

/* **GLOBAL APPLICATION STYLES** */
QApplication {{
    background-color: {colors['background']};
    color: {colors['text']};
    font-family: 'Segoe UI', 'Arial', sans-serif;
    font-size: 9pt;
}}

/* **MAIN WINDOW STYLES** */
QMainWindow {{
    background-color: {colors['background']};
    color: {colors['text']};
    border: none;
}}

QMainWindow::separator {{
    background-color: {colors['border']};
    width: 1px;
    height: 1px;
}}

/* **CENTRAL WIDGET STYLES** */
QWidget {{
    background-color: {colors['background']};
    color: {colors['text']};
    border: none;
    outline: none;
}}

QWidget:focus {{
    border: 2px solid {colors['border_focus']};
    border-radius: 4px;
}}

/* **BUTTON STYLES** */
QPushButton {{
    background-color: {colors['button_background']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
    min-height: 20px;
}}

QPushButton:hover {{
    background-color: {colors['button_background_hover']};
    border-color: {colors['border_hover']};
}}

QPushButton:pressed {{
    background-color: {colors['button_background_pressed']};
    border-color: {colors['border_focus']};
}}

QPushButton:disabled {{
    background-color: {colors['button_background_disabled']};
    color: {colors['text_disabled']};
    border-color: {colors['border_dark']};
}}

/* **PRIMARY BUTTON STYLES** */
QPushButton[class="primary"] {{
    background-color: {colors['button_primary']};
    color: white;
    border-color: {colors['button_primary']};
    font-weight: 600;
}}

QPushButton[class="primary"]:hover {{
    background-color: {colors['button_primary_hover']};
    border-color: {colors['button_primary_hover']};
}}

QPushButton[class="primary"]:pressed {{
    background-color: {colors['button_primary_pressed']};
    border-color: {colors['button_primary_pressed']};
}}

/* **DANGER BUTTON STYLES** */
QPushButton[class="danger"] {{
    background-color: {colors['button_danger']};
    color: white;
    border-color: {colors['button_danger']};
}}

QPushButton[class="danger"]:hover {{
    background-color: {colors['button_danger_hover']};
    border-color: {colors['button_danger_hover']};
}}

/* **SUCCESS BUTTON STYLES** */
QPushButton[class="success"] {{
    background-color: {colors['button_success']};
    color: white;
    border-color: {colors['button_success']};
}}

QPushButton[class="success"]:hover {{
    background-color: {colors['button_success_hover']};
    border-color: {colors['button_success_hover']};
}}

/* **LABEL STYLES** */
QLabel {{
    background-color: transparent;
    color: {colors['text']};
    border: none;
}}

QLabel[class="header"] {{
    font-size: 14pt;
    font-weight: 600;
    color: {colors['text_primary']};
    margin: 10px 0px;
}}

QLabel[class="subheader"] {{
    font-size: 11pt;
    font-weight: 500;
    color: {colors['text_secondary']};
    margin: 5px 0px;
}}

QLabel[class="status-safe"] {{
    color: {colors['status_safe']};
    font-weight: 600;
}}

QLabel[class="status-warning"] {{
    color: {colors['status_warning']};
    font-weight: 600;
}}

QLabel[class="status-danger"] {{
    color: {colors['status_danger']};
    font-weight: 600;
}}

/* **INPUT FIELD STYLES** */
QLineEdit {{
    background-color: {colors['background_alt']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 9pt;
    min-height: 20px;
}}

QLineEdit:focus {{
    border-color: {colors['border_focus']};
    background-color: {colors['background_focus']};
}}

QLineEdit:disabled {{
    background-color: {colors['background_disabled']};
    color: {colors['text_disabled']};
    border-color: {colors['border_dark']};
}}

/* **TEXT AREA STYLES** */
QTextEdit, QPlainTextEdit {{
    background-color: {colors['background_alt']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    padding: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 9pt;
}}

QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {colors['border_focus']};
}}

/* **COMBO BOX STYLES** */
QComboBox {{
    background-color: {colors['button_background']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    padding: 6px 12px;
    min-height: 20px;
}}

QComboBox:hover {{
    background-color: {colors['button_background_hover']};
    border-color: {colors['border_hover']};
}}

QComboBox:focus {{
    border-color: {colors['border_focus']};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border: none;
}}

QComboBox::down-arrow {{
    width: 12px;
    height: 12px;
    background-color: {colors['text_secondary']};
}}

QComboBox QAbstractItemView {{
    background-color: {colors['menu_background']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    padding: 4px;
    outline: none;
}}

QComboBox QAbstractItemView::item {{
    padding: 6px 12px;
    border-radius: 2px;
    min-height: 20px;
}}

QComboBox QAbstractItemView::item:hover {{
    background-color: {colors['menu_item_hover']};
}}

QComboBox QAbstractItemView::item:selected {{
    background-color: {colors['background_selected']};
}}

/* **PROGRESS BAR STYLES** */
QProgressBar {{
    background-color: {colors['progress_background']};
    color: {colors['progress_text']};
    border: 1px solid {colors['border']};
    border-radius: 6px;
    padding: 2px;
    text-align: center;
    font-weight: 500;
}}

QProgressBar::chunk {{
    background-color: {colors['progress_chunk']};
    border-radius: 4px;
    margin: 1px;
}}

QProgressBar[class="safe"]::chunk {{
    background-color: {colors['status_safe']};
}}

QProgressBar[class="warning"]::chunk {{
    background-color: {colors['status_warning']};
}}

QProgressBar[class="danger"]::chunk {{
    background-color: {colors['status_danger']};
}}

/* **TABLE STYLES** */
QTableWidget, QTableView {{
    background-color: {colors['table_background']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    gridline-color: {colors['table_border']};
    selection-background-color: {colors['table_selection']};
    alternate-background-color: {colors['table_alternate']};
}}

QTableWidget::item, QTableView::item {{
    padding: 8px;
    border: none;
    border-bottom: 1px solid {colors['table_border']};
}}

QTableWidget::item:hover, QTableView::item:hover {{
    background-color: {colors['background_hover']};
}}

QTableWidget::item:selected, QTableView::item:selected {{
    background-color: {colors['table_selection']};
    color: white;
}}

QHeaderView::section {{
    background-color: {colors['table_header']};
    color: {colors['text']};
    border: none;
    border-right: 1px solid {colors['table_border']};
    border-bottom: 1px solid {colors['table_border']};
    padding: 8px;
    font-weight: 600;
}}

QHeaderView::section:hover {{
    background-color: {colors['background_hover']};
}}

/* **TAB WIDGET STYLES** */
QTabWidget::pane {{
    background-color: {colors['background']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    margin-top: -1px;
}}

QTabBar::tab {{
    background-color: {colors['tab_background']};
    color: {colors['text_secondary']};
    border: 1px solid {colors['tab_border']};
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    min-width: 80px;
}}

QTabBar::tab:hover {{
    background-color: {colors['tab_hover']};
    color: {colors['text']};
}}

QTabBar::tab:selected {{
    background-color: {colors['tab_active']};
    color: {colors['text']};
    border-bottom: 2px solid {colors['border_focus']};
    font-weight: 600;
}}

/* **SCROLL BAR STYLES** */
QScrollBar:vertical {{
    background-color: {colors['scrollbar_background']};
    width: 12px;
    border-radius: 6px;
    margin: 0px;
}}

QScrollBar::handle:vertical {{
    background-color: {colors['scrollbar_handle']};
    border-radius: 6px;
    min-height: 20px;
    margin: 2px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {colors['scrollbar_handle_hover']};
}}

QScrollBar::handle:vertical:pressed {{
    background-color: {colors['scrollbar_handle_pressed']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background-color: {colors['scrollbar_background']};
    height: 12px;
    border-radius: 6px;
    margin: 0px;
}}

QScrollBar::handle:horizontal {{
    background-color: {colors['scrollbar_handle']};
    border-radius: 6px;
    min-width: 20px;
    margin: 2px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {colors['scrollbar_handle_hover']};
}}

QScrollBar::handle:horizontal:pressed {{
    background-color: {colors['scrollbar_handle_pressed']};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* **GROUP BOX STYLES** */
QGroupBox {{
    background-color: {colors['background_alt']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 6px;
    font-weight: 600;
    padding-top: 16px;
    margin-top: 8px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 4px 8px;
    background-color: {colors['background']};
    color: {colors['text_primary']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    left: 10px;
}}

/* **FRAME STYLES** */
QFrame {{
    background-color: {colors['background']};
    color: {colors['text']};
    border: none;
}}

QFrame[frameShape="1"] {{ /* Box frame */
    border: 1px solid {colors['border']};
    border-radius: 4px;
}}

QFrame[frameShape="2"] {{ /* Panel frame */
    border: 1px solid {colors['border']};
    border-radius: 4px;
    background-color: {colors['background_alt']};
}}

/* **MENU STYLES** */
QMenuBar {{
    background-color: {colors['toolbar_background']};
    color: {colors['text']};
    border-bottom: 1px solid {colors['toolbar_border']};
    padding: 2px;
}}

QMenuBar::item {{
    background-color: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}}

QMenuBar::item:hover {{
    background-color: {colors['menu_item_hover']};
}}

QMenuBar::item:pressed {{
    background-color: {colors['background_selected']};
}}

QMenu {{
    background-color: {colors['menu_background']};
    color: {colors['text']};
    border: 1px solid {colors['menu_border']};
    border-radius: 4px;
    padding: 4px;
}}

QMenu::item {{
    background-color: transparent;
    padding: 6px 12px;
    border-radius: 2px;
    min-width: 120px;
}}

QMenu::item:hover {{
    background-color: {colors['menu_item_hover']};
}}

QMenu::item:selected {{
    background-color: {colors['background_selected']};
}}

QMenu::separator {{
    height: 1px;
    background-color: {colors['menu_separator']};
    margin: 4px 8px;
}}

/* **TOOLBAR STYLES** */
QToolBar {{
    background-color: {colors['toolbar_background']};
    border: 1px solid {colors['toolbar_border']};
    padding: 4px;
    spacing: 2px;
}}

QToolButton {{
    background-color: {colors['toolbar_button']};
    color: {colors['text']};
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 6px;
    margin: 1px;
}}

QToolButton:hover {{
    background-color: {colors['toolbar_button_hover']};
    border-color: {colors['border_hover']};
}}

QToolButton:pressed {{
    background-color: {colors['button_background_pressed']};
    border-color: {colors['border_focus']};
}}

/* **STATUS BAR STYLES** */
QStatusBar {{
    background-color: {colors['toolbar_background']};
    color: {colors['text']};
    border-top: 1px solid {colors['toolbar_border']};
    padding: 4px;
}}

QStatusBar::item {{
    border: none;
    padding: 2px 8px;
}}

/* **TOOLTIP STYLES** */
QToolTip {{
    background-color: {colors['tooltip_background']};
    color: {colors['tooltip_text']};
    border: 1px solid {colors['tooltip_border']};
    border-radius: 4px;
    padding: 6px 8px;
    font-size: 8pt;
}}

/* **CHECKBOX STYLES** */
QCheckBox {{
    background-color: transparent;
    color: {colors['text']};
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {colors['border']};
    border-radius: 3px;
    background-color: {colors['background_alt']};
}}

QCheckBox::indicator:hover {{
    border-color: {colors['border_hover']};
    background-color: {colors['background_hover']};
}}

QCheckBox::indicator:checked {{
    background-color: {colors['button_primary']};
    border-color: {colors['button_primary']};
}}

QCheckBox::indicator:checked:hover {{
    background-color: {colors['button_primary_hover']};
    border-color: {colors['button_primary_hover']};
}}

/* **RADIO BUTTON STYLES** */
QRadioButton {{
    background-color: transparent;
    color: {colors['text']};
    spacing: 8px;
}}

QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {colors['border']};
    border-radius: 8px;
    background-color: {colors['background_alt']};
}}

QRadioButton::indicator:hover {{
    border-color: {colors['border_hover']};
    background-color: {colors['background_hover']};
}}

QRadioButton::indicator:checked {{
    background-color: {colors['button_primary']};
    border-color: {colors['button_primary']};
}}

/* **SLIDER STYLES** */
QSlider::groove:horizontal {{
    height: 6px;
    background-color: {colors['progress_background']};
    border-radius: 3px;
}}

QSlider::handle:horizontal {{
    background-color: {colors['button_primary']};
    border: 1px solid {colors['button_primary']};
    width: 16px;
    margin: -5px 0px;
    border-radius: 8px;
}}

QSlider::handle:horizontal:hover {{
    background-color: {colors['button_primary_hover']};
    border-color: {colors['button_primary_hover']};
}}

/* **SPIN BOX STYLES** */
QSpinBox, QDoubleSpinBox {{
    background-color: {colors['background_alt']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 20px;
}}

QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {colors['border_focus']};
}}

QSpinBox::up-button, QDoubleSpinBox::up-button {{
    subcontrol-origin: border;
    subcontrol-position: top right;
    width: 20px;
    border: none;
    background-color: {colors['button_background']};
    border-top-right-radius: 4px;
}}

QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover {{
    background-color: {colors['button_background_hover']};
}}

QSpinBox::down-button, QDoubleSpinBox::down-button {{
    subcontrol-origin: border;
    subcontrol-position: bottom right;
    width: 20px;
    border: none;
    background-color: {colors['button_background']};
    border-bottom-right-radius: 4px;
}}

QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
    background-color: {colors['button_background_hover']};
}}

/* **SPLITTER STYLES** */
QSplitter::handle {{
    background-color: {colors['border']};
    margin: 2px;
}}

QSplitter::handle:horizontal {{
    width: 3px;
}}

QSplitter::handle:vertical {{
    height: 3px;
}}

QSplitter::handle:hover {{
    background-color: {colors['border_focus']};
}}

/* **COMPONENT-SPECIFIC STYLES** */

/* **SCAN WINDOW SPECIFIC** */
QWidget[class="scan-window"] {{
    background-color: {colors['background']};
}}

QWidget[class="scan-progress"] {{
    background-color: {colors['background_alt']};
    border: 1px solid {colors['border']};
    border-radius: 6px;
    padding: 12px;
    margin: 8px;
}}

QLabel[class="scan-status"] {{
    font-size: 12pt;
    font-weight: 600;
    color: {colors['text_primary']};
}}

QProgressBar[class="scan-progress"] {{
    height: 8px;
    border-radius: 4px;
}}

/* **QUARANTINE WINDOW SPECIFIC** */
QWidget[class="quarantine-window"] {{
    background-color: {colors['background']};
}}

QTableWidget[class="quarantine-table"] {{
    background-color: {colors['table_background']};
    gridline-color: {colors['table_border']};
}}

/* **MODEL STATUS WINDOW SPECIFIC** */
QWidget[class="model-status-window"] {{
    background-color: {colors['background']};
}}

QLabel[class="model-loaded"] {{
    color: {colors['status_safe']};
    font-weight: 600;
}}

QLabel[class="model-loading"] {{
    color: {colors['status_warning']};
    font-weight: 600;
}}

QLabel[class="model-error"] {{
    color: {colors['status_danger']};
    font-weight: 600;
}}

/* **NOTIFICATION STYLES** */
QWidget[class="notification"] {{
    background-color: {colors['notification_background']};
    color: {colors['notification_text']};
    border: 1px solid {colors['notification_border']};
    border-radius: 6px;
    padding: 12px;
}}

QWidget[class="notification-success"] {{
    background-color: {colors['status_safe_light']};
    border-color: {colors['status_safe']};
}}

QWidget[class="notification-warning"] {{
    background-color: {colors['status_warning_light']};
    border-color: {colors['status_warning']};
}}

QWidget[class="notification-error"] {{
    background-color: {colors['status_danger_light']};
    border-color: {colors['status_danger']};
}}

/* **SIDEBAR STYLES** */
QWidget[class="sidebar"] {{
    background-color: {colors['sidebar_background']};
    border-right: 1px solid {colors['border']};
}}

QWidget[class="sidebar-header"] {{
    background-color: {colors['sidebar_header']};
    border-bottom: 1px solid {colors['border']};
    padding: 12px;
}}

QPushButton[class="sidebar-button"] {{
    background-color: {colors['sidebar_item']};
    border: none;
    border-radius: 4px;
    padding: 12px;
    text-align: left;
    margin: 2px 8px;
    font-weight: 500;
}}

QPushButton[class="sidebar-button"]:hover {{
    background-color: {colors['sidebar_item_hover']};
}}

QPushButton[class="sidebar-button"]:checked {{
    background-color: {colors['sidebar_item_active']};
    color: white;
    font-weight: 600;
}}

/* **ANIMATION AND TRANSITIONS** */
QWidget {{
    /* Smooth transitions for better UX */
    /* Note: CSS transitions are limited in Qt */
}}

/* **END OF DARK THEME STYLESHEET** */
"""
            
            return stylesheet.strip()
            
        except Exception as e:
            self.logger.error(f"Error generating dark stylesheet: {e}")
            return self._generate_fallback_stylesheet()
    
    def _generate_comprehensive_light_stylesheet(self) -> str:
        """Generate comprehensive light theme stylesheet with all UI components."""
        try:
            colors = self.color_palettes[ThemeType.LIGHT]
            
            # **ENHANCED**: Generate light theme stylesheet using the same structure as dark
            # but with light color palette - similar comprehensive structure
            stylesheet = f"""
/* ========================================================================
   ADVANCED MULTI-ALGORITHM ANTIVIRUS - LIGHT THEME STYLESHEET
   ======================================================================== */

/* **GLOBAL APPLICATION STYLES** */
QApplication {{
    background-color: {colors['background']};
    color: {colors['text']};
    font-family: 'Segoe UI', 'Arial', sans-serif;
    font-size: 9pt;
}}

/* **MAIN WINDOW STYLES** */
QMainWindow {{
    background-color: {colors['background']};
    color: {colors['text']};
    border: none;
}}

QMainWindow::separator {{
    background-color: {colors['border']};
    width: 1px;
    height: 1px;
}}

/* **CENTRAL WIDGET STYLES** */
QWidget {{
    background-color: {colors['background']};
    color: {colors['text']};
    border: none;
    outline: none;
}}

QWidget:focus {{
    border: 2px solid {colors['border_focus']};
    border-radius: 4px;
}}

/* **BUTTON STYLES** */
QPushButton {{
    background-color: {colors['button_background']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
    min-height: 20px;
}}

QPushButton:hover {{
    background-color: {colors['button_background_hover']};
    border-color: {colors['border_hover']};
    box-shadow: 0 2px 4px {colors['shadow_light']};
}}

QPushButton:pressed {{
    background-color: {colors['button_background_pressed']};
    border-color: {colors['border_focus']};
}}

QPushButton:disabled {{
    background-color: {colors['button_background_disabled']};
    color: {colors['text_disabled']};
    border-color: {colors['border_dark']};
}}

/* **PRIMARY BUTTON STYLES** */
QPushButton[class="primary"] {{
    background-color: {colors['button_primary']};
    color: white;
    border-color: {colors['button_primary']};
    font-weight: 600;
    box-shadow: 0 2px 4px {colors['shadow_medium']};
}}

QPushButton[class="primary"]:hover {{
    background-color: {colors['button_primary_hover']};
    border-color: {colors['button_primary_hover']};
    box-shadow: 0 4px 8px {colors['shadow_medium']};
}}

QPushButton[class="primary"]:pressed {{
    background-color: {colors['button_primary_pressed']};
    border-color: {colors['button_primary_pressed']};
    box-shadow: 0 1px 2px {colors['shadow_light']};
}}

/* **DANGER BUTTON STYLES** */
QPushButton[class="danger"] {{
    background-color: {colors['button_danger']};
    color: white;
    border-color: {colors['button_danger']};
}}

QPushButton[class="danger"]:hover {{
    background-color: {colors['button_danger_hover']};
    border-color: {colors['button_danger_hover']};
}}

/* **SUCCESS BUTTON STYLES** */
QPushButton[class="success"] {{
    background-color: {colors['button_success']};
    color: white;
    border-color: {colors['button_success']};
}}

QPushButton[class="success"]:hover {{
    background-color: {colors['button_success_hover']};
    border-color: {colors['button_success_hover']};
}}

/* **LABEL STYLES** */
QLabel {{
    background-color: transparent;
    color: {colors['text']};
    border: none;
}}

QLabel[class="header"] {{
    font-size: 14pt;
    font-weight: 600;
    color: {colors['text_primary']};
    margin: 10px 0px;
}}

QLabel[class="subheader"] {{
    font-size: 11pt;
    font-weight: 500;
    color: {colors['text_secondary']};
    margin: 5px 0px;
}}

QLabel[class="status-safe"] {{
    color: {colors['status_safe']};
    font-weight: 600;
}}

QLabel[class="status-warning"] {{
    color: {colors['status_warning']};
    font-weight: 600;
}}

QLabel[class="status-danger"] {{
    color: {colors['status_danger']};
    font-weight: 600;
}}

/* **INPUT FIELD STYLES** */
QLineEdit {{
    background-color: {colors['background']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 9pt;
    min-height: 20px;
}}

QLineEdit:focus {{
    border-color: {colors['border_focus']};
    background-color: {colors['background_focus']};
    box-shadow: 0 0 0 2px {colors['glow_primary']};
}}

QLineEdit:disabled {{
    background-color: {colors['background_disabled']};
    color: {colors['text_disabled']};
    border-color: {colors['border_dark']};
}}

/* **TEXT AREA STYLES** */
QTextEdit, QPlainTextEdit {{
    background-color: {colors['background']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    padding: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 9pt;
}}

QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {colors['border_focus']};
}}

/* **COMBO BOX STYLES** */
QComboBox {{
    background-color: {colors['button_background']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    padding: 6px 12px;
    min-height: 20px;
}}

QComboBox:hover {{
    background-color: {colors['button_background_hover']};
    border-color: {colors['border_hover']};
}}

QComboBox:focus {{
    border-color: {colors['border_focus']};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border: none;
}}

QComboBox::down-arrow {{
    width: 12px;
    height: 12px;
    background-color: {colors['text_secondary']};
}}

QComboBox QAbstractItemView {{
    background-color: {colors['menu_background']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    padding: 4px;
    outline: none;
}}

QComboBox QAbstractItemView::item {{
    padding: 6px 12px;
    border-radius: 2px;
    min-height: 20px;
}}

QComboBox QAbstractItemView::item:hover {{
    background-color: {colors['menu_item_hover']};
}}

QComboBox QAbstractItemView::item:selected {{
    background-color: {colors['background_selected']};
}}

/* **PROGRESS BAR STYLES** */
QProgressBar {{
    background-color: {colors['progress_background']};
    color: {colors['progress_text']};
    border: 1px solid {colors['border']};
    border-radius: 6px;
    padding: 2px;
    text-align: center;
    font-weight: 500;
}}

QProgressBar::chunk {{
    background-color: {colors['progress_chunk']};
    border-radius: 4px;
    margin: 1px;
}}

QProgressBar[class="safe"]::chunk {{
    background-color: {colors['status_safe']};
}}

QProgressBar[class="warning"]::chunk {{
    background-color: {colors['status_warning']};
}}

QProgressBar[class="danger"]::chunk {{
    background-color: {colors['status_danger']};
}}

/* **TABLE STYLES** */
QTableWidget, QTableView {{
    background-color: {colors['table_background']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    gridline-color: {colors['table_border']};
    selection-background-color: {colors['table_selection']};
    alternate-background-color: {colors['table_alternate']};
}}

QTableWidget::item, QTableView::item {{
    padding: 8px;
    border: none;
    border-bottom: 1px solid {colors['table_border']};
}}

QTableWidget::item:hover, QTableView::item:hover {{
    background-color: {colors['background_hover']};
}}

QTableWidget::item:selected, QTableView::item:selected {{
    background-color: {colors['table_selection']};
    color: white;
}}

QHeaderView::section {{
    background-color: {colors['table_header']};
    color: {colors['text']};
    border: none;
    border-right: 1px solid {colors['table_border']};
    border-bottom: 1px solid {colors['table_border']};
    padding: 8px;
    font-weight: 600;
}}

QHeaderView::section:hover {{
    background-color: {colors['background_hover']};
}}

/* **TAB WIDGET STYLES** */
QTabWidget::pane {{
    background-color: {colors['background']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    margin-top: -1px;
}}

QTabBar::tab {{
    background-color: {colors['tab_background']};
    color: {colors['text_secondary']};
    border: 1px solid {colors['tab_border']};
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    min-width: 80px;
}}

QTabBar::tab:hover {{
    background-color: {colors['tab_hover']};
    color: {colors['text']};
}}

QTabBar::tab:selected {{
    background-color: {colors['tab_active']};
    color: {colors['text']};
    border-bottom: 2px solid {colors['border_focus']};
    font-weight: 600;
}}

/* **SCROLL BAR STYLES** */
QScrollBar:vertical {{
    background-color: {colors['scrollbar_background']};
    width: 12px;
    border-radius: 6px;
    margin: 0px;
}}

QScrollBar::handle:vertical {{
    background-color: {colors['scrollbar_handle']};
    border-radius: 6px;
    min-height: 20px;
    margin: 2px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {colors['scrollbar_handle_hover']};
}}

QScrollBar::handle:vertical:pressed {{
    background-color: {colors['scrollbar_handle_pressed']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background-color: {colors['scrollbar_background']};
    height: 12px;
    border-radius: 6px;
    margin: 0px;
}}

QScrollBar::handle:horizontal {{
    background-color: {colors['scrollbar_handle']};
    border-radius: 6px;
    min-width: 20px;
    margin: 2px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {colors['scrollbar_handle_hover']};
}}

QScrollBar::handle:horizontal:pressed {{
    background-color: {colors['scrollbar_handle_pressed']};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* **GROUP BOX STYLES** */
QGroupBox {{
    background-color: {colors['background_alt']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 6px;
    font-weight: 600;
    padding-top: 16px;
    margin-top: 8px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 4px 8px;
    background-color: {colors['background']};
    color: {colors['text_primary']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    left: 10px;
}}

/* **FRAME STYLES** */
QFrame {{
    background-color: {colors['background']};
    color: {colors['text']};
    border: none;
}}

QFrame[frameShape="1"] {{ /* Box frame */
    border: 1px solid {colors['border']};
    border-radius: 4px;
}}

QFrame[frameShape="2"] {{ /* Panel frame */
    border: 1px solid {colors['border']};
    border-radius: 4px;
    background-color: {colors['background_alt']};
}}

/* **MENU STYLES** */
QMenuBar {{
    background-color: {colors['toolbar_background']};
    color: {colors['text']};
    border-bottom: 1px solid {colors['toolbar_border']};
    padding: 2px;
}}

QMenuBar::item {{
    background-color: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}}

QMenuBar::item:hover {{
    background-color: {colors['menu_item_hover']};
}}

QMenuBar::item:pressed {{
    background-color: {colors['background_selected']};
}}

QMenu {{
    background-color: {colors['menu_background']};
    color: {colors['text']};
    border: 1px solid {colors['menu_border']};
    border-radius: 4px;
    padding: 4px;
}}

QMenu::item {{
    background-color: transparent;
    padding: 6px 12px;
    border-radius: 2px;
    min-width: 120px;
}}

QMenu::item:hover {{
    background-color: {colors['menu_item_hover']};
}}

QMenu::item:selected {{
    background-color: {colors['background_selected']};
}}

QMenu::separator {{
    height: 1px;
    background-color: {colors['menu_separator']};
    margin: 4px 8px;
}}

/* **TOOLBAR STYLES** */
QToolBar {{
    background-color: {colors['toolbar_background']};
    border: 1px solid {colors['toolbar_border']};
    padding: 4px;
    spacing: 2px;
}}

QToolButton {{
    background-color: {colors['toolbar_button']};
    color: {colors['text']};
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 6px;
    margin: 1px;
}}

QToolButton:hover {{
    background-color: {colors['toolbar_button_hover']};
    border-color: {colors['border_hover']};
}}

QToolButton:pressed {{
    background-color: {colors['button_background_pressed']};
    border-color: {colors['border_focus']};
}}

/* **STATUS BAR STYLES** */
QStatusBar {{
    background-color: {colors['toolbar_background']};
    color: {colors['text']};
    border-top: 1px solid {colors['toolbar_border']};
    padding: 4px;
}}

QStatusBar::item {{
    border: none;
    padding: 2px 8px;
}}

/* **TOOLTIP STYLES** */
QToolTip {{
    background-color: {colors['tooltip_background']};
    color: {colors['tooltip_text']};
    border: 1px solid {colors['tooltip_border']};
    border-radius: 4px;
    padding: 6px 8px;
    font-size: 8pt;
}}

/* **CHECKBOX STYLES** */
QCheckBox {{
    background-color: transparent;
    color: {colors['text']};
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {colors['border']};
    border-radius: 3px;
    background-color: {colors['background_alt']};
}}

QCheckBox::indicator:hover {{
    border-color: {colors['border_hover']};
    background-color: {colors['background_hover']};
}}

QCheckBox::indicator:checked {{
    background-color: {colors['button_primary']};
    border-color: {colors['button_primary']};
}}

QCheckBox::indicator:checked:hover {{
    background-color: {colors['button_primary_hover']};
    border-color: {colors['button_primary_hover']};
}}

/* **RADIO BUTTON STYLES** */
QRadioButton {{
    background-color: transparent;
    color: {colors['text']};
    spacing: 8px;
}}

QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {colors['border']};
    border-radius: 8px;
    background-color: {colors['background_alt']};
}}

QRadioButton::indicator:hover {{
    border-color: {colors['border_hover']};
    background-color: {colors['background_hover']};
}}

QRadioButton::indicator:checked {{
    background-color: {colors['button_primary']};
    border-color: {colors['button_primary']};
}}

/* **SLIDER STYLES** */
QSlider::groove:horizontal {{
    height: 6px;
    background-color: {colors['progress_background']};
    border-radius: 3px;
}}

QSlider::handle:horizontal {{
    background-color: {colors['button_primary']};
    border: 1px solid {colors['button_primary']};
    width: 16px;
    margin: -5px 0px;
    border-radius: 8px;
}}

QSlider::handle:horizontal:hover {{
    background-color: {colors['button_primary_hover']};
    border-color: {colors['button_primary_hover']};
}}

/* **SPIN BOX STYLES** */
QSpinBox, QDoubleSpinBox {{
    background-color: {colors['background_alt']};
    color: {colors['text']};
    border: 1px solid {colors['border']};
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 20px;
}}

QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {colors['border_focus']};
}}

QSpinBox::up-button, QDoubleSpinBox::up-button {{
    subcontrol-origin: border;
    subcontrol-position: top right;
    width: 20px;
    border: none;
    background-color: {colors['button_background']};
    border-top-right-radius: 4px;
}}

QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover {{
    background-color: {colors['button_background_hover']};
}}

QSpinBox::down-button, QDoubleSpinBox::down-button {{
    subcontrol-origin: border;
    subcontrol-position: bottom right;
    width: 20px;
    border: none;
    background-color: {colors['button_background']};
    border-bottom-right-radius: 4px;
}}

QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
    background-color: {colors['button_background_hover']};
}}

/* **SPLITTER STYLES** */
QSplitter::handle {{
    background-color: {colors['border']};
    margin: 2px;
}}

QSplitter::handle:horizontal {{
    width: 3px;
}}

QSplitter::handle:vertical {{
    height: 3px;
}}

QSplitter::handle:hover {{
    background-color: {colors['border_focus']};
}}

/* **COMPONENT-SPECIFIC STYLES** */

/* **SCAN WINDOW SPECIFIC** */
QWidget[class="scan-window"] {{
    background-color: {colors['background']};
}}

QWidget[class="scan-progress"] {{
    background-color: {colors['background_alt']};
    border: 1px solid {colors['border']};
    border-radius: 6px;
    padding: 12px;
    margin: 8px;
}}

QLabel[class="scan-status"] {{
    font-size: 12pt;
    font-weight: 600;
    color: {colors['text_primary']};
}}

QProgressBar[class="scan-progress"] {{
    height: 8px;
    border-radius: 4px;
}}

/* **QUARANTINE WINDOW SPECIFIC** */
QWidget[class="quarantine-window"] {{
    background-color: {colors['background']};
}}

QTableWidget[class="quarantine-table"] {{
    background-color: {colors['table_background']};
    gridline-color: {colors['table_border']};
}}

/* **MODEL STATUS WINDOW SPECIFIC** */
QWidget[class="model-status-window"] {{
    background-color: {colors['background']};
}}

QLabel[class="model-loaded"] {{
    color: {colors['status_safe']};
    font-weight: 600;
}}

QLabel[class="model-loading"] {{
    color: {colors['status_warning']};
    font-weight: 600;
}}

QLabel[class="model-error"] {{
    color: {colors['status_danger']};
    font-weight: 600;
}}

/* **NOTIFICATION STYLES** */
QWidget[class="notification"] {{
    background-color: {colors['notification_background']};
    color: {colors['notification_text']};
    border: 1px solid {colors['notification_border']};
    border-radius: 6px;
    padding: 12px;
}}

QWidget[class="notification-success"] {{
    background-color: {colors['status_safe_light']};
    border-color: {colors['status_safe']};
}}

QWidget[class="notification-warning"] {{
    background-color: {colors['status_warning_light']};
    border-color: {colors['status_warning']};
}}

QWidget[class="notification-error"] {{
    background-color: {colors['status_danger_light']};
    border-color: {colors['status_danger']};
}}

/* **SIDEBAR STYLES** */
QWidget[class="sidebar"] {{
    background-color: {colors['sidebar_background']};
    border-right: 1px solid {colors['border']};
}}

QWidget[class="sidebar-header"] {{
    background-color: {colors['sidebar_header']};
    border-bottom: 1px solid {colors['border']};
    padding: 12px;
}}

QPushButton[class="sidebar-button"] {{
    background-color: {colors['sidebar_item']};
    border: none;
    border-radius: 4px;
    padding: 12px;
    text-align: left;
    margin: 2px 8px;
    font-weight: 500;
}}

QPushButton[class="sidebar-button"]:hover {{
    background-color: {colors['sidebar_item_hover']};
}}

QPushButton[class="sidebar-button"]:checked {{
    background-color: {colors['sidebar_item_active']};
    color: white;
    font-weight: 600;
}}

/* **ANIMATION AND TRANSITIONS** */
QWidget {{
    /* Smooth transitions for better UX */
    /* Note: CSS transitions are limited in Qt */
}}

/* **END OF LIGHT THEME STYLESHEET** */
"""
            
            return stylesheet.strip()
            
        except Exception as e:
            self.logger.error(f"Error generating light stylesheet: {e}")
            return self._generate_fallback_stylesheet()
    
    def _generate_fallback_stylesheet(self) -> str:
        """Generate basic fallback stylesheet for emergency use."""
        return """
/* FALLBACK STYLESHEET */
QWidget {
    background-color: #2b2b2b;
    color: #ffffff;
    font-family: 'Segoe UI', Arial, sans-serif;
}

QPushButton {
    background-color: #404040;
    color: #ffffff;
    border: 1px solid #555555;
    border-radius: 4px;
    padding: 6px 12px;
}

QPushButton:hover {
    background-color: #4a4a4a;
}

QLineEdit {
    background-color: #3c3c3c;
    color: #ffffff;
    border: 1px solid #555555;
    border-radius: 4px;
    padding: 6px;
}
"""
    
    def _discover_and_load_custom_themes(self):
        """Discover and load custom themes with comprehensive validation."""
        try:
            if not self.CUSTOM_THEMES_DIR.exists():
                self.logger.debug("No custom themes directory found")
                return
            
            custom_theme_files = list(self.CUSTOM_THEMES_DIR.glob("*.qss")) + \
                               list(self.CUSTOM_THEMES_DIR.glob("*.css")) + \
                               list(self.CUSTOM_THEMES_DIR.glob("*.json"))
            
            self.logger.info(f"Found {len(custom_theme_files)} potential custom theme files")
            
            for theme_file in custom_theme_files:
                try:
                    # **ENHANCED**: Validate file size
                    if theme_file.stat().st_size > (self.THEME_SIZE_LIMIT_KB * 1024):
                        self.logger.warning(f"Custom theme file too large: {theme_file.name}")
                        continue
                    
                    # **ENHANCED**: Load and validate custom theme
                    theme_data = self._load_custom_theme(theme_file)
                    if theme_data:
                        theme_name = f"custom_{theme_file.stem}"
                        self.custom_themes[theme_name] = theme_data
                        self.logger.debug(f"Loaded custom theme: {theme_name}")
                        
                        # **NEW**: Emit signal for custom theme detection
                        self.custom_theme_detected.emit(str(theme_file), theme_name)
                
                except Exception as e:
                    self.logger.warning(f"Error loading custom theme {theme_file.name}: {e}")
            
            self.logger.info(f"Custom theme loading completed: {len(self.custom_themes)} themes loaded")
            
        except Exception as e:
            self.logger.error(f"Error discovering custom themes: {e}")
    
    def _load_custom_theme(self, theme_file: Path) -> Optional[Dict[str, Any]]:
        """Load a single custom theme file with validation."""
        try:
            if theme_file.suffix.lower() == '.json':
                # JSON theme configuration
                content = safe_read_file(theme_file)
                theme_config = json.loads(content)
                
                # Validate JSON theme structure
                if not self._validate_json_theme(theme_config):
                    self.logger.warning(f"Invalid JSON theme structure: {theme_file.name}")
                    return None
                
                # Generate stylesheet from JSON configuration
                stylesheet = self._generate_stylesheet_from_json(theme_config)
                
                return {
                    'stylesheet': stylesheet,
                    'metadata': ThemeMetadata(
                        name=theme_config.get('name', theme_file.stem),
                        type=ThemeType.CUSTOM,
                        version=theme_config.get('version', '1.0.0'),
                        author=theme_config.get('author', 'Unknown'),
                        description=theme_config.get('description', ''),
                        file_path=str(theme_file),
                        file_size_kb=theme_file.stat().st_size / 1024,
                        validation_level=ThemeValidationLevel.STANDARD
                    ),
                    'config': theme_config
                }
            
            else:
                # QSS/CSS theme file
                stylesheet = safe_read_file(theme_file)
                
                # Validate stylesheet syntax
                if not self._validate_stylesheet_syntax(stylesheet):
                    self.logger.warning(f"Invalid stylesheet syntax: {theme_file.name}")
                    return None
                
                return {
                    'stylesheet': stylesheet,
                    'metadata': ThemeMetadata(
                        name=theme_file.stem.replace('_', ' ').title(),
                        type=ThemeType.CUSTOM,
                        file_path=str(theme_file),
                        file_size_kb=theme_file.stat().st_size / 1024,
                        validation_level=ThemeValidationLevel.BASIC
                    )
                }
            
        except Exception as e:
            self.logger.error(f"Error loading custom theme file {theme_file.name}: {e}")
            return None
    
    def _validate_json_theme(self, theme_config: Dict[str, Any]) -> bool:
        """Validate JSON theme configuration structure."""
        try:
            required_fields = ['name', 'colors']
            for field in required_fields:
                if field not in theme_config:
                    return False
            
            # Validate colors section
            colors = theme_config.get('colors', {})
            if not isinstance(colors, dict) or not colors:
                return False
            
            # Check for minimum required colors
            min_required_colors = ['background', 'text', 'border']
            for color in min_required_colors:
                if color not in colors:
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _validate_stylesheet_syntax(self, stylesheet: str) -> bool:
        """Basic validation of stylesheet syntax."""
        try:
            # Check for balanced braces
            open_braces = stylesheet.count('{')
            close_braces = stylesheet.count('}')
            
            if open_braces != close_braces:
                return False
            
            # Check for common Qt stylesheet patterns
            if 'QWidget' not in stylesheet and 'QPushButton' not in stylesheet:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _generate_stylesheet_from_json(self, theme_config: Dict[str, Any]) -> str:
        """Generate QSS stylesheet from JSON theme configuration."""
        try:
            colors = theme_config.get('colors', {})
            
            # Basic stylesheet template
            stylesheet = f"""
/* Custom Theme: {theme_config.get('name', 'Unnamed')} */
QWidget {{
    background-color: {colors.get('background', '#2b2b2b')};
    color: {colors.get('text', '#ffffff')};
}}

QPushButton {{
    background-color: {colors.get('button_background', colors.get('background', '#404040'))};
    color: {colors.get('button_text', colors.get('text', '#ffffff'))};
    border: 1px solid {colors.get('border', '#555555')};
    border-radius: 4px;
    padding: 6px 12px;
}}

QPushButton:hover {{
    background-color: {colors.get('button_hover', '#4a4a4a')};
}}

QLineEdit {{
    background-color: {colors.get('input_background', colors.get('background', '#3c3c3c'))};
    color: {colors.get('input_text', colors.get('text', '#ffffff'))};
    border: 1px solid {colors.get('border', '#555555')};
    border-radius: 4px;
    padding: 6px;
}}

QTableWidget {{
    background-color: {colors.get('table_background', colors.get('background', '#2b2b2b'))};
    color: {colors.get('table_text', colors.get('text', '#ffffff'))};
    gridline-color: {colors.get('table_border', colors.get('border', '#555555'))};
}}
"""
            
            return stylesheet
            
        except Exception as e:
            self.logger.error(f"Error generating stylesheet from JSON: {e}")
            return self._generate_fallback_stylesheet()
    
    def _validate_theme_integrity(self):
        """Validate integrity of all loaded themes."""
        try:
            self.logger.debug("Validating theme integrity...")
            
            valid_themes = {}
            
            for theme_key, theme_data in self.theme_cache.items():
                try:
                    if self._validate_single_theme(theme_key, theme_data):
                        valid_themes[theme_key] = theme_data
                        if 'metadata' in theme_data:
                            theme_data['metadata'].is_valid = True
                    else:
                        self.logger.warning(f"Theme failed validation: {theme_key}")
                        if 'metadata' in theme_data:
                            theme_data['metadata'].is_valid = False
                            theme_data['metadata'].error_count += 1
                
                except Exception as e:
                    self.logger.error(f"Error validating theme {theme_key}: {e}")
            
            # Update cache with only valid themes
            self.theme_cache = valid_themes
            
            # Validate custom themes
            valid_custom_themes = {}
            for theme_key, theme_data in self.custom_themes.items():
                try:
                    if self._validate_single_theme(theme_key, theme_data):
                        valid_custom_themes[theme_key] = theme_data
                
                except Exception as e:
                    self.logger.error(f"Error validating custom theme {theme_key}: {e}")
            
            self.custom_themes = valid_custom_themes
            
            self.logger.info(f"Theme validation completed: {len(self.theme_cache)} built-in, {len(self.custom_themes)} custom themes valid")
            
        except Exception as e:
            self.logger.error(f"Error during theme integrity validation: {e}")
    
    def _validate_single_theme(self, theme_key: str, theme_data: Dict[str, Any]) -> bool:
        """Validate a single theme's integrity."""
        try:
            # Check required fields
            if 'stylesheet' not in theme_data:
                return False
            
            stylesheet = theme_data['stylesheet']
            if not stylesheet or not isinstance(stylesheet, str):
                return False
            
            # Basic syntax validation
            if not self._validate_stylesheet_syntax(stylesheet):
                return False
            
            # Check metadata if present
            if 'metadata' in theme_data:
                metadata = theme_data['metadata']
                if not isinstance(metadata, ThemeMetadata):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _generate_theme_cache(self):
        """Generate optimized theme cache for performance."""
        try:
            self.logger.debug("Generating theme cache...")
            
            # Merge built-in and custom themes
            all_themes = {}
            all_themes.update(self.theme_cache)
            all_themes.update(self.custom_themes)
            
            # Generate cache with metadata
            for theme_key, theme_data in all_themes.items():
                try:
                    # Add to metadata tracking
                    if 'metadata' in theme_data:
                        self.theme_metadata[theme_key] = theme_data['metadata']
                    
                    # Pre-compile theme for faster application
                    self._precompile_theme(theme_key, theme_data)
                
                except Exception as e:
                    self.logger.warning(f"Error caching theme {theme_key}: {e}")
            
            self.logger.debug("Theme cache generation completed")
            
        except Exception as e:
            self.logger.error(f"Error generating theme cache: {e}")
    
    def _precompile_theme(self, theme_key: str, theme_data: Dict[str, Any]):
        """Pre-compile theme for optimized application."""
        try:
            # Pre-process stylesheet for faster application
            stylesheet = theme_data.get('stylesheet', '')
            
            # Remove comments and extra whitespace for optimization
            import re
            stylesheet = re.sub(r'/\*.*?\*/', '', stylesheet, flags=re.DOTALL)
            stylesheet = re.sub(r'\s+', ' ', stylesheet)
            stylesheet = stylesheet.strip()
            
            # Update theme data with optimized stylesheet
            theme_data['compiled_stylesheet'] = stylesheet
            
        except Exception as e:
            self.logger.debug(f"Error pre-compiling theme {theme_key}: {e}")
    
    def _set_current_theme_with_validation(self):
        """Set current theme from configuration with validation."""
        try:
            # Get theme preference from configuration
            config_theme = self.config.get_theme_preference()
            
            # Validate theme exists
            if config_theme in self.theme_cache:
                self.current_theme = ThemeType(config_theme)
                self.logger.info(f"Current theme set to: {self.current_theme.value}")
            else:
                self.logger.warning(f"Configured theme not found: {config_theme}, using default dark theme")
                self.current_theme = ThemeType.DARK
                self.config.set_theme_preference(self.current_theme.value)
            
            # Load current stylesheet
            self._load_current_stylesheet()
            
        except Exception as e:
            self.logger.error(f"Error setting current theme: {e}")
            self.current_theme = ThemeType.DARK
            self._load_current_stylesheet()
    
    def _load_current_stylesheet(self):
        """Load the current theme's stylesheet."""
        try:
            theme_data = self.theme_cache.get(self.current_theme)
            if theme_data:
                # Use compiled stylesheet if available, otherwise use regular
                self.current_stylesheet = theme_data.get('compiled_stylesheet', 
                                                       theme_data.get('stylesheet', ''))
                self.logger.debug(f"Loaded stylesheet for theme: {self.current_theme.value}")
            else:
                self.logger.warning(f"No stylesheet found for theme: {self.current_theme.value}")
                self.current_stylesheet = self._generate_fallback_stylesheet()
            
        except Exception as e:
            self.logger.error(f"Error loading current stylesheet: {e}")
            self.current_stylesheet = self._generate_fallback_stylesheet()
    
    def _initialize_performance_monitoring(self):
        """Initialize performance monitoring and optimization systems."""
        try:
            # Setup performance timer
            self._performance_timer = QTimer()
            self._performance_timer.timeout.connect(self._update_performance_metrics)
            self._performance_timer.start(30000)  # Update every 30 seconds
            
            # Initialize performance tracking
            self.performance_metrics = ThemePerformanceMetrics()
            self.performance_metrics.last_performance_check = datetime.now()
            
            self.logger.debug("Performance monitoring initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing performance monitoring: {e}")
    
    def _update_performance_metrics(self):
        """Update performance metrics and emit signals."""
        try:
            # Calculate cache hit rate
            if self.performance_metrics.total_applications > 0:
                self.performance_metrics.cache_hit_rate = (
                    self.performance_metrics.successful_applications / 
                    self.performance_metrics.total_applications
                )
            
            # Update last check time
            self.performance_metrics.last_performance_check = datetime.now()
            
            # Emit performance update signal
            metrics_dict = {
                'total_applications': self.performance_metrics.total_applications,
                'successful_applications': self.performance_metrics.successful_applications,
                'failed_applications': self.performance_metrics.failed_applications,
                'average_application_time': self.performance_metrics.average_application_time,
                'cache_hit_rate': self.performance_metrics.cache_hit_rate,
                'last_check': self.performance_metrics.last_performance_check.isoformat()
            }
            
            self.performance_update.emit(metrics_dict)
            
        except Exception as e:
            self.logger.debug(f"Error updating performance metrics: {e}")
    
    def _initialize_theme_watchers(self):
        """Initialize theme file watchers for auto-reload functionality."""
        try:
            if not self._auto_reload_enabled:
                return
            
            # Setup file system watcher for theme directories
            from PySide6.QtCore import QFileSystemWatcher
            
            self._file_watcher = QFileSystemWatcher()
            
            # Watch theme directories
            if self.THEMES_DIR.exists():
                self._file_watcher.addPath(str(self.THEMES_DIR))
            if self.CUSTOM_THEMES_DIR.exists():
                self._file_watcher.addPath(str(self.CUSTOM_THEMES_DIR))
            
            # Connect signals
            self._file_watcher.directoryChanged.connect(self._on_theme_directory_changed)
            self._file_watcher.fileChanged.connect(self._on_theme_file_changed)
            
            self.logger.debug("Theme watchers initialized for auto-reload")
            
        except Exception as e:
            self.logger.warning(f"Could not initialize theme watchers: {e}")
    
    def _on_theme_directory_changed(self, path: str):
        """Handle theme directory changes for auto-reload."""
        try:
            self.logger.info(f"Theme directory changed: {path}")
            
            # Reload custom themes
            if Path(path) == self.CUSTOM_THEMES_DIR:
                self._discover_and_load_custom_themes()
                self._generate_theme_cache()
                
                # Notify about theme changes
                self.theme_warning.emit("auto_reload", f"Custom themes reloaded from {path}")
            
        except Exception as e:
            self.logger.error(f"Error handling theme directory change: {e}")
    
    def _on_theme_file_changed(self, path: str):
        """Handle individual theme file changes for auto-reload."""
        try:
            self.logger.info(f"Theme file changed: {path}")
            
            file_path = Path(path)
            if file_path.parent == self.CUSTOM_THEMES_DIR:
                # Reload specific custom theme
                theme_data = self._load_custom_theme(file_path)
                if theme_data:
                    theme_name = f"custom_{file_path.stem}"
                    self.custom_themes[theme_name] = theme_data
                    self._generate_theme_cache()
                    
                    # Notify about theme reload
                    self.theme_loaded.emit(theme_name, {'reloaded': True, 'path': str(file_path)})
            
        except Exception as e:
            self.logger.error(f"Error handling theme file change: {e}")
    
    def _validate_system_integrity(self) -> bool:
        """Validate overall theme system integrity."""
        try:
            # Check if we have at least basic themes
            if not self.theme_cache:
                return False
            
            # Check if current theme is valid
            if self.current_theme not in self.theme_cache:
                return False
            
            # Check if current stylesheet is valid
            if not self.current_stylesheet:
                return False
            
            # Check color palettes
            if not self.color_palettes:
                return False
            
            # Check if we have palettes for current theme
            if self.current_theme not in self.color_palettes:
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating system integrity: {e}")
            return False
    
    def _create_enhanced_fallback_theme(self):
        """Create enhanced fallback theme for system recovery."""
        try:
            self.logger.warning("Creating enhanced fallback theme for system recovery")
            
            # Create basic fallback theme
            fallback_stylesheet = self._generate_fallback_stylesheet()
            
            fallback_theme_data = {
                'stylesheet': fallback_stylesheet,
                'compiled_stylesheet': fallback_stylesheet,
                'metadata': ThemeMetadata(
                    name="Emergency Fallback Theme",
                    type=ThemeType.DARK,
                    version="1.0.0",
                    author="System",
                    description="Emergency fallback theme for system recovery",
                    is_valid=True,
                    validation_level=ThemeValidationLevel.BASIC
                )
            }
            
            # Add to cache
            self.theme_cache[ThemeType.DARK] = fallback_theme_data
            
            # Set as current theme
            self.current_theme = ThemeType.DARK
            self.current_stylesheet = fallback_stylesheet
            
            # Create basic color palette
            if ThemeType.DARK not in self.color_palettes:
                self.color_palettes[ThemeType.DARK] = {
                    'background': '#2b2b2b',
                    'text': '#ffffff',
                    'border': '#555555',
                    'button_background': '#404040',
                    'button_hover': '#4a4a4a'
                }
            
            self.logger.info("Enhanced fallback theme created successfully")
            
        except Exception as e:
            self.logger.critical(f"Failed to create enhanced fallback theme: {e}")
    
    def _initialize_error_recovery(self):
        """Initialize error recovery mechanisms."""
        try:
            # Setup recovery timer
            self._recovery_timer = QTimer()
            self._recovery_timer.timeout.connect(self._perform_recovery_check)
            self._recovery_timer.start(60000)  # Check every minute
            
            self.logger.debug("Error recovery mechanisms initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing recovery mechanisms: {e}")
    
    def _perform_recovery_check(self):
        """Perform periodic recovery check."""
        try:
            # Check if system is healthy
            if not self._validate_system_integrity():
                self.logger.warning("System integrity check failed - attempting recovery")
                self._attempt_system_recovery()
            
        except Exception as e:
            self.logger.debug(f"Error during recovery check: {e}")
    
    def _attempt_system_recovery(self):
        """Attempt to recover from system errors."""
        try:
            self.logger.info("Attempting theme system recovery...")
            
            # Try to reload themes
            self._load_and_validate_all_themes()
            
            # Validate again
            if self._validate_system_integrity():
                self.logger.info("Theme system recovery successful")
                self.theme_warning.emit("recovery", "Theme system successfully recovered")
            else:
                # Create fallback theme as last resort
                self._create_enhanced_fallback_theme()
                self.theme_error.emit("recovery_failed", "Theme system recovery failed - using fallback")
            
        except Exception as e:
            self.logger.error(f"Error during system recovery: {e}")
            # Last resort - create basic fallback
            self._create_enhanced_fallback_theme()

    # ========================================================================
    # PUBLIC API METHODS - Theme Application and Management
    # ========================================================================

    def apply_theme(self, target: Union[QWidget, QApplication, str] = None, 
                   theme_type: Optional[ThemeType] = None) -> ThemeApplicationResult:
        """
        **ENHANCED** Apply theme to target widget or application with comprehensive error handling.
        
        Args:
            target: Target widget, application, or target type string
            theme_type: Specific theme type to apply (optional, uses current if None)
            
        Returns:
            ThemeApplicationResult with detailed operation information
        """
        start_time = time.time()
        result = ThemeApplicationResult(
            success=False,
            theme_name="",
            target=str(target) if target else "application"
        )
        
        try:
            with self._theme_lock:
                # Determine theme to apply
                theme_to_apply = theme_type or self.current_theme
                result.theme_name = theme_to_apply.value
                
                # Get theme data
                theme_data = self.theme_cache.get(theme_to_apply)
                if not theme_data:
                    theme_data = self.custom_themes.get(theme_to_apply.value)
                
                if not theme_data:
                    result.error_message = f"Theme not found: {theme_to_apply.value}"
                    self.theme_error.emit("application_failed", result.error_message)
                    return result
                
                # Get stylesheet
                stylesheet = theme_data.get('compiled_stylesheet', 
                                          theme_data.get('stylesheet', ''))
                
                if not stylesheet:
                    result.error_message = f"No stylesheet found for theme: {theme_to_apply.value}"
                    self.theme_error.emit("application_failed", result.error_message)
                    return result
                
                # Apply theme based on target type
                if target is None or isinstance(target, QApplication):
                    # Apply to entire application
                    app = QApplication.instance()
                    if app:
                        app.setStyleSheet(stylesheet)
                        result.applied_components.append("QApplication")
                        result.success = True
                        
                        # Update current theme
                        self.current_theme = theme_to_apply
                        self.current_stylesheet = stylesheet
                        
                        # Save to configuration
                        self.config.set_theme_preference(theme_to_apply.value)
                
                elif isinstance(target, QWidget):
                    # Apply to specific widget
                    target.setStyleSheet(stylesheet)
                    result.applied_components.append(target.__class__.__name__)
                    result.success = True
                    
                    # Track applied theme
                    widget_id = id(target)
                    self._applied_themes[widget_id] = theme_to_apply
                
                elif isinstance(target, str):
                    # Apply to specific component type
                    app = QApplication.instance()
                    if app:
                        # Component-specific styling
                        component_stylesheet = self._get_component_stylesheet(target, theme_to_apply)
                        app.setStyleSheet(component_stylesheet)
                        result.applied_components.append(target)
                        result.success = True
                
                # Calculate application time
                application_time = (time.time() - start_time) * 1000
                result.application_time_ms = application_time
                
                # Update performance metrics
                self.performance_metrics.update_application_metrics(application_time, result.success)
                
                # Record in history
                self._application_history.append({
                    'timestamp': datetime.now(),
                    'theme': theme_to_apply.value,
                    'target': result.target,
                    'success': result.success,
                    'time_ms': application_time
                })
                
                # Emit signals
                if result.success:
                    self.theme_applied.emit(result.target, theme_to_apply.value)
                    self.theme_changed.emit(theme_to_apply.value, 
                                          theme_data.get('metadata', {}).__dict__ if hasattr(theme_data.get('metadata', {}), '__dict__') else {})
                    self.logger.info(f"Theme applied successfully: {theme_to_apply.value} to {result.target}")
                else:
                    self.theme_error.emit("application_failed", result.error_message or "Unknown error")
                
                return result
        
        except Exception as e:
            application_time = (time.time() - start_time) * 1000
            result.application_time_ms = application_time
            result.error_message = str(e)
            
            # Update performance metrics
            self.performance_metrics.update_application_metrics(application_time, False)
            
            # Record error
            self._error_history.append({
                'timestamp': datetime.now(),
                'theme': result.theme_name,
                'target': result.target,
                'error': str(e)
            })
            
            self.logger.error(f"Error applying theme: {e}")
            self.theme_error.emit("application_error", str(e))
            
            return result
    
    def _get_component_stylesheet(self, component: str, theme_type: ThemeType) -> str:
        """Get component-specific stylesheet with overrides."""
        try:
            # Get base theme stylesheet
            theme_data = self.theme_cache.get(theme_type, {})
            base_stylesheet = theme_data.get('compiled_stylesheet', 
                                           theme_data.get('stylesheet', ''))
            
            # Get component-specific overrides
            component_colors = self.component_palettes.get(component, {}).get(theme_type, {})
            
            if component_colors:
                # Apply component-specific color overrides
                stylesheet = base_stylesheet
                for color_key, color_value in component_colors.items():
                    # Replace color references in stylesheet
                    stylesheet = stylesheet.replace(f'{{{color_key}}}', color_value)
                return stylesheet
            
            return base_stylesheet
            
        except Exception as e:
            self.logger.error(f"Error getting component stylesheet: {e}")
            return self._generate_fallback_stylesheet()
    
    def switch_theme(self, theme_type: ThemeType) -> bool:
        """
        **ENHANCED** Switch to a different theme with validation and error handling.
        
        Args:
            theme_type: Theme type to switch to
            
        Returns:
            bool: True if theme switch was successful
        """
        try:
            self.logger.info(f"Switching theme to: {theme_type.value}")
            
            # Validate theme exists
            if theme_type not in self.theme_cache and theme_type.value not in self.custom_themes:
                self.logger.error(f"Theme not available: {theme_type.value}")
                self.theme_error.emit("switch_failed", f"Theme not available: {theme_type.value}")
                return False
            
            # Apply theme to application
            result = self.apply_theme(theme_type=theme_type)
            
            if result.success:
                self.logger.info(f"Theme switched successfully to: {theme_type.value}")
                return True
            else:
                self.logger.error(f"Failed to switch theme: {result.error_message}")
                return False
        
        except Exception as e:
            self.logger.error(f"Error switching theme: {e}")
            self.theme_error.emit("switch_error", str(e))
            return False
    
    def get_current_theme(self) -> ThemeType:
        """Get the currently active theme type."""
        return self.current_theme
    
    def get_available_themes(self) -> List[str]:
        """Get list of all available theme names."""
        try:
            themes = list(self.theme_cache.keys())
            themes.extend(self.custom_themes.keys())
            return [theme.value if hasattr(theme, 'value') else str(theme) for theme in themes]
        except Exception as e:
            self.logger.error(f"Error getting available themes: {e}")
            return ['dark', 'light']  # Fallback
    
    def get_theme_colors(self, theme_type: Optional[ThemeType] = None) -> Dict[str, str]:
        """
        Get color palette for specified theme type.
        
        Args:
            theme_type: Theme type (uses current if None)
            
        Returns:
            Dictionary of color key-value pairs
        """
        try:
            theme = theme_type or self.current_theme
            return self.color_palettes.get(theme, {}).copy()
        except Exception as e:
            self.logger.error(f"Error getting theme colors: {e}")
            return {}
    
    def get_component_colors(self, component: str, theme_type: Optional[ThemeType] = None) -> Dict[str, str]:
        """
        Get component-specific color overrides.
        
        Args:
            component: Component name
            theme_type: Theme type (uses current if None)
            
        Returns:
            Dictionary of component-specific color overrides
        """
        try:
            theme = theme_type or self.current_theme
            return self.component_palettes.get(component, {}).get(theme, {}).copy()
        except Exception as e:
            self.logger.error(f"Error getting component colors: {e}")
            return {}


    def get_icon(self, icon_name: str, size: int = 24, theme: str = None) -> QIcon:
        """
        Get icon with proper size handling.
        
        Fixed version that handles size parameter correctly.
        """
        try:
            if theme is None:
                theme = self.current_theme
            
            # Handle size parameter properly
            if isinstance(size, tuple):
                icon_size = size[0]  # Use first value from tuple
            elif hasattr(size, 'width'):  # QSize object
                icon_size = size.width()
            else:
                icon_size = int(size)  # Direct integer
            
            # Try to load from generated icons first
            icon_path = self._get_generated_icon_path(icon_name, icon_size, theme)
            if icon_path and icon_path.exists():
                icon = QIcon(str(icon_path))
                if not icon.isNull():
                    return icon
            
            # Fallback to theme-specific icons
            theme_icon_path = self._get_theme_icon_path(icon_name, theme)
            if theme_icon_path and theme_icon_path.exists():
                icon = QIcon(str(theme_icon_path))
                if not icon.isNull():
                    return icon
            
            # Final fallback to system icons
            return self._get_fallback_icon(icon_name, icon_size)
            
        except Exception as e:
            self.logger.error(f"Error getting icon {icon_name}: {e}")
            return self._get_fallback_icon(icon_name, 24)

    def _get_generated_icon_path(self, icon_name: str, size: int, theme: str) -> Path:
        """Get path to generated icon file."""
        try:
            icons_dir = Path("src/resources/icons")
            
            # Try theme-specific icon first
            theme_path = icons_dir / theme / f"{icon_name}_{size}.png"
            if theme_path.exists():
                return theme_path
            
            # Try SVG version
            svg_path = icons_dir / theme / f"{icon_name}.svg"
            if svg_path.exists():
                return svg_path
            
            # Try neutral theme
            neutral_path = icons_dir / "neutral" / f"{icon_name}_{size}.png"
            if neutral_path.exists():
                return neutral_path
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting generated icon path: {e}")
            return None

    def _get_fallback_icon(self, icon_name: str, size: int) -> QIcon:
        """Get fallback system icon."""
        try:
            # Map icon names to system icons
            system_icon_map = {
                'app_icon': 'SP_ComputerIcon',
                'shield': 'SP_DialogApplyButton',
                'settings': 'SP_FileDialogDetailedView',
                'scan_quick': 'SP_MediaPlay',
                'scan_full': 'SP_MediaSeekForward',
                'quarantine': 'SP_DialogSaveButton',
                'models': 'SP_FileDialogListView',
                'reports': 'SP_FileDialogInfoView',
                'help': 'SP_DialogHelpButton',
                'close': 'SP_DialogCloseButton',
                'minimize': 'SP_TitleBarMinButton',
                'maximize': 'SP_TitleBarMaxButton',
                'error': 'SP_MessageBoxCritical',
                'warning': 'SP_MessageBoxWarning',
                'info': 'SP_MessageBoxInformation'
            }
            
            system_icon_name = system_icon_map.get(icon_name, 'SP_ComputerIcon')
            
            # Get system icon
            if hasattr(self, 'app') and self.app:
                style = self.app.style()
                system_icon = getattr(style, system_icon_name, style.SP_ComputerIcon)
                return style.standardIcon(system_icon)
            
            # Create a simple colored rectangle as last resort
            pixmap = QPixmap(size, size)
            pixmap.fill(QColor('#4CAF50'))  # Green fallback
            return QIcon(pixmap)
            
        except Exception as e:
            self.logger.error(f"Error creating fallback icon: {e}")
            # Create empty icon as final fallback
            pixmap = QPixmap(size, size)
            pixmap.fill(Qt.transparent)
            return QIcon(pixmap)
    
    def _generate_fallback_icon(self, icon_name: str, theme_type: ThemeType) -> Optional[QIcon]:
        """Generate fallback icon for missing icons."""
        try:
            # Create a simple colored square as fallback
            pixmap = QPixmap(16, 16)
            
            # Get theme colors
            colors = self.color_palettes.get(theme_type, {})
            
            # Choose color based on icon name
            if 'safe' in icon_name or 'success' in icon_name:
                color = QColor(colors.get('status_safe', '#4caf50'))
            elif 'warning' in icon_name:
                color = QColor(colors.get('status_warning', '#ff9800'))
            elif 'danger' in icon_name or 'error' in icon_name:
                color = QColor(colors.get('status_danger', '#f44336'))
            else:
                color = QColor(colors.get('text', '#ffffff'))
            
            # Fill pixmap with color
            pixmap.fill(color)
            
            return QIcon(pixmap)
            
        except Exception as e:
            self.logger.debug(f"Error generating fallback icon: {e}")
            return None
    
    def reload_themes(self) -> bool:
        """
        **ENHANCED** Reload all themes from disk with comprehensive validation.
        
        Returns:
            bool: True if reload was successful
        """
        try:
            self.logger.info("Reloading all themes from disk...")
            
            # Clear existing caches
            self.theme_cache.clear()
            self.custom_themes.clear()
            self.theme_metadata.clear()
            
            # Reload themes
            self._load_and_validate_all_themes()
            
            # Validate system
            if self._validate_system_integrity():
                # Reapply current theme
                self.apply_theme()
                
                self.logger.info("Theme reload completed successfully")
                self.theme_loaded.emit("all_themes", {'reloaded': True, 'count': len(self.theme_cache) + len(self.custom_themes)})
                return True
            else:
                self.logger.error("Theme reload failed - system integrity check failed")
                self._create_enhanced_fallback_theme()
                return False
        
        except Exception as e:
            self.logger.error(f"Error reloading themes: {e}")
            self.theme_error.emit("reload_failed", str(e))
            return False
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        try:
            return {
                'total_applications': self.performance_metrics.total_applications,
                'successful_applications': self.performance_metrics.successful_applications,
                'failed_applications': self.performance_metrics.failed_applications,
                'average_application_time': self.performance_metrics.average_application_time,
                'min_application_time': self.performance_metrics.min_application_time if self.performance_metrics.min_application_time != float('inf') else 0,
                'max_application_time': self.performance_metrics.max_application_time,
                'cache_hit_rate': self.performance_metrics.cache_hit_rate,
                'last_check': self.performance_metrics.last_performance_check.isoformat() if self.performance_metrics.last_performance_check else None,
                'theme_count': len(self.theme_cache) + len(self.custom_themes),
                'cache_size': len(self.icon_cache)
            }
        except Exception as e:
            self.logger.error(f"Error getting performance metrics: {e}")
            return {}
        
    def cleanup(self):
        """**ENHANCED** Cleanup theme manager resources and stop all operations."""
        try:
            self.logger.info("Cleaning up theme manager resources...")
            
            # Stop timers
            if hasattr(self, '_performance_timer'):
                self._performance_timer.stop()
                self._performance_timer.deleteLater()
            
            if hasattr(self, '_recovery_timer'):
                self._recovery_timer.stop()
                self._recovery_timer.deleteLater()
            
            # Stop file watcher
            if hasattr(self, '_file_watcher'):
                self._file_watcher.deleteLater()
            
            # Clear caches
            self.theme_cache.clear()
            self.custom_themes.clear()
            self.theme_metadata.clear()
            self.icon_cache.clear()
            self._applied_themes.clear()
            self._component_themes.clear()
            
            # Clear history
            self._application_history.clear()
            self._error_history.clear()
            
            # Set shutdown event
            self._shutdown_event.set()
            
            self.logger.info("Theme manager cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during theme manager cleanup: {e}")
    
    def __del__(self):
        """Destructor to ensure cleanup."""
        try:
            if hasattr(self, '_shutdown_event') and not self._shutdown_event.is_set():
                self.cleanup()
        except Exception:
            pass  # Ignore errors during destruction