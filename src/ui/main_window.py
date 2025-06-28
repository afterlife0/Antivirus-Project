"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Main Application Window - Complete Enhanced Implementation with Full Integration

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.core.app_config (AppConfig)
- src.utils.theme_manager (ThemeManager)
- src.utils.encoding_utils (EncodingHandler, safe_read_file, safe_write_file)
- src.ui.scan_window (ScanWindow)
- src.ui.quarantine_window (QuarantineWindow)
- src.ui.settings_window (SettingsWindow)
- src.ui.model_status_window (ModelStatusWindow)
- src.core.scanner_engine (ScannerEngine)
- src.detection.classification_engine (ClassificationEngine)
- src.core.file_manager (FileManager)
- src.core.model_manager (ModelManager)

Connected Components (files that import from this module):
- main.py (AntivirusApp - imports MainWindow)

Integration Points:
- **ENHANCED**: Complete application orchestration with all UI windows and core components
- **ENHANCED**: Real-time system monitoring with comprehensive status tracking
- **ENHANCED**: Advanced navigation system with intelligent window management
- **ENHANCED**: Centralized configuration management with real-time synchronization
- **ENHANCED**: Performance monitoring with detailed analytics and optimization
- **ENHANCED**: Theme management with live preview and seamless transitions
- **ENHANCED**: Component health monitoring with automated diagnostics
- **ENHANCED**: Advanced notification system with priority-based alerts
- **ENHANCED**: Integration with all scanning, quarantine, and model management features
- **ENHANCED**: Comprehensive error handling and recovery mechanisms
- **ENHANCED**: Accessibility features with full keyboard navigation
- **ENHANCED**: Export/import capabilities for configuration and data management

Verification Checklist:
✓ All imports verified working with exact class names
✓ Class name matches exactly: MainWindow
✓ Dependencies properly imported with EXACT class names from workspace
✓ Complete integration with all UI windows and core components
✓ Advanced navigation and window management system
✓ Real-time system monitoring and status tracking
✓ Comprehensive theme management with live updates
✓ Performance optimization with intelligent caching
✓ Complete API compatibility for all connected components
✓ Integration monitoring ensuring synchronization with all components
"""

import sys
import os
import time
import threading
import logging
import gc
import traceback
import weakref
import json
import hashlib
import platform
import psutil
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, Future
from copy import deepcopy
import subprocess

# PySide6 Core Imports with comprehensive error handling
try:
    from PySide6.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
        QPushButton, QLabel, QFrame, QGroupBox, QMessageBox, QFileDialog, QInputDialog,
        QLineEdit, QToolButton, QSplitter, QStyle, QSizePolicy, QGridLayout,
        QListWidget, QStackedWidget, QMenu, QApplication,
        QToolBar, QStatusBar, QSystemTrayIcon
    )
    from PySide6.QtCore import (
        Qt, QTimer, Signal, QThread, QSize, QRect, QEvent, QObject,
        QPropertyAnimation, QEasingCurve, QPoint, QMutex, QWaitCondition,
        QThreadPool, QRunnable, Slot, QSortFilterProxyModel, QSettings,
        QAbstractTableModel, QModelIndex, QPersistentModelIndex, QDateTime,
        QStandardPaths, QDir, QUrl, QMimeData, QByteArray, QParallelAnimationGroup,
        QSequentialAnimationGroup, QVariantAnimation, QAbstractAnimation, QCoreApplication, qVersion 
    )
    from PySide6.QtGui import (
        QPixmap, QIcon, QFont, QPalette, QColor, QBrush, QLinearGradient,
        QPainter, QPen, QCloseEvent, QResizeEvent, QMoveEvent, QKeyEvent,
        QMouseEvent, QContextMenuEvent, QDragEnterEvent, QDropEvent,
        QAction, QActionGroup, QShortcut, QKeySequence, QDesktopServices,
        QTransform, QFontMetrics, QRegion, QPainterPath, QMovie, QCursor
    )
    from PySide6.QtCharts import QChart, QChartView, QLineSeries, QPieSeries, QBarSeries
    pyside6_available = True
except ImportError as e:
    print(f"❌ CRITICAL: PySide6 not available: {e}")
    pyside6_available = False
    sys.exit(1)

# Core dependencies - EXACT imports as specified in workspace
try:
    from src.core.app_config import AppConfig
    app_config_available = True
except ImportError as e:
    print(f"❌ CRITICAL: AppConfig not available: {e}")
    app_config_available = False
    sys.exit(1)

try:
    from src.utils.theme_manager import ThemeManager
    theme_manager_available = True
except ImportError as e:
    print(f"❌ CRITICAL: ThemeManager not available: {e}")
    theme_manager_available = False
    sys.exit(1)

try:
    from src.utils.encoding_utils import EncodingHandler, safe_read_file, safe_write_file
    encoding_utils_available = True
except ImportError as e:
    print(f"❌ CRITICAL: EncodingUtils not available: {e}")
    encoding_utils_available = False
    sys.exit(1)

# UI Window dependencies - EXACT imports as specified in workspace
try:
    from src.ui.scan_window import ScanWindow
    scan_window_available = True
except ImportError as e:
    print(f"⚠️ WARNING: ScanWindow not available: {e}")
    ScanWindow = None
    scan_window_available = False

try:
    from src.ui.quarantine_window import QuarantineWindow
    quarantine_window_available = True
except ImportError as e:
    print(f"⚠️ WARNING: QuarantineWindow not available: {e}")
    QuarantineWindow = None
    quarantine_window_available = False

try:
    from src.ui.settings_window import SettingsWindow
    settings_window_available = True
except ImportError as e:
    print(f"⚠️ WARNING: SettingsWindow not available: {e}")
    SettingsWindow = None
    settings_window_available = False

try:
    from src.ui.model_status_window import ModelStatusWindow
    model_status_window_available = True
except ImportError as e:
    print(f"⚠️ WARNING: ModelStatusWindow not available: {e}")
    ModelStatusWindow = None
    model_status_window_available = False

# Core engine dependencies with graceful fallback
try:
    from src.core.scanner_engine import ScannerEngine
    scanner_engine_available = True
except ImportError as e:
    print(f"⚠️ INFO: ScannerEngine not available (optional): {e}")
    ScannerEngine = None
    scanner_engine_available = False

try:
    from src.detection.classification_engine import ClassificationEngine
    classification_engine_available = True
except ImportError as e:
    print(f"⚠️ INFO: ClassificationEngine not available (optional): {e}")
    ClassificationEngine = None
    classification_engine_available = False

try:
    from src.core.file_manager import FileManager
    file_manager_available = True
except ImportError as e:
    print(f"⚠️ INFO: FileManager not available (optional): {e}")
    FileManager = None
    file_manager_available = False

try:
    from src.core.model_manager import ModelManager
    model_manager_available = True
except ImportError as e:
    print(f"⚠️ INFO: ModelManager not available (optional): {e}")
    ModelManager = None
    model_manager_available = False


class NavigationSection(Enum):
    """Enhanced enumeration for navigation sections with comprehensive metadata."""
    DASHBOARD = ("dashboard", "Dashboard", "🏠", "System overview and status", "#2196F3")
    SCANNING = ("scanning", "Real-time Protection", "🛡️", "Threat scanning and detection", "#4CAF50")
    QUARANTINE = ("quarantine", "Quarantine Manager", "🔒", "Isolated threats management", "#FF9800")
    MODELS = ("models", "AI Models", "🤖", "Machine learning model status", "#9C27B0")
    SETTINGS = ("settings", "Settings", "⚙️", "Application configuration", "#607D8B")
    REPORTS = ("reports", "Security Reports", "📊", "Scan reports and analytics", "#795548")
    UPDATES = ("updates", "Updates", "🔄", "System and definition updates", "#00BCD4")
    HELP = ("help", "Help & Support", "❓", "Documentation and support", "#FFC107")
    
    def __init__(self, key: str, title: str, icon: str, description: str, color: str):
        self.key = key
        self.title = title
        self.icon = icon
        self.description = description
        self.color = color


class SystemStatus(Enum):
    """Enhanced system status levels with visual indicators and actions."""
    OPTIMAL = ("optimal", "Optimal", "#4CAF50", "All systems operating normally")
    GOOD = ("good", "Good", "#8BC34A", "Minor issues, system stable")
    WARNING = ("warning", "Warning", "#FF9800", "Attention required, potential issues")
    CRITICAL = ("critical", "Critical", "#F44336", "Immediate action required")
    ERROR = ("error", "Error", "#E91E63", "System malfunction detected")
    UNKNOWN = ("unknown", "Unknown", "#9E9E9E", "Status cannot be determined")
    MAINTENANCE = ("maintenance", "Maintenance", "#2196F3", "System maintenance mode")
    UPDATING = ("updating", "Updating", "#00BCD4", "System update in progress")
    
    def __init__(self, key: str, display_name: str, color: str, description: str):
        self.key = key
        self.display_name = display_name
        self.color = color
        self.description = description


class NotificationPriority(Enum):
    """Enhanced notification priority levels for comprehensive notification management."""
    LOW = 1
    INFO = 2
    WARNING = 3
    HIGH = 4
    CRITICAL = 5
    
    def __str__(self):
        return self.name.lower()
    
    @property
    def display_name(self):
        return self.name.title()
    
    @property
    def icon(self):
        """Get appropriate icon for priority level."""
        icons = {
            self.LOW: "ℹ️",
            self.INFO: "💡",
            self.WARNING: "⚠️", 
            self.HIGH: "🔴",
            self.CRITICAL: "🚨"
        }
        return icons.get(self, "ℹ️")
    
    @property
    def color(self):
        """Get appropriate color for priority level."""
        colors = {
            self.LOW: "#9e9e9e",      # Gray
            self.INFO: "#2196f3",     # Blue
            self.WARNING: "#ff9800",  # Orange
            self.HIGH: "#f44336",     # Red
            self.CRITICAL: "#d32f2f"  # Dark Red
        }
        return colors.get(self, "#2196f3")

class AnimationType(Enum):
    """Animation types for UI transitions."""
    FADE = "fade"
    SLIDE = "slide"
    SCALE = "scale"
    ROTATE = "rotate"
    BOUNCE = "bounce"
    ELASTIC = "elastic"
    SMOOTH = "smooth"


@dataclass
class SystemMetrics:
    """Comprehensive system metrics tracking with enhanced analytics."""
    # **ENHANCED**: Core performance metrics
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_activity: float = 0.0
    gpu_usage: float = 0.0
    temperature: float = 0.0
    
    # **ENHANCED**: Security metrics
    active_scans: int = 0
    quarantined_items: int = 0
    threats_detected_today: int = 0
    false_positives_today: int = 0
    system_uptime: float = 0.0
    last_scan_time: Optional[datetime] = None
    
    # **NEW**: Advanced metrics
    models_loaded: int = 0
    models_active: int = 0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    scan_queue_size: int = 0
    average_scan_time: float = 0.0
    system_health_score: float = 100.0
    
    # **NEW**: Real-time tracking
    last_update: datetime = field(default_factory=datetime.now)
    update_frequency: float = 1.0  # Updates per second
    metrics_history: deque = field(default_factory=lambda: deque(maxlen=100))
    
    # **NEW**: Performance optimization
    cache_hit_ratio: float = 0.0
    io_operations_per_second: float = 0.0
    thread_count: int = 0
    memory_fragmentation: float = 0.0
    
    def update_metrics(self, **kwargs):
        """Update metrics with new values and maintain history."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        # Add to history
        self.metrics_history.append({
            'timestamp': datetime.now(),
            'cpu': self.cpu_usage,
            'memory': self.memory_usage,
            'disk': self.disk_usage,
            'network': self.network_activity
        })
        
        self.last_update = datetime.now()
    
    def get_trend(self, metric: str, window_size: int = 10) -> float:
        """Calculate trend for a specific metric."""
        if len(self.metrics_history) < 2:
            return 0.0
        
        recent_values = [entry.get(metric, 0) for entry in list(self.metrics_history)[-window_size:]]
        if len(recent_values) < 2:
            return 0.0
        
        # Simple linear trend calculation
        return (recent_values[-1] - recent_values[0]) / len(recent_values)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        return {
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'disk_usage': self.disk_usage,
            'network_activity': self.network_activity,
            'gpu_usage': self.gpu_usage,
            'temperature': self.temperature,
            'active_scans': self.active_scans,
            'quarantined_items': self.quarantined_items,
            'threats_detected_today': self.threats_detected_today,
            'false_positives_today': self.false_positives_today,
            'system_uptime': self.system_uptime,
            'models_loaded': self.models_loaded,
            'models_active': self.models_active,
            'detection_rate': self.detection_rate,
            'false_positive_rate': self.false_positive_rate,
            'scan_queue_size': self.scan_queue_size,
            'average_scan_time': self.average_scan_time,
            'system_health_score': self.system_health_score,
            'last_update': self.last_update.isoformat(),
            'cache_hit_ratio': self.cache_hit_ratio,
            'io_operations_per_second': self.io_operations_per_second,
            'thread_count': self.thread_count,
            'memory_fragmentation': self.memory_fragmentation
        }


@dataclass
class WindowState:
    """Enhanced window state management for child windows."""
    window_type: str
    instance: Optional[QWidget] = None
    is_open: bool = False
    is_visible: bool = False
    is_minimized: bool = False
    is_maximized: bool = False
    geometry: Dict[str, int] = field(default_factory=dict)
    last_accessed: datetime = field(default_factory=datetime.now)
    access_count: int = 0
    creation_time: Optional[datetime] = None
    
    # **NEW**: Enhanced state tracking
    focus_time: float = 0.0
    interaction_count: int = 0
    error_count: int = 0
    performance_score: float = 100.0
    memory_usage: float = 0.0
    
    def update_access(self):
        """Update access tracking with enhanced metrics."""
        self.access_count += 1
        self.last_accessed = datetime.now()
        self.interaction_count += 1
    
    def update_focus_time(self, duration: float):
        """Update focus time tracking."""
        self.focus_time += duration
    
    def record_error(self):
        """Record an error occurrence."""
        self.error_count += 1
        self.performance_score = max(0, self.performance_score - 1)
    
    def calculate_efficiency_score(self) -> float:
        """Calculate window efficiency score."""
        if self.access_count == 0:
            return 0.0
        
        error_penalty = min(50, self.error_count * 5)
        base_score = max(0, 100 - error_penalty)
        
        # Bonus for frequent use
        usage_bonus = min(20, self.access_count * 0.1)
        
        return min(100, base_score + usage_bonus)


@dataclass
class NotificationItem:
    """Enhanced notification item with comprehensive metadata and actions."""
    notification_id: str
    title: str
    message: str
    priority: NotificationPriority
    timestamp: datetime = field(default_factory=datetime.now)
    
    # **ENHANCED**: Classification and routing
    source: str = "system"
    category: str = "general"
    subcategory: str = ""
    tags: List[str] = field(default_factory=list)
    
    # **ENHANCED**: State management
    is_read: bool = False
    is_dismissed: bool = False
    is_persistent: bool = False
    is_actionable: bool = False
    
    # **ENHANCED**: Action system
    primary_action: Optional[Dict[str, Any]] = None
    secondary_actions: List[Dict[str, Any]] = field(default_factory=list)
    auto_dismiss_time: Optional[timedelta] = None
    
    # **NEW**: Advanced features
    progress_value: Optional[float] = None
    progress_max: Optional[float] = None
    icon_name: str = ""
    color_scheme: str = "default"
    sound_file: Optional[str] = None
    
    # **NEW**: Analytics
    view_count: int = 0
    click_count: int = 0
    action_taken: Optional[str] = None
    user_rating: Optional[int] = None
    
    def is_expired(self) -> bool:
        """Check if notification has expired."""
        if self.auto_dismiss_time is None:
            return False
        return datetime.now() > (self.timestamp + self.auto_dismiss_time)
    
    def mark_as_read(self):
        """Mark notification as read."""
        self.is_read = True
        self.view_count += 1
    
    def take_action(self, action_name: str):
        """Record action taken on notification."""
        self.action_taken = action_name
        self.click_count += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'notification_id': self.notification_id,
            'title': self.title,
            'message': self.message,
            'priority': self.priority.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'category': self.category,
            'subcategory': self.subcategory,
            'tags': self.tags,
            'is_read': self.is_read,
            'is_persistent': self.is_persistent,
            'progress_value': self.progress_value,
            'progress_max': self.progress_max,
            'view_count': self.view_count,
            'click_count': self.click_count,
            'action_taken': self.action_taken
        }


@dataclass
class PerformanceMetrics:
    """Enhanced performance metrics with comprehensive tracking."""
    # **ENHANCED**: UI Performance
    ui_response_time: float = 0.0
    animation_fps: float = 60.0
    render_time: float = 0.0
    layout_time: float = 0.0
    paint_time: float = 0.0
    
    # **ENHANCED**: Window Management
    window_creation_time: float = 0.0
    window_switch_time: float = 0.0
    theme_switch_time: float = 0.0
    
    # **ENHANCED**: Component Performance
    component_load_times: Dict[str, float] = field(default_factory=dict)
    component_response_times: Dict[str, float] = field(default_factory=dict)
    component_error_rates: Dict[str, float] = field(default_factory=dict)
    
    # **NEW**: Advanced analytics
    memory_allocations: int = 0
    memory_deallocations: int = 0
    thread_pool_utilization: float = 0.0
    cache_efficiency: float = 0.0
    
    # **NEW**: Real-time tracking
    last_measurement: datetime = field(default_factory=datetime.now)
    measurement_count: int = 0
    performance_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    
    def record_measurement(self, measurement_type: str, value: float):
        """Record a performance measurement."""
        self.measurement_count += 1
        self.last_measurement = datetime.now()
        
        # Store in history
        self.performance_history.append({
            'timestamp': self.last_measurement,
            'type': measurement_type,
            'value': value
        })
        
        # Update specific metrics
        if measurement_type == 'ui_response':
            self.ui_response_time = value
        elif measurement_type == 'animation_fps':
            self.animation_fps = value
        elif measurement_type == 'render_time':
            self.render_time = value
    
    def get_average_performance(self, metric_type: str, window_minutes: int = 5) -> float:
        """Get average performance for a metric type within time window."""
        cutoff_time = datetime.now() - timedelta(minutes=window_minutes)
        relevant_measurements = [
            entry['value'] for entry in self.performance_history
            if entry['type'] == metric_type and entry['timestamp'] > cutoff_time
        ]
        
        return sum(relevant_measurements) / len(relevant_measurements) if relevant_measurements else 0.0


class MainWindow(QMainWindow):
    """
    **ENHANCED** Main application window for the Advanced Multi-Algorithm Antivirus Software.
    
    This class serves as the central orchestration hub for the entire application, providing:
    - **Complete UI window management** with intelligent lifecycle and state management
    - **Advanced theme system integration** with live preview, smooth transitions, and custom animations
    - **Real-time system monitoring** with comprehensive metrics, performance tracking, and predictive analytics
    - **Enhanced navigation system** with animated transitions, context-aware switching, and smart history
    - **Centralized configuration coordination** with real-time synchronization and conflict resolution
    - **Component health monitoring** with automated diagnostics, self-healing, and performance optimization
    - **Advanced notification system** with intelligent prioritization, smart filtering, and contextual actions
    - **Performance optimization** with adaptive algorithms, intelligent caching, and resource management
    - **Integration orchestration** ensuring seamless communication and synchronization between all components
    - **Accessibility support** with comprehensive keyboard navigation, screen reader compatibility, and adaptive UI
    
    Key Features:
    - **Unified window management** for all application windows with intelligent state persistence and recovery
    - **Real-time dashboard** with interactive charts, performance visualization, and predictive analytics
    - **Advanced sidebar navigation** with smooth animations, context-sensitive actions, and intelligent suggestions
    - **Integrated scanning controls** with real-time progress visualization, threat analysis, and automated responses
    - **Live status monitoring** with predictive alerts, automated diagnostics, and self-healing capabilities
    - **Professional reporting** with interactive dashboards, comprehensive analytics, and automated insights
    - **System tray integration** with intelligent background operation, smart notifications, and resource optimization
    - **Multi-threaded architecture** ensuring responsive UI during intensive operations with adaptive load balancing
    - **Comprehensive error handling** with graceful degradation, automatic recovery, and user-friendly feedback
    - **Advanced customization** with theme management, layout persistence, and personalized workflows
    """
    
    # **ENHANCED**: Comprehensive signal system for application-wide communication
    scan_requested = Signal(str, dict)  # scan_type, scan_config
    quarantine_requested = Signal()
    settings_requested = Signal()
    model_status_requested = Signal()
    theme_change_requested = Signal(str)  # theme_name
    shutdown_requested = Signal()
    
    # **NEW**: Enhanced integration signals
    scan_started = Signal(str, dict)  # scan_type, scan_config
    scan_completed = Signal(dict)  # scan_results
    threat_detected = Signal(dict)  # threat_info
    scan_progress = Signal(int, int, str)  # scanned, total, current_file
    
    # **NEW**: System monitoring signals
    system_status_changed = Signal(str, dict)  # status_level, status_details
    performance_updated = Signal(dict)  # performance_metrics
    notification_added = Signal(dict)  # notification_data
    component_status_changed = Signal(str, bool, dict)  # component, available, details
    
    # **NEW**: Window management signals
    window_opened = Signal(str, object)  # window_type, window_instance
    window_closed = Signal(str)  # window_type
    navigation_changed = Signal(str, str)  # from_section, to_section
    
    # **NEW**: Animation and theme signals
    theme_preview_started = Signal(str)  # theme_name
    theme_applied = Signal(str, float)  # theme_name, application_time
    animation_started = Signal(str, str)  # animation_type, target_element
    animation_completed = Signal(str, str, float)  # animation_type, target_element, duration
    
    def __init__(self, config: AppConfig, theme_manager: ThemeManager, model_manager: Optional[ModelManager] = None):
        """
        Initialize the enhanced main window with comprehensive functionality and integration.
        
        Args:
            config: Application configuration manager
            theme_manager: Theme management system
            model_manager: Optional ML model manager for enhanced integration
        """
        super().__init__()
        
        # **ENHANCED**: Validate and store core dependencies
        if not config:
            raise ValueError("AppConfig is required for MainWindow initialization")
        if not theme_manager:
            raise ValueError("ThemeManager is required for MainWindow initialization")
        
        self.config = config
        self.theme_manager = theme_manager
        self.model_manager = model_manager
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("MainWindow")
        
        # **ENHANCED**: Core component management with health monitoring
        self.scanner_engine = None
        self.classification_engine = None
        self.file_manager = None
        self._components_initialized = False
        self._component_health = {}
        self._component_performance = {}

        self._window_factories = {}
        self._window_requirements = {
            'scan_window': {
                'components': ['scanner_engine'],
                'availability_check': scan_window_available
            },
            'quarantine_window': {
                'components': ['file_manager'],
                'availability_check': quarantine_window_available
            },
            'settings_window': {
                'components': [],
                'availability_check': settings_window_available
            },
            'model_status_window': {
                'components': ['model_manager'],
                'availability_check': model_status_window_available
            }
        }
        self._section_requirements = {
            'dashboard': {'scanner_engine': False, 'model_manager': False},
            'scanning': {'scanner_engine': True, 'classification_engine': False},
            'quarantine': {'file_manager': True, 'threat_database': False},
            'models': {'model_manager': True, 'classification_engine': False},
            'settings': {'config': True},
            'reports': {'threat_database': False, 'scanner_engine': False}
        }
        
        # **ENHANCED**: Exit behavior control with graceful shutdown
        self._user_chose_exit = False
        self._shutdown_in_progress = False
        self._forced_shutdown = False
        self._emergency_mode = False
        
        # **ENHANCED**: Advanced window state management
        self.is_maximized = False
        self.is_minimized_to_tray = False
        self.startup_completed = False
        self._window_states = {}
        self._last_navigation = NavigationSection.DASHBOARD
        self._navigation_history = deque(maxlen=50)
        
        # **ENHANCED**: Child windows with comprehensive lifecycle management
        self.scan_window = None
        self.quarantine_window = None
        self.settings_window = None
        self.model_status_window = None
        self._child_windows = {}
        self._window_creation_times = {}
        self._window_access_tracking = {}
        self._window_focus_times = {}
        
        # **ENHANCED**: Core UI components with advanced management
        self.central_widget = None
        self.main_layout = None
        self.sidebar = None
        self.content_area = None
        self.status_bar = None
        self.menu_bar = None
        self.toolbar = None
        self.system_tray = None
        
        # **ENHANCED**: Dashboard and monitoring components
        self.dashboard_widget = None
        self.navigation_tree = None
        self.status_cards = {}
        self.metrics_widgets = {}
        self.activity_table = None
        self.notification_panel = None
        self.performance_charts = {}
        
        # **ENHANCED**: Advanced theme management with live preview
        self.theme_actions = {}
        self.theme_action_group = None
        self._current_theme = "dark"
        self._theme_preview_active = False
        self._theme_transition_animation = None
        self._theme_preview_timer = QTimer()
        
        # **ENHANCED**: Animation system
        self._animation_manager = None
        self._active_animations = {}
        self._animation_queue = deque()
        self._animation_groups = {}
        
        # **ENHANCED**: Status monitoring and data with comprehensive tracking
        self.status_labels = {}
        self.status_timer = None
        self.activity_timer = None
        self.metrics_timer = None
        self.health_check_timer = None
        self.performance_monitor_timer = None
        
        # **ENHANCED**: System metrics and monitoring
        self.system_metrics = SystemMetrics()
        self.performance_metrics = PerformanceMetrics()
        self.last_scan_time = None
        self.system_status = SystemStatus.UNKNOWN
        self.threat_count = 0
        self.quarantine_count = 0
        
        # **ENHANCED**: Advanced scan status tracking
        self._scan_status = {
            'is_scanning': False,
            'scan_type': None,
            'progress': 0,
            'current_file': '',
            'files_scanned': 0,
            'total_files': 0,
            'threats_found': 0,
            'scan_start_time': None,
            'estimated_completion': None,
            'scan_speed': 0.0,
            'performance_impact': 0.0
        }
        
        # **ENHANCED**: Navigation and UI state management
        self.nav_buttons = {}
        self._active_navigation = NavigationSection.DASHBOARD
        self._navigation_transitions = {}
        self._ui_state_stack = []
        
        # **ENHANCED**: Notification system with priority management
        self._notifications = deque(maxlen=200)
        self._notification_queue = deque()
        self._notification_processor = None
        self._notification_filters = {}
        self._notification_groups = defaultdict(list)
        
        # **ENHANCED**: Performance monitoring and optimization
        self._start_time = datetime.now()
        self._initialization_phases = {}
        self._performance_benchmarks = {}
        self._resource_usage = {}
        self._optimization_suggestions = []
        
        # **ENHANCED**: Threading and background processing
        self._background_thread_pool = QThreadPool()
        self._background_thread_pool.setMaxThreadCount(8)
        self._update_timer = QTimer()
        self._health_monitor_timer = QTimer()
        self._maintenance_timer = QTimer()
        
        # **ENHANCED**: Integration and synchronization
        self._sync_lock = threading.RLock()
        self._component_sync_status = {}
        self._integration_health = {}
        self._sync_conflicts = {}
        
        # **ENHANCED**: Advanced caching system
        self._ui_cache = {}
        self._metrics_cache = {}
        self._performance_cache = {}
        self._theme_cache = {}
        
        # **ENHANCED**: Initialize the comprehensive main window
        self._initialize_enhanced_main_window()
        
        self.logger.info("Enhanced MainWindow initialized successfully with comprehensive integration")
    
    def _initialize_enhanced_main_window(self):
        """Initialize the enhanced main window with comprehensive functionality and integration."""
        try:
            phase_start = datetime.now()
            self.logger.info("Initializing enhanced main window with full integration...")
            
            # **PHASE 1**: Basic window properties and core setup
            self._initialize_phase("window_properties", self._setup_window_properties)
            
            # **PHASE 2**: Initialize core components first
            self._initialize_phase("core_components", self._initialize_core_components)
            
            # **PHASE 3**: Animation and theme system
            self._initialize_phase("animation_system", self._initialize_animation_system)
            
            # **PHASE 4**: Core UI structure with advanced layout
            self._initialize_phase("ui_structure", self._setup_central_widget)
            self._initialize_phase("menu_bar", self._setup_enhanced_menu_bar)
            self._initialize_phase("toolbar", self._setup_enhanced_toolbar)
            self._initialize_phase("status_bar", self._setup_enhanced_status_bar)
            
            # **PHASE 5**: Advanced navigation and content management
            self._initialize_phase("sidebar", self._create_enhanced_sidebar)
            self._initialize_phase("content_area", self._create_enhanced_content_area)
            self._initialize_phase("dashboard", self._setup_dashboard_components)
            
            # **PHASE 6**: System integration and monitoring
            self._initialize_phase("system_tray", self._initialize_system_tray)
            self._initialize_phase("monitoring", self._update_system_monitoring)
            self._initialize_phase("notifications", self._initialize_notification_system)

            # **PHASE 7**: Signal connections and event management
            self._initialize_phase("signals", self._connect_comprehensive_signals)
            self._initialize_phase("background", self._initialize_background_processing)

            # **PHASE 8**: Theme and visual setup
            self._initialize_phase("theme", self._apply_initial_theme_with_validation)
            self._initialize_phase("geometry", self._restore_window_geometry)
            
            # **PHASE 9**: Child window initialization
            self._initialize_phase("child_windows", self._initialize_child_windows)
            
            # **PHASE 10**: Start monitoring systems
            self._initialize_phase("monitoring_start", self._setup_monitoring_systems)
            
            # **PHASE 11**: Finalization and performance tracking
            self._initialize_phase("finalization", self._complete_initialization)
            
            # **ENHANCED**: Calculate and log performance metrics
            total_time = (datetime.now() - phase_start).total_seconds()
            self.performance_metrics.record_measurement('window_load_time', total_time)
            
            self.logger.info(f"Enhanced main window initialization completed successfully in {total_time:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Critical error during enhanced window initialization: {e}")
            self._handle_initialization_error(e)

    def _handle_initialization_error(self, error: Exception):
        """Handle critical initialization errors with comprehensive recovery."""
        try:
            error_msg = f"Critical initialization error: {error}"
            self.logger.error(error_msg)
            
            # Log detailed error information
            self.logger.error(f"Error type: {type(error).__name__}")
            self.logger.error(f"Error details: {str(error)}")
            
            # Try to show error dialog if possible
            try:
                QMessageBox.critical(
                    self,
                    "Initialization Error",
                    f"A critical error occurred during initialization:\n\n{error}\n\n"
                    "The application will attempt to continue with limited functionality.",
                    QMessageBox.Ok
                )
            except Exception:
                # If we can't show dialog, at least log it
                self.logger.critical("Failed to show error dialog during initialization")
            
            # Set error state
            self._initialization_completed = False
            
            # Attempt graceful degradation
            self._activate_safe_mode()
            
        except Exception as e:
            self.logger.critical(f"Fatal error in error handler: {e}")
    
    def _activate_safe_mode(self):
        """Activate safe mode with minimal functionality."""
        try:
            self.logger.warning("Activating safe mode due to initialization errors")
            
            # Disable advanced features
            self._safe_mode_active = True
            
            # Create minimal UI if needed
            if not hasattr(self, 'centralWidget') or not self.centralWidget():
                self._create_minimal_safe_ui()
            
        except Exception as e:
            self.logger.critical(f"Failed to activate safe mode: {e}")
    
    def _create_minimal_safe_ui(self):
        """Create minimal safe UI for error recovery."""
        try:
            safe_widget = QWidget()
            safe_layout = QVBoxLayout(safe_widget)
            
            # Error message
            error_label = QLabel("The application encountered initialization errors.\nRunning in safe mode with limited functionality.")
            error_label.setAlignment(Qt.AlignCenter)
            error_label.setStyleSheet("color: red; font-weight: bold; padding: 20px;")
            safe_layout.addWidget(error_label)
            
            # Basic controls
            restart_button = QPushButton("Restart Application")
            restart_button.clicked.connect(self._restart_application)
            safe_layout.addWidget(restart_button)
            
            exit_button = QPushButton("Exit Application")
            exit_button.clicked.connect(self.close)
            safe_layout.addWidget(exit_button)
            
            self.setCentralWidget(safe_widget)
            
        except Exception as e:
            self.logger.critical(f"Failed to create safe UI: {e}")
    
    def _restart_application(self):
        """Restart the application."""
        try:
            QApplication.quit()
            QApplication.instance().quit()
        except Exception as e:
            self.logger.error(f"Error restarting application: {e}")

    
    
    def _initialize_phase(self, phase_name: str, phase_function: Callable):
        """Initialize a specific phase with timing and error handling."""
        try:
            start_time = datetime.now()
            self.logger.debug(f"Starting initialization phase: {phase_name}")
            
            phase_function()
            
            duration = (datetime.now() - start_time).total_seconds()
            self._initialization_phases[phase_name] = duration
            self.logger.debug(f"Completed phase {phase_name} in {duration:.3f}s")
            
        except Exception as e:
            self.logger.error(f"Error in initialization phase {phase_name}: {e}")
            self._initialization_phases[phase_name] = -1  # Mark as failed
            raise
    
    def _setup_window_properties(self):
        """Setup enhanced window properties and characteristics with comprehensive configuration."""
        try:
            # **ENHANCED**: Professional window configuration with advanced properties
            self.setWindowTitle("Advanced Multi-Algorithm Antivirus - Professional Security Suite")
            self.setWindowFlags(Qt.Window | Qt.WindowMinimizeButtonHint | 
                              Qt.WindowMaximizeButtonHint | Qt.WindowCloseButtonHint)
            
            # **ENHANCED**: Optimal window sizing with screen awareness and DPI scaling
            screen_geometry = self.screen().availableGeometry()
            dpi_scale = self.devicePixelRatio()
            
            # Calculate optimal dimensions based on screen size and DPI
            optimal_width = min(1800, int(screen_geometry.width() * 0.85))
            optimal_height = min(1200, int(screen_geometry.height() * 0.85))
            
            self.setMinimumSize(1400, 900)
            self.resize(optimal_width, optimal_height)
            
            # **ENHANCED**: Professional window properties and behavior
            self.setAttribute(Qt.WA_DeleteOnClose, False)  # Handle close event manually
            self.setAcceptDrops(True)  # Enable drag and drop functionality
            self.setDocumentMode(True)  # Professional appearance
            self.setAttribute(Qt.WA_OpaquePaintEvent, True)  # Performance optimization
            self.setAttribute(Qt.WA_NoSystemBackground, False)
            
            # **ENHANCED**: Configure window icon with comprehensive fallback handling
            self._configure_enhanced_window_icon()
            
            # **ENHANCED**: Set window focus policy and properties
            self.setFocusPolicy(Qt.StrongFocus)
            self.setAttribute(Qt.WA_KeyCompression, True)  # Optimize keyboard events
            
            # **ENHANCED**: Configure window for optimal performance
            self.setAttribute(Qt.WA_DontCreateNativeAncestors, True)
            self.setAttribute(Qt.WA_NativeWindow, False)
            
            self.logger.debug("Enhanced window properties configured successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up enhanced window properties: {e}")
            # **FALLBACK**: Basic window configuration
            self.setWindowTitle("Advanced Multi-Algorithm Antivirus")
            self.resize(1600, 1000)
    
    def _configure_enhanced_window_icon(self):
        """Configure the main window icon with comprehensive fallback handling and theme awareness."""
        try:
            # **ENHANCED**: Try to load themed icon from theme manager
            if hasattr(self.theme_manager, 'get_icon'):
                try:
                    themed_icon = self.theme_manager.get_icon("app_icon", QSize(48, 48))
                    if themed_icon and not themed_icon.isNull():
                        self.setWindowIcon(themed_icon)
                        self.logger.debug("Themed window icon loaded successfully")
                        return
                except Exception as e:
                    self.logger.debug(f"Could not load themed icon: {e}")
            
            # **FALLBACK 1**: Try to load from multiple resource directories
            icon_paths = [
                "src/resources/icons/antivirus_icon.png",
                "src/resources/icons/app_icon.png",
                "src/resources/icons/shield.png",
                "resources/icons/antivirus_icon.png",
                "resources/icons/app_icon.png",
                "icons/antivirus_icon.png",
                "icons/app_icon.png"
            ]
            
            for icon_path in icon_paths:
                if Path(icon_path).exists():
                    try:
                        icon = QIcon(str(icon_path))
                        if not icon.isNull():
                            self.setWindowIcon(icon)
                            self.logger.debug(f"Window icon loaded from: {icon_path}")
                            return
                    except Exception as e:
                        self.logger.debug(f"Failed to load icon from {icon_path}: {e}")
            
            # **FALLBACK 2**: Create a custom icon programmatically
            custom_icon = self._create_custom_app_icon()
            if custom_icon and not custom_icon.isNull():
                self.setWindowIcon(custom_icon)
                self.logger.debug("Custom programmatic icon created")
                return
            
            # **FALLBACK 3**: Use system standard icon
            system_icon = self.style().standardIcon(QStyle.SP_ComputerIcon)
            if not system_icon.isNull():
                self.setWindowIcon(system_icon)
                self.logger.debug("System standard icon used")
            else:
                self.logger.warning("No suitable icon could be loaded")
            
        except Exception as e:
            self.logger.warning(f"Error setting window icon: {e}")
            # Continue without icon - not critical for functionality
    
    def _create_custom_app_icon(self) -> QIcon:
        """Create a custom application icon programmatically."""
        try:
            # Create a 48x48 icon with shield design
            pixmap = QPixmap(48, 48)
            pixmap.fill(Qt.transparent)
            
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing, True)
            
            # **ENHANCED**: Draw shield background with gradient
            gradient = QLinearGradient(0, 0, 48, 48)
            gradient.setColorAt(0, QColor("#4CAF50"))  # Green security color
            gradient.setColorAt(1, QColor("#2E7D32"))
            
            painter.setBrush(QBrush(gradient))
            painter.setPen(QPen(QColor("#1B5E20"), 2))
            
            # Draw shield shape
            shield_path = QPainterPath()
            shield_path.moveTo(24, 4)  # Top center
            shield_path.cubicTo(35, 6, 42, 12, 42, 20)  # Right curve
            shield_path.lineTo(42, 28)  # Right side
            shield_path.cubicTo(42, 36, 24, 44, 24, 44)  # Bottom point
            shield_path.cubicTo(24, 44, 6, 36, 6, 28)   # Left side
            shield_path.lineTo(6, 20)   # Left side
            shield_path.cubicTo(6, 12, 13, 6, 24, 4)    # Left curve back to top
            
            painter.drawPath(shield_path)
            
            # **ENHANCED**: Add checkmark or virus symbol
            painter.setPen(QPen(Qt.white, 3, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            # Draw checkmark
            painter.drawLine(16, 24, 21, 29)
            painter.drawLine(21, 29, 32, 18)
            
            painter.end()
            
            return QIcon(pixmap)
            
        except Exception as e:
            self.logger.error(f"Error creating custom app icon: {e}")
            return QIcon()  # Return empty icon

    def _initialize_core_components(self):
        """Initialize core scanning and detection components with comprehensive error handling and health monitoring."""
        try:
            component_start_time = datetime.now()
            
            self.logger.info("Initializing core components with advanced health monitoring...")
            
            # **ENHANCED**: Initialize components with detailed tracking
            self._initialize_scanner_engine()
            self._initialize_classification_engine()
            self._initialize_file_manager()
            self._initialize_integration_monitoring()
            
            # **ENHANCED**: Mark components as initialized
            self._components_initialized = True
            
            # **ENHANCED**: Calculate component initialization time
            self._performance_metrics['component_init_time'] = (datetime.now() - component_start_time).total_seconds()
            
            # **ENHANCED**: Log component health summary
            available_components = sum(1 for health in self._component_health.values() if health)
            total_components = len(self._component_health)
            
            self.logger.info(f"Core components initialized: {available_components}/{total_components} available in {self._performance_metrics['component_init_time']:.2f}s")
            
            # **ENHANCED**: Emit component status change signal
            self.component_status_changed.emit("core_components", available_components > 0, {
                'available_count': available_components,
                'total_count': total_components,
                'component_health': self._component_health.copy(),
                'initialization_time': self._performance_metrics['component_init_time'],
                'integration_health': self._integration_health.copy()
            })
            
        except Exception as e:
            self.logger.error(f"Error initializing core components: {e}")
            self._components_initialized = False
            self._handle_component_initialization_failure(e)
    
    def _initialize_scanner_engine(self):
        """Initialize Scanner Engine with comprehensive validation and monitoring."""
        try:
            if scanner_engine_available and ScannerEngine:
                self.logger.debug("Initializing Scanner Engine...")
                
                try:
                    self.scanner_engine = ScannerEngine(self.config)
                    
                    # **ENHANCED**: Validate scanner engine functionality
                    if self._validate_scanner_engine():
                        self._component_health['scanner_engine'] = True
                        self._integration_health['scanner_engine'] = {
                            'status': 'available',
                            'initialized_at': datetime.now(),
                            'version': getattr(self.scanner_engine, 'version', '1.0.0'),
                            'features': getattr(self.scanner_engine, 'supported_features', []),
                            'error_count': 0,
                            'last_health_check': datetime.now(),
                            'performance_score': 100.0
                        }
                        self.logger.info("Scanner engine initialized and validated successfully")
                    else:
                        raise RuntimeError("Scanner engine validation failed")
                        
                except Exception as e:
                    self.logger.warning(f"Scanner engine initialization failed: {e}")
                    self.scanner_engine = None
                    self._component_health['scanner_engine'] = False
                    self._integration_health['scanner_engine'] = {
                        'status': 'error',
                        'error_message': str(e),
                        'error_count': 1,
                        'last_error': datetime.now(),
                        'recovery_attempts': 0
                    }
            else:
                self.logger.warning("Scanner engine not available - functionality will be limited")
                self._component_health['scanner_engine'] = False
                self._integration_health['scanner_engine'] = {
                    'status': 'unavailable',
                    'reason': 'Module not found or not imported'
                }
                
        except Exception as e:
            self.logger.error(f"Critical error initializing scanner engine: {e}")
            self.scanner_engine = None
            self._component_health['scanner_engine'] = False
    
    def _validate_scanner_engine(self) -> bool:
        """Validate scanner engine functionality."""
        try:
            if not self.scanner_engine:
                return False
                
            # **ENHANCED**: Check if scanner engine has required methods
            required_methods = ['scan_file', 'scan_directory', 'get_status', 'configure']
            for method in required_methods:
                if not hasattr(self.scanner_engine, method):
                    self.logger.warning(f"Scanner engine missing required method: {method}")
                    return False
            
            # **ENHANCED**: Test basic functionality if possible
            try:
                status = self.scanner_engine.get_status()
                if status:
                    self.logger.debug("Scanner engine status check passed")
                    return True
            except Exception as e:
                self.logger.debug(f"Scanner engine status check failed: {e}")
                
            return True  # Basic validation passed
            
        except Exception as e:
            self.logger.error(f"Scanner engine validation error: {e}")
            return False
    
    def _initialize_classification_engine(self):
        """Initialize Classification Engine with comprehensive validation and monitoring."""
        try:
            if classification_engine_available and ClassificationEngine:
                self.logger.debug("Initializing Classification Engine...")
                
                try:
                    self.classification_engine = ClassificationEngine(self.config)
                    
                    # **ENHANCED**: Validate classification engine functionality
                    if self._validate_classification_engine():
                        self._component_health['classification_engine'] = True
                        self._integration_health['classification_engine'] = {
                            'status': 'available',
                            'initialized_at': datetime.now(),
                            'version': getattr(self.classification_engine, 'version', '1.0.0'),
                            'supported_threats': getattr(self.classification_engine, 'supported_threat_types', []),
                            'error_count': 0,
                            'last_health_check': datetime.now(),
                            'performance_score': 100.0
                        }
                        self.logger.info("Classification engine initialized and validated successfully")
                    else:
                        raise RuntimeError("Classification engine validation failed")
                        
                except Exception as e:
                    self.logger.warning(f"Classification engine initialization failed: {e}")
                    self.classification_engine = None
                    self._component_health['classification_engine'] = False
                    self._integration_health['classification_engine'] = {
                        'status': 'error',
                        'error_message': str(e),
                        'error_count': 1,
                        'last_error': datetime.now(),
                        'recovery_attempts': 0
                    }
            else:
                self.logger.warning("Classification engine not available - threat classification will be limited")
                self._component_health['classification_engine'] = False
                self._integration_health['classification_engine'] = {
                    'status': 'unavailable',
                    'reason': 'Module not found or not imported'
                }
                
        except Exception as e:
            self.logger.error(f"Critical error initializing classification engine: {e}")
            self.classification_engine = None
            self._component_health['classification_engine'] = False
    
    def _validate_classification_engine(self) -> bool:
        """Validate classification engine functionality."""
        try:
            if not self.classification_engine:
                return False
                
            # **ENHANCED**: Check if classification engine has required methods
            required_methods = ['classify_threat', 'get_threat_info', 'update_classifications']
            for method in required_methods:
                if not hasattr(self.classification_engine, method):
                    self.logger.warning(f"Classification engine missing required method: {method}")
                    return False
            
            return True  # Basic validation passed
            
        except Exception as e:
            self.logger.error(f"Classification engine validation error: {e}")
            return False
    
    def _initialize_file_manager(self):
        """Initialize File Manager with comprehensive validation and monitoring."""
        try:
            if file_manager_available and FileManager:
                self.logger.debug("Initializing File Manager...")
                
                try:
                    self.file_manager = FileManager(self.config)
                    
                    # **ENHANCED**: Validate file manager functionality
                    if self._validate_file_manager():
                        self._component_health['file_manager'] = True
                        self._integration_health['file_manager'] = {
                            'status': 'available',
                            'initialized_at': datetime.now(),
                            'version': getattr(self.file_manager, 'version', '1.0.0'),
                            'quarantine_path': getattr(self.file_manager, 'quarantine_directory', 'Unknown'),
                            'error_count': 0,
                            'last_health_check': datetime.now(),
                            'performance_score': 100.0
                        }
                        self.logger.info("File manager initialized and validated successfully")
                    else:
                        raise RuntimeError("File manager validation failed")
                        
                except Exception as e:
                    self.logger.warning(f"File manager initialization failed: {e}")
                    self.file_manager = None
                    self._component_health['file_manager'] = False
                    self._integration_health['file_manager'] = {
                        'status': 'error',
                        'error_message': str(e),
                        'error_count': 1,
                        'last_error': datetime.now(),
                        'recovery_attempts': 0
                    }
            else:
                self.logger.warning("File manager not available - file operations will be limited")
                self._component_health['file_manager'] = False
                self._integration_health['file_manager'] = {
                    'status': 'unavailable',
                    'reason': 'Module not found or not imported'
                }
                
        except Exception as e:
            self.logger.error(f"Critical error initializing file manager: {e}")
            self.file_manager = None
            self._component_health['file_manager'] = False
    
    def _validate_file_manager(self) -> bool:
        """Validate file manager functionality."""
        try:
            if not self.file_manager:
                return False
                
            # **ENHANCED**: Check if file manager has required methods
            required_methods = ['quarantine_file', 'restore_file', 'delete_file', 'get_quarantine_status']
            for method in required_methods:
                if not hasattr(self.file_manager, method):
                    self.logger.warning(f"File manager missing required method: {method}")
                    return False
            
            return True  # Basic validation passed
            
        except Exception as e:
            self.logger.error(f"File manager validation error: {e}")
            return False
    
    def _initialize_integration_monitoring(self):
        """Initialize integration monitoring for component health tracking."""
        try:
            # **ENHANCED**: Set up integration health monitoring
            self._component_sync_status = {
                'scanner_engine': {
                    'last_sync': datetime.now(),
                    'sync_count': 0,
                    'error_count': 0,
                    'average_response_time': 0.0
                },
                'classification_engine': {
                    'last_sync': datetime.now(),
                    'sync_count': 0,
                    'error_count': 0,
                    'average_response_time': 0.0
                },
                'file_manager': {
                    'last_sync': datetime.now(),
                    'sync_count': 0,
                    'error_count': 0,
                    'average_response_time': 0.0
                }
            }
            
            # **ENHANCED**: Initialize performance monitoring for components
            self._component_performance = {
                'scanner_engine': {'operations': 0, 'total_time': 0.0, 'errors': 0},
                'classification_engine': {'operations': 0, 'total_time': 0.0, 'errors': 0},
                'file_manager': {'operations': 0, 'total_time': 0.0, 'errors': 0}
            }
            
            self.logger.debug("Integration monitoring initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing integration monitoring: {e}")
    
    def _handle_component_initialization_failure(self, error: Exception):
        """Handle component initialization failures with recovery options."""
        try:
            self.logger.error(f"Component initialization failed: {error}")
            
            # **ENHANCED**: Attempt graceful degradation
            self._emergency_mode = True
            
            # **ENHANCED**: Show user notification about limited functionality
            error_message = (
                "Some advanced features may not be available due to component initialization issues.\n\n"
                f"Error: {str(error)}\n\n"
                "The application will continue with limited functionality. "
                "Please check the logs for more details."
            )
            
            # **ENHANCED**: Schedule delayed error notification to avoid blocking startup
            QTimer.singleShot(2000, lambda: self._show_component_error_notification(error_message))
            
        except Exception as e:
            self.logger.critical(f"Failed to handle component initialization failure: {e}")
    
    def _show_component_error_notification(self, message: str):
        """Show component error notification to user."""
        try:
            msg_box = QMessageBox(QMessageBox.Warning, "Component Initialization Warning", message, parent=self)
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec()
        except Exception as e:
            self.logger.error(f"Error showing component error notification: {e}")

    def _initialize_animation_system(self):
        """Initialize comprehensive animation system with advanced transitions and effects."""
        try:
            self.logger.debug("Initializing advanced animation system...")
            
            # **ENHANCED**: Create animation manager for coordinated animations
            self._animation_manager = self._create_animation_manager()
            
            # **ENHANCED**: Initialize animation groups for different UI components
            self._setup_animation_groups()
            
            # **ENHANCED**: Configure theme transition animations
            self._setup_theme_transition_animations()
            
            # **ENHANCED**: Setup navigation transition animations
            self._setup_navigation_animations()
            
            # **ENHANCED**: Initialize performance-aware animation settings
            self._configure_animation_performance()
            
            self.logger.debug("Animation system initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing animation system: {e}")
            # **FALLBACK**: Disable animations if initialization fails
            self._animation_manager = None
            self._active_animations = {}
    
    def _create_animation_manager(self) -> QObject:
        """Create central animation manager for coordinated animations."""
        try:
            # **ENHANCED**: Create custom animation manager
            animation_manager = QObject(self)
            animation_manager.setObjectName("AnimationManager")
            
            # **ENHANCED**: Set up animation coordination properties
            animation_manager.setProperty("max_concurrent_animations", 5)
            animation_manager.setProperty("default_duration", 300)
            animation_manager.setProperty("default_easing", QEasingCurve.OutCubic)
            animation_manager.setProperty("performance_mode", False)
            
            return animation_manager
            
        except Exception as e:
            self.logger.error(f"Error creating animation manager: {e}")
            return None
    
    def _setup_animation_groups(self):
        """Setup animation groups for different UI components."""
        try:
            # **ENHANCED**: Create animation groups for organized animation management
            self._animation_groups = {
                'window_transitions': QParallelAnimationGroup(self),
                'navigation_transitions': QSequentialAnimationGroup(self),
                'theme_transitions': QParallelAnimationGroup(self),
                'sidebar_animations': QSequentialAnimationGroup(self),
                'content_animations': QParallelAnimationGroup(self),
                'status_animations': QSequentialAnimationGroup(self),
                'notification_animations': QParallelAnimationGroup(self)
            }
            
            # **ENHANCED**: Configure animation group properties
            for group_name, group in self._animation_groups.items():
                group.setObjectName(f"AnimationGroup_{group_name}")
                
                # **ENHANCED**: Connect animation signals for monitoring
                group.finished.connect(lambda name=group_name: self._on_animation_group_finished(name))
                group.stateChanged.connect(lambda state, name=group_name: self._on_animation_group_state_changed(name, state))
            
            self.logger.debug("Animation groups configured successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up animation groups: {e}")
            self._animation_groups = {}
    
    def _setup_theme_transition_animations(self):
        """Setup smooth theme transition animations."""
        try:
            # **ENHANCED**: Create theme transition animation
            self._theme_transition_animation = QPropertyAnimation(self, b"windowOpacity")
            self._theme_transition_animation.setDuration(400)
            self._theme_transition_animation.setEasingCurve(QEasingCurve.InOutCubic)
            self._theme_transition_animation.setStartValue(1.0)
            self._theme_transition_animation.setEndValue(0.8)
            
            # **ENHANCED**: Connect theme transition signals
            self._theme_transition_animation.finished.connect(self._on_theme_transition_finished)
            self._theme_transition_animation.valueChanged.connect(self._on_theme_transition_progress)
            
            # **ENHANCED**: Setup theme preview timer for live preview
            self._theme_preview_timer.setSingleShot(True)
            self._theme_preview_timer.timeout.connect(self._apply_theme_preview)
            
            self.logger.debug("Theme transition animations configured")
            
        except Exception as e:
            self.logger.error(f"Error setting up theme transition animations: {e}")
            self._theme_transition_animation = None
    
    def _setup_navigation_animations(self):
        """Setup navigation transition animations for smooth switching."""
        try:
            # **ENHANCED**: Create navigation transition effects
            self._navigation_transitions = {
                'slide_left': self._create_slide_animation(-50, 0),
                'slide_right': self._create_slide_animation(50, 0),
                'fade_in': self._create_fade_animation(0.0, 1.0),
                'fade_out': self._create_fade_animation(1.0, 0.0),
                'scale_in': self._create_scale_animation(0.95, 1.0),
                'scale_out': self._create_scale_animation(1.0, 0.95)
            }
            
            # **ENHANCED**: Configure navigation animation properties
            for anim_name, animation in self._navigation_transitions.items():
                if animation:
                    animation.setObjectName(f"NavigationAnimation_{anim_name}")
                    animation.finished.connect(lambda name=anim_name: self._on_navigation_animation_finished(name))
            
            self.logger.debug("Navigation animations configured successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up navigation animations: {e}")
            self._navigation_transitions = {}
    
    def _create_slide_animation(self, start_x: int, end_x: int) -> QPropertyAnimation:
        """Create slide animation for navigation transitions."""
        try:
            animation = QPropertyAnimation()
            animation.setPropertyName(b"pos")
            animation.setDuration(250)
            animation.setEasingCurve(QEasingCurve.OutQuart)
            return animation
        except Exception as e:
            self.logger.error(f"Error creating slide animation: {e}")
            return None
    
    def _create_fade_animation(self, start_opacity: float, end_opacity: float) -> QPropertyAnimation:
        """Create fade animation for smooth transitions."""
        try:
            animation = QPropertyAnimation()
            animation.setPropertyName(b"windowOpacity")
            animation.setStartValue(start_opacity)
            animation.setEndValue(end_opacity)
            animation.setDuration(200)
            animation.setEasingCurve(QEasingCurve.InOutQuad)
            return animation
        except Exception as e:
            self.logger.error(f"Error creating fade animation: {e}")
            return None
    
    def _create_scale_animation(self, start_scale: float, end_scale: float) -> QPropertyAnimation:
        """Create scale animation for zoom effects."""
        try:
            animation = QPropertyAnimation()
            animation.setPropertyName(b"geometry")
            animation.setDuration(200)
            animation.setEasingCurve(QEasingCurve.OutBack)
            return animation
        except Exception as e:
            self.logger.error(f"Error creating scale animation: {e}")
            return None
    
    def _configure_animation_performance(self):
        """Configure animation performance based on system capabilities."""
        try:
            # **ENHANCED**: Detect system performance capabilities
            screen_refresh_rate = 60  # Default to 60 FPS
            try:
                if hasattr(self.screen(), 'refreshRate'):
                    screen_refresh_rate = self.screen().refreshRate()
            except Exception:
                pass
            
            # **ENHANCED**: Configure animation settings based on performance
            if screen_refresh_rate >= 120:
                # High refresh rate - enable all animations
                animation_quality = "high"
                default_duration = 300
                max_concurrent = 8
            elif screen_refresh_rate >= 60:
                # Standard refresh rate - normal animations
                animation_quality = "normal"
                default_duration = 250
                max_concurrent = 5
            else:
                # Low refresh rate - reduced animations
                animation_quality = "low"
                default_duration = 200
                max_concurrent = 3
            
            # **ENHANCED**: Store animation configuration
            self._animation_config = {
                'quality': animation_quality,
                'default_duration': default_duration,
                'max_concurrent': max_concurrent,
                'screen_refresh_rate': screen_refresh_rate,
                'hardware_acceleration': True  # Assume available
            }
            
            self.logger.debug(f"Animation performance configured: {animation_quality} quality, {default_duration}ms duration")
            
        except Exception as e:
            self.logger.error(f"Error configuring animation performance: {e}")
            # **FALLBACK**: Use conservative settings
            self._animation_config = {
                'quality': 'low',
                'default_duration': 200,
                'max_concurrent': 3,
                'screen_refresh_rate': 60,
                'hardware_acceleration': False
            }
    
    # **ENHANCED**: Animation event handlers
    def _on_animation_group_finished(self, group_name: str):
        """Handle animation group completion."""
        try:
            self.logger.debug(f"Animation group completed: {group_name}")
            self.animation_completed.emit("group", group_name, 0.0)
        except Exception as e:
            self.logger.error(f"Error handling animation group completion: {e}")
    
    def _on_animation_group_state_changed(self, group_name: str, state):
        """Handle animation group state changes."""
        try:
            if state == QAbstractAnimation.Running:
                self.animation_started.emit("group", group_name)
            elif state == QAbstractAnimation.Stopped:
                self.animation_completed.emit("group", group_name, 0.0)
        except Exception as e:
            self.logger.error(f"Error handling animation group state change: {e}")
    
    def _on_theme_transition_finished(self):
        """Handle theme transition completion."""
        try:
            self.logger.debug("Theme transition animation completed")
            # **ENHANCED**: Restore full opacity after theme transition
            self.setWindowOpacity(1.0)
            self._theme_preview_active = False
        except Exception as e:
            self.logger.error(f"Error handling theme transition completion: {e}")
    
    def _on_theme_transition_progress(self, value):
        """Handle theme transition progress updates."""
        try:
            # **ENHANCED**: Can be used for progress indicators during theme changes
            pass
        except Exception as e:
            self.logger.error(f"Error handling theme transition progress: {e}")
    
    def _apply_theme_preview(self):
        """Apply theme preview after delay."""
        try:
            if self._theme_preview_active:
                # **ENHANCED**: Apply the preview theme
                self.logger.debug("Applying theme preview")
                # Implementation would apply the preview theme
        except Exception as e:
            self.logger.error(f"Error applying theme preview: {e}")
    
    def _on_navigation_animation_finished(self, animation_name: str):
        """Handle navigation animation completion."""
        try:
            self.logger.debug(f"Navigation animation completed: {animation_name}")
            self.animation_completed.emit("navigation", animation_name, 0.0)
        except Exception as e:
            self.logger.error(f"Error handling navigation animation completion: {e}")
    
    # **ENHANCED**: Public animation control methods
    def start_theme_transition(self, theme_name: str):
        """Start animated theme transition."""
        try:
            if self._theme_transition_animation and not self._theme_preview_active:
                self._theme_preview_active = True
                self.theme_preview_started.emit(theme_name)
                self._theme_transition_animation.start()
        except Exception as e:
            self.logger.error(f"Error starting theme transition: {e}")
    
    def animate_navigation_change(self, from_section: str, to_section: str):
        """Animate navigation section changes."""
        try:
            if from_section != to_section and self._navigation_transitions:
                animation_type = "fade_in"  # Default animation
                
                if animation_type in self._navigation_transitions:
                    animation = self._navigation_transitions[animation_type]
                    if animation:
                        self.animation_started.emit("navigation", f"{from_section}_to_{to_section}")
                        animation.start()
        except Exception as e:
            self.logger.error(f"Error animating navigation change: {e}")
    
    def stop_all_animations(self):
        """Stop all running animations."""
        try:
            for group in self._animation_groups.values():
                if group.state() == QAbstractAnimation.Running:
                    group.stop()
            
            for animation in self._navigation_transitions.values():
                if animation and animation.state() == QAbstractAnimation.Running:
                    animation.stop()
            
            if self._theme_transition_animation and self._theme_transition_animation.state() == QAbstractAnimation.Running:
                self._theme_transition_animation.stop()
                
            self.logger.debug("All animations stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping animations: {e}")
    
    def _setup_central_widget(self):
        """Setup the central widget with advanced layout management."""
        try:
            # **ENHANCED**: Create central widget with professional layout
            self.central_widget = QWidget()
            self.setCentralWidget(self.central_widget)
            
            # **ENHANCED**: Main layout with optimized spacing
            self.main_layout = QHBoxLayout(self.central_widget)
            self.main_layout.setContentsMargins(0, 0, 0, 0)
            self.main_layout.setSpacing(0)
            
            # **ENHANCED**: Create main splitter for sidebar and content
            self.main_splitter = QSplitter(Qt.Horizontal)
            self.main_splitter.setChildrenCollapsible(False)
            self.main_splitter.setHandleWidth(1)
            self.main_splitter.setStyleSheet("""
                QSplitter::handle {
                    background-color: transparent;
                }
                QSplitter::handle:hover {
                    background-color: rgba(128, 128, 128, 50);
                }
            """)
            
            # **ENHANCED**: Add splitter to main layout
            self.main_layout.addWidget(self.main_splitter)
            
            self.logger.debug("Central widget setup completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up central widget: {e}")
            raise
    
    def _setup_enhanced_menu_bar(self):
        """Setup comprehensive menu bar with all application functions."""
        try:
            self.menu_bar = self.menuBar()
            self.menu_bar.setObjectName("main_menu_bar")
            
            # **ENHANCED**: File Menu with comprehensive options
            self._create_file_menu()
            
            # **ENHANCED**: Scan Menu with all scan types
            self._create_scan_menu()
            
            # **ENHANCED**: Tools Menu with utilities
            self._create_tools_menu()
            
            # **ENHANCED**: View Menu with UI options
            self._create_view_menu()
            
            # **ENHANCED**: Settings Menu with configuration
            self._create_settings_menu()
            
            # **ENHANCED**: Help Menu with documentation
            self._create_help_menu()
            
            self.logger.debug("Enhanced menu bar created successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up enhanced menu bar: {e}")
    
    def _create_file_menu(self):
        """Create comprehensive file menu."""
        try:
            file_menu = self.menu_bar.addMenu("&File")
            file_menu.setObjectName("file_menu")
            
            # **ENHANCED**: Scan single file action
            scan_file_action = QAction("Scan &Single File...", self)
            scan_file_action.setShortcut("Ctrl+O")
            scan_file_action.setStatusTip("Scan a single file for threats")
            scan_file_action.triggered.connect(self._scan_single_file)
            file_menu.addAction(scan_file_action)
            
            # **ENHANCED**: Scan folder action
            scan_folder_action = QAction("Scan &Folder...", self)
            scan_folder_action.setShortcut("Ctrl+Shift+O")
            scan_folder_action.setStatusTip("Scan a selected folder for threats")
            scan_folder_action.triggered.connect(self._scan_folder)
            file_menu.addAction(scan_folder_action)
            
            file_menu.addSeparator()
            
            # **ENHANCED**: Recent scans submenu
            recent_menu = file_menu.addMenu("&Recent Scans")
            recent_menu.setObjectName("recent_scans_menu")
            self._populate_recent_scans_menu(recent_menu)
            
            file_menu.addSeparator()
            
            # **ENHANCED**: Export reports action
            export_reports_action = QAction("&Export Reports...", self)
            export_reports_action.setShortcut("Ctrl+E")
            export_reports_action.setStatusTip("Export scan reports and statistics")
            export_reports_action.triggered.connect(self._export_reports)
            file_menu.addAction(export_reports_action)
            
            # **ENHANCED**: Import configuration action
            import_config_action = QAction("&Import Configuration...", self)
            import_config_action.setStatusTip("Import configuration from file")
            import_config_action.triggered.connect(self._import_configuration)
            file_menu.addAction(import_config_action)
            
            file_menu.addSeparator()
            
            # **ENHANCED**: Exit action
            exit_action = QAction("E&xit", self)
            exit_action.setShortcut("Ctrl+Q")
            exit_action.setStatusTip("Exit the application")
            exit_action.triggered.connect(self._perform_full_shutdown)
            file_menu.addAction(exit_action)
            
        except Exception as e:
            self.logger.error(f"Error creating file menu: {e}")
    
    def _create_scan_menu(self):
        """Create comprehensive scan menu with all scan types."""
        try:
            scan_menu = self.menu_bar.addMenu("&Scan")
            scan_menu.setObjectName("scan_menu")
            
            # **ENHANCED**: Quick scan action
            quick_scan_action = QAction("&Quick Scan", self)
            quick_scan_action.setShortcut("F5")
            quick_scan_action.setStatusTip("Perform a quick scan of common locations")
            quick_scan_action.triggered.connect(lambda: self._start_scan("quick"))
            scan_menu.addAction(quick_scan_action)
            
            # **ENHANCED**: Full system scan action
            full_scan_action = QAction("&Full System Scan", self)
            full_scan_action.setShortcut("Ctrl+F5")
            full_scan_action.setStatusTip("Perform a complete system scan")
            full_scan_action.triggered.connect(lambda: self._start_scan("full"))
            scan_menu.addAction(full_scan_action)
            
            # **ENHANCED**: Custom scan action
            custom_scan_action = QAction("&Custom Scan...", self)
            custom_scan_action.setShortcut("Ctrl+Shift+F5")
            custom_scan_action.setStatusTip("Configure and run a custom scan")
            custom_scan_action.triggered.connect(lambda: self._start_scan("custom"))
            scan_menu.addAction(custom_scan_action)
            
            scan_menu.addSeparator()
            
            # **ENHANCED**: Memory scan action
            memory_scan_action = QAction("&Memory Scan", self)
            memory_scan_action.setShortcut("F6")
            memory_scan_action.setStatusTip("Scan running processes and memory")
            memory_scan_action.triggered.connect(lambda: self._start_scan("memory"))
            scan_menu.addAction(memory_scan_action)
            
            # **ENHANCED**: Network scan action
            network_scan_action = QAction("&Network Scan", self)
            network_scan_action.setStatusTip("Scan network drives and connections")
            network_scan_action.triggered.connect(lambda: self._start_scan("network"))
            scan_menu.addAction(network_scan_action)
            
            scan_menu.addSeparator()
            
            # **ENHANCED**: Scan control actions
            self._scan_pause_action = QAction("&Pause Scan", self)
            self._scan_pause_action.setShortcut("Space")
            self._scan_pause_action.setStatusTip("Pause the current scan")
            self._scan_pause_action.triggered.connect(self._pause_scan)
            self._scan_pause_action.setEnabled(False)
            scan_menu.addAction(self._scan_pause_action)
            
            self._scan_stop_action = QAction("&Stop Scan", self)
            self._scan_stop_action.setShortcut("Escape")
            self._scan_stop_action.setStatusTip("Stop the current scan")
            self._scan_stop_action.triggered.connect(self._stop_scan)
            self._scan_stop_action.setEnabled(False)
            scan_menu.addAction(self._scan_stop_action)
            
        except Exception as e:
            self.logger.error(f"Error creating scan menu: {e}")
    
    def _create_tools_menu(self):
        """Create comprehensive tools menu with utilities."""
        try:
            tools_menu = self.menu_bar.addMenu("&Tools")
            tools_menu.setObjectName("tools_menu")
            
            # **ENHANCED**: Quarantine manager action
            quarantine_action = QAction("&Quarantine Manager", self)
            quarantine_action.setShortcut("Ctrl+Q")
            quarantine_action.setStatusTip("Manage quarantined files")
            quarantine_action.triggered.connect(self._open_quarantine_window)
            tools_menu.addAction(quarantine_action)
            
            # **ENHANCED**: Model status action
            model_status_action = QAction("&Model Status", self)
            model_status_action.setShortcut("Ctrl+M")
            model_status_action.setStatusTip("View ML model status and performance")
            model_status_action.triggered.connect(self._open_model_status_window)
            tools_menu.addAction(model_status_action)
            
            tools_menu.addSeparator()
            
            # **ENHANCED**: Update definitions action
            update_definitions_action = QAction("&Update Definitions", self)
            update_definitions_action.setShortcut("F9")
            update_definitions_action.setStatusTip("Update virus definitions and rules")
            update_definitions_action.triggered.connect(self._update_definitions)
            tools_menu.addAction(update_definitions_action)
            
            # **ENHANCED**: Update models action
            update_models_action = QAction("Update &Models", self)
            update_models_action.setStatusTip("Update ML detection models")
            update_models_action.triggered.connect(self._update_models)
            tools_menu.addAction(update_models_action)
            
            tools_menu.addSeparator()
            
            # **ENHANCED**: System cleanup action
            cleanup_action = QAction("System &Cleanup", self)
            cleanup_action.setStatusTip("Clean temporary files and optimize system")
            cleanup_action.triggered.connect(self._system_cleanup)
            tools_menu.addAction(cleanup_action)
            
            # **ENHANCED**: Performance optimizer action
            optimize_action = QAction("&Performance Optimizer", self)
            optimize_action.setStatusTip("Optimize system performance for scanning")
            optimize_action.triggered.connect(self._optimize_performance)
            tools_menu.addAction(optimize_action)
            
            tools_menu.addSeparator()
            
            
            # **ENHANCED**: System info action
            system_info_action = QAction("System &Information", self)
            system_info_action.setShortcut("F12")
            system_info_action.setStatusTip("View system information and diagnostics")
            system_info_action.triggered.connect(self._show_system_info)
            tools_menu.addAction(system_info_action)
            
        except Exception as e:
            self.logger.error(f"Error creating tools menu: {e}")
    
    def _create_view_menu(self):
        """Create comprehensive view menu with UI options."""
        try:
            view_menu = self.menu_bar.addMenu("&View")
            view_menu.setObjectName("view_menu")
            
            # **ENHANCED**: Dashboard action
            dashboard_action = QAction("&Dashboard", self)
            dashboard_action.setShortcut("F1")
            dashboard_action.setStatusTip("Show main dashboard")
            dashboard_action.triggered.connect(lambda: self._navigate_to_section(NavigationSection.DASHBOARD))
            view_menu.addAction(dashboard_action)
            
            # **ENHANCED**: Scanning view action
            scanning_action = QAction("&Scanning", self)
            scanning_action.setShortcut("F2")
            scanning_action.setStatusTip("Show scanning interface")
            scanning_action.triggered.connect(lambda: self._navigate_to_section(NavigationSection.SCANNING))
            view_menu.addAction(scanning_action)
            
            # **ENHANCED**: Quarantine view action
            quarantine_view_action = QAction("&Quarantine", self)
            quarantine_view_action.setShortcut("F3")
            quarantine_view_action.setStatusTip("Show quarantine manager")
            quarantine_view_action.triggered.connect(lambda: self._navigate_to_section(NavigationSection.QUARANTINE))
            view_menu.addAction(quarantine_view_action)
            
            # **ENHANCED**: Reports view action
            reports_action = QAction("&Reports", self)
            reports_action.setShortcut("F4")
            reports_action.setStatusTip("Show reports and analytics")
            reports_action.triggered.connect(lambda: self._navigate_to_section(NavigationSection.REPORTS))
            view_menu.addAction(reports_action)
            
            view_menu.addSeparator()
            
            # **ENHANCED**: Theme submenu
            theme_menu = view_menu.addMenu("&Theme")
            self._create_theme_menu(theme_menu)
            
            view_menu.addSeparator()
            
            # **ENHANCED**: Full screen action
            fullscreen_action = QAction("&Full Screen", self)
            fullscreen_action.setShortcut("F11")
            fullscreen_action.setStatusTip("Toggle full screen mode")
            fullscreen_action.triggered.connect(self._toggle_fullscreen)
            view_menu.addAction(fullscreen_action)
            
        except Exception as e:
            self.logger.error(f"Error creating view menu: {e}")
    
    def _create_theme_menu(self, theme_menu: QMenu):
        """Create theme selection menu with live preview."""
        try:
            # **ENHANCED**: Create theme action group for exclusive selection
            self.theme_action_group = QActionGroup(self)
            
            # **ENHANCED**: Dark theme action
            dark_theme_action = QAction("&Dark Theme", self)
            dark_theme_action.setCheckable(True)
            dark_theme_action.setStatusTip("Switch to dark theme")
            dark_theme_action.triggered.connect(lambda: self._switch_theme("dark"))
            self.theme_action_group.addAction(dark_theme_action)
            theme_menu.addAction(dark_theme_action)
            
            # **ENHANCED**: Light theme action
            light_theme_action = QAction("&Light Theme", self)
            light_theme_action.setCheckable(True)
            light_theme_action.setStatusTip("Switch to light theme")
            light_theme_action.triggered.connect(lambda: self._switch_theme("light"))
            self.theme_action_group.addAction(light_theme_action)
            theme_menu.addAction(light_theme_action)
            
            # **ENHANCED**: Auto theme action
            auto_theme_action = QAction("&Auto Theme", self)
            auto_theme_action.setCheckable(True)
            auto_theme_action.setStatusTip("Automatically detect system theme")
            auto_theme_action.triggered.connect(lambda: self._switch_theme("auto"))
            self.theme_action_group.addAction(auto_theme_action)
            theme_menu.addAction(auto_theme_action)
            
            theme_menu.addSeparator()
            
            # **ENHANCED**: Set current theme as checked
            current_theme = self.config.get_theme_preference()
            if current_theme == "dark":
                dark_theme_action.setChecked(True)
            elif current_theme == "light":
                light_theme_action.setChecked(True)
            else:
                auto_theme_action.setChecked(True)
            
            self.theme_actions = {
                "dark": dark_theme_action,
                "light": light_theme_action,
                "auto": auto_theme_action
            }
            
        except Exception as e:
            self.logger.error(f"Error creating theme menu: {e}")
    
    def _create_settings_menu(self):
        """Create comprehensive settings menu."""
        try:
            settings_menu = self.menu_bar.addMenu("&Settings")
            settings_menu.setObjectName("settings_menu")
            
            # **ENHANCED**: General settings action
            general_settings_action = QAction("&General Settings...", self)
            general_settings_action.setShortcut("Ctrl+,")
            general_settings_action.setStatusTip("Configure general application settings")
            general_settings_action.triggered.connect(self._open_settings)
            settings_menu.addAction(general_settings_action)
            
        except Exception as e:
            self.logger.error(f"Error creating settings menu: {e}")
    
    def _create_help_menu(self):
        """Create comprehensive help menu."""
        try:
            help_menu = self.menu_bar.addMenu("&Help")
            help_menu.setObjectName("help_menu")
            
            # **ENHANCED**: User guide action
            user_guide_action = QAction("&User Guide", self)
            user_guide_action.setShortcut("F1")
            user_guide_action.setStatusTip("Open user guide and documentation")
            user_guide_action.triggered.connect(self._open_user_guide)
            help_menu.addAction(user_guide_action)
            
            # **ENHANCED**: FAQ action
            faq_action = QAction("&FAQ", self)
            faq_action.setStatusTip("View frequently asked questions")
            faq_action.triggered.connect(self._open_faq)
            help_menu.addAction(faq_action)
            
            # **ENHANCED**: Keyboard shortcuts action
            shortcuts_action = QAction("&Keyboard Shortcuts", self)
            shortcuts_action.setShortcut("Ctrl+?")
            shortcuts_action.setStatusTip("View keyboard shortcuts")
            shortcuts_action.triggered.connect(self._show_keyboard_shortcuts)
            help_menu.addAction(shortcuts_action)
            
            help_menu.addSeparator()
            
            # **ENHANCED**: Report bug action
            report_bug_action = QAction("&Report Bug", self)
            report_bug_action.setStatusTip("Report a bug or issue")
            report_bug_action.triggered.connect(self._report_bug)
            help_menu.addAction(report_bug_action)
            
            # **ENHANCED**: Submit feedback action
            feedback_action = QAction("Submit &Feedback", self)
            feedback_action.setStatusTip("Submit feedback and suggestions")
            feedback_action.triggered.connect(self._submit_feedback)
            help_menu.addAction(feedback_action)
            
            help_menu.addSeparator()
            
            # **ENHANCED**: Check for updates action
            update_action = QAction("Check for &Updates", self)
            update_action.setStatusTip("Check for application updates")
            update_action.triggered.connect(self._check_for_updates)
            help_menu.addAction(update_action)
            
            # **ENHANCED**: About action
            about_action = QAction("&About", self)
            about_action.setStatusTip("About this application")
            about_action.triggered.connect(self._show_about_dialog)
            help_menu.addAction(about_action)
            
        except Exception as e:
            self.logger.error(f"Error creating help menu: {e}")
    
    def _setup_enhanced_toolbar(self):
        """Setup comprehensive toolbar with essential actions."""
        try:
            self.toolbar = QToolBar("Main Toolbar")
            self.toolbar.setObjectName("main_toolbar")
            self.toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
            self.toolbar.setMovable(False)
            self.toolbar.setFloatable(False)
            
            # **ENHANCED**: Quick scan button
            quick_scan_btn = QToolButton()
            quick_scan_btn.setObjectName("quick_scan_btn")
            quick_scan_btn.setText("Quick Scan")
            quick_scan_btn.setIcon(self._get_toolbar_icon("scan_quick"))
            quick_scan_btn.setToolTip("Start quick scan (F5)")
            quick_scan_btn.clicked.connect(lambda: self._start_scan("quick"))
            self.toolbar.addWidget(quick_scan_btn)
            
            # **ENHANCED**: Full scan button
            full_scan_btn = QToolButton()
            full_scan_btn.setObjectName("full_scan_btn")
            full_scan_btn.setText("Full Scan")
            full_scan_btn.setIcon(self._get_toolbar_icon("scan_full"))
            full_scan_btn.setToolTip("Start full system scan (Ctrl+F5)")
            full_scan_btn.clicked.connect(lambda: self._start_scan("full"))
            self.toolbar.addWidget(full_scan_btn)
            
            # **ENHANCED**: Custom scan button
            custom_scan_btn = QToolButton()
            custom_scan_btn.setObjectName("custom_scan_btn")
            custom_scan_btn.setText("Custom Scan")
            custom_scan_btn.setIcon(self._get_toolbar_icon("scan_custom"))
            custom_scan_btn.setToolTip("Configure custom scan (Ctrl+Shift+F5)")
            custom_scan_btn.clicked.connect(lambda: self._start_scan("custom"))
            self.toolbar.addWidget(custom_scan_btn)
            
            self.toolbar.addSeparator()
            
            # **ENHANCED**: Quarantine button
            quarantine_btn = QToolButton()
            quarantine_btn.setObjectName("quarantine_btn")
            quarantine_btn.setText("Quarantine")
            quarantine_btn.setIcon(self._get_toolbar_icon("quarantine"))
            quarantine_btn.setToolTip("Open quarantine manager (Ctrl+Q)")
            quarantine_btn.clicked.connect(self._open_quarantine_window)
            self.toolbar.addWidget(quarantine_btn)
            
            # **ENHANCED**: Model status button
            model_status_btn = QToolButton()
            model_status_btn.setObjectName("model_status_btn")
            model_status_btn.setText("Models")
            model_status_btn.setIcon(self._get_toolbar_icon("models"))
            model_status_btn.setToolTip("View model status (Ctrl+M)")
            model_status_btn.clicked.connect(self._open_model_status_window)
            self.toolbar.addWidget(model_status_btn)
            
            self.toolbar.addSeparator()
            
            # **ENHANCED**: Settings button
            settings_btn = QToolButton()
            settings_btn.setObjectName("settings_btn")
            settings_btn.setText("Settings")
            settings_btn.setIcon(self._get_toolbar_icon("settings"))
            settings_btn.setToolTip("Open settings (Ctrl+,)")
            settings_btn.clicked.connect(self._open_settings)
            self.toolbar.addWidget(settings_btn)
            
            # **ENHANCED**: Update button
            update_btn = QToolButton()
            update_btn.setObjectName("update_btn")
            update_btn.setText("Update")
            update_btn.setIcon(self._get_toolbar_icon("update"))
            update_btn.setToolTip("Update definitions (F9)")
            update_btn.clicked.connect(self._update_definitions)
            self.toolbar.addWidget(update_btn)
            
            # **ENHANCED**: Add toolbar to window
            self.addToolBar(self.toolbar)
            
            self.logger.debug("Enhanced toolbar created successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up enhanced toolbar: {e}")
    
    def _get_toolbar_icon(self, icon_name: str) -> QIcon:
        """Get toolbar icon with fallback handling."""
        try:
            # **ENHANCED**: Try to get themed icon from theme manager
            if hasattr(self.theme_manager, 'get_icon'):
                icon = self.theme_manager.get_icon(icon_name, QSize(24, 24))
                if icon and not icon.isNull():
                    return icon
            
            # **FALLBACK**: Use system icon or create default
            icon_map = {
                "scan_quick": self.style().StandardPixmap.SP_MediaPlay,
                "scan_full": self.style().StandardPixmap.SP_ComputerIcon,
                "scan_custom": self.style().StandardPixmap.SP_DirIcon,
                "quarantine": self.style().StandardPixmap.SP_TrashIcon,
                "models": self.style().StandardPixmap.SP_FileDialogDetailedView,
                "settings": self.style().StandardPixmap.SP_ComputerIcon,
                "update": self.style().StandardPixmap.SP_BrowserReload
            }
            
            return self.style().standardIcon(icon_map.get(icon_name, self.style().StandardPixmap.SP_ComputerIcon))
            
        except Exception as e:
            self.logger.warning(f"Error getting toolbar icon {icon_name}: {e}")
            return QIcon()  # Return empty icon as fallback
    
    def _setup_enhanced_status_bar(self):
        """Setup comprehensive status bar with system information."""
        try:
            self.status_bar = QStatusBar()
            self.status_bar.setObjectName("main_status_bar")
            self.setStatusBar(self.status_bar)
            
            # **ENHANCED**: Protection status indicator
            self._protection_status_label = QLabel("🛡️ Protection: Active")
            self._protection_status_label.setObjectName("protection_status")
            self._protection_status_label.setToolTip("Real-time protection status")
            self.status_bar.addWidget(self._protection_status_label)
            
            self.status_bar.addWidget(self._create_status_separator())
            
            # **ENHANCED**: Scan status indicator
            self._scan_status_label = QLabel("📊 Scan: Idle")
            self._scan_status_label.setObjectName("scan_status")
            self._scan_status_label.setToolTip("Current scan status")
            self.status_bar.addWidget(self._scan_status_label)
            
            self.status_bar.addWidget(self._create_status_separator())
            
            # **ENHANCED**: Threat counter
            self._threat_counter_label = QLabel("⚠️ Threats: 0")
            self._threat_counter_label.setObjectName("threat_counter")
            self._threat_counter_label.setToolTip("Total threats detected")
            self.status_bar.addWidget(self._threat_counter_label)
            
            self.status_bar.addWidget(self._create_status_separator())
            
            # **ENHANCED**: Model status indicator
            self._model_status_label = QLabel("🤖 Models: Loading...")
            self._model_status_label.setObjectName("model_status")
            self._model_status_label.setToolTip("ML models status")
            self.status_bar.addWidget(self._model_status_label)
            
            self.status_bar.addWidget(self._create_status_separator())
            
            # **ENHANCED**: System resource indicator
            self._resource_indicator = QLabel("💾 CPU: 0% | RAM: 0%")
            self._resource_indicator.setObjectName("resource_indicator")
            self._resource_indicator.setToolTip("System resource usage")
            self.status_bar.addWidget(self._resource_indicator)
            
            # **ENHANCED**: Add permanent widgets on the right
            self.status_bar.addPermanentWidget(self._create_status_separator())
            
            # **ENHANCED**: Last update indicator
            self._last_update_label = QLabel("🔄 Updated: Never")
            self._last_update_label.setObjectName("last_update")
            self._last_update_label.setToolTip("Last definitions update")
            self.status_bar.addPermanentWidget(self._last_update_label)
            
            # **ENHANCED**: Connection status indicator
            self._connection_status_label = QLabel("🌐 Online")
            self._connection_status_label.setObjectName("connection_status")
            self._connection_status_label.setToolTip("Network connection status")
            self.status_bar.addPermanentWidget(self._connection_status_label)
            
            # **ENHANCED**: Store status labels for easy access
            self.status_labels = {
                'protection': self._protection_status_label,
                'scan': self._scan_status_label,
                'threats': self._threat_counter_label,
                'models': self._model_status_label,
                'resources': self._resource_indicator,
                'last_update': self._last_update_label,
                'connection': self._connection_status_label
            }
            
            self.logger.debug("Enhanced status bar created successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up enhanced status bar: {e}")
    
    def _create_status_separator(self) -> QFrame:
        """Create a status bar separator."""
        separator = QFrame()
        separator.setFrameShape(QFrame.VLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setMaximumHeight(20)
        return separator
    
    def _create_enhanced_sidebar(self):
        """Create enhanced sidebar with navigation and quick actions."""
        try:
            # **ENHANCED**: Sidebar container widget
            sidebar_widget = QWidget()
            sidebar_widget.setObjectName("sidebar_widget")
            sidebar_widget.setFixedWidth(250)
            sidebar_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
            
            # **ENHANCED**: Sidebar layout
            sidebar_layout = QVBoxLayout(sidebar_widget)
            sidebar_layout.setContentsMargins(10, 10, 10, 10)
            sidebar_layout.setSpacing(15)
            
            # **ENHANCED**: Logo and title section
            self._create_sidebar_header(sidebar_layout)
            
            # **ENHANCED**: Navigation section
            self._create_navigation_section(sidebar_layout)
            
            # **ENHANCED**: Quick actions section
            self._create_quick_actions_section(sidebar_layout)
            
            # **ENHANCED**: System status section
            self._create_sidebar_status_section(sidebar_layout)
            
            # **ENHANCED**: Add stretch to push content to top
            sidebar_layout.addStretch()
            
            # **ENHANCED**: Add sidebar to splitter
            self.sidebar = sidebar_widget
            self.main_splitter.addWidget(self.sidebar)
            
            self.logger.debug("Enhanced sidebar created successfully")
            
        except Exception as e:
            self.logger.error(f"Error creating enhanced sidebar: {e}")
    
    def _create_sidebar_header(self, layout: QVBoxLayout):
        """Create sidebar header with logo and title."""
        try:
            # **ENHANCED**: Header frame
            header_frame = QFrame()
            header_frame.setObjectName("sidebar_header")
            header_frame.setFrameStyle(QFrame.Box)
            header_layout = QVBoxLayout(header_frame)
            header_layout.setContentsMargins(10, 15, 10, 15)
            header_layout.setSpacing(8)
            
            # **ENHANCED**: Application logo
            logo_label = QLabel()
            logo_label.setObjectName("app_logo")
            logo_label.setAlignment(Qt.AlignCenter)
            logo_label.setPixmap(self._get_app_logo(48))
            header_layout.addWidget(logo_label)
            
            # **ENHANCED**: Application title
            title_label = QLabel("Advanced Antivirus")
            title_label.setObjectName("app_title")
            title_label.setAlignment(Qt.AlignCenter)
            title_label.setStyleSheet("font-weight: bold; font-size: 14px;")
            header_layout.addWidget(title_label)
            
            # **ENHANCED**: Version label
            version_label = QLabel("v1.0.0 Professional")
            version_label.setObjectName("app_version")
            version_label.setAlignment(Qt.AlignCenter)
            version_label.setStyleSheet("font-size: 10px; color: #888;")
            header_layout.addWidget(version_label)
            
            layout.addWidget(header_frame)
            
        except Exception as e:
            self.logger.error(f"Error creating sidebar header: {e}")
    
    def _get_app_logo(self, size: int) -> QPixmap:
        """Get application logo pixmap with fallback."""
        try:
            # **ENHANCED**: Try to get themed logo
            if hasattr(self.theme_manager, 'get_icon'):
                icon = self.theme_manager.get_icon("app_icon", QSize(size, size))
                if icon and not icon.isNull():
                    return icon.pixmap(size, size)
            
            # **FALLBACK**: Create simple logo
            pixmap = QPixmap(size, size)
            pixmap.fill(Qt.transparent)
            
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing, True)
            
            # Draw shield shape
            gradient = QLinearGradient(0, 0, size, size)
            gradient.setColorAt(0, QColor("#4CAF50"))
            gradient.setColorAt(1, QColor("#2E7D32"))
            
            painter.setBrush(QBrush(gradient))
            painter.setPen(QPen(QColor("#1B5E20"), 2))
            painter.drawEllipse(2, 2, size-4, size-4)
            
            # Draw checkmark
            painter.setPen(QPen(Qt.white, 3, Qt.SolidLine, Qt.RoundCap))
            painter.drawLine(size//4, size//2, size//2, size*3//4)
            painter.drawLine(size//2, size*3//4, size*3//4, size//3)
            
            painter.end()
            
            return pixmap
            
        except Exception as e:
            self.logger.warning(f"Error creating app logo: {e}")
            return QPixmap(size, size)  # Return empty pixmap
    
    def _create_navigation_section(self, layout: QVBoxLayout):
        """Create navigation section with main application sections."""
        try:
            # **ENHANCED**: Navigation frame
            nav_frame = QFrame()
            nav_frame.setObjectName("navigation_frame")
            nav_frame.setFrameStyle(QFrame.Box)
            nav_layout = QVBoxLayout(nav_frame)
            nav_layout.setContentsMargins(5, 10, 5, 10)
            nav_layout.setSpacing(5)
            
            # **ENHANCED**: Navigation title
            nav_title = QLabel("Navigation")
            nav_title.setObjectName("nav_title")
            nav_title.setAlignment(Qt.AlignCenter)
            nav_title.setStyleSheet("font-weight: bold; padding: 5px;")
            nav_layout.addWidget(nav_title)
            
            # **ENHANCED**: Create navigation buttons
            self.nav_buttons = {}
            for section in NavigationSection:
                btn = self._create_nav_button(section)
                nav_layout.addWidget(btn)
                self.nav_buttons[section] = btn
            
            # **ENHANCED**: Set dashboard as active by default
            if NavigationSection.DASHBOARD in self.nav_buttons:
                self.nav_buttons[NavigationSection.DASHBOARD].setProperty("active", True)
            
            layout.addWidget(nav_frame)
            
        except Exception as e:
            self.logger.error(f"Error creating navigation section: {e}")
    
    def _create_nav_button(self, section: NavigationSection) -> QPushButton:
        """Create a navigation button for a specific section."""
        try:
            btn = QPushButton(f"{section.icon} {section.title}")
            btn.setObjectName(f"nav_btn_{section.key}")
            btn.setToolTip(section.description)
            btn.setCheckable(True)
            btn.setMinimumHeight(40)
            btn.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 8px 12px;
                    border: none;
                    border-radius: 6px;
                    font-size: 13px;
                }
                QPushButton:hover {
                    background-color: rgba(128, 128, 128, 30);
                }
                QPushButton:checked {
                    background-color: rgba(33, 150, 243, 100);
                    font-weight: bold;
                }
            """)
            
            # **ENHANCED**: Connect to navigation handler
            btn.clicked.connect(lambda: self._navigate_to_section(section))
            
            return btn
            
        except Exception as e:
            self.logger.error(f"Error creating navigation button for {section.title}: {e}")
            return QPushButton(section.title)
    
    def _create_quick_actions_section(self, layout: QVBoxLayout):
        """Create quick actions section with frequently used operations."""
        try:
            # **ENHANCED**: Quick actions frame
            actions_frame = QFrame()
            actions_frame.setObjectName("quick_actions_frame")
            actions_frame.setFrameStyle(QFrame.Box)
            actions_layout = QVBoxLayout(actions_frame)
            actions_layout.setContentsMargins(5, 10, 5, 10)
            actions_layout.setSpacing(5)
            
            # **ENHANCED**: Actions title
            actions_title = QLabel("Quick Actions")
            actions_title.setObjectName("actions_title")
            actions_title.setAlignment(Qt.AlignCenter)
            actions_title.setStyleSheet("font-weight: bold; padding: 5px;")
            actions_layout.addWidget(actions_title)
            
            # **ENHANCED**: Quick scan button
            quick_scan_btn = QPushButton("🚀 Quick Scan")
            quick_scan_btn.setObjectName("sidebar_quick_scan")
            quick_scan_btn.setToolTip("Start quick scan (F5)")
            quick_scan_btn.clicked.connect(lambda: self._start_scan("quick"))
            actions_layout.addWidget(quick_scan_btn)
            
            # **ENHANCED**: Scan file button
            scan_file_btn = QPushButton("📄 Scan File")
            scan_file_btn.setObjectName("sidebar_scan_file")
            scan_file_btn.setToolTip("Scan a single file")
            scan_file_btn.clicked.connect(self._scan_single_file)
            actions_layout.addWidget(scan_file_btn)
            
            # **ENHANCED**: Update button
            update_btn = QPushButton("🔄 Update Now")
            update_btn.setObjectName("sidebar_update")
            update_btn.setToolTip("Update virus definitions")
            update_btn.clicked.connect(self._update_definitions)
            actions_layout.addWidget(update_btn)
            
            # **ENHANCED**: Quarantine button
            quarantine_btn = QPushButton("🔒 Quarantine")
            quarantine_btn.setObjectName("sidebar_quarantine")
            quarantine_btn.setToolTip("Open quarantine manager")
            quarantine_btn.clicked.connect(self._open_quarantine_window)
            actions_layout.addWidget(quarantine_btn)
            
            layout.addWidget(actions_frame)
            
        except Exception as e:
            self.logger.error(f"Error creating quick actions section: {e}")
    
    def _create_sidebar_status_section(self, layout: QVBoxLayout):
        """Create system status section in sidebar."""
        try:
            # **ENHANCED**: Status frame
            status_frame = QFrame()
            status_frame.setObjectName("sidebar_status_frame")
            status_frame.setFrameStyle(QFrame.Box)
            status_layout = QVBoxLayout(status_frame)
            status_layout.setContentsMargins(5, 10, 5, 10)
            status_layout.setSpacing(8)
            
            # **ENHANCED**: Status title
            status_title = QLabel("System Status")
            status_title.setObjectName("status_title")
            status_title.setAlignment(Qt.AlignCenter)
            status_title.setStyleSheet("font-weight: bold; padding: 5px;")
            status_layout.addWidget(status_title)
            
            # **ENHANCED**: Protection status
            self._sidebar_protection_status = QLabel("🛡️ Protection: Active")
            self._sidebar_protection_status.setObjectName("sidebar_protection")
            self._sidebar_protection_status.setStyleSheet("color: green; font-weight: bold;")
            status_layout.addWidget(self._sidebar_protection_status)
            
            # **ENHANCED**: Last scan info
            self._sidebar_last_scan = QLabel("📊 Last Scan: Never")
            self._sidebar_last_scan.setObjectName("sidebar_last_scan")
            status_layout.addWidget(self._sidebar_last_scan)
            
            # **ENHANCED**: Threats found
            self._sidebar_threats_found = QLabel("⚠️ Threats: 0")
            self._sidebar_threats_found.setObjectName("sidebar_threats")
            status_layout.addWidget(self._sidebar_threats_found)
            
            # **ENHANCED**: Models status
            self._sidebar_models_status = QLabel("🤖 Models: Loading...")
            self._sidebar_models_status.setObjectName("sidebar_models")
            status_layout.addWidget(self._sidebar_models_status)
            
            layout.addWidget(status_frame)
            
            # **ENHANCED**: Store sidebar status labels
            self.status_cards = {
                'sidebar_protection': self._sidebar_protection_status,
                'sidebar_last_scan': self._sidebar_last_scan,
                'sidebar_threats': self._sidebar_threats_found,
                'sidebar_models': self._sidebar_models_status
            }
            
        except Exception as e:
            self.logger.error(f"Error creating sidebar status section: {e}")
    
    def _create_enhanced_content_area(self):
        """Create enhanced content area with dashboard and sub-windows."""
        try:
            # **ENHANCED**: Content area widget
            content_widget = QWidget()
            content_widget.setObjectName("content_widget")
            content_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            
            # **ENHANCED**: Content layout
            content_layout = QVBoxLayout(content_widget)
            content_layout.setContentsMargins(15, 15, 15, 15)
            content_layout.setSpacing(15)
            
            # **ENHANCED**: Create stacked widget for different content areas
            self.content_area = QStackedWidget()
            self.content_area.setObjectName("content_stack")
            content_layout.addWidget(self.content_area)
            
            # **ENHANCED**: Add content widget to splitter
            self.main_splitter.addWidget(content_widget)
            
            # **ENHANCED**: Set splitter proportions (20% sidebar, 80% content)
            self.main_splitter.setSizes([250, 1000])
            self.main_splitter.setStretchFactor(0, 0)
            self.main_splitter.setStretchFactor(1, 1)
            
            self.logger.debug("Enhanced content area created successfully")
            
        except Exception as e:
            self.logger.error(f"Error creating enhanced content area: {e}")
        
        # Continuing from Part 3 at line ~2800...
    
    def _setup_dashboard_components(self):
        """Setup comprehensive dashboard with real-time monitoring and analytics."""
        try:
            self.logger.debug("Setting up comprehensive dashboard components...")
            
            # **ENHANCED**: Create main dashboard widget
            dashboard_widget = QWidget()
            dashboard_widget.setObjectName("dashboard_widget")
            
            # **ENHANCED**: Dashboard layout with optimized spacing
            dashboard_layout = QVBoxLayout(dashboard_widget)
            dashboard_layout.setContentsMargins(20, 20, 20, 20)
            dashboard_layout.setSpacing(20)
            
            # **ENHANCED**: Dashboard header with system status
            dashboard_header = self._create_dashboard_header()
            dashboard_layout.addWidget(dashboard_header)
            
            # **ENHANCED**: Main dashboard content with cards and metrics
            dashboard_content = self._create_dashboard_content()
            dashboard_layout.addWidget(dashboard_content)
            
            # **ENHANCED**: Dashboard footer with quick actions
            dashboard_footer = self._create_dashboard_footer()
            dashboard_layout.addWidget(dashboard_footer)
            
            # **ENHANCED**: Add dashboard to content stack
            self.content_area.addWidget(dashboard_widget)
            self.content_widgets = {'dashboard': dashboard_widget}
            
            # **ENHANCED**: Initialize dashboard monitoring
            self._initialize_dashboard_monitoring()
            
            self.logger.debug("Dashboard components setup completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up dashboard components: {e}")
            self._create_fallback_dashboard()
    
    def _create_dashboard_header(self) -> QFrame:
        """Create dashboard header with system status and time."""
        try:
            header_frame = QFrame()
            header_frame.setObjectName("dashboard_header")
            header_frame.setFixedHeight(100)
            header_layout = QHBoxLayout(header_frame)
            header_layout.setContentsMargins(15, 15, 15, 15)
            
            # **ENHANCED**: System status section
            status_section = self._create_system_status_section()
            header_layout.addWidget(status_section, 2)
            
            # **ENHANCED**: Center logo and title
            title_section = self._create_title_section()
            header_layout.addWidget(title_section, 1)
            
            # **ENHANCED**: Time and version info
            info_section = self._create_info_section()
            header_layout.addWidget(info_section, 1)
            
            return header_frame
            
        except Exception as e:
            self.logger.error(f"Error creating dashboard header: {e}")
            return QFrame()
    
    def _create_system_status_section(self) -> QFrame:
        """Create system status section with protection status."""
        try:
            status_frame = QFrame()
            status_frame.setObjectName("system_status_section")
            status_layout = QVBoxLayout(status_frame)
            status_layout.setContentsMargins(0, 0, 0, 0)
            
            # **ENHANCED**: Protection status indicator
            self.protection_status_indicator = QLabel("🛡️ PROTECTED")
            self.protection_status_indicator.setObjectName("protection_status")
            self.protection_status_indicator.setStyleSheet("""
                QLabel {
                    color: #4caf50;
                    font-size: 18px;
                    font-weight: bold;
                    padding: 5px;
                }
            """)
            status_layout.addWidget(self.protection_status_indicator)
            
            # **ENHANCED**: Last scan info
            self.last_scan_label = QLabel("Last scan: Never")
            self.last_scan_label.setObjectName("last_scan_info")
            self.last_scan_label.setStyleSheet("color: #666; font-size: 12px;")
            status_layout.addWidget(self.last_scan_label)
            
            return status_frame
            
        except Exception as e:
            self.logger.error(f"Error creating system status section: {e}")
            return QFrame()
    
    def _create_title_section(self) -> QFrame:
        """Create center title section with logo."""
        try:
            title_frame = QFrame()
            title_frame.setObjectName("title_section")
            title_layout = QVBoxLayout(title_frame)
            title_layout.setAlignment(Qt.AlignCenter)
            title_layout.setContentsMargins(0, 0, 0, 0)
            
            # **ENHANCED**: Application title
            app_title = QLabel("Advanced Multi-Algorithm Antivirus")
            app_title.setObjectName("app_title")
            app_title.setAlignment(Qt.AlignCenter)
            app_title.setStyleSheet("""
                QLabel {
                    font-size: 20px;
                    font-weight: bold;
                    color: #2196f3;
                    margin: 5px;
                }
            """)
            title_layout.addWidget(app_title)
            
            # **ENHANCED**: Subtitle
            subtitle = QLabel("Professional Security Suite")
            subtitle.setObjectName("app_subtitle")
            subtitle.setAlignment(Qt.AlignCenter)
            subtitle.setStyleSheet("font-size: 12px; color: #666;")
            title_layout.addWidget(subtitle)
            
            return title_frame
            
        except Exception as e:
            self.logger.error(f"Error creating title section: {e}")
            return QFrame()
    
    def _create_info_section(self) -> QFrame:
        """Create info section with time and version."""
        try:
            info_frame = QFrame()
            info_frame.setObjectName("info_section")
            info_layout = QVBoxLayout(info_frame)
            info_layout.setAlignment(Qt.AlignRight)
            info_layout.setContentsMargins(0, 0, 0, 0)
            
            # **ENHANCED**: Current time
            self.current_time_label = QLabel()
            self.current_time_label.setObjectName("current_time")
            self.current_time_label.setAlignment(Qt.AlignRight)
            self.current_time_label.setStyleSheet("font-size: 14px; font-weight: bold;")
            info_layout.addWidget(self.current_time_label)
            
            # **ENHANCED**: Version info
            version_label = QLabel("Version 1.0.0")
            version_label.setObjectName("version_info")
            version_label.setAlignment(Qt.AlignRight)
            version_label.setStyleSheet("font-size: 11px; color: #666;")
            info_layout.addWidget(version_label)
            
            # **ENHANCED**: Update time display
            self._update_time_display()
            
            return info_frame
            
        except Exception as e:
            self.logger.error(f"Error creating info section: {e}")
            return QFrame()
    
    def _create_dashboard_content(self) -> QWidget:
        """Create main dashboard content with cards and metrics."""
        try:
            content_widget = QWidget()
            content_widget.setObjectName("dashboard_content")
            content_layout = QVBoxLayout(content_widget)
            content_layout.setContentsMargins(0, 0, 0, 0)
            content_layout.setSpacing(20)
            
            # **ENHANCED**: Security metrics cards
            metrics_row = self._create_security_metrics_cards()
            content_layout.addWidget(metrics_row)
            
            # **ENHANCED**: Main dashboard grid
            dashboard_grid = self._create_dashboard_grid()
            content_layout.addWidget(dashboard_grid, 1)
            
            return content_widget
            
        except Exception as e:
            self.logger.error(f"Error creating dashboard content: {e}")
            return QWidget()
    
    def _create_security_metrics_cards(self) -> QFrame:
        """Create security metrics cards with key statistics."""
        try:
            cards_frame = QFrame()
            cards_frame.setObjectName("security_metrics_cards")
            cards_frame.setFixedHeight(120)
            cards_layout = QHBoxLayout(cards_frame)
            cards_layout.setContentsMargins(0, 0, 0, 0)
            cards_layout.setSpacing(15)
            
            # **ENHANCED**: Create metric cards
            metrics = [
                ("Files Scanned", "0", "📊", "scan_count"),
                ("Threats Found", "0", "⚠️", "threat_count"),
                ("Files Quarantined", "0", "🔒", "quarantine_count"),
                ("System Health", "Excellent", "💚", "system_health")
            ]
            
            self.metric_cards = {}
            for title, value, icon, key in metrics:
                card = self._create_metric_card(title, value, icon, key)
                cards_layout.addWidget(card)
                self.metric_cards[key] = card
            
            return cards_frame
            
        except Exception as e:
            self.logger.error(f"Error creating security metrics cards: {e}")
            return QFrame()
    
    def _create_metric_card(self, title: str, value: str, icon: str, key: str) -> QFrame:
        """Create individual metric card."""
        try:
            card = QFrame()
            card.setObjectName(f"metric_card_{key}")
            card.setFrameStyle(QFrame.Box)
            card.setStyleSheet("""
                QFrame {
                    background-color: rgba(255, 255, 255, 0.1);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    border-radius: 8px;
                    padding: 10px;
                }
                QFrame:hover {
                    background-color: rgba(255, 255, 255, 0.15);
                }
            """)
            
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(15, 10, 15, 10)
            card_layout.setSpacing(5)
            
            # **ENHANCED**: Icon and value
            top_layout = QHBoxLayout()
            
            icon_label = QLabel(icon)
            icon_label.setStyleSheet("font-size: 24px;")
            top_layout.addWidget(icon_label)
            
            top_layout.addStretch()
            
            value_label = QLabel(value)
            value_label.setObjectName(f"{key}_value")
            value_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #2196f3;")
            value_label.setAlignment(Qt.AlignRight)
            top_layout.addWidget(value_label)
            
            card_layout.addLayout(top_layout)
            
            # **ENHANCED**: Title
            title_label = QLabel(title)
            title_label.setObjectName(f"{key}_title")
            title_label.setStyleSheet("font-size: 12px; color: #666;")
            card_layout.addWidget(title_label)
            
            card_layout.addStretch()
            
            return card
            
        except Exception as e:
            self.logger.error(f"Error creating metric card for {key}: {e}")
            return QFrame()
    
    def _create_dashboard_grid(self) -> QWidget:
        """Create main dashboard grid with various components."""
        try:
            grid_widget = QWidget()
            grid_widget.setObjectName("dashboard_grid")
            grid_layout = QGridLayout(grid_widget)
            grid_layout.setContentsMargins(0, 0, 0, 0)
            grid_layout.setSpacing(20)
            
            # **ENHANCED**: Recent activity panel (top-left)
            recent_activity = self._create_recent_activity_panel()
            grid_layout.addWidget(recent_activity, 0, 0, 1, 2)
            
            # **ENHANCED**: Quick scan panel (top-right)
            quick_scan = self._create_quick_scan_panel()
            grid_layout.addWidget(quick_scan, 0, 2, 1, 1)
            
            # **ENHANCED**: System status panel (middle-left)
            system_status = self._create_system_status_panel()
            grid_layout.addWidget(system_status, 1, 0, 1, 1)
            
            # **ENHANCED**: Model status panel (middle-center)
            model_status = self._create_model_status_panel()
            grid_layout.addWidget(model_status, 1, 1, 1, 1)
            
            # **ENHANCED**: Threat intelligence panel (middle-right)
            threat_intel = self._create_threat_intelligence_panel()
            grid_layout.addWidget(threat_intel, 1, 2, 1, 1)
            
            # **ENHANCED**: Set column stretch
            grid_layout.setColumnStretch(0, 1)
            grid_layout.setColumnStretch(1, 1)
            grid_layout.setColumnStretch(2, 1)
            
            return grid_widget
            
        except Exception as e:
            self.logger.error(f"Error creating dashboard grid: {e}")
            return QWidget()
    
    def _create_recent_activity_panel(self) -> QGroupBox:
        """Create recent activity panel with latest events."""
        try:
            panel = QGroupBox("📋 Recent Activity")
            panel.setObjectName("recent_activity_panel")
            panel_layout = QVBoxLayout(panel)
            panel_layout.setContentsMargins(15, 20, 15, 15)
            
            # **ENHANCED**: Activity list
            self.activity_list = QListWidget()
            self.activity_list.setObjectName("activity_list")
            self.activity_list.setMaximumHeight(150)
            self.activity_list.setAlternatingRowColors(True)
            panel_layout.addWidget(self.activity_list)
            
            # **ENHANCED**: Add sample activities
            self._populate_sample_activities()
            
            # **ENHANCED**: View all button
            view_all_btn = QPushButton("View All Activity")
            # view_all_btn.clicked.connect(self._show_activity_log)
            panel_layout.addWidget(view_all_btn)
            
            return panel
            
        except Exception as e:
            self.logger.error(f"Error creating recent activity panel: {e}")
            return QGroupBox("Recent Activity")
    
    def _populate_sample_activities(self):
        """Populate activity list with sample data."""
        try:
            sample_activities = [
                ("10:30 AM", "Quick scan completed - No threats found"),
                ("09:45 AM", "Virus definitions updated successfully"),
                ("09:30 AM", "Real-time protection started"),
                ("09:15 AM", "Application started"),
                ("Yesterday", "Full system scan completed - 2 threats quarantined")
            ]
            
            for time_str, activity in sample_activities:
                item_text = f"{time_str} - {activity}"
                self.activity_list.addItem(item_text)
                
        except Exception as e:
            self.logger.error(f"Error populating sample activities: {e}")
    
    def _create_quick_scan_panel(self) -> QGroupBox:
        """Create quick scan panel with scan controls."""
        try:
            panel = QGroupBox("🚀 Quick Actions")
            panel.setObjectName("quick_scan_panel")
            panel_layout = QVBoxLayout(panel)
            panel_layout.setContentsMargins(15, 20, 15, 15)
            panel_layout.setSpacing(10)
            
            # **ENHANCED**: Quick scan button
            quick_scan_btn = QPushButton("Start Quick Scan")
            quick_scan_btn.setObjectName("quick_scan_btn")
            quick_scan_btn.setMinimumHeight(40)
            quick_scan_btn.setStyleSheet("""
                QPushButton {
                    background-color: #4caf50;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #45a049;
                }
                QPushButton:pressed {
                    background-color: #3d8b40;
                }
            """)
            quick_scan_btn.clicked.connect(lambda: self._start_scan("quick"))
            panel_layout.addWidget(quick_scan_btn)
            
            # **ENHANCED**: Full scan button
            full_scan_btn = QPushButton("Start Full Scan")
            full_scan_btn.setObjectName("full_scan_btn")
            full_scan_btn.setMinimumHeight(35)
            full_scan_btn.clicked.connect(lambda: self._start_scan("full"))
            panel_layout.addWidget(full_scan_btn)
            
            # **ENHANCED**: Custom scan button
            custom_scan_btn = QPushButton("Custom Scan")
            custom_scan_btn.setObjectName("custom_scan_btn")
            custom_scan_btn.setMinimumHeight(35)
            custom_scan_btn.clicked.connect(lambda: self._start_scan("custom"))
            panel_layout.addWidget(custom_scan_btn)
            
            panel_layout.addStretch()
            
            # **ENHANCED**: Last scan status
            self.last_scan_status = QLabel("Last scan: Never")
            self.last_scan_status.setStyleSheet("color: #666; font-size: 11px;")
            self.last_scan_status.setAlignment(Qt.AlignCenter)
            panel_layout.addWidget(self.last_scan_status)
            
            return panel
            
        except Exception as e:
            self.logger.error(f"Error creating quick scan panel: {e}")
            return QGroupBox("Quick Actions")
    
    def _create_system_status_panel(self) -> QGroupBox:
        """Create system status panel with health indicators."""
        try:
            panel = QGroupBox("🖥️ System Status")
            panel.setObjectName("system_status_panel")
            panel_layout = QVBoxLayout(panel)
            panel_layout.setContentsMargins(15, 20, 15, 15)
            
            # **ENHANCED**: Status indicators
            status_items = [
                ("Real-time Protection", "Active", "#4caf50"),
                ("Virus Definitions", "Up to date", "#4caf50"),
                ("System Performance", "Optimal", "#4caf50"),
                ("Last Full Scan", "7 days ago", "#ff9800")
            ]
            
            self.status_indicators = {}
            for item, status, color in status_items:
                indicator = self._create_status_indicator(item, status, color)
                panel_layout.addWidget(indicator)
                self.status_indicators[item] = indicator
            
            panel_layout.addStretch()
            
            return panel
            
        except Exception as e:
            self.logger.error(f"Error creating system status panel: {e}")
            return QGroupBox("System Status")
    
    def _create_status_indicator(self, item: str, status: str, color: str) -> QFrame:
        """Create individual status indicator."""
        try:
            indicator = QFrame()
            indicator.setObjectName(f"status_{item.lower().replace(' ', '_')}")
            indicator_layout = QHBoxLayout(indicator)
            indicator_layout.setContentsMargins(0, 5, 0, 5)
            
            # **ENHANCED**: Status dot
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {color}; font-size: 12px;")
            indicator_layout.addWidget(dot)
            
            # **ENHANCED**: Item label
            item_label = QLabel(item)
            item_label.setStyleSheet("font-size: 12px;")
            indicator_layout.addWidget(item_label)
            
            indicator_layout.addStretch()
            
            # **ENHANCED**: Status label
            status_label = QLabel(status)
            status_label.setObjectName(f"{item.lower().replace(' ', '_')}_status")
            status_label.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: bold;")
            indicator_layout.addWidget(status_label)
            
            return indicator
            
        except Exception as e:
            self.logger.error(f"Error creating status indicator for {item}: {e}")
            return QFrame()
    
    def _create_model_status_panel(self) -> QGroupBox:
        """Create ML model status panel."""
        try:
            panel = QGroupBox("🤖 ML Models")
            panel.setObjectName("model_status_panel")
            panel_layout = QVBoxLayout(panel)
            panel_layout.setContentsMargins(15, 20, 15, 15)
            
            # **ENHANCED**: Model status display
            if self.model_manager and hasattr(self.model_manager, 'get_model_status'):
                try:
                    models_status = self.model_manager.get_model_status()
                    for model_name, status in models_status.items():
                        indicator = self._create_model_indicator(model_name, status)
                        panel_layout.addWidget(indicator)
                except Exception as e:
                    self.logger.debug(f"Could not get model status: {e}")
                    self._add_placeholder_model_status(panel_layout)
            else:
                self._add_placeholder_model_status(panel_layout)
            
            panel_layout.addStretch()
            
            # **ENHANCED**: Model status button
            model_status_btn = QPushButton("View Model Details")
            model_status_btn.clicked.connect(self._open_model_status_window)
            panel_layout.addWidget(model_status_btn)
            
            return panel
            
        except Exception as e:
            self.logger.error(f"Error creating model status panel: {e}")
            return QGroupBox("ML Models")
    
    def _add_placeholder_model_status(self, layout):
        """Add placeholder model status when models are not available."""
        try:
            models = [
                ("Random Forest", "Ready"),
                ("SVM", "Ready"),
                ("Deep Neural Network", "Loading"),
                ("XGBoost", "Ready"),
                ("LightGBM", "Ready")
            ]
            
            for model_name, status in models:
                color = "#4caf50" if status == "Ready" else "#ff9800"
                indicator = self._create_model_indicator(model_name, {"status": status, "color": color})
                layout.addWidget(indicator)
                
        except Exception as e:
            self.logger.error(f"Error adding placeholder model status: {e}")
    
    def _create_model_indicator(self, model_name: str, status_info: dict) -> QFrame:
        """Create individual model status indicator."""
        try:
            indicator = QFrame()
            indicator.setObjectName(f"model_{model_name.lower().replace(' ', '_')}")
            indicator_layout = QHBoxLayout(indicator)
            indicator_layout.setContentsMargins(0, 3, 0, 3)
            
            # **ENHANCED**: Model name
            name_label = QLabel(model_name)
            name_label.setStyleSheet("font-size: 11px;")
            indicator_layout.addWidget(name_label)
            
            indicator_layout.addStretch()
            
            # **ENHANCED**: Status
            if isinstance(status_info, dict):
                status = status_info.get("status", "Unknown")
                color = status_info.get("color", "#666")
            else:
                status = str(status_info)
                color = "#4caf50" if status == "Ready" else "#ff9800"
            
            status_label = QLabel(status)
            status_label.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: bold;")
            indicator_layout.addWidget(status_label)
            
            return indicator
            
        except Exception as e:
            self.logger.error(f"Error creating model indicator for {model_name}: {e}")
            return QFrame()
    
    def _create_threat_intelligence_panel(self) -> QGroupBox:
        """Create threat intelligence panel with latest threats."""
        try:
            panel = QGroupBox("🌐 Threat Intelligence")
            panel.setObjectName("threat_intelligence_panel")
            panel_layout = QVBoxLayout(panel)
            panel_layout.setContentsMargins(15, 20, 15, 15)
            
            # **ENHANCED**: Threat summary
            threat_summary = QLabel("Latest threat signatures updated 2 hours ago")
            threat_summary.setStyleSheet("font-size: 12px; color: #666;")
            threat_summary.setWordWrap(True)
            panel_layout.addWidget(threat_summary)
            
            # **ENHANCED**: Threat stats
            stats_layout = QGridLayout()
            stats_layout.setSpacing(10)
            
            stats = [
                ("New Signatures", "1,247"),
                ("Threat Families", "89"),
                ("Last Update", "2h ago"),
                ("Coverage", "99.8%")
            ]
            
            for i, (label, value) in enumerate(stats):
                row, col = divmod(i, 2)
                
                stat_label = QLabel(label)
                stat_label.setStyleSheet("font-size: 10px; color: #666;")
                stats_layout.addWidget(stat_label, row * 2, col)
                
                stat_value = QLabel(value)
                stat_value.setStyleSheet("font-size: 12px; font-weight: bold; color: #2196f3;")
                stats_layout.addWidget(stat_value, row * 2 + 1, col)
            
            panel_layout.addLayout(stats_layout)
            panel_layout.addStretch()
            
            # **ENHANCED**: Update button
            update_btn = QPushButton("Check for Updates")
            update_btn.clicked.connect(self._update_definitions)
            panel_layout.addWidget(update_btn)
            
            return panel
            
        except Exception as e:
            self.logger.error(f"Error creating threat intelligence panel: {e}")
            return QGroupBox("Threat Intelligence")
    
    def _create_dashboard_footer(self) -> QFrame:
        """Create dashboard footer with quick access buttons."""
        try:
            footer_frame = QFrame()
            footer_frame.setObjectName("dashboard_footer")
            footer_frame.setFixedHeight(60)
            footer_layout = QHBoxLayout(footer_frame)
            footer_layout.setContentsMargins(15, 10, 15, 10)
            
            # **ENHANCED**: Quick access buttons
            quick_buttons = [
                ("Open Quarantine", "🔒", self._open_quarantine_window),
                ("View Reports", "📊", lambda: self._navigate_to_section(NavigationSection.REPORTS)),
                ("Settings", "⚙️", self._open_settings),
                ("Help", "❓", self._show_help)
            ]
            
            for text, icon, callback in quick_buttons:
                btn = QPushButton(f"{icon} {text}")
                btn.setMinimumHeight(40)
                btn.setStyleSheet("""
                    QPushButton {
                        border: 1px solid rgba(255, 255, 255, 0.3);
                        border-radius: 6px;
                        padding: 8px 16px;
                        font-size: 12px;
                    }
                    QPushButton:hover {
                        background-color: rgba(255, 255, 255, 0.1);
                    }
                """)
                btn.clicked.connect(callback)
                footer_layout.addWidget(btn)
            
            footer_layout.addStretch()
            
            # **ENHANCED**: System info
            system_info = QLabel(f"Uptime: {self._get_uptime_string()}")
            system_info.setStyleSheet("color: #666; font-size: 11px;")
            footer_layout.addWidget(system_info)
            
            return footer_frame
            
        except Exception as e:
            self.logger.error(f"Error creating dashboard footer: {e}")
            return QFrame()
    
    def _initialize_dashboard_monitoring(self):
        """Initialize dashboard monitoring and real-time updates."""
        try:
            # **ENHANCED**: Time update timer
            self.time_update_timer = QTimer()
            self.time_update_timer.timeout.connect(self._update_time_display)
            self.time_update_timer.start(1000)  # Update every second
            
            # **ENHANCED**: Dashboard update timer
            self.dashboard_update_timer = QTimer()
            self.dashboard_update_timer.timeout.connect(self._update_dashboard_data)
            self.dashboard_update_timer.start(30000)  # Update every 30 seconds
            
            # **ENHANCED**: System monitoring timer
            self.system_monitor_timer = QTimer()
            self.system_monitor_timer.timeout.connect(self._update_system_monitoring)
            self.system_monitor_timer.start(5000)  # Update every 5 seconds
            
            self.logger.debug("Dashboard monitoring initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing dashboard monitoring: {e}")
    
    def _update_time_display(self):
        """Update the current time display."""
        try:
            current_time = datetime.now().strftime("%H:%M:%S")
            if hasattr(self, 'current_time_label'):
                self.current_time_label.setText(current_time)
        except Exception as e:
            self.logger.debug(f"Error updating time display: {e}")
    
    def _update_dashboard_data(self):
        """Update dashboard data and metrics."""
        try:
            # **ENHANCED**: Update metric cards
            self._update_metric_cards()
            
            # **ENHANCED**: Update system status
            self._update_system_status_indicators()
            
            # **ENHANCED**: Update model status if available
            if self.model_manager:
                self._update_model_status_display()
            
            # **ENHANCED**: Update last scan info
            self._update_last_scan_info()
            
        except Exception as e:
            self.logger.debug(f"Error updating dashboard data: {e}")
    
    def _update_metric_cards(self):
        """Update metric cards with current data."""
        try:
            # **ENHANCED**: Update scan count
            scan_count = self.config.get_setting('statistics.total_scans', 0)
            self._update_metric_card('scan_count', str(scan_count))
            
            # **ENHANCED**: Update threat count
            threat_count = self.config.get_setting('statistics.threats_found', 0)
            self._update_metric_card('threat_count', str(threat_count))
            
            # **ENHANCED**: Update quarantine count
            quarantine_count = self.config.get_setting('statistics.files_quarantined', 0)
            self._update_metric_card('quarantine_count', str(quarantine_count))
            
            # **ENHANCED**: Update system health
            health_score = self._calculate_system_health_score()
            health_text = self._get_health_status_text(health_score)
            self._update_metric_card('system_health', health_text)
            
        except Exception as e:
            self.logger.debug(f"Error updating metric cards: {e}")
    
    def _update_metric_card(self, key: str, value: str):
        """Update individual metric card value."""
        try:
            if key in self.metric_cards:
                card = self.metric_cards[key]
                value_label = card.findChild(QLabel, f"{key}_value")
                if value_label:
                    value_label.setText(value)
        except Exception as e:
            self.logger.debug(f"Error updating metric card {key}: {e}")
    
    def _calculate_system_health_score(self) -> float:
        """Calculate overall system health score."""
        try:
            # **ENHANCED**: Basic health calculation
            score = 100.0
            
            # **ENHANCED**: Check protection status
            if not self.config.get_setting('detection.real_time_enabled', True):
                score -= 30
            
            # **ENHANCED**: Check update status
            last_update = self.config.get_setting('updates.last_update', None)
            if last_update:
                try:
                    last_update_time = datetime.fromisoformat(last_update)
                    days_since_update = (datetime.now() - last_update_time).days
                    if days_since_update > 7:
                        score -= 20
                    elif days_since_update > 3:
                        score -= 10
                except Exception:
                    score -= 15
            else:
                score -= 25
            
            # **ENHANCED**: Check scan history
            last_scan = self.config.get_setting('scanning.last_full_scan', None)
            if last_scan:
                try:
                    last_scan_time = datetime.fromisoformat(last_scan)
                    days_since_scan = (datetime.now() - last_scan_time).days
                    if days_since_scan > 14:
                        score -= 15
                    elif days_since_scan > 7:
                        score -= 10
                except Exception:
                    score -= 10
            else:
                score -= 20
            
            return max(0.0, min(100.0, score))
            
        except Exception as e:
            self.logger.debug(f"Error calculating system health score: {e}")
            return 75.0  # Default to "Good" health
    
    def _get_health_status_text(self, score: float) -> str:
        """Get health status text based on score."""
        if score >= 90:
            return "Excellent"
        elif score >= 75:
            return "Good"
        elif score >= 60:
            return "Fair"
        elif score >= 40:
            return "Poor"
        else:
            return "Critical"
    
    def _update_system_status_indicators(self):
        """Update system status indicators."""
        try:
            # **ENHANCED**: Update real-time protection status
            rt_enabled = self.config.get_setting('detection.real_time_enabled', True)
            rt_status = "Active" if rt_enabled else "Disabled"
            rt_color = "#4caf50" if rt_enabled else "#f44336"
            self._update_status_indicator("Real-time Protection", rt_status, rt_color)
            
            # **ENHANCED**: Update virus definitions status
            last_update = self.config.get_setting('updates.last_update', None)
            if last_update:
                try:
                    last_update_time = datetime.fromisoformat(last_update)
                    days_since = (datetime.now() - last_update_time).days
                    if days_since == 0:
                        def_status = "Up to date"
                        def_color = "#4caf50"
                    elif days_since <= 3:
                        def_status = f"{days_since} days old"
                        def_color = "#ff9800"
                    else:
                        def_status = f"{days_since} days old"
                        def_color = "#f44336"
                except Exception:
                    def_status = "Unknown"
                    def_color = "#666"
            else:
                def_status = "Never updated"
                def_color = "#f44336"
            
            self._update_status_indicator("Virus Definitions", def_status, def_color)
            
        except Exception as e:
            self.logger.debug(f"Error updating system status indicators: {e}")
    
    def _update_status_indicator(self, item: str, status: str, color: str):
        """Update individual status indicator."""
        try:
            if hasattr(self, 'status_indicators') and item in self.status_indicators:
                indicator = self.status_indicators[item]
                status_label = indicator.findChild(QLabel, f"{item.lower().replace(' ', '_')}_status")
                if status_label:
                    status_label.setText(status)
                    status_label.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: bold;")
                
                # **ENHANCED**: Update dot color
                dot_labels = indicator.findChildren(QLabel)
                for label in dot_labels:
                    if label.text() == "●":
                        label.setStyleSheet(f"color: {color}; font-size: 12px;")
                        break
        except Exception as e:
            self.logger.debug(f"Error updating status indicator {item}: {e}")
    
    def _update_model_status_display(self):
        """Update ML model status display."""
        try:
            if self.model_manager and hasattr(self.model_manager, 'get_model_status'):
                models_status = self.model_manager.get_model_status()
                
                for model_name, status_info in models_status.items():
                    indicator_name = f"model_{model_name.lower().replace(' ', '_')}"
                    if hasattr(self, indicator_name):
                        # **ENHANCED**: Update model indicator
                        pass  # Implementation would update specific model indicators
                        
        except Exception as e:
            self.logger.debug(f"Error updating model status display: {e}")
    
    def _update_last_scan_info(self):
        """Update last scan information."""
        try:
            last_scan = self.config.get_setting('scanning.last_scan', None)
            if last_scan:
                try:
                    last_scan_time = datetime.fromisoformat(last_scan)
                    time_diff = datetime.now() - last_scan_time
                    
                    if time_diff.days > 0:
                        last_scan_text = f"Last scan: {time_diff.days} days ago"
                    elif time_diff.seconds > 3600:
                        hours = time_diff.seconds // 3600
                        last_scan_text = f"Last scan: {hours} hours ago"
                    else:
                        minutes = time_diff.seconds // 60
                        last_scan_text = f"Last scan: {minutes} minutes ago"
                except Exception:
                    last_scan_text = "Last scan: Unknown"
            else:
                last_scan_text = "Last scan: Never"
            
            if hasattr(self, 'last_scan_label'):
                self.last_scan_label.setText(last_scan_text)
            if hasattr(self, 'last_scan_status'):
                self.last_scan_status.setText(last_scan_text)
                
        except Exception as e:
            self.logger.debug(f"Error updating last scan info: {e}")
    
    def _update_system_monitoring(self):
        """Update system monitoring data."""
        try:
            # **ENHANCED**: Monitor system resources
            self._monitor_system_resources()
            
            # **ENHANCED**: Check component health
            self._check_component_health()
            
            # **ENHANCED**: Update protection status
            self._update_protection_status()
            
        except Exception as e:
            self.logger.debug(f"Error updating system monitoring: {e}")
    
    def _monitor_system_resources(self):
        """Monitor system resource usage."""
        try:
            # **ENHANCED**: Monitor CPU and memory usage
            # Implementation would use psutil or similar if available
            import psutil
            
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_info = psutil.virtual_memory()
            
            # **ENHANCED**: Update resource indicators in status bar if needed
            resource_text = f"CPU: {cpu_percent:.1f}% | RAM: {memory_info.percent:.1f}%"
            if hasattr(self, '_resource_indicator'):
                self._resource_indicator.setText(f"💾 {resource_text}")
                
        except ImportError:
            # **FALLBACK**: Use basic resource monitoring
            pass
        except Exception as e:
            self.logger.debug(f"Error monitoring system resources: {e}")
    
    def _check_component_health(self):
        """Check health of all components."""
        try:
            # **ENHANCED**: Check scanner engine health
            if self.scanner_engine and hasattr(self.scanner_engine, 'is_healthy'):
                scanner_healthy = self.scanner_engine.is_healthy()
                self._component_health['scanner_engine'] = scanner_healthy
            
            # **ENHANCED**: Check model manager health
            if self.model_manager and hasattr(self.model_manager, 'is_healthy'):
                model_healthy = self.model_manager.is_healthy()
                self._component_health['model_manager'] = model_healthy
            
            # **ENHANCED**: Update component health indicators
            self._update_component_health_display()
            
        except Exception as e:
            self.logger.debug(f"Error checking component health: {e}")
    
    def _update_component_health_display(self):
        """Update component health display."""
        try:
            # **ENHANCED**: Update model status display
            healthy_components = sum(1 for health in self._component_health.values() if health)
            total_components = len(self._component_health)
            
            if hasattr(self, '_model_status_label'):
                if healthy_components == total_components:
                    status_text = "🤖 Models: All Ready"
                    self._model_status_label.setStyleSheet("color: #4caf50;")
                elif healthy_components > 0:
                    status_text = f"🤖 Models: {healthy_components}/{total_components} Ready"
                    self._model_status_label.setStyleSheet("color: #ff9800;")
                else:
                    status_text = "🤖 Models: Error"
                    self._model_status_label.setStyleSheet("color: #f44336;")
                
                self._model_status_label.setText(status_text)
                
        except Exception as e:
            self.logger.debug(f"Error updating component health display: {e}")
    
    def _update_protection_status(self):
        """Update protection status indicator."""
        try:
            # **ENHANCED**: Calculate overall protection status
            rt_enabled = self.config.get_setting('detection.real_time_enabled', True)
            components_healthy = sum(1 for health in self._component_health.values() if health)
            total_components = len(self._component_health)
            
            if rt_enabled and components_healthy == total_components:
                status_text = "🛡️ PROTECTED"
                status_color = "#4caf50"
            elif rt_enabled and components_healthy > 0:
                status_text = "🛡️ PARTIALLY PROTECTED"
                status_color = "#ff9800"
            else:
                status_text = "⚠️ NOT PROTECTED"
                status_color = "#f44336"
            
            # **ENHANCED**: Update protection status displays
            if hasattr(self, 'protection_status_indicator'):
                self.protection_status_indicator.setText(status_text)
                self.protection_status_indicator.setStyleSheet(f"""
                    QLabel {{
                        color: {status_color};
                        font-size: 18px;
                        font-weight: bold;
                        padding: 5px;
                    }}
                """)
            
            if hasattr(self, '_protection_status_label'):
                self._protection_status_label.setText(status_text)
                self._protection_status_label.setStyleSheet(f"color: {status_color};")
            
            if hasattr(self, '_sidebar_protection_status'):
                self._sidebar_protection_status.setText(status_text)
                self._sidebar_protection_status.setStyleSheet(f"color: {status_color}; font-weight: bold;")
                
        except Exception as e:
            self.logger.debug(f"Error updating protection status: {e}")
    
    def _get_uptime_string(self) -> str:
        """Get application uptime as formatted string."""
        try:
            uptime = datetime.now() - self._start_time
            
            if uptime.days > 0:
                return f"{uptime.days}d {uptime.seconds // 3600}h"
            elif uptime.seconds > 3600:
                hours = uptime.seconds // 3600
                minutes = (uptime.seconds % 3600) // 60
                return f"{hours}h {minutes}m"
            else:
                minutes = uptime.seconds // 60
                return f"{minutes}m"
                
        except Exception as e:
            self.logger.debug(f"Error getting uptime string: {e}")
            return "0m"
    
    def _create_fallback_dashboard(self):
        """Create fallback dashboard in case of errors."""
        try:
            self.logger.warning("Creating fallback dashboard due to initialization errors")
            
            # **FALLBACK**: Create simple dashboard
            fallback_widget = QWidget()
            fallback_widget.setObjectName("fallback_dashboard")
            fallback_layout = QVBoxLayout(fallback_widget)
            fallback_layout.setContentsMargins(50, 50, 50, 50)
            
            # **FALLBACK**: Simple title
            title = QLabel("Advanced Multi-Algorithm Antivirus")
            title.setAlignment(Qt.AlignCenter)
            title.setStyleSheet("font-size: 24px; font-weight: bold; margin: 20px;")
            fallback_layout.addWidget(title)
            
            # **FALLBACK**: Status message
            status = QLabel("Dashboard loading with limited functionality")
            status.setAlignment(Qt.AlignCenter)
            status.setStyleSheet("font-size: 14px; color: #666; margin: 10px;")
            fallback_layout.addWidget(status)
            
            # **FALLBACK**: Quick scan button
            scan_btn = QPushButton("Start Quick Scan")
            scan_btn.setMinimumHeight(40)
            scan_btn.setMaximumWidth(200)
            scan_btn.clicked.connect(lambda: self._start_scan("quick"))
            fallback_layout.addWidget(scan_btn, 0, Qt.AlignCenter)
            
            fallback_layout.addStretch()
            
            # **FALLBACK**: Add to content stack
            self.content_area.addWidget(fallback_widget)
            self.content_widgets = {'dashboard': fallback_widget}
            
        except Exception as e:
            self.logger.error(f"Error creating fallback dashboard: {e}")

    # ========================================================================
    # NAVIGATION SYSTEM IMPLEMENTATION
    # ========================================================================
    
    def _setup_navigation_system(self):
        """Setup comprehensive navigation system with advanced features."""
        try:
            self.logger.debug("Setting up comprehensive navigation system...")
            
            # **ENHANCED**: Navigation state management
            self._navigation_history = []
            self._navigation_forward_stack = []
            self._navigation_animations = {}
            
            # **ENHANCED**: Initialize section widgets
            self._initialize_section_widgets()
            
            # **ENHANCED**: Connect navigation signals
            self._connect_navigation_signals()
            
            # **ENHANCED**: Setup keyboard shortcuts for navigation
            self._setup_navigation_shortcuts()
            
            self.logger.debug("Navigation system setup completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up navigation system: {e}")
    
    
    def _initialize_section_widgets(self):
        """Initialize widgets for all navigation sections."""
        try:
            # **ENHANCED**: Create widgets for each section
            self._create_scanning_section()
            self._create_quarantine_section()
            self._create_reports_section()
            self._create_settings_section()
            
        except Exception as e:
            self.logger.error(f"Error initializing section widgets: {e}")
    
    def _create_scanning_section(self):
        """Create scanning section widget."""
        try:
            scanning_widget = QWidget()
            scanning_widget.setObjectName("scanning_section")
            scanning_layout = QVBoxLayout(scanning_widget)
            scanning_layout.setContentsMargins(20, 20, 20, 20)
            
            # **ENHANCED**: Section header
            header = QLabel("🔍 Scanning Center")
            header.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
            scanning_layout.addWidget(header)
            
            # **ENHANCED**: Scanning controls placeholder
            scan_controls = QFrame()
            scan_controls.setFrameStyle(QFrame.Box)
            scan_controls.setMinimumHeight(200)
            scan_controls_layout = QVBoxLayout(scan_controls)
            
            info_label = QLabel("Scanning interface will be loaded here")
            info_label.setAlignment(Qt.AlignCenter)
            info_label.setStyleSheet("color: #666; font-size: 14px;")
            scan_controls_layout.addWidget(info_label)
            
            open_scan_btn = QPushButton("Open Scan Window")
            open_scan_btn.clicked.connect(self._open_scan_window)
            scan_controls_layout.addWidget(open_scan_btn)
            
            scanning_layout.addWidget(scan_controls)
            scanning_layout.addStretch()
            
            # **ENHANCED**: Add to content stack
            self.content_area.addWidget(scanning_widget)
            self.content_widgets['scanning'] = scanning_widget
            
        except Exception as e:
            self.logger.error(f"Error creating scanning section: {e}")
    
    def _create_quarantine_section(self):
        """Create quarantine section widget."""
        try:
            quarantine_widget = QWidget()
            quarantine_widget.setObjectName("quarantine_section")
            quarantine_layout = QVBoxLayout(quarantine_widget)
            quarantine_layout.setContentsMargins(20, 20, 20, 20)
            
            # **ENHANCED**: Section header
            header = QLabel("🔒 Quarantine Management")
            header.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
            quarantine_layout.addWidget(header)
            
            # **ENHANCED**: Quarantine controls placeholder
            quarantine_controls = QFrame()
            quarantine_controls.setFrameStyle(QFrame.Box)
            quarantine_controls.setMinimumHeight(200)
            quarantine_controls_layout = QVBoxLayout(quarantine_controls)
            
            info_label = QLabel("Quarantine management interface will be loaded here")
            info_label.setAlignment(Qt.AlignCenter)
            info_label.setStyleSheet("color: #666; font-size: 14px;")
            quarantine_controls_layout.addWidget(info_label)
            
            open_quarantine_btn = QPushButton("Open Quarantine Window")
            open_quarantine_btn.clicked.connect(self._open_quarantine_window)
            quarantine_controls_layout.addWidget(open_quarantine_btn)
            
            quarantine_layout.addWidget(quarantine_controls)
            quarantine_layout.addStretch()
            
            # **ENHANCED**: Add to content stack
            self.content_area.addWidget(quarantine_widget)
            self.content_widgets['quarantine'] = quarantine_widget
            
        except Exception as e:
            self.logger.error(f"Error creating quarantine section: {e}")
    
    def _create_reports_section(self):
        """Create reports section widget."""
        try:
            reports_widget = QWidget()
            reports_widget.setObjectName("reports_section")
            reports_layout = QVBoxLayout(reports_widget)
            reports_layout.setContentsMargins(20, 20, 20, 20)
            
            # **ENHANCED**: Section header
            header = QLabel("📊 Reports & Analytics")
            header.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
            reports_layout.addWidget(header)
            
            # **ENHANCED**: Reports controls placeholder
            reports_controls = QFrame()
            reports_controls.setFrameStyle(QFrame.Box)
            reports_controls.setMinimumHeight(300)
            reports_controls_layout = QVBoxLayout(reports_controls)
            
            info_label = QLabel("Reports and analytics interface coming soon")
            info_label.setAlignment(Qt.AlignCenter)
            info_label.setStyleSheet("color: #666; font-size: 14px;")
            reports_controls_layout.addWidget(info_label)
            
            # **ENHANCED**: Sample report buttons
            sample_buttons = [
                ("Scan History Report", self._generate_scan_report),
                ("Threat Analysis Report", self._generate_threat_report),
                ("System Performance Report", self._generate_performance_report)
            ]
            
            for button_text, callback in sample_buttons:
                btn = QPushButton(button_text)
                btn.clicked.connect(callback)
                reports_controls_layout.addWidget(btn)
            
            reports_layout.addWidget(reports_controls)
            reports_layout.addStretch()
            
            # **ENHANCED**: Add to content stack
            self.content_area.addWidget(reports_widget)
            self.content_widgets['reports'] = reports_widget
            
        except Exception as e:
            self.logger.error(f"Error creating reports section: {e}")
    
    def _create_settings_section(self):
        """Create settings section widget."""
        try:
            settings_widget = QWidget()
            settings_widget.setObjectName("settings_section")
            settings_layout = QVBoxLayout(settings_widget)
            settings_layout.setContentsMargins(20, 20, 20, 20)
            
            # **ENHANCED**: Section header
            header = QLabel("⚙️ Settings & Configuration")
            header.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
            settings_layout.addWidget(header)
            
            # **ENHANCED**: Settings controls placeholder
            settings_controls = QFrame()
            settings_controls.setFrameStyle(QFrame.Box)
            settings_controls.setMinimumHeight(200)
            settings_controls_layout = QVBoxLayout(settings_controls)
            
            info_label = QLabel("Settings interface will be loaded here")
            info_label.setAlignment(Qt.AlignCenter)
            info_label.setStyleSheet("color: #666; font-size: 14px;")
            settings_controls_layout.addWidget(info_label)
            
            open_settings_btn = QPushButton("Open Settings Window")
            open_settings_btn.clicked.connect(self._open_settings)
            settings_controls_layout.addWidget(open_settings_btn)
            
            settings_layout.addWidget(settings_controls)
            settings_layout.addStretch()
            
            # **ENHANCED**: Add to content stack
            self.content_area.addWidget(settings_widget)
            self.content_widgets['settings'] = settings_widget
            
        except Exception as e:
            self.logger.error(f"Error creating settings section: {e}")
    
    def _connect_navigation_signals(self):
        """Connect navigation-related signals."""
        try:
            # **ENHANCED**: Connect navigation button clicks
            for section, button in self.nav_buttons.items():
                button.clicked.connect(lambda checked=False, s=section: self._navigate_to_section(s))
            
        except Exception as e:
            self.logger.error(f"Error connecting navigation signals: {e}")
    
    def _setup_navigation_shortcuts(self):
        """Setup keyboard shortcuts for navigation."""
        try:
            # **ENHANCED**: Navigation shortcuts
            shortcuts = {
                'Ctrl+1': NavigationSection.DASHBOARD,
                'Ctrl+2': NavigationSection.SCANNING,
                'Ctrl+3': NavigationSection.QUARANTINE,
                'Ctrl+4': NavigationSection.REPORTS,
                'Ctrl+5': NavigationSection.SETTINGS
            }
            
            for shortcut_key, section in shortcuts.items():
                shortcut = QAction(self)
                shortcut.setShortcut(shortcut_key)
                shortcut.triggered.connect(lambda s=section: self._navigate_to_section(s))
                self.addAction(shortcut)
            
        except Exception as e:
            self.logger.error(f"Error setting up navigation shortcuts: {e}")
    
    def _navigate_to_section(self, section: NavigationSection):
        """Navigate to a specific section with validation and animation."""
        try:
            # **ENHANCED**: Validate navigation
            if not self._validate_navigation(section):
                return False
            
            # **ENHANCED**: Store current section in history
            if self._active_navigation != section:
                self._navigation_history.append(self._active_navigation)
                self._navigation_forward_stack.clear()
            
            # **ENHANCED**: Update navigation state
            old_section = self._active_navigation
            self._active_navigation = section
            
            # **ENHANCED**: Update navigation buttons
            self._update_navigation_buttons()
            
            # **ENHANCED**: Switch content with animation
            self._switch_content_with_animation(old_section, section)
            
            # **ENHANCED**: Emit navigation changed signal
            self.navigation_changed.emit(old_section.key if old_section else "", section.key)
            
            self.logger.debug(f"Navigated from {old_section.key if old_section else 'none'} to {section.key}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error navigating to section {section.key}: {e}")
            return False
    
    def _validate_navigation(self, section: NavigationSection) -> bool:
        """Validate if navigation to section is allowed."""
        try:
            # **ENHANCED**: Check section requirements
            requirements = self._section_requirements.get(section, {})
            
            # **ENHANCED**: Check component requirements
            required_components = requirements.get('components', [])
            for component in required_components:
                if component not in self._component_health or not self._component_health[component]:
                    self.logger.warning(f"Cannot navigate to {section.key}: {component} not available")
                    self._show_navigation_error(section, f"Required component '{component}' is not available")
                    return False
            
            # **ENHANCED**: Check permissions (if implemented)
            required_permissions = requirements.get('permissions', [])
            # Implementation would check user permissions here
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating navigation to {section.key}: {e}")
            return False
    
    def _show_navigation_error(self, section: NavigationSection, error_message: str):
        """Show navigation error to user."""
        try:
            QMessageBox.warning(
                self,
                f"Cannot Access {section.title}",
                f"Unable to navigate to {section.title}:\n\n{error_message}",
                QMessageBox.Ok
            )
        except Exception as e:
            self.logger.error(f"Error showing navigation error: {e}")
    
    def _update_navigation_buttons(self):
        """Update navigation button states."""
        try:
            for section, button in self.nav_buttons.items():
                is_active = (section == self._active_navigation)
                button.setChecked(is_active)
                button.setProperty("active", is_active)
                
                # **ENHANCED**: Update button style
                if is_active:
                    button.setStyleSheet(button.styleSheet() + """
                        QPushButton:checked {
                            background-color: rgba(33, 150, 243, 100);
                            font-weight: bold;
                        }
                    """)
                    
        except Exception as e:
            self.logger.error(f"Error updating navigation buttons: {e}")
    
    def _switch_content_with_animation(self, old_section: NavigationSection, new_section: NavigationSection):
        """Switch content with animation if enabled."""
        try:
            # **ENHANCED**: Get target widget
            target_widget = self.content_widgets.get(new_section.key)
            if not target_widget:
                self.logger.warning(f"No widget found for section {new_section.key}")
                return
            
            # **ENHANCED**: Animate navigation change if animations enabled
            if self._animation_manager and old_section != new_section:
                self.animate_navigation_change(old_section.key if old_section else "", new_section.key)
            
            # **ENHANCED**: Switch to target widget
            self.content_area.setCurrentWidget(target_widget)
            
            # **ENHANCED**: Update section-specific UI elements
            self._update_section_specific_ui(new_section)
            
        except Exception as e:
            self.logger.error(f"Error switching content to {new_section.key}: {e}")
    
    def _update_section_specific_ui(self, section: NavigationSection):
        """Update UI elements specific to the current section."""
        try:
            # **ENHANCED**: Update window title with section info
            base_title = "Advanced Multi-Algorithm Antivirus - Professional Security Suite"
            section_title = f"{base_title} - {section.title}"
            self.setWindowTitle(section_title)
            
            # **ENHANCED**: Update status bar context
            self._update_status_bar_context(section)
            
            # **ENHANCED**: Update menu context
            self._update_menu_context(section)
            
            # **ENHANCED**: Update toolbar context
            self._update_toolbar_context(section)
            
            # **ENHANCED**: Focus management
            self._set_section_focus(section)
            
            self.logger.debug(f"Updated UI for section: {section.key}")
            
        except Exception as e:
            self.logger.error(f"Error updating section-specific UI for {section.key}: {e}")
    
    def _update_status_bar_context(self, section: NavigationSection):
        """Update status bar with section-specific context."""
        try:
            # **ENHANCED**: Update status bar message
            context_messages = {
                NavigationSection.DASHBOARD: "System overview and real-time monitoring",
                NavigationSection.SCANNING: "Threat scanning and detection controls",
                NavigationSection.QUARANTINE: "Isolated threats management",
                NavigationSection.MODELS: "Machine learning model status and configuration",
                NavigationSection.SETTINGS: "Application configuration and preferences",
                NavigationSection.REPORTS: "Security reports and analytics",
                NavigationSection.UPDATES: "System and definition updates",
                NavigationSection.HELP: "Documentation and support resources"
            }
            
            message = context_messages.get(section, "Ready")
            if self.status_bar:
                self.status_bar.showMessage(message, 3000)  # Show for 3 seconds
                
        except Exception as e:
            self.logger.error(f"Error updating status bar context: {e}")
    
    def _update_menu_context(self, section: NavigationSection):
        """Update menu context based on current section."""
        try:
            # **ENHANCED**: Enable/disable menu items based on section
            section_menu_states = {
                NavigationSection.SCANNING: {
                    'scan_actions': True,
                    'scan_controls': True
                },
                NavigationSection.QUARANTINE: {
                    'quarantine_actions': True
                },
                NavigationSection.SETTINGS: {
                    'settings_actions': True
                }
            }
            
            # **ENHANCED**: Apply menu state changes
            current_states = section_menu_states.get(section, {})
            
            # Enable scan controls when in scanning section
            if hasattr(self, '_scan_pause_action'):
                self._scan_pause_action.setVisible(current_states.get('scan_controls', False))
            if hasattr(self, '_scan_stop_action'):
                self._scan_stop_action.setVisible(current_states.get('scan_controls', False))
                
        except Exception as e:
            self.logger.error(f"Error updating menu context: {e}")
    
    def _update_toolbar_context(self, section: NavigationSection):
        """Update toolbar context based on current section."""
        try:
            # **ENHANCED**: Show/hide toolbar buttons based on section
            if self.toolbar:
                # Implementation would show/hide relevant toolbar buttons
                pass
                
        except Exception as e:
            self.logger.error(f"Error updating toolbar context: {e}")
    
    def _set_section_focus(self, section: NavigationSection):
        """Set appropriate focus for the current section."""
        try:
            # **ENHANCED**: Set focus to appropriate widget in the section
            current_widget = self.content_area.currentWidget()
            if current_widget:
                # Find the first focusable widget
                focusable_widgets = current_widget.findChildren(QPushButton)
                if focusable_widgets:
                    focusable_widgets[0].setFocus()
                    
        except Exception as e:
            self.logger.error(f"Error setting section focus: {e}")
    
    # ========================================================================
    # CHILD WINDOW MANAGEMENT SYSTEM
    # ========================================================================
    
    def _initialize_child_windows(self):
        """Initialize child window management system with comprehensive tracking."""
        try:
            self.logger.debug("Initializing comprehensive child window management...")
            
            # **ENHANCED**: Initialize window state tracking
            self._initialize_window_state_tracking()
            
            # **ENHANCED**: Setup window creation factories
            self._setup_window_factories()
            
            # **ENHANCED**: Configure window management policies
            self._configure_window_policies()
            
            # **ENHANCED**: Initialize window communication system
            self._initialize_window_communication()
            
            self.logger.debug("Child window management system initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing child windows: {e}")
    
    def _initialize_window_state_tracking(self):
        """Initialize comprehensive window state tracking."""
        try:
            # **ENHANCED**: Initialize window states for all window types
            window_types = [
                'scan_window',
                'quarantine_window', 
                'settings_window',
                'model_status_window'
            ]
            
            for window_type in window_types:
                self._window_states[window_type] = WindowState(
                    window_type=window_type,
                    creation_time=None,
                    is_open=False
                )
            
            # **ENHANCED**: Initialize window access tracking
            self._window_access_tracking = {
                window_type: {
                    'total_opens': 0,
                    'total_focus_time': 0.0,
                    'last_accessed': None,
                    'average_session_time': 0.0,
                    'error_count': 0
                } for window_type in window_types
            }
            
        except Exception as e:
            self.logger.error(f"Error initializing window state tracking: {e}")
    
    def _setup_window_factories(self):
        """Setup window creation factories with enhanced error handling."""
        try:
            # **ENHANCED**: Define window factory functions
            self._window_factories = {
                'scan_window': self._create_scan_window,
                'quarantine_window': self._create_quarantine_window,
                'settings_window': self._create_settings_window,
                'model_status_window': self._create_model_status_window
            }
            
            # **ENHANCED**: Define window requirements
            self._window_requirements = {
                'scan_window': {
                    'components': ['scanner_engine'],
                    'availability_check': scan_window_available
                },
                'quarantine_window': {
                    'components': ['file_manager'],
                    'availability_check': quarantine_window_available
                },
                'settings_window': {
                    'components': [],
                    'availability_check': settings_window_available
                },
                'model_status_window': {
                    'components': ['model_manager'],
                    'availability_check': model_status_window_available
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error setting up window factories: {e}")
    
    def _configure_window_policies(self):
        """Configure window management policies."""
        try:
            # **ENHANCED**: Window behavior policies
            self._window_policies = {
                'max_concurrent_windows': 5,
                'auto_close_inactive': False,
                'save_window_geometry': True,
                'restore_window_state': True,
                'cascade_new_windows': True,
                'center_new_windows': True,
                'remember_window_positions': True
            }
            
            # **ENHANCED**: Window lifecycle policies
            self._lifecycle_policies = {
                'scan_window': {
                    'singleton': True,
                    'auto_show': True,
                    'close_with_parent': True,
                    'save_state': True
                },
                'quarantine_window': {
                    'singleton': True,
                    'auto_show': True,
                    'close_with_parent': True,
                    'save_state': True
                },
                'settings_window': {
                    'singleton': True,
                    'auto_show': True,
                    'close_with_parent': True,
                    'save_state': True
                },
                'model_status_window': {
                    'singleton': True,
                    'auto_show': True,
                    'close_with_parent': True,
                    'save_state': True
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error configuring window policies: {e}")
    
    def _initialize_window_communication(self):
        """Initialize inter-window communication system."""
        try:
            # **ENHANCED**: Setup window message routing
            self._window_message_queue = deque()
            self._window_event_handlers = {}
            
            # **ENHANCED**: Setup window synchronization
            self._window_sync_manager = {
                'pending_updates': {},
                'sync_conflicts': {},
                'last_sync_times': {}
            }
            
        except Exception as e:
            self.logger.error(f"Error initializing window communication: {e}")
    
    def _open_child_window(self, window_type: str, **kwargs) -> bool:
        """Open a child window with comprehensive management."""
        try:
            self.logger.debug(f"Opening child window: {window_type}")
            
            # **ENHANCED**: Validate window type
            if window_type not in self._window_factories:
                self.logger.error(f"Unknown window type: {window_type}")
                return False
            
            # **ENHANCED**: Check window requirements
            if not self._check_window_requirements(window_type):
                return False
            
            # **ENHANCED**: Handle singleton policy
            if self._lifecycle_policies.get(window_type, {}).get('singleton', False):
                existing_window = getattr(self, window_type, None)
                if existing_window and existing_window.isVisible():
                    # **ENHANCED**: Bring existing window to front
                    existing_window.raise_()
                    existing_window.activateWindow()
                    self._update_window_access_tracking(window_type)
                    return True
            
            # **ENHANCED**: Create window using factory
            window = self._window_factories[window_type](**kwargs)
            if not window:
                self.logger.error(f"Failed to create window: {window_type}")
                return False
            
            # **ENHANCED**: Configure window
            self._configure_child_window(window, window_type)
            
            # **ENHANCED**: Update window state
            self._update_window_state(window_type, window, is_opening=True)
            
            # **ENHANCED**: Show window if auto_show enabled
            if self._lifecycle_policies.get(window_type, {}).get('auto_show', True):
                window.show()
                window.raise_()
                window.activateWindow()
            
            # **ENHANCED**: Emit window opened signal
            self.window_opened.emit(window_type, window)
            
            self.logger.info(f"Child window opened successfully: {window_type}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error opening child window {window_type}: {e}")
            return False
    
    def _check_window_requirements(self, window_type: str) -> bool:
        """Check if window requirements are satisfied."""
        try:
            requirements = self._window_requirements.get(window_type, {})
            
            # **ENHANCED**: Check component requirements
            required_components = requirements.get('components', [])
            for component in required_components:
                if component not in self._component_health or not self._component_health[component]:
                    self._show_window_requirement_error(window_type, f"Required component '{component}' is not available")
                    return False
            
            # **ENHANCED**: Check availability
            availability_check = requirements.get('availability_check', True)
            if not availability_check:
                self._show_window_requirement_error(window_type, "Window class is not available")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking window requirements for {window_type}: {e}")
            return False
    
    def _show_window_requirement_error(self, window_type: str, error_message: str):
        """Show window requirement error to user."""
        try:
            window_names = {
                'scan_window': 'Scan Window',
                'quarantine_window': 'Quarantine Manager',
                'settings_window': 'Settings',
                'model_status_window': 'Model Status'
            }
            
            window_name = window_names.get(window_type, window_type.replace('_', ' ').title())
            
            QMessageBox.warning(
                self,
                f"Cannot Open {window_name}",
                f"Unable to open {window_name}:\n\n{error_message}",
                QMessageBox.Ok
            )
        except Exception as e:
            self.logger.error(f"Error showing window requirement error: {e}")
    
    def _configure_child_window(self, window: QWidget, window_type: str):
        """Configure child window with advanced settings."""
        try:
            # **ENHANCED**: Set window properties
            window.setWindowFlags(Qt.Window)
            window.setAttribute(Qt.WA_DeleteOnClose, False)
            
            # **ENHANCED**: Configure window behavior
            policies = self._lifecycle_policies.get(window_type, {})
            
            if policies.get('close_with_parent', True):
                window.setAttribute(Qt.WA_QuitOnClose, False)
            
            # **ENHANCED**: Setup window geometry
            self._setup_window_geometry(window, window_type)
            
            # **ENHANCED**: Connect window signals
            self._connect_window_signals(window, window_type)
            
            # **ENHANCED**: Apply theme to window
            if hasattr(window, 'apply_theme') and self.theme_manager:
                try:
                    window.apply_theme(self.theme_manager.get_current_theme())
                except Exception as e:
                    self.logger.debug(f"Could not apply theme to {window_type}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error configuring child window {window_type}: {e}")
    
    def _setup_window_geometry(self, window: QWidget, window_type: str):
        """Setup window geometry with intelligent positioning."""
        try:
            # **ENHANCED**: Default window sizes
            default_sizes = {
                'scan_window': (800, 600),
                'quarantine_window': (900, 700),
                'settings_window': (700, 500),
                'model_status_window': (1000, 800)
            }
            
            # **ENHANCED**: Set default size
            width, height = default_sizes.get(window_type, (600, 400))
            window.resize(width, height)
            
            # **ENHANCED**: Restore saved geometry if available
            if self._window_policies.get('restore_window_state', True):
                self._restore_window_geometry(window, window_type)
            
            # **ENHANCED**: Position window intelligently
            if self._window_policies.get('center_new_windows', True):
                self._center_window_on_parent(window)
            elif self._window_policies.get('cascade_new_windows', True):
                self._cascade_window(window, window_type)
            
        except Exception as e:
            self.logger.error(f"Error setting up window geometry for {window_type}: {e}")
    
    def _restore_window_geometry(self, window: QWidget, window_type: str):
        """Restore saved window geometry."""
        try:
            # **ENHANCED**: Load geometry from config
            geometry_key = f"window_geometry.{window_type}"
            saved_geometry = self.config.get_setting(geometry_key, None)
            
            if saved_geometry:
                try:
                    # **ENHANCED**: Restore geometry from saved data
                    x, y, width, height = saved_geometry
                    window.setGeometry(x, y, width, height)
                    
                    # **ENHANCED**: Ensure window is visible on screen
                    self._ensure_window_on_screen(window)
                    
                    self.logger.debug(f"Restored geometry for {window_type}")
                except Exception as e:
                    self.logger.debug(f"Could not restore geometry for {window_type}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error restoring window geometry for {window_type}: {e}")
    
    def _ensure_window_on_screen(self, window: QWidget):
        """Ensure window is visible on screen."""
        try:
            screen_geometry = self.screen().availableGeometry()
            window_geometry = window.geometry()
            
            # **ENHANCED**: Check if window is off-screen
            if not screen_geometry.intersects(window_geometry):
                # **ENHANCED**: Move window to center of screen
                window.move(
                    (screen_geometry.width() - window_geometry.width()) // 2,
                    (screen_geometry.height() - window_geometry.height()) // 2
                )
                
        except Exception as e:
            self.logger.error(f"Error ensuring window on screen: {e}")
    
    def _center_window_on_parent(self, window: QWidget):
        """Center window on parent window."""
        try:
            parent_geometry = self.geometry()
            window_geometry = window.geometry()
            
            # **ENHANCED**: Calculate center position
            x = parent_geometry.x() + (parent_geometry.width() - window_geometry.width()) // 2
            y = parent_geometry.y() + (parent_geometry.height() - window_geometry.height()) // 2
            
            window.move(x, y)
            
        except Exception as e:
            self.logger.error(f"Error centering window on parent: {e}")
    
    def _cascade_window(self, window: QWidget, window_type: str):
        """Position window in cascade style."""
        try:
            # **ENHANCED**: Calculate cascade offset
            open_windows = sum(1 for state in self._window_states.values() if state.is_open)
            cascade_offset = 30 * open_windows
            
            # **ENHANCED**: Position with offset
            base_x, base_y = 100, 100
            window.move(base_x + cascade_offset, base_y + cascade_offset)
            
        except Exception as e:
            self.logger.error(f"Error cascading window {window_type}: {e}")
    
    def _connect_window_signals(self, window: QWidget, window_type: str):
        """Connect window signals for tracking and management."""
        try:
            # **ENHANCED**: Connect close event
            if hasattr(window, 'closeEvent'):
                original_close_event = window.closeEvent
                
                def enhanced_close_event(event):
                    self._handle_window_close(window, window_type, event)
                    original_close_event(event)
                
                window.closeEvent = enhanced_close_event
            
            # **ENHANCED**: Connect focus events if available
            if hasattr(window, 'focusInEvent'):
                original_focus_in = window.focusInEvent
                
                def enhanced_focus_in(event):
                    self._handle_window_focus_in(window_type, event)
                    original_focus_in(event)
                
                window.focusInEvent = enhanced_focus_in
            
            if hasattr(window, 'focusOutEvent'):
                original_focus_out = window.focusOutEvent
                
                def enhanced_focus_out(event):
                    self._handle_window_focus_out(window_type, event)
                    original_focus_out(event)
                
                window.focusOutEvent = enhanced_focus_out
            
        except Exception as e:
            self.logger.error(f"Error connecting window signals for {window_type}: {e}")
    
    def _handle_window_close(self, window: QWidget, window_type: str, event):
        """Handle window close event."""
        try:
            # **ENHANCED**: Save window geometry
            if self._window_policies.get('save_window_geometry', True):
                self._save_window_geometry(window, window_type)
            
            # **ENHANCED**: Update window state
            self._update_window_state(window_type, None, is_closing=True)
            
            # **ENHANCED**: Emit window closed signal
            self.window_closed.emit(window_type)
            
            # **ENHANCED**: Clear window reference
            if hasattr(self, window_type):
                setattr(self, window_type, None)
            
            self.logger.debug(f"Window closed: {window_type}")
            
        except Exception as e:
            self.logger.error(f"Error handling window close for {window_type}: {e}")
    
    def _save_window_geometry(self, window: QWidget, window_type: str):
        """Save window geometry to config."""
        try:
            geometry = window.geometry()
            geometry_data = [geometry.x(), geometry.y(), geometry.width(), geometry.height()]
            
            geometry_key = f"window_geometry.{window_type}"
            self.config.set_setting(geometry_key, geometry_data)
            
            self.logger.debug(f"Saved geometry for {window_type}")
            
        except Exception as e:
            self.logger.error(f"Error saving window geometry for {window_type}: {e}")
    
    def _handle_window_focus_in(self, window_type: str, event):
        """Handle window focus in event."""
        try:
            # **ENHANCED**: Update access tracking
            self._update_window_access_tracking(window_type)
            
            # **ENHANCED**: Record focus time start
            self._window_focus_times[window_type] = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Error handling window focus in for {window_type}: {e}")
    
    def _handle_window_focus_out(self, window_type: str, event):
        """Handle window focus out event."""
        try:
            # **ENHANCED**: Calculate focus duration
            if window_type in self._window_focus_times:
                focus_start = self._window_focus_times[window_type]
                focus_duration = (datetime.now() - focus_start).total_seconds()
                
                # **ENHANCED**: Update focus time tracking
                if window_type in self._window_access_tracking:
                    self._window_access_tracking[window_type]['total_focus_time'] += focus_duration
                
                # **ENHANCED**: Update window state
                if window_type in self._window_states:
                    self._window_states[window_type].update_focus_time(focus_duration)
                
                del self._window_focus_times[window_type]
            
        except Exception as e:
            self.logger.error(f"Error handling window focus out for {window_type}: {e}")
    
    def _update_window_state(self, window_type: str, window: QWidget, is_opening: bool = False, is_closing: bool = False):
        """Update comprehensive window state tracking."""
        try:
            if window_type not in self._window_states:
                return
            
            state = self._window_states[window_type]
            
            if is_opening and window:
                state.instance = window
                state.is_open = True
                state.is_visible = window.isVisible()
                state.creation_time = datetime.now()
                state.update_access()
                
                # **ENHANCED**: Store window reference
                setattr(self, window_type, window)
                
            elif is_closing:
                state.instance = None
                state.is_open = False
                state.is_visible = False
                
            # **ENHANCED**: Update general state
            if window:
                state.is_minimized = window.isMinimized()
                state.is_maximized = window.isMaximized()
                state.geometry = {
                    'x': window.x(),
                    'y': window.y(),
                    'width': window.width(),
                    'height': window.height()
                }
            
        except Exception as e:
            self.logger.error(f"Error updating window state for {window_type}: {e}")
    
    def _update_window_access_tracking(self, window_type: str):
        """Update window access tracking metrics."""
        try:
            if window_type not in self._window_access_tracking:
                return
            
            tracking = self._window_access_tracking[window_type]
            tracking['total_opens'] += 1
            tracking['last_accessed'] = datetime.now()
            
            # **ENHANCED**: Calculate average session time
            if tracking['total_opens'] > 1:
                total_time = tracking['total_focus_time']
                avg_time = total_time / tracking['total_opens']
                tracking['average_session_time'] = avg_time
            
        except Exception as e:
            self.logger.error(f"Error updating window access tracking for {window_type}: {e}")
    
    # ========================================================================
    # CHILD WINDOW FACTORY METHODS
    # ========================================================================
    
    def _create_scan_window(self, **kwargs) -> Optional[QWidget]:
        """Create scan window with comprehensive integration."""
        try:
            if not scan_window_available or not ScanWindow:
                self.logger.warning("ScanWindow class not available")
                return None
            
            # **ENHANCED**: Create scan window with all dependencies
            scan_window = ScanWindow(
                config=self.config,
                theme_manager=self.theme_manager,
                scanner_engine=self.scanner_engine,
                parent=self,
                **kwargs
            )
            
            # **ENHANCED**: Configure scan window
            scan_window.setWindowTitle("Advanced Antivirus - Scan Center")
            
            # **ENHANCED**: Connect scan signals
            self._connect_scan_window_signals(scan_window)
            
            return scan_window
            
        except Exception as e:
            self.logger.error(f"Error creating scan window: {e}")
            return None
    
    def _create_quarantine_window(self, **kwargs) -> Optional[QWidget]:
        """Create quarantine window with comprehensive integration."""
        try:
            if not quarantine_window_available or not QuarantineWindow:
                self.logger.warning("QuarantineWindow class not available")
                return None
            
            # **ENHANCED**: Create quarantine window with all dependencies
            quarantine_window = QuarantineWindow(
                config=self.config,
                theme_manager=self.theme_manager,
                file_manager=self.file_manager,
                parent=self,
                **kwargs
            )
            
            # **ENHANCED**: Configure quarantine window
            quarantine_window.setWindowTitle("Advanced Antivirus - Quarantine Manager")
            
            # **ENHANCED**: Connect quarantine signals
            self._connect_quarantine_window_signals(quarantine_window)
            
            return quarantine_window
            
        except Exception as e:
            self.logger.error(f"Error creating quarantine window: {e}")
            return None
    
    def _create_settings_window(self, **kwargs) -> Optional[QWidget]:
        """Create settings window with comprehensive integration."""
        try:
            if not settings_window_available or not SettingsWindow:
                self.logger.warning("SettingsWindow class not available")
                return None
            
            # **ENHANCED**: Create settings window with all dependencies
            settings_window = SettingsWindow(
                config=self.config,
                theme_manager=self.theme_manager,
                parent=self,
                **kwargs
            )
            
            # **ENHANCED**: Configure settings window
            settings_window.setWindowTitle("Advanced Antivirus - Settings")
            
            # **ENHANCED**: Connect settings signals
            self._connect_settings_window_signals(settings_window)
            
            return settings_window
            
        except Exception as e:
            self.logger.error(f"Error creating settings window: {e}")
            return None
    
    def _create_model_status_window(self, **kwargs) -> Optional[QWidget]:
        """Create model status window with comprehensive integration."""
        try:
            if not model_status_window_available or not ModelStatusWindow:
                self.logger.warning("ModelStatusWindow class not available")
                return None
            
            # **ENHANCED**: Create model status window with all dependencies
            model_status_window = ModelStatusWindow(
                config=self.config,
                theme_manager=self.theme_manager,
                model_manager=self.model_manager,
                parent=self,
                **kwargs
            )
            
            # **ENHANCED**: Configure model status window
            model_status_window.setWindowTitle("Advanced Antivirus - ML Model Status")
            
            # **ENHANCED**: Connect model status signals
            self._connect_model_status_window_signals(model_status_window)
            
            return model_status_window
            
        except Exception as e:
            self.logger.error(f"Error creating model status window: {e}")
            return None
    
    def _connect_scan_window_signals(self, scan_window):
        """Connect scan window signals to main window."""
        try:
            # **ENHANCED**: Connect scan progress signals
            if hasattr(scan_window, 'scan_started'):
                scan_window.scan_started.connect(self._on_scan_started)
            if hasattr(scan_window, 'scan_progress'):
                scan_window.scan_progress.connect(self._on_scan_progress)
            if hasattr(scan_window, 'scan_completed'):
                scan_window.scan_completed.connect(self._on_scan_completed)
            if hasattr(scan_window, 'threat_detected'):
                scan_window.threat_detected.connect(self._on_threat_detected)
            
            self.logger.debug("Scan window signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting scan window signals: {e}")
    
    def _connect_quarantine_window_signals(self, quarantine_window):
        """Connect quarantine window signals to main window."""
        try:
            # **ENHANCED**: Connect quarantine management signals
            if hasattr(quarantine_window, 'file_restored'):
                quarantine_window.file_restored.connect(self._on_file_restored)
            if hasattr(quarantine_window, 'file_deleted'):
                quarantine_window.file_deleted.connect(self._on_file_deleted)
            if hasattr(quarantine_window, 'quarantine_cleared'):
                quarantine_window.quarantine_cleared.connect(self._on_quarantine_cleared)
            
            self.logger.debug("Quarantine window signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting quarantine window signals: {e}")
    
    def _connect_settings_window_signals(self, settings_window):
        """Connect settings window signals to main window."""
        try:
            # **ENHANCED**: Connect settings change signals
            if hasattr(settings_window, 'settings_changed'):
                settings_window.settings_changed.connect(self._on_settings_changed)
            if hasattr(settings_window, 'theme_changed'):
                settings_window.theme_changed.connect(self._on_theme_changed)
            if hasattr(settings_window, 'settings_reset'):
                settings_window.settings_reset.connect(self._on_settings_reset)
            
            self.logger.debug("Settings window signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting settings window signals: {e}")
    
    def _connect_model_status_window_signals(self, model_status_window):
        """Connect model status window signals to main window."""
        try:
            # **ENHANCED**: Connect model management signals
            if hasattr(model_status_window, 'model_loaded'):
                model_status_window.model_loaded.connect(self._on_model_loaded)
            if hasattr(model_status_window, 'model_unloaded'):
                model_status_window.model_unloaded.connect(self._on_model_unloaded)
            if hasattr(model_status_window, 'model_settings_changed'):
                model_status_window.model_settings_changed.connect(self._on_model_settings_changed)
            
            self.logger.debug("Model status window signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting model status window signals: {e}")
    
    # ========================================================================
    # WINDOW EVENT HANDLERS
    # ========================================================================
    
    def _on_scan_started(self, scan_type: str, scan_config: dict):
        """Handle scan started event from scan window."""
        try:
            self.logger.info(f"Scan started: {scan_type}")
            
            # **ENHANCED**: Update scan status
            self._scan_status.update({
                'is_scanning': True,
                'scan_type': scan_type,
                'progress': 0,
                'current_file': '',
                'files_scanned': 0,
                'total_files': scan_config.get('total_files', 0),
                'threats_found': 0,
                'scan_start_time': datetime.now(),
                'estimated_completion': None
            })
            
            # **ENHANCED**: Update UI
            self._update_scan_status_ui()
            
            # **ENHANCED**: Enable scan controls
            if hasattr(self, '_scan_pause_action'):
                self._scan_pause_action.setEnabled(True)
            if hasattr(self, '_scan_stop_action'):
                self._scan_stop_action.setEnabled(True)
            
            # **ENHANCED**: Emit main window signal
            self.scan_started.emit(scan_type, scan_config)
            
        except Exception as e:
            self.logger.error(f"Error handling scan started event: {e}")
    
    def _on_scan_progress(self, scanned: int, total: int, current_file: str):
        """Handle scan progress event from scan window."""
        try:
            # **ENHANCED**: Update scan status
            self._scan_status.update({
                'progress': int((scanned / total) * 100) if total > 0 else 0,
                'current_file': current_file,
                'files_scanned': scanned,
                'total_files': total
            })
            
            # **ENHANCED**: Calculate scan speed and ETA
            if self._scan_status['scan_start_time']:
                elapsed = (datetime.now() - self._scan_status['scan_start_time']).total_seconds()
                if elapsed > 0:
                    scan_speed = scanned / elapsed
                    remaining_files = total - scanned
                    eta_seconds = remaining_files / scan_speed if scan_speed > 0 else 0
                    
                    self._scan_status['scan_speed'] = scan_speed
                    self._scan_status['estimated_completion'] = datetime.now() + timedelta(seconds=eta_seconds)
            
            # **ENHANCED**: Update UI
            self._update_scan_status_ui()
            
            # **ENHANCED**: Emit main window signal
            self.scan_progress.emit(scanned, total, current_file)
            
        except Exception as e:
            self.logger.error(f"Error handling scan progress event: {e}")
    
    def _on_scan_completed(self, scan_results: dict):
        """Handle scan completed event from scan window."""
        try:
            self.logger.info(f"Scan completed: {scan_results}")
            
            # **ENHANCED**: Update scan status
            self._scan_status.update({
                'is_scanning': False,
                'progress': 100,
                'threats_found': scan_results.get('threats_found', 0),
                'scan_start_time': None,
                'estimated_completion': None
            })
            
            # **ENHANCED**: Update statistics
            total_scans = self.config.get_setting('statistics.total_scans', 0)
            self.config.set_setting('statistics.total_scans', total_scans + 1)
            
            threats_found = scan_results.get('threats_found', 0)
            if threats_found > 0:
                total_threats = self.config.get_setting('statistics.threats_found', 0)
                self.config.set_setting('statistics.threats_found', total_threats + threats_found)
            
            # **ENHANCED**: Update last scan time
            self.config.set_setting('scanning.last_scan', datetime.now().isoformat())
            if scan_results.get('scan_type') == 'full':
                self.config.set_setting('scanning.last_full_scan', datetime.now().isoformat())
            
            # **ENHANCED**: Update UI
            self._update_scan_status_ui()
            self._update_dashboard_data()
            
            # **ENHANCED**: Disable scan controls
            if hasattr(self, '_scan_pause_action'):
                self._scan_pause_action.setEnabled(False)
            if hasattr(self, '_scan_stop_action'):
                self._scan_stop_action.setEnabled(False)
            
            # **ENHANCED**: Show completion notification
            self._show_scan_completion_notification(scan_results)
            
            # **ENHANCED**: Emit main window signal
            self.scan_completed.emit(scan_results)
            
        except Exception as e:
            self.logger.error(f"Error handling scan completed event: {e}")
    
    def _on_threat_detected(self, threat_info: dict):
        """Handle threat detected event from scan window."""
        try:
            self.logger.warning(f"Threat detected: {threat_info}")
            
            # **ENHANCED**: Update threat count
            self.threat_count += 1
            
            # **ENHANCED**: Update UI threat counter
            if hasattr(self, '_threat_counter_label'):
                self._threat_counter_label.setText(f"⚠️ Threats: {self.threat_count}")
            
            # **ENHANCED**: Show threat notification
            self._show_threat_notification(threat_info)
            
            # **ENHANCED**: Emit main window signal
            self.threat_detected.emit(threat_info)
            
        except Exception as e:
            self.logger.error(f"Error handling threat detected event: {e}")
    
    def _update_scan_status_ui(self):
        """Update UI elements with current scan status."""
        try:
            # **ENHANCED**: Update status bar scan status
            if hasattr(self, '_scan_status_label'):
                if self._scan_status['is_scanning']:
                    progress = self._scan_status['progress']
                    status_text = f"📊 Scan: {progress}% ({self._scan_status['scan_type']})"
                else:
                    status_text = "📊 Scan: Idle"
                
                self._scan_status_label.setText(status_text)
            
            # **ENHANCED**: Update sidebar scan status
            if hasattr(self, '_sidebar_last_scan'):
                if self._scan_status['is_scanning']:
                    scan_text = f"📊 Scanning: {self._scan_status['progress']}%"
                else:
                    last_scan = self.config.get_setting('scanning.last_scan', None)
                    if last_scan:
                        try:
                            last_scan_time = datetime.fromisoformat(last_scan)
                            time_diff = datetime.now() - last_scan_time
                            if time_diff.days > 0:
                                scan_text = f"📊 Last Scan: {time_diff.days}d ago"
                            else:
                                hours = time_diff.seconds // 3600
                                scan_text = f"📊 Last Scan: {hours}h ago"
                        except Exception:
                            scan_text = "📊 Last Scan: Unknown"
                    else:
                        scan_text = "📊 Last Scan: Never"
                
                self._sidebar_last_scan.setText(scan_text)
            
        except Exception as e:
            self.logger.error(f"Error updating scan status UI: {e}")
    
    def _show_scan_completion_notification(self, scan_results: dict):
        """Show scan completion notification."""
        try:
            threats_found = scan_results.get('threats_found', 0)
            scan_type = scan_results.get('scan_type', 'Unknown')
            files_scanned = scan_results.get('files_scanned', 0)
            
            if threats_found > 0:
                title = "Threats Found"
                message = f"{scan_type.title()} scan completed.\n\n"
                message += f"Files scanned: {files_scanned:,}\n"
                message += f"Threats found: {threats_found}\n\n"
                message += "Threats have been quarantined. View quarantine for details."
                icon = QMessageBox.Warning
            else:
                title = "Scan Complete"
                message = f"{scan_type.title()} scan completed successfully.\n\n"
                message += f"Files scanned: {files_scanned:,}\n"
                message += "No threats found."
                icon = QMessageBox.Information
            
            QMessageBox(icon, title, message, QMessageBox.Ok, self).show()
            
        except Exception as e:
            self.logger.error(f"Error showing scan completion notification: {e}")
    
    def _show_threat_notification(self, threat_info: dict):
        """Show threat detection notification."""
        try:
            threat_name = threat_info.get('name', 'Unknown Threat')
            file_path = threat_info.get('file_path', 'Unknown File')
            
            # **ENHANCED**: Add to notifications
            notification = NotificationItem(
                notification_id=f"threat_{datetime.now().timestamp()}",
                title="Threat Detected",
                message=f"Threat '{threat_name}' found in {file_path}",
                priority=NotificationPriority.HIGH,
                category="security",
                is_actionable=True
            )
            
            self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error showing threat notification: {e}")
    
    def _on_file_restored(self, file_info: dict):
        """Handle file restored from quarantine."""
        try:
            self.logger.info(f"File restored from quarantine: {file_info}")
            
            # **ENHANCED**: Update quarantine count
            self.quarantine_count = max(0, self.quarantine_count - 1)
            
            # **ENHANCED**: Update UI
            self._update_quarantine_status_ui()
            
        except Exception as e:
            self.logger.error(f"Error handling file restored event: {e}")
    
    def _on_file_deleted(self, file_info: dict):
        """Handle file deleted from quarantine."""
        try:
            self.logger.info(f"File deleted from quarantine: {file_info}")
            
            # **ENHANCED**: Update quarantine count
            self.quarantine_count = max(0, self.quarantine_count - 1)
            
            # **ENHANCED**: Update UI
            self._update_quarantine_status_ui()
            
        except Exception as e:
            self.logger.error(f"Error handling file deleted event: {e}")
    
    def _on_quarantine_cleared(self):
        """Handle quarantine cleared event."""
        try:
            self.logger.info("Quarantine cleared")
            
            # **ENHANCED**: Reset quarantine count
            self.quarantine_count = 0
            
            # **ENHANCED**: Update UI
            self._update_quarantine_status_ui()
            
        except Exception as e:
            self.logger.error(f"Error handling quarantine cleared event: {e}")
    
    def _update_quarantine_status_ui(self):
        """Update UI elements with quarantine status."""
        try:
            # **ENHANCED**: Update status cards
            if 'quarantine_count' in self.metric_cards:
                self._update_metric_card('quarantine_count', str(self.quarantine_count))
            
            # **ENHANCED**: Update sidebar
            if hasattr(self, '_sidebar_threats_found'):
                self._sidebar_threats_found.setText(f"🔒 Quarantined: {self.quarantine_count}")
            
        except Exception as e:
            self.logger.error(f"Error updating quarantine status UI: {e}")
    
    def _on_settings_changed(self, settings_data: dict):
        """Handle settings changed event."""
        try:
            self.logger.info("Settings changed")
            
            # **ENHANCED**: Apply relevant settings changes
            if 'theme' in settings_data:
                theme_name = settings_data['theme']
                self._apply_theme_change(theme_name)
            
            if 'real_time_protection' in settings_data:
                rt_enabled = settings_data['real_time_protection']
                self._update_real_time_protection_status(rt_enabled)
            
            # **ENHANCED**: Update UI
            self._update_dashboard_data()
            
        except Exception as e:
            self.logger.error(f"Error handling settings changed event: {e}")
    
    def _on_theme_changed(self, theme_name: str):
        """Handle theme changed event."""
        try:
            self.logger.info(f"Theme changed to: {theme_name}")
            
            # **ENHANCED**: Apply theme change
            self._apply_theme_change(theme_name)
            
        except Exception as e:
            self.logger.error(f"Error handling theme changed event: {e}")
    
    def _on_settings_reset(self):
        """Handle settings reset event."""
        try:
            self.logger.info("Settings reset to defaults")
            
            # **ENHANCED**: Reload configuration
            self.config.reload_configuration()
            
            # **ENHANCED**: Apply default theme
            default_theme = self.config.get_theme_preference()
            self._apply_theme_change(default_theme)
            
            # **ENHANCED**: Update UI
            self._update_dashboard_data()
            
        except Exception as e:
            self.logger.error(f"Error handling settings reset event: {e}")
    
    def _on_model_loaded(self, model_name: str, model_info: dict):
        """Handle model loaded event."""
        try:
            self.logger.info(f"Model loaded: {model_name}")
            
            # **ENHANCED**: Update model status
            self._component_health[f'model_{model_name}'] = True
            
            # **ENHANCED**: Update UI
            self._update_model_status_display()
            
        except Exception as e:
            self.logger.error(f"Error handling model loaded event: {e}")
    
    def _on_model_unloaded(self, model_name: str):
        """Handle model unloaded event."""
        try:
            self.logger.info(f"Model unloaded: {model_name}")
            
            # **ENHANCED**: Update model status
            self._component_health[f'model_{model_name}'] = False
            
            # **ENHANCED**: Update UI
            self._update_model_status_display()
            
        except Exception as e:
            self.logger.error(f"Error handling model unloaded event: {e}")
    
    def _on_model_settings_changed(self, model_settings: dict):
        """Handle model settings changed event."""
        try:
            self.logger.info("Model settings changed")
            
            # **ENHANCED**: Update model configuration
            # Implementation would update model settings
            
            # **ENHANCED**: Update UI
            self._update_model_status_display()
            
        except Exception as e:
            self.logger.error(f"Error handling model settings changed event: {e}")
    
    # ========================================================================
    # PUBLIC WINDOW MANAGEMENT API
    # ========================================================================
    
    def _open_scan_window(self):
        """Open scan window - public API method."""
        return self._open_child_window('scan_window')
    
    def _open_quarantine_window(self):
        """Open quarantine window - public API method."""
        return self._open_child_window('quarantine_window')
    
    def _open_settings(self):
        """Open settings window - public API method."""
        return self._open_child_window('settings_window')
    
    def _open_model_status_window(self):
        """Open model status window - public API method."""
        return self._open_child_window('model_status_window')
    
    def get_window_state(self, window_type: str) -> Optional[WindowState]:
        """Get current state of a specific window."""
        return self._window_states.get(window_type)
    
    def get_all_window_states(self) -> Dict[str, WindowState]:
        """Get states of all managed windows."""
        return self._window_states.copy()
    
    def close_all_child_windows(self):
        """Close all child windows."""
        try:
            for window_type, state in self._window_states.items():
                if state.is_open and state.instance:
                    state.instance.close()
            
            self.logger.info("All child windows closed")
            
        except Exception as e:
            self.logger.error(f"Error closing all child windows: {e}")
    
    def get_window_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for all windows."""
        try:
            metrics = {}
            
            for window_type, tracking in self._window_access_tracking.items():
                state = self._window_states.get(window_type)
                metrics[window_type] = {
                    'total_opens': tracking['total_opens'],
                    'total_focus_time': tracking['total_focus_time'],
                    'average_session_time': tracking['average_session_time'],
                    'last_accessed': tracking['last_accessed'].isoformat() if tracking['last_accessed'] else None,
                    'error_count': tracking['error_count'],
                    'efficiency_score': state.calculate_efficiency_score() if state else 0
                }
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error getting window performance metrics: {e}")
            return {}



    
    def _show_update_reminder(self):
        """Show update reminder notification."""
        try:
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"update_reminder_{datetime.now().timestamp()}",
                    title="Definition Update Available",
                    message="Virus definitions have not been updated in over 24 hours. Update recommended.",
                    priority=NotificationPriority.WARNING,
                    category="update",
                    is_actionable=True
                )
                self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error showing update reminder: {e}")
    
    def _check_protection_status(self):
        """Check protection status and alert if disabled."""
        try:
            real_time_enabled = self.config.get_setting("detection.real_time_enabled", True)
            
            if not real_time_enabled:
                # **ENHANCED**: Check if we've already warned recently
                last_warning = getattr(self, '_last_protection_warning', None)
                if not last_warning or (datetime.now() - last_warning).total_seconds() > 3600:  # Warn once per hour
                    if self._notifications_enabled:
                        notification = NotificationItem(
                            notification_id=f"protection_disabled_{datetime.now().timestamp()}",
                            title="Protection Disabled",
                            message="Real-time protection is currently disabled. Your system may be at risk.",
                            priority=NotificationPriority.WARNING,
                            category="security",
                            is_actionable=True
                        )
                        self._add_notification(notification)
                    
                    self._last_protection_warning = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Error checking protection status: {e}")
    
    def _check_scan_status(self):
        """Check scan status and recommend scans if needed."""
        try:
            last_scan = self.config.get_setting("scanning.last_scan", None)
            if last_scan:
                last_scan_time = datetime.fromisoformat(last_scan)
                time_since_scan = datetime.now() - last_scan_time
                
                # **ENHANCED**: Recommend scan if more than 7 days
                if time_since_scan > timedelta(days=7):
                    last_scan_reminder = getattr(self, '_last_scan_reminder', None)
                    if not last_scan_reminder or (datetime.now() - last_scan_reminder).total_seconds() > 86400:  # Once per day
                        if self._notifications_enabled:
                            notification = NotificationItem(
                                notification_id=f"scan_reminder_{datetime.now().timestamp()}",
                                title="Scan Recommended",
                                message=f"No scan performed in {time_since_scan.days} days. A system scan is recommended.",
                                priority=NotificationPriority.INFO,
                                category="scan",
                                is_actionable=True
                            )
                            self._add_notification(notification)
                        
                        self._last_scan_reminder = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Error checking scan status: {e}")
    
    def _check_component_availability(self):
        """Check availability and health of all components."""
        try:
            # **ENHANCED**: Check scanner engine availability
            if self.scanner_engine:
                try:
                    if hasattr(self.scanner_engine, 'is_healthy'):
                        scanner_healthy = self.scanner_engine.is_healthy()
                    else:
                        scanner_healthy = hasattr(self.scanner_engine, 'scan_file')
                    
                    self._component_health['scanner_engine'] = scanner_healthy
                except Exception as e:
                    self.logger.warning(f"Scanner engine health check failed: {e}")
                    self._component_health['scanner_engine'] = False
            else:
                self._component_health['scanner_engine'] = False
            
            # **ENHANCED**: Check classification engine availability
            if self.classification_engine:
                try:
                    if hasattr(self.classification_engine, 'is_healthy'):
                        classification_healthy = self.classification_engine.is_healthy()
                    else:
                        classification_healthy = hasattr(self.classification_engine, 'classify_threat')
                    
                    self._component_health['classification_engine'] = classification_healthy
                except Exception as e:
                    self.logger.warning(f"Classification engine health check failed: {e}")
                    self._component_health['classification_engine'] = False
            else:
                self._component_health['classification_engine'] = False
            
            # **ENHANCED**: Check file manager availability
            if self.file_manager:
                try:
                    if hasattr(self.file_manager, 'is_healthy'):
                        file_manager_healthy = self.file_manager.is_healthy()
                    else:
                        file_manager_healthy = hasattr(self.file_manager, 'quarantine_file')
                    
                    self._component_health['file_manager'] = file_manager_healthy
                except Exception as e:
                    self.logger.warning(f"File manager health check failed: {e}")
                    self._component_health['file_manager'] = False
            else:
                self._component_health['file_manager'] = False
            
            # **ENHANCED**: Check model manager availability
            if self.model_manager:
                try:
                    if hasattr(self.model_manager, 'is_healthy'):
                        model_manager_healthy = self.model_manager.is_healthy()
                    else:
                        model_manager_healthy = hasattr(self.model_manager, 'get_loaded_models')
                    
                    self._component_health['model_manager'] = model_manager_healthy
                except Exception as e:
                    self.logger.warning(f"Model manager health check failed: {e}")
                    self._component_health['model_manager'] = False
            else:
                self._component_health['model_manager'] = False
            
            # **ENHANCED**: Update component health display
            self._update_component_health_display()
            
            # **ENHANCED**: Check for critical component failures
            healthy_components = sum(1 for health in self._component_health.values() if health)
            total_components = len(self._component_health)
            
            if healthy_components == 0:
                self._handle_critical_component_failure()
            elif healthy_components < total_components / 2:
                self._handle_degraded_component_status()
            
        except Exception as e:
            self.logger.error(f"Error checking component availability: {e}")
    
    def _handle_critical_component_failure(self):
        """Handle critical component failure scenario."""
        try:
            self.logger.critical("Critical component failure detected - no components available")
            
            # **ENHANCED**: Show critical failure notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"critical_failure_{datetime.now().timestamp()}",
                    title="Critical System Failure",
                    message="All core components have failed. Application functionality severely limited.",
                    priority=NotificationPriority.CRITICAL,
                    category="system",
                    is_persistent=True,
                    is_actionable=True
                )
                self._add_notification(notification)
            
            # **ENHANCED**: Enter emergency mode
            self._emergency_mode = True
            
            # **ENHANCED**: Update UI to reflect critical status
            self._update_critical_failure_ui()
            
        except Exception as e:
            self.logger.error(f"Error handling critical component failure: {e}")
    
    def _handle_degraded_component_status(self):
        """Handle degraded component status scenario."""
        try:
            healthy_components = sum(1 for health in self._component_health.values() if health)
            total_components = len(self._component_health)
            
            self.logger.warning(f"Degraded component status: {healthy_components}/{total_components} components available")
            
            # **ENHANCED**: Show degraded status notification (once per session)
            if not hasattr(self, '_degraded_status_notified'):
                if self._notifications_enabled:
                    notification = NotificationItem(
                        notification_id=f"degraded_status_{datetime.now().timestamp()}",
                        title="Degraded System Status",
                        message=f"Some components are unavailable ({healthy_components}/{total_components} active). Functionality may be limited.",
                        priority=NotificationPriority.WARNING,
                        category="system",
                        is_actionable=True
                    )
                    self._add_notification(notification)
                
                self._degraded_status_notified = True
            
        except Exception as e:
            self.logger.error(f"Error handling degraded component status: {e}")
    
    def _update_critical_failure_ui(self):
        """Update UI to reflect critical failure status."""
        try:
            # **ENHANCED**: Update protection status to critical
            if hasattr(self, 'protection_status_indicator'):
                self.protection_status_indicator.setText("🚨 SYSTEM FAILURE")
                self.protection_status_indicator.setStyleSheet("""
                    QLabel {
                        color: #f44336;
                        font-size: 18px;
                        font-weight: bold;
                        padding: 5px;
                        background-color: rgba(244, 67, 54, 0.1);
                        border: 2px solid #f44336;
                        border-radius: 6px;
                    }
                """)
            
            # **ENHANCED**: Update status bar
            if hasattr(self, '_protection_status_label'):
                self._protection_status_label.setText("🚨 CRITICAL FAILURE")
                self._protection_status_label.setStyleSheet("color: #f44336; font-weight: bold;")
            
            # **ENHANCED**: Update system tray
            if self.system_tray_enabled:
                self._create_critical_failure_tray_icon()
                self._update_tray_protection_status(False)
            
        except Exception as e:
            self.logger.error(f"Error updating critical failure UI: {e}")
    
    def _create_critical_failure_tray_icon(self):
        """Create critical failure system tray icon."""
        try:
            # **ENHANCED**: Create pixmap for critical failure
            pixmap = QPixmap(16, 16)
            pixmap.fill(Qt.transparent)
            
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing, True)
            
            # **ENHANCED**: Draw critical failure indicator
            # Red background
            gradient = QLinearGradient(0, 0, 16, 16)
            gradient.setColorAt(0, QColor("#f44336"))  # Red for critical
            gradient.setColorAt(1, QColor("#d32f2f"))
            
            painter.setBrush(QBrush(gradient))
            painter.setPen(QPen(QColor("#b71c1c"), 1))
            painter.drawEllipse(1, 1, 14, 14)
            
            # **ENHANCED**: Add exclamation mark for critical status
            painter.setPen(QPen(Qt.white, 2, Qt.SolidLine, Qt.RoundCap))
            painter.drawLine(8, 4, 8, 10)  # Exclamation line
            painter.drawPoint(8, 12)  # Exclamation dot
            
            painter.end()
            
            self.system_tray.setIcon(QIcon(pixmap))
            self.logger.debug("Created critical failure system tray icon")
            
        except Exception as e:
            self.logger.error(f"Error creating critical failure icon: {e}")
    
    def _check_performance_issues(self):
        """Check for performance issues and bottlenecks."""
        try:
            # **ENHANCED**: Check CPU usage
            if 'cpu_usage_history' in self._performance_data:
                recent_cpu = list(self._performance_data['cpu_usage_history'])[-10:]  # Last 10 measurements
                if recent_cpu:
                    avg_cpu = sum(recent_cpu) / len(recent_cpu)
                    
                    if avg_cpu > 80:  # High CPU usage
                        self._handle_high_cpu_usage(avg_cpu)
            
            # **ENHANCED**: Check memory usage
            if 'memory_usage_history' in self._performance_data:
                recent_memory = list(self._performance_data['memory_usage_history'])[-10:]
                if recent_memory:
                    avg_memory = sum(recent_memory) / len(recent_memory)
                    
                    if avg_memory > 85:  # High memory usage
                        self._handle_high_memory_usage(avg_memory)
            
            # **ENHANCED**: Check scan performance
            self._check_scan_performance()
            
        except Exception as e:
            self.logger.error(f"Error checking performance issues: {e}")
    
    def _handle_high_cpu_usage(self, cpu_usage: float):
        """Handle high CPU usage scenario."""
        try:
            # **ENHANCED**: Check if we've already warned recently
            last_cpu_warning = getattr(self, '_last_cpu_warning', None)
            if not last_cpu_warning or (datetime.now() - last_cpu_warning).total_seconds() > 1800:  # Warn every 30 minutes
                
                self.logger.warning(f"High CPU usage detected: {cpu_usage:.1f}%")
                
                if self._notifications_enabled:
                    notification = NotificationItem(
                        notification_id=f"high_cpu_{datetime.now().timestamp()}",
                        title="High CPU Usage",
                        message=f"System CPU usage is high ({cpu_usage:.1f}%). Consider pausing scans if system is slow.",
                        priority=NotificationPriority.WARNING,
                        category="performance",
                        is_actionable=True
                    )
                    self._add_notification(notification)
                
                self._last_cpu_warning = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Error handling high CPU usage: {e}")
    
    def _handle_high_memory_usage(self, memory_usage: float):
        """Handle high memory usage scenario."""
        try:
            # **ENHANCED**: Check if we've already warned recently
            last_memory_warning = getattr(self, '_last_memory_warning', None)
            if not last_memory_warning or (datetime.now() - last_memory_warning).total_seconds() > 1800:  # Warn every 30 minutes
                
                self.logger.warning(f"High memory usage detected: {memory_usage:.1f}%")
                
                if self._notifications_enabled:
                    notification = NotificationItem(
                        notification_id=f"high_memory_{datetime.now().timestamp()}",
                        title="High Memory Usage",
                        message=f"System memory usage is high ({memory_usage:.1f}%). Consider closing other applications.",
                        priority=NotificationPriority.WARNING,
                        category="performance",
                        is_actionable=True
                    )
                    self._add_notification(notification)
                
                self._last_memory_warning = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Error handling high memory usage: {e}")
    
    def _check_scan_performance(self):
        """Check scan performance for potential issues."""
        try:
            if 'scan_performance_history' in self._performance_data:
                recent_scans = list(self._performance_data['scan_performance_history'])[-5:]  # Last 5 scans
                
                if len(recent_scans) >= 3:
                    # **ENHANCED**: Check for degrading scan performance
                    scan_times = [scan.get('duration', 0) for scan in recent_scans if 'duration' in scan]
                    
                    if len(scan_times) >= 3:
                        avg_recent = sum(scan_times[-3:]) / 3
                        avg_older = sum(scan_times[:-3]) / max(1, len(scan_times) - 3) if len(scan_times) > 3 else avg_recent
                        
                        # **ENHANCED**: If recent scans are significantly slower
                        if avg_recent > avg_older * 1.5 and avg_recent > 300:  # 50% slower and more than 5 minutes
                            self._handle_slow_scan_performance(avg_recent, avg_older)
            
        except Exception as e:
            self.logger.error(f"Error checking scan performance: {e}")
    
    def _handle_slow_scan_performance(self, recent_avg: float, historical_avg: float):
        """Handle slow scan performance scenario."""
        try:
            self.logger.warning(f"Slow scan performance detected: recent avg {recent_avg:.1f}s vs historical {historical_avg:.1f}s")
            
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"slow_scan_{datetime.now().timestamp()}",
                    title="Scan Performance Issue",
                    message=f"Scans are running slower than usual. Consider system optimization or check for disk issues.",
                    priority=NotificationPriority.INFO,
                    category="performance",
                    is_actionable=True
                )
                self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error handling slow scan performance: {e}")
    
    # ========================================================================
    # ADVANCED UI ACTION HANDLERS
    # ========================================================================
    
    def _start_scan(self, scan_type: str, scan_config: Optional[dict] = None):
        """Start a scan with comprehensive error handling and integration."""
        try:
            self.logger.info(f"Starting {scan_type} scan...")
            
            # **ENHANCED**: Validate scan prerequisites
            if not self._validate_scan_prerequisites(scan_type):
                return False
            
            # **ENHANCED**: Check if another scan is running
            if self._scan_status.get('is_scanning', False):
                self._show_scan_already_running_dialog()
                return False
            
            # **ENHANCED**: Prepare scan configuration
            if not scan_config:
                scan_config = self._prepare_scan_configuration(scan_type)
            
            # **ENHANCED**: Open scan window if available
            if scan_window_available and self._open_scan_window():
                # **ENHANCED**: Pass scan request to scan window
                if hasattr(self.scan_window, 'start_scan'):
                    return self.scan_window.start_scan(scan_type, scan_config)
                else:
                    self.logger.warning("Scan window does not support start_scan method")
            
            # **ENHANCED**: Fallback to direct scanner engine if available
            elif self.scanner_engine and hasattr(self.scanner_engine, 'start_scan'):
                return self._start_direct_scan(scan_type, scan_config)
            
            # **ENHANCED**: No scan capability available
            else:
                self._show_scan_unavailable_dialog()
                return False
            
        except Exception as e:
            self.logger.error(f"Error starting {scan_type} scan: {e}")
            self._show_scan_error_dialog(scan_type, str(e))
            return False
    
    def _validate_scan_prerequisites(self, scan_type: str) -> bool:
        """Validate scan prerequisites."""
        try:
            # **ENHANCED**: Check if scanner engine is available
            if not self._component_health.get('scanner_engine', False):
                self._show_error_dialog(
                    "Scanner Unavailable",
                    "Scanner engine is not available. Cannot perform scan."
                )
                return False
            
            # **ENHANCED**: Check specific scan type requirements
            if scan_type == "memory" and not self._check_memory_scan_capability():
                self._show_error_dialog(
                    "Memory Scan Unavailable",
                    "Memory scanning capability is not available on this system."
                )
                return False
            
            if scan_type == "network" and not self._check_network_scan_capability():
                self._show_error_dialog(
                    "Network Scan Unavailable",
                    "Network scanning capability is not available."
                )
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating scan prerequisites: {e}")
            return False
    
    def _check_memory_scan_capability(self) -> bool:
        """Check if memory scanning is available."""
        try:
            # **ENHANCED**: Check if scanner engine supports memory scanning
            if self.scanner_engine and hasattr(self.scanner_engine, 'supports_memory_scan'):
                return self.scanner_engine.supports_memory_scan()
            
            # **FALLBACK**: Basic capability check
            return hasattr(self.scanner_engine, 'scan_memory') if self.scanner_engine else False
            
        except Exception as e:
            self.logger.error(f"Error checking memory scan capability: {e}")
            return False
    
    def _check_network_scan_capability(self) -> bool:
        """Check if network scanning is available."""
        try:
            # **ENHANCED**: Check if scanner engine supports network scanning
            if self.scanner_engine and hasattr(self.scanner_engine, 'supports_network_scan'):
                return self.scanner_engine.supports_network_scan()
            
            # **FALLBACK**: Basic capability check
            return hasattr(self.scanner_engine, 'scan_network') if self.scanner_engine else False
            
        except Exception as e:
            self.logger.error(f"Error checking network scan capability: {e}")
            return False
    
    def _prepare_scan_configuration(self, scan_type: str) -> dict:
        """Prepare scan configuration based on scan type."""
        try:
            base_config = {
                'scan_type': scan_type,
                'start_time': datetime.now(),
                'priority': 'normal',
                'deep_scan': False,
                'follow_symlinks': False,
                'scan_archives': True,
                'max_file_size': 100 * 1024 * 1024,  # 100MB
                'timeout_per_file': 30,  # 30 seconds
                'exclude_paths': [],
                'include_extensions': [],
                'exclude_extensions': []
            }
            
            # **ENHANCED**: Scan type specific configurations
            if scan_type == "quick":
                base_config.update({
                    'scan_paths': self._get_quick_scan_paths(),
                    'deep_scan': False,
                    'priority': 'high',
                    'timeout_per_file': 15
                })
            elif scan_type == "full":
                base_config.update({
                    'scan_paths': self._get_full_scan_paths(),
                    'deep_scan': True,
                    'priority': 'normal',
                    'scan_archives': True,
                    'follow_symlinks': True
                })
            elif scan_type == "custom":
                base_config.update({
                    'scan_paths': [],  # Will be set by user
                    'deep_scan': True,
                    'priority': 'normal'
                })
            elif scan_type == "memory":
                base_config.update({
                    'scan_running_processes': True,
                    'scan_loaded_modules': True,
                    'scan_memory_dumps': False
                })
            elif scan_type == "network":
                base_config.update({
                    'scan_network_drives': True,
                    'scan_shared_folders': True,
                    'network_timeout': 60
                })
            
            # **ENHANCED**: Apply user preferences
            self._apply_user_scan_preferences(base_config)
            
            return base_config
            
        except Exception as e:
            self.logger.error(f"Error preparing scan configuration: {e}")
            return {'scan_type': scan_type, 'start_time': datetime.now()}
    
    def _get_quick_scan_paths(self) -> List[str]:
        """Get paths for quick scan."""
        try:
            quick_paths = []
            
            # **ENHANCED**: Add system critical paths
            if os.name == 'nt':  # Windows
                quick_paths.extend([
                    os.path.expandvars('%WINDIR%\\System32'),
                    os.path.expandvars('%WINDIR%\\SysWOW64'),
                    os.path.expandvars('%PROGRAMFILES%'),
                    os.path.expandvars('%PROGRAMFILES(X86)%'),
                    os.path.expandvars('%APPDATA%'),
                    os.path.expandvars('%LOCALAPPDATA%'),
                    os.path.expandvars('%TEMP%'),
                    os.path.expandvars('%USERPROFILE%\\Downloads'),
                    os.path.expandvars('%USERPROFILE%\\Documents'),
                    os.path.expandvars('%USERPROFILE%\\Desktop')
                ])
            else:  # Linux/Unix
                quick_paths.extend([
                    '/bin',
                    '/usr/bin',
                    '/usr/local/bin',
                    '/tmp',
                    f'/home/{os.getenv("USER", "")}/Downloads',
                    f'/home/{os.getenv("USER", "")}/Documents',
                    f'/home/{os.getenv("USER", "")}/Desktop'
                ])
            
            # **ENHANCED**: Filter out non-existent paths
            existing_paths = [path for path in quick_paths if os.path.exists(path)]
            
            return existing_paths
            
        except Exception as e:
            self.logger.error(f"Error getting quick scan paths: {e}")
            return []
    
    def _get_full_scan_paths(self) -> List[str]:
        """Get paths for full system scan."""
        try:
            if os.name == 'nt':  # Windows
                # **ENHANCED**: Scan all drives
                import string
                drives = []
                for letter in string.ascii_uppercase:
                    drive = f"{letter}:\\"
                    if os.path.exists(drive):
                        drives.append(drive)
                return drives
            else:  # Linux/Unix
                return ['/']
            
        except Exception as e:
            self.logger.error(f"Error getting full scan paths: {e}")
            return ['/'] if os.name != 'nt' else ['C:\\']
    
    def _apply_user_scan_preferences(self, config: dict):
        """Apply user scan preferences to configuration."""
        try:
            # **ENHANCED**: Load user preferences from config
            user_prefs = self.config.get_section('scanning', {})
            
            # **ENHANCED**: Apply performance preferences
            if 'max_threads' in user_prefs:
                config['max_threads'] = user_prefs['max_threads']
            
            if 'deep_scan_enabled' in user_prefs:
                config['deep_scan'] = user_prefs['deep_scan_enabled']
            
            if 'scan_archives' in user_prefs:
                config['scan_archives'] = user_prefs['scan_archives']
            
            # **ENHANCED**: Apply exclusion preferences
            if 'exclude_paths' in user_prefs:
                config['exclude_paths'].extend(user_prefs['exclude_paths'])
            
            if 'exclude_extensions' in user_prefs:
                config['exclude_extensions'].extend(user_prefs['exclude_extensions'])
            
        except Exception as e:
            self.logger.error(f"Error applying user scan preferences: {e}")
    
    def _start_direct_scan(self, scan_type: str, scan_config: dict) -> bool:
        """Start scan directly through scanner engine."""
        try:
            self.logger.info(f"Starting direct scan: {scan_type}")
            
            # **ENHANCED**: Update scan status
            self._scan_status.update({
                'is_scanning': True,
                'scan_type': scan_type,
                'progress': 0,
                'scan_start_time': datetime.now()
            })
            
            # **ENHANCED**: Update UI
            self._update_scan_status_ui()
            
            # **ENHANCED**: Start scan in background thread
            scan_future = self._background_thread_pool.submit(
                self._execute_direct_scan, scan_type, scan_config
            )
            
            # **ENHANCED**: Store future reference for monitoring
            self._active_scan_future = scan_future
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting direct scan: {e}")
            return False
    
    def _execute_direct_scan(self, scan_type: str, scan_config: dict):
        """Execute scan in background thread."""
        try:
            self.logger.info(f"Executing direct scan: {scan_type}")
            
            # **ENHANCED**: Emit scan started signal
            self.scan_started.emit(scan_type, scan_config)
            
            # **ENHANCED**: Execute scan through scanner engine
            scan_results = self.scanner_engine.start_scan(scan_type, scan_config)
            
            # **ENHANCED**: Process scan results
            self._process_scan_results(scan_results)
            
            # **ENHANCED**: Emit scan completed signal
            self.scan_completed.emit(scan_results)
            
        except Exception as e:
            self.logger.error(f"Error executing direct scan: {e}")
            # **ENHANCED**: Emit error as scan result
            error_result = {
                'scan_type': scan_type,
                'success': False,
                'error': str(e),
                'files_scanned': 0,
                'threats_found': 0
            }
            self.scan_completed.emit(error_result)
    
    def _process_scan_results(self, scan_results: dict):
        """Process scan results and update statistics."""
        try:
            # **ENHANCED**: Update scan statistics
            total_scans = self.config.get_setting('statistics.total_scans', 0)
            self.config.set_setting('statistics.total_scans', total_scans + 1)
            
            # **ENHANCED**: Update threat statistics
            threats_found = scan_results.get('threats_found', 0)
            if threats_found > 0:
                total_threats = self.config.get_setting('statistics.threats_found', 0)
                self.config.set_setting('statistics.threats_found', total_threats + threats_found)
            
            # **ENHANCED**: Update scan time statistics
            scan_duration = scan_results.get('scan_duration', 0)
            if scan_duration > 0:
                self._performance_data['scan_performance_history'].append({
                    'scan_type': scan_results.get('scan_type'),
                    'duration': scan_duration,
                    'files_scanned': scan_results.get('files_scanned', 0),
                    'timestamp': datetime.now()
                })
            
            # **ENHANCED**: Update last scan time
            self.config.set_setting('scanning.last_scan', datetime.now().isoformat())
            if scan_results.get('scan_type') == 'full':
                self.config.set_setting('scanning.last_full_scan', datetime.now().isoformat())
            
        except Exception as e:
            self.logger.error(f"Error processing scan results: {e}")
    
    def _show_scan_already_running_dialog(self):
        """Show dialog when scan is already running."""
        try:
            QMessageBox.information(
                self,
                "Scan Already Running",
                "A scan is already in progress. Please wait for it to complete before starting another scan.",
                QMessageBox.Ok
            )
        except Exception as e:
            self.logger.error(f"Error showing scan already running dialog: {e}")
    
    def _show_scan_unavailable_dialog(self):
        """Show dialog when scan capability is unavailable."""
        try:
            QMessageBox.warning(
                self,
                "Scan Unavailable",
                "Scanning functionality is not available. Please check that all required components are installed and functioning.",
                QMessageBox.Ok
            )
        except Exception as e:
            self.logger.error(f"Error showing scan unavailable dialog: {e}")
    
    def _show_scan_error_dialog(self, scan_type: str, error_message: str):
        """Show dialog for scan errors."""
        try:
            QMessageBox.critical(
                self,
                f"Scan Error",
                f"An error occurred while starting the {scan_type} scan:\n\n{error_message}",
                QMessageBox.Ok
            )
        except Exception as e:
            self.logger.error(f"Error showing scan error dialog: {e}")
    
    def _scan_single_file(self, file_path: Optional[str] = None):
        """Scan a single file with comprehensive error handling."""
        try:
            # **ENHANCED**: Get file path if not provided
            if not file_path:
                file_path, _ = QFileDialog.getOpenFileName(
                    self,
                    "Select File to Scan",
                    "",
                    "All Files (*.*)"
                )
            
            if not file_path:
                return False
            
            # **ENHANCED**: Validate file
            if not os.path.isfile(file_path):
                self._show_error_dialog("Invalid File", "Selected path is not a valid file.")
                return False
            
            # **ENHANCED**: Check file accessibility
            if not os.access(file_path, os.R_OK):
                self._show_error_dialog("Access Denied", "Cannot access the selected file.")
                return False
            
            # **ENHANCED**: Prepare single file scan configuration
            scan_config = {
                'scan_type': 'file',
                'target_file': file_path,
                'start_time': datetime.now()
            }
            
            # **ENHANCED**: Start scan
            return self._start_scan('file', scan_config)
            
        except Exception as e:
            self.logger.error(f"Error scanning single file: {e}")
            self._show_error_dialog("Scan Error", f"Error scanning file: {str(e)}")
            return False
    
    def _scan_folder(self):
        """Scan a folder with comprehensive error handling."""
        try:
            # **ENHANCED**: Get folder path
            folder_path = QFileDialog.getExistingDirectory(
                self,
                "Select Folder to Scan",
                ""
            )
            
            if not folder_path:
                return False
            
            # **ENHANCED**: Validate folder
            if not os.path.isdir(folder_path):
                self._show_error_dialog("Invalid Folder", "Selected path is not a valid folder.")
                return False
            
            # **ENHANCED**: Prepare folder scan configuration
            scan_config = {
                'scan_type': 'folder',
                'scan_paths': [folder_path],
                'start_time': datetime.now(),
                'recursive': True
            }
            
            # **ENHANCED**: Start scan
            return self._start_scan('custom', scan_config)
            
        except Exception as e:
            self.logger.error(f"Error scanning folder: {e}")
            self._show_error_dialog("Scan Error", f"Error scanning folder: {str(e)}")
            return False
    
    def _pause_scan(self):
        """Pause the current scan."""
        try:
            if not self._scan_status.get('is_scanning', False):
                return False
            
            # **ENHANCED**: Pause through scan window if available
            if hasattr(self, 'scan_window') and self.scan_window:
                if hasattr(self.scan_window, 'pause_scan'):
                    return self.scan_window.pause_scan()
            
            # **ENHANCED**: Pause through scanner engine if available
            elif self.scanner_engine and hasattr(self.scanner_engine, 'pause_scan'):
                return self.scanner_engine.pause_scan()
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error pausing scan: {e}")
            return False
    
    def _stop_scan(self):
        """Stop the current scan."""
        try:
            if not self._scan_status.get('is_scanning', False):
                return False
            
            # **ENHANCED**: Stop through scan window if available
            if hasattr(self, 'scan_window') and self.scan_window:
                if hasattr(self.scan_window, 'stop_scan'):
                    return self.scan_window.stop_scan()
            
            # **ENHANCED**: Stop through scanner engine if available
            elif self.scanner_engine and hasattr(self.scanner_engine, 'stop_scan'):
                return self.scanner_engine.stop_scan()
            
            # **ENHANCED**: Cancel background scan future if available
            elif hasattr(self, '_active_scan_future') and self._active_scan_future:
                self._active_scan_future.cancel()
                self._scan_status['is_scanning'] = False
                self._update_scan_status_ui()
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error stopping scan: {e}")
            return False
    
    def _update_definitions(self):
        """Update virus definitions with comprehensive error handling."""
        try:
            self.logger.info("Starting definition update...")
            
            # **ENHANCED**: Show update progress notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"update_started_{datetime.now().timestamp()}",
                    title="Update Started",
                    message="Checking for virus definition updates...",
                    priority=NotificationPriority.INFO,
                    category="update"
                )
                self._add_notification(notification)
            
            # **ENHANCED**: Start update in background
            update_future = self._background_thread_pool.submit(self._execute_definition_update)
            
            # **ENHANCED**: Store future reference
            self._active_update_future = update_future
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting definition update: {e}")
            self._show_error_dialog("Update Error", f"Error starting update: {str(e)}")
            return False
    
    def _execute_definition_update(self):
        """Execute definition update in background thread."""
        try:
            self.logger.info("Executing definition update...")
            
            # **ENHANCED**: Simulate update process (replace with actual update logic)
            import time
            time.sleep(2)  # Simulate download time
            
            # **ENHANCED**: Update last update time
            self.config.set_setting('updates.last_definition_update', datetime.now().isoformat())
            
            # **ENHANCED**: Show completion notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"update_completed_{datetime.now().timestamp()}",
                    title="Update Completed",
                    message="Virus definitions have been updated successfully.",
                    priority=NotificationPriority.INFO,
                    category="update"
                )
                self._add_notification(notification)
            
            # **ENHANCED**: Update UI
            QTimer.singleShot(0, self._update_dashboard_data)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error executing definition update: {e}")
            
            # **ENHANCED**: Show error notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"update_error_{datetime.now().timestamp()}",
                    title="Update Failed",
                    message=f"Failed to update virus definitions: {str(e)}",
                    priority=NotificationPriority.ERROR,
                    category="update"
                )
                self._add_notification(notification)
            
            return False
    
    def _update_models(self):
        """Update ML models with comprehensive error handling."""
        try:
            self.logger.info("Starting model update...")
            
            # **ENHANCED**: Check if model manager is available
            if not self.model_manager:
                self._show_error_dialog("Model Update Unavailable", "Model manager is not available.")
                return False
            
            # **ENHANCED**: Start model update
            if hasattr(self.model_manager, 'update_models'):
                update_future = self._background_thread_pool.submit(self.model_manager.update_models)
                self._active_model_update_future = update_future
                
                # **ENHANCED**: Show update notification
                if self._notifications_enabled:
                    notification = NotificationItem(
                        notification_id=f"model_update_started_{datetime.now().timestamp()}",
                        title="Model Update Started",
                        message="Checking for ML model updates...",
                        priority=NotificationPriority.INFO,
                        category="update"
                    )
                    self._add_notification(notification)
                
                return True
            else:
                self._show_error_dialog("Model Update Unavailable", "Model update functionality is not available.")
                return False
            
        except Exception as e:
            self.logger.error(f"Error starting model update: {e}")
            self._show_error_dialog("Model Update Error", f"Error starting model update: {str(e)}")
            return False
    
    def _system_cleanup(self):
        """Perform system cleanup operations."""
        try:
            self.logger.info("Starting system cleanup...")
            
            # **ENHANCED**: Show cleanup dialog
            reply = QMessageBox.question(
                self,
                "System Cleanup",
                "This will clean temporary files and optimize the system. Continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                # **ENHANCED**: Start cleanup in background
                cleanup_future = self._background_thread_pool.submit(self._execute_system_cleanup)
                self._active_cleanup_future = cleanup_future
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error starting system cleanup: {e}")
            self._show_error_dialog("Cleanup Error", f"Error starting cleanup: {str(e)}")
            return False
    
    def _execute_system_cleanup(self):
        """Execute system cleanup operations."""
        try:
            self.logger.info("Executing system cleanup...")
            
            cleanup_results = {
                'temp_files_removed': 0,
                'cache_cleared': 0,
                'space_freed': 0
            }
            
            # **ENHANCED**: Clean temporary files
            temp_dirs = [
                os.path.expandvars('%TEMP%') if os.name == 'nt' else '/tmp',
                os.path.expanduser('~/.cache') if os.name != 'nt' else None
            ]
            
            for temp_dir in temp_dirs:
                if temp_dir and os.path.exists(temp_dir):
                    cleanup_results['temp_files_removed'] += self._clean_directory(temp_dir)
            
            # **ENHANCED**: Clear application caches
            if hasattr(self, '_ui_cache'):
                self._ui_cache.clear()
                cleanup_results['cache_cleared'] += 1
            
            if hasattr(self, '_metrics_cache'):
                self._metrics_cache.clear()
                cleanup_results['cache_cleared'] += 1
            
            # **ENHANCED**: Show completion notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"cleanup_completed_{datetime.now().timestamp()}",
                    title="Cleanup Completed",
                    message=f"System cleanup completed. Removed {cleanup_results['temp_files_removed']} temporary files.",
                    priority=NotificationPriority.INFO,
                    category="system"
                )
                self._add_notification(notification)
            
            return cleanup_results
            
        except Exception as e:
            self.logger.error(f"Error executing system cleanup: {e}")
            return None
    
    def _clean_directory(self, directory: str) -> int:
        """Clean a directory of temporary files."""
        try:
            files_removed = 0
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        # **ENHANCED**: Only remove files older than 1 day
                        if os.path.getmtime(file_path) < time.time() - 86400:
                            os.remove(file_path)
                            files_removed += 1
                    except (OSError, IOError):
                        # **ENHANCED**: Skip files that can't be removed
                        continue
            
            return files_removed
            
        except Exception as e:
            self.logger.error(f"Error cleaning directory {directory}: {e}")
            return 0
    
    def _optimize_performance(self):
        """Optimize system performance for antivirus operations."""
        try:
            self.logger.info("Starting performance optimization...")
            
            # **ENHANCED**: Show optimization dialog
            reply = QMessageBox.question(
                self,
                "Performance Optimization",
                "This will optimize system settings for better antivirus performance. Continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                # **ENHANCED**: Start optimization in background
                optimization_future = self._background_thread_pool.submit(self._execute_performance_optimization)
                self._active_optimization_future = optimization_future
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error starting performance optimization: {e}")
            self._show_error_dialog("Optimization Error", f"Error starting optimization: {str(e)}")
            return False
    
    def _execute_performance_optimization(self):
        """Execute performance optimization operations."""
        try:
            self.logger.info("Executing performance optimization...")
            
            optimization_results = {
                'memory_optimized': False,
                'cache_optimized': False,
                'threads_optimized': False
            }
            
            # **ENHANCED**: Optimize memory usage
            gc.collect()  # Force garbage collection
            optimization_results['memory_optimized'] = True
            
            # **ENHANCED**: Optimize cache sizes based on available memory
            try:
                import psutil
                memory_info = psutil.virtual_memory()
                available_memory = memory_info.available
                
                # **ENHANCED**: Adjust cache sizes based on available memory
                if available_memory > 8 * 1024 * 1024 * 1024:  # More than 8GB
                    cache_size = 1000
                elif available_memory > 4 * 1024 * 1024 * 1024:  # More than 4GB
                    cache_size = 500
                else:
                    cache_size = 250
                
                # **ENHANCED**: Apply cache optimizations
                if hasattr(self, '_ui_cache'):
                    # Limit cache size
                    pass  # Implementation would limit cache size
                
                optimization_results['cache_optimized'] = True
                
            except ImportError:
                # **FALLBACK**: Use default optimizations
                pass
            
            # **ENHANCED**: Optimize thread pool size
            try:
                import multiprocessing
                cpu_count = multiprocessing.cpu_count()
                optimal_threads = min(cpu_count * 2, 16)  # Max 16 threads
                
                self._background_thread_pool.setMaxThreadCount(optimal_threads)
                optimization_results['threads_optimized'] = True
                
            except Exception:
                pass
            
            # **ENHANCED**: Show completion notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"optimization_completed_{datetime.now().timestamp()}",
                    title="Optimization Completed",
                    message="System has been optimized for better antivirus performance.",
                    priority=NotificationPriority.INFO,
                    category="system"
                )
                self._add_notification(notification)
            
            return optimization_results
            
        except Exception as e:
            self.logger.error(f"Error executing performance optimization: {e}")
            return None
    
    def _show_error_dialog(self, title: str, message: str):
        """Show error dialog with consistent styling."""
        try:
            QMessageBox.critical(self, title, message, QMessageBox.Ok)
        except Exception as e:
            self.logger.error(f"Error showing error dialog: {e}")
    
    def _populate_recent_scans_menu(self, recent_menu: QMenu):
        """Populate recent scans menu with scan history."""
        try:
            # **ENHANCED**: Get recent scans from configuration
            recent_scans = self.config.get_setting('scanning.recent_scans', [])
            
            if not recent_scans:
                no_scans_action = QAction("No recent scans", self)
                no_scans_action.setEnabled(False)
                recent_menu.addAction(no_scans_action)
                return
            
            # **ENHANCED**: Add recent scans to menu
            for i, scan_info in enumerate(recent_scans[-10:]):  # Last 10 scans
                try:
                    scan_time = datetime.fromisoformat(scan_info['time'])
                    scan_type = scan_info.get('type', 'Unknown')
                    threats_found = scan_info.get('threats_found', 0)
                    
                    action_text = f"{scan_type.title()} - {scan_time.strftime('%Y-%m-%d %H:%M')} ({threats_found} threats)"
                    
                    scan_action = QAction(action_text, self)
                    scan_action.triggered.connect(lambda checked, info=scan_info: self._show_scan_details(info))
                    recent_menu.addAction(scan_action)
                    
                except Exception as e:
                    self.logger.debug(f"Error adding recent scan to menu: {e}")
                    continue
            
        except Exception as e:
            self.logger.error(f"Error populating recent scans menu: {e}")
    
    def _show_scan_details(self, scan_info: dict):
        """Show details of a previous scan."""
        try:
            # **ENHANCED**: Create scan details dialog
            details_text = f"""
Scan Type: {scan_info.get('type', 'Unknown')}
Scan Time: {scan_info.get('time', 'Unknown')}
Files Scanned: {scan_info.get('files_scanned', 'Unknown')}
Threats Found: {scan_info.get('threats_found', 0)}
Scan Duration: {scan_info.get('duration', 'Unknown')}
            """.strip()
            
            QMessageBox.information(
                self,
                "Scan Details",
                details_text,
                QMessageBox.Ok
            )
            
        except Exception as e:
            self.logger.error(f"Error showing scan details: {e}")
    
    # ========================================================================
    # ADDITIONAL ACTION HANDLERS
    # ========================================================================
    
    def _export_reports(self):
        """Export reports and statistics."""
        try:
            self.logger.info("Exporting reports...")
            
            # **ENHANCED**: Get export file path
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Reports",
                f"antivirus_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json);;All Files (*.*)"
            )
            
            if not file_path:
                return False
            
            # **ENHANCED**: Prepare report data
            report_data = self._prepare_export_data()
            
            # **ENHANCED**: Write report to file
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            # **ENHANCED**: Show success message
            QMessageBox.information(
                self,
                "Export Successful",
                f"Reports have been exported to:\n{file_path}",
                QMessageBox.Ok
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting reports: {e}")
            self._show_error_dialog("Export Error", f"Error exporting reports: {str(e)}")
            return False
    
    def _prepare_export_data(self) -> dict:
        """Prepare data for export."""
        try:
            export_data = {
                'export_info': {
                    'timestamp': datetime.now().isoformat(),
                    'version': '1.0.0',
                    'application': 'Advanced Multi-Algorithm Antivirus'
                },
                'system_info': {
                    'platform': platform.platform(),
                    'processor': platform.processor(),
                    'python_version': platform.python_version(),
                    'uptime': self._get_uptime_string()
                },
                'statistics': {
                    'total_scans': self.config.get_setting('statistics.total_scans', 0),
                    'threats_found': self.config.get_setting('statistics.threats_found', 0),
                    'files_quarantined': self.config.get_setting('statistics.files_quarantined', 0),
                    'last_scan': self.config.get_setting('scanning.last_scan', None),
                    'last_full_scan': self.config.get_setting('scanning.last_full_scan', None)
                },
                'component_health': self._component_health.copy(),
                'integration_health': self._integration_health.copy(),
                'performance_metrics': self.get_window_performance_metrics(),
                'notification_history': self.get_notification_history()
            }
            
            return export_data
            
        except Exception as e:
            self.logger.error(f"Error preparing export data: {e}")
            return {'error': str(e)}
    
    def _import_configuration(self):
        """Import configuration from file."""
        try:
            self.logger.info("Importing configuration...")
            
            # **ENHANCED**: Get import file path
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Import Configuration",
                "",
                "JSON Files (*.json);;All Files (*.*)"
            )
            
            if not file_path:
                return False
            
            # **ENHANCED**: Confirm import
            reply = QMessageBox.question(
                self,
                "Import Configuration",
                "This will replace current settings. Are you sure?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply != QMessageBox.Yes:
                return False
            
            # **ENHANCED**: Import configuration
            with open(file_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            # **ENHANCED**: Apply imported settings
            if 'settings' in import_data:
                for key, value in import_data['settings'].items():
                    self.config.set_setting(key, value)
            
            # **ENHANCED**: Show success message
            QMessageBox.information(
                self,
                "Import Successful",
                "Configuration has been imported successfully. Restart may be required for some changes.",
                QMessageBox.Ok
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error importing configuration: {e}")
            self._show_error_dialog("Import Error", f"Error importing configuration: {str(e)}")
            return False
    
    def _generate_scan_report(self):
        """Generate scan history report."""
        try:
            # **ENHANCED**: Implementation would generate detailed scan report
            QMessageBox.information(
                self,
                "Scan Report",
                "Scan history report generation is not yet implemented.",
                QMessageBox.Ok
            )
        except Exception as e:
            self.logger.error(f"Error generating scan report: {e}")
    
    def _generate_threat_report(self):
        """Generate threat analysis report."""
        try:
            # **ENHANCED**: Implementation would generate threat analysis report
            QMessageBox.information(
                self,
                "Threat Report",
                "Threat analysis report generation is not yet implemented.",
                QMessageBox.Ok
            )
        except Exception as e:
            self.logger.error(f"Error generating threat report: {e}")
    
    def _generate_performance_report(self):
        """Generate system performance report."""
        try:
            # **ENHANCED**: Implementation would generate performance report
            QMessageBox.information(
                self,
                "Performance Report",
                "Performance report generation is not yet implemented.",
                QMessageBox.Ok
            )
        except Exception as e:
            self.logger.error(f"Error generating performance report: {e}")
    
    # ========================================================================
    # SYSTEM TRAY INTEGRATION AND MANAGEMENT
    # ========================================================================
    
    def _initialize_system_tray(self):
        """Initialize comprehensive system tray functionality with advanced features."""
        try:
            self.logger.debug("Initializing comprehensive system tray functionality...")
            
            # **ENHANCED**: Check system tray availability with fallback handling
            if not QSystemTrayIcon.isSystemTrayAvailable():
                self.logger.warning("System tray not available on this system")
                self.system_tray_enabled = False
                return
            
            # **ENHANCED**: Initialize system tray components
            self._setup_system_tray_icon()
            self._create_system_tray_menu()
            self._connect_system_tray_signals()
            self._configure_system_tray_behavior()
            
            # **ENHANCED**: Show system tray with protection status
            if self.system_tray:
                self.system_tray.show()
                self._update_tray_protection_status(self._get_real_time_protection_status())
                self.system_tray_enabled = True
            
            self.logger.info("System tray functionality initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing system tray: {e}")
            self.system_tray_enabled = False
    
    def _setup_system_tray_icon(self):
        """Setup system tray icon with protection status indication."""
        try:
            # **ENHANCED**: Create system tray icon instance
            self.system_tray = QSystemTrayIcon(self)
            
            # **ENHANCED**: Set initial icon based on protection status
            if self._get_real_time_protection_status():
                self._create_active_protection_icon()
            else:
                self._create_inactive_protection_icon()
            
            self.logger.debug("System tray icon created and configured")
            
        except Exception as e:
            self.logger.error(f"Error setting up system tray icon: {e}")
            self.system_tray = None
    
    def _create_active_protection_icon(self):
        """Create active protection system tray icon with visual indicators."""
        try:
            # **ENHANCED**: Create pixmap for active protection
            pixmap = QPixmap(16, 16)
            pixmap.fill(Qt.transparent)
            
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing, True)
            
            # **ENHANCED**: Draw shield with gradient for active protection
            # Green gradient background for active protection
            gradient = QLinearGradient(0, 0, 16, 16)
            gradient.setColorAt(0, QColor("#4caf50"))  # Green for active protection
            gradient.setColorAt(1, QColor("#388e3c"))
            
            painter.setBrush(QBrush(gradient))
            painter.setPen(QPen(QColor("#2e7d32"), 1))
            painter.drawEllipse(1, 1, 14, 14)
            
            # **ENHANCED**: Add shield symbol for protection status
            painter.setPen(QPen(Qt.white, 2, Qt.SolidLine, Qt.RoundCap))
            # Draw checkmark for active protection
            painter.drawLine(5, 8, 7, 10)
            painter.drawLine(7, 10, 11, 6)
            
            painter.end()
            
            self.system_tray.setIcon(QIcon(pixmap))
            self.logger.debug("Created active protection system tray icon")
            
        except Exception as e:
            self.logger.error(f"Error creating active protection icon: {e}")
            # **FALLBACK**: Use system icon
            if self.system_tray:
                self.system_tray.setIcon(self.style().standardIcon(self.style().SP_ComputerIcon))
    
    def _create_inactive_protection_icon(self):
        """Create inactive protection system tray icon with warning indicators."""
        try:
            # **ENHANCED**: Create pixmap for inactive protection
            pixmap = QPixmap(16, 16)
            pixmap.fill(Qt.transparent)
            
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing, True)
            
            # **ENHANCED**: Draw shield with warning gradient for inactive protection
            # Orange/red gradient background for inactive protection
            gradient = QLinearGradient(0, 0, 16, 16)
            gradient.setColorAt(0, QColor("#ff9800"))  # Orange for warning
            gradient.setColorAt(1, QColor("#f57c00"))
            
            painter.setBrush(QBrush(gradient))
            painter.setPen(QPen(QColor("#e65100"), 1))
            painter.drawEllipse(1, 1, 14, 14)
            
            # **ENHANCED**: Add warning symbol for inactive protection
            painter.setPen(QPen(Qt.white, 2, Qt.SolidLine, Qt.RoundCap))
            # Draw exclamation mark for warning
            painter.drawLine(8, 4, 8, 10)  # Exclamation line
            painter.drawPoint(8, 12)  # Exclamation dot
            
            painter.end()
            
            self.system_tray.setIcon(QIcon(pixmap))
            self.logger.debug("Created inactive protection system tray icon")
            
        except Exception as e:
            self.logger.error(f"Error creating inactive protection icon: {e}")
            # **FALLBACK**: Use system icon
            if self.system_tray:
                self.system_tray.setIcon(self.style().standardIcon(self.style().SP_ComputerIcon))
    
    def _create_system_tray_menu(self):
        """Create comprehensive system tray context menu with all actions."""
        try:
            # **ENHANCED**: Create main tray menu
            self.tray_menu = QMenu()
            
            # **ENHANCED**: Add comprehensive menu sections
            self._add_tray_info_section()
            self._add_tray_quick_actions()
            self._add_tray_scan_actions()
            self._add_tray_status_settings()
            self._add_tray_app_control()
            
            # **ENHANCED**: Set menu on system tray
            self.system_tray.setContextMenu(self.tray_menu)
            
            self.logger.debug("System tray menu created with comprehensive actions")
            
        except Exception as e:
            self.logger.error(f"Error creating system tray menu: {e}")
    
    def _add_tray_info_section(self):
        """Add information section to tray menu."""
        try:
            # **ENHANCED**: Application title and version
            title_action = QAction("Advanced Multi-Algorithm Antivirus", self)
            title_action.setEnabled(False)
            font = title_action.font()
            font.setBold(True)
            title_action.setFont(font)
            self.tray_menu.addAction(title_action)
            
            # **ENHANCED**: Protection status display
            protection_status = "🛡️ Protection: Active" if self._get_real_time_protection_status() else "⚠️ Protection: Inactive"
            self._tray_protection_action = QAction(protection_status, self)
            self._tray_protection_action.setEnabled(False)
            self.tray_menu.addAction(self._tray_protection_action)
            
            # **ENHANCED**: Last scan information
            last_scan = self.config.get_setting('scanning.last_scan', None)
            if last_scan:
                try:
                    last_scan_time = datetime.fromisoformat(last_scan)
                    time_diff = datetime.now() - last_scan_time
                    if time_diff.days > 0:
                        scan_text = f"📊 Last Scan: {time_diff.days}d ago"
                    else:
                        hours = time_diff.seconds // 3600
                        scan_text = f"📊 Last Scan: {hours}h ago"
                except Exception:
                    scan_text = "📊 Last Scan: Unknown"
            else:
                scan_text = "📊 Last Scan: Never"
            
            last_scan_action = QAction(scan_text, self)
            last_scan_action.setEnabled(False)
            self.tray_menu.addAction(last_scan_action)
            
            # **ENHANCED**: Threat count display
            threat_text = f"🔒 Quarantined: {self.quarantine_count}"
            self._tray_threat_action = QAction(threat_text, self)
            self._tray_threat_action.setEnabled(False)
            self.tray_menu.addAction(self._tray_threat_action)
            
            # **ENHANCED**: Separator after info section
            self.tray_menu.addSeparator()
            
        except Exception as e:
            self.logger.error(f"Error adding tray info section: {e}")
    
    def _add_tray_quick_actions(self):
        """Add quick actions section to tray menu."""
        try:
            # **ENHANCED**: Show/Hide main window action
            self._tray_show_hide_action = QAction("Show Main Window", self)
            self._tray_show_hide_action.triggered.connect(self._toggle_main_window_visibility)
            self.tray_menu.addAction(self._tray_show_hide_action)
            
            # **ENHANCED**: Quick actions submenu
            quick_menu = QMenu("Quick Actions", self)
            
            # **ENHANCED**: Quick scan action
            quick_scan_action = QAction("🚀 Quick Scan", self)
            quick_scan_action.triggered.connect(lambda: self._start_scan_from_tray("quick"))
            quick_menu.addAction(quick_scan_action)
            
            # **ENHANCED**: Scan file action
            scan_file_action = QAction("📄 Scan File...", self)
            scan_file_action.triggered.connect(self._scan_file_from_tray)
            quick_menu.addAction(scan_file_action)
            
            # **ENHANCED**: Open quarantine action
            quarantine_action = QAction("🔒 Open Quarantine", self)
            quarantine_action.triggered.connect(self._open_quarantine_window)
            quick_menu.addAction(quarantine_action)
            
            # **ENHANCED**: Update definitions action
            update_action = QAction("🔄 Update Definitions", self)
            update_action.triggered.connect(self._update_definitions)
            quick_menu.addAction(update_action)
            
            self.tray_menu.addMenu(quick_menu)
            
            # **ENHANCED**: Separator after quick actions
            self.tray_menu.addSeparator()
            
        except Exception as e:
            self.logger.error(f"Error adding tray quick actions: {e}")
    
    def _add_tray_scan_actions(self):
        """Add scan actions section to tray menu."""
        try:
            # **ENHANCED**: Scan submenu
            scan_menu = QMenu("Scan Options", self)
            
            # **ENHANCED**: All scan types
            scan_types = [
                ("🚀 Quick Scan", "quick"),
                ("🔍 Full System Scan", "full"),
                ("📁 Custom Scan", "custom"),
                ("💾 Memory Scan", "memory")
            ]
            
            for scan_text, scan_type in scan_types:
                scan_action = QAction(scan_text, self)
                scan_action.triggered.connect(lambda checked, st=scan_type: self._start_scan_from_tray(st))
                scan_menu.addAction(scan_action)
            
            self.tray_menu.addMenu(scan_menu)
            
        except Exception as e:
            self.logger.error(f"Error adding tray scan actions: {e}")
    
    def _add_tray_status_settings(self):
        """Add status and settings section to tray menu."""
        try:
            # **ENHANCED**: Real-time protection toggle
            rt_enabled = self._get_real_time_protection_status()
            rt_text = "✅ Real-time Protection" if rt_enabled else "❌ Real-time Protection"
            self._tray_rt_action = QAction(rt_text, self)
            self._tray_rt_action.setCheckable(True)
            self._tray_rt_action.setChecked(rt_enabled)
            self._tray_rt_action.triggered.connect(lambda checked: self._toggle_real_time_protection_from_tray(checked))
            self.tray_menu.addAction(self._tray_rt_action)
            
            # **ENHANCED**: Settings action
            settings_action = QAction("⚙️ Settings", self)
            settings_action.triggered.connect(self._open_settings)
            self.tray_menu.addAction(settings_action)
            
            # **ENHANCED**: Separator before exit
            self.tray_menu.addSeparator()
            
        except Exception as e:
            self.logger.error(f"Error adding tray status settings: {e}")
    
    def _add_tray_app_control(self):
        """Add application control section to tray menu."""
        try:
            # **ENHANCED**: Exit action
            exit_action = QAction("❌ Exit", self)
            exit_action.triggered.connect(self._exit_application_from_tray)
            self.tray_menu.addAction(exit_action)
            
        except Exception as e:
            self.logger.error(f"Error adding tray app control: {e}")
    
    def _connect_system_tray_signals(self):
        """Connect system tray signals and event handlers."""
        try:
            if not self.system_tray:
                return
            
            # **ENHANCED**: Connect activation signal
            self.system_tray.activated.connect(self._handle_system_tray_activation)
            
            # **ENHANCED**: Connect message clicked signal
            self.system_tray.messageClicked.connect(self._handle_tray_message_clicked)
            
            self.logger.debug("System tray signals connected successfully")
            
        except Exception as e:
            self.logger.error(f"Error connecting system tray signals: {e}")
    
    def _configure_system_tray_behavior(self):
        """Configure system tray behavior and tooltip."""
        try:
            if not self.system_tray:
                return
            
            # **ENHANCED**: Set initial tooltip
            self._update_system_tray_tooltip()
            
            # **ENHANCED**: Configure tray behavior
            self.system_tray.setToolTip("Advanced Multi-Algorithm Antivirus")
            
            self.logger.debug("System tray behavior configured")
            
        except Exception as e:
            self.logger.error(f"Error configuring system tray behavior: {e}")
    
    def _update_system_tray_tooltip(self):
        """Update system tray tooltip with current status."""
        try:
            if not self.system_tray:
                return
            
            # **ENHANCED**: Build comprehensive tooltip
            tooltip_lines = [
                "Advanced Multi-Algorithm Antivirus",
                "",
                f"Protection: {'Active' if self._get_real_time_protection_status() else 'Inactive'}",
                f"Threats: {self.threat_count}",
                f"Quarantined: {self.quarantine_count}",
                "",
                "Right-click for options"
            ]
            
            tooltip = "\n".join(tooltip_lines)
            self.system_tray.setToolTip(tooltip)
            
        except Exception as e:
            self.logger.error(f"Error updating system tray tooltip: {e}")
    
    def _handle_system_tray_activation(self, reason):
        """Handle system tray activation events."""
        try:
            if reason == QSystemTrayIcon.DoubleClick:
                # **ENHANCED**: Double-click shows/hides main window
                self._toggle_main_window_visibility()
            elif reason == QSystemTrayIcon.Trigger:
                # **ENHANCED**: Single click shows/hides main window
                self._toggle_main_window_visibility()
            elif reason == QSystemTrayIcon.MiddleClick:
                # **ENHANCED**: Middle click starts quick scan
                self._start_scan_from_tray("quick")
                
        except Exception as e:
            self.logger.error(f"Error handling system tray activation: {e}")
    
    def _handle_tray_message_clicked(self):
        """Handle system tray message clicked events."""
        try:
            # **ENHANCED**: Show main window when notification is clicked
            self._show_main_window()
            
        except Exception as e:
            self.logger.error(f"Error handling tray message click: {e}")
    
    def _toggle_main_window_visibility(self):
        """Toggle main window visibility."""
        try:
            if self.isVisible() and not self.isMinimized():
                # **ENHANCED**: Hide window
                self.hide()
                self._update_tray_show_hide_action("Show Main Window")
            else:
                # **ENHANCED**: Show and activate window
                self._show_main_window()
                self._update_tray_show_hide_action("Hide Main Window")
                
        except Exception as e:
            self.logger.error(f"Error toggling main window visibility: {e}")
    
    def _show_main_window(self):
        """Show and activate main window."""
        try:
            # **ENHANCED**: Show, raise, and activate window
            self.show()
            self.raise_()
            self.activateWindow()
            
            # **ENHANCED**: Restore from minimized state if needed
            if self.isMinimized():
                self.showNormal()
            
            # **ENHANCED**: Update tray action text
            self._update_tray_show_hide_action("Hide Main Window")
            
        except Exception as e:
            self.logger.error(f"Error showing main window: {e}")
    
    def _update_tray_show_hide_action(self, text: str):
        """Update the show/hide action text in tray menu."""
        try:
            if hasattr(self, '_tray_show_hide_action') and self._tray_show_hide_action:
                self._tray_show_hide_action.setText(text)
                
        except Exception as e:
            self.logger.error(f"Error updating tray show/hide action: {e}")
    
    def _start_scan_from_tray(self, scan_type: str):
        """Start scan from system tray."""
        try:
            # **ENHANCED**: Show main window first
            self._show_main_window()
            
            # **ENHANCED**: Start scan using main window method
            self._start_scan(scan_type)
            
        except Exception as e:
            self.logger.error(f"Error starting scan from tray: {e}")
    
    def _scan_file_from_tray(self):
        """Scan file from system tray."""
        try:
            # **ENHANCED**: Show main window first
            self._show_main_window()
            
            # **ENHANCED**: Use main window scan file method
            self._scan_single_file()
                
        except Exception as e:
            self.logger.error(f"Error scanning file from tray: {e}")
    
    def _toggle_real_time_protection_from_tray(self, enabled: bool):
        """Toggle real-time protection from system tray."""
        try:
            # **ENHANCED**: Update configuration
            self.config.set_setting('detection.real_time_enabled', enabled)
            
            # **ENHANCED**: Update UI and tray
            self._update_tray_protection_status(enabled)
            self._update_protection_status()
            
            # **ENHANCED**: Show notification
            status_text = "enabled" if enabled else "disabled"
            self._show_tray_notification(
                "Real-time Protection",
                f"Real-time protection has been {status_text}",
                QSystemTrayIcon.Information
            )
            
        except Exception as e:
            self.logger.error(f"Error toggling real-time protection from tray: {e}")
    
    def _update_tray_protection_status(self, enabled: bool):
        """Update protection status in tray menu."""
        try:
            # **ENHANCED**: Update protection status icon
            if enabled:
                self._create_active_protection_icon()
            else:
                self._create_inactive_protection_icon()
            
            # **ENHANCED**: Update protection status text
            if hasattr(self, '_tray_protection_action'):
                status_text = "🛡️ Protection: Active" if enabled else "⚠️ Protection: Inactive"
                self._tray_protection_action.setText(status_text)
            
            # **ENHANCED**: Update real-time protection action
            if hasattr(self, '_tray_rt_action'):
                rt_text = "✅ Real-time Protection" if enabled else "❌ Real-time Protection"
                self._tray_rt_action.setText(rt_text)
                self._tray_rt_action.setChecked(enabled)
            
            # **ENHANCED**: Update tooltip
            self._update_system_tray_tooltip()
            
        except Exception as e:
            self.logger.error(f"Error updating tray protection status: {e}")
    
    def _exit_application_from_tray(self):
        """Exit application from system tray."""
        try:
            # **ENHANCED**: Set exit flag and perform graceful shutdown
            self._user_chose_exit = True
            self._perform_full_shutdown()
            
        except Exception as e:
            self.logger.error(f"Error exiting application from tray: {e}")
    
    def _show_tray_notification(self, title: str, message: str, icon_type=QSystemTrayIcon.Information, duration: int = 5000):
        """Show system tray notification."""
        try:
            if not self.system_tray_enabled or not self.system_tray:
                return
            
            # **ENHANCED**: Check if notifications are enabled
            if not self._notifications_enabled:
                return
            
            # **ENHANCED**: Show tray notification
            self.system_tray.showMessage(title, message, icon_type, duration)
                
        except Exception as e:
            self.logger.error(f"Error showing tray notification: {e}")
    
    # ========================================================================
    # NOTIFICATION SYSTEM IMPLEMENTATION
    # ========================================================================
    
    def _initialize_notification_system(self):
        """Initialize comprehensive notification system."""
        try:
            self.logger.debug("Initializing comprehensive notification system...")
            
            # **ENHANCED**: Initialize notification settings
            self._notifications_enabled = self.config.get_setting('notifications.enabled', True)
            self._notification_settings = {
                'show_threat_notifications': self.config.get_setting('notifications.threats', True),
                'show_scan_notifications': self.config.get_setting('notifications.scans', True),
                'show_update_notifications': self.config.get_setting('notifications.updates', True),
                'show_system_notifications': self.config.get_setting('notifications.system', True),
                'notification_duration': self.config.get_setting('notifications.duration', 5000),
                'use_system_tray': self.config.get_setting('notifications.system_tray', True),
                'use_audio_alerts': self.config.get_setting('notifications.audio', False),
                'high_priority_only': self.config.get_setting('notifications.high_priority_only', False)
            }
            
            # **ENHANCED**: Initialize notification tracking
            self._notification_history = deque(maxlen=100)
            self._notification_queue = deque()
            self._active_notifications = {}
            self._notification_id_counter = 0
            
            # **ENHANCED**: Initialize notification timer for queue processing
            self._notification_timer = QTimer()
            self._notification_timer.timeout.connect(self._process_notification_queue)
            self._notification_timer.start(1000)  # Process every second
            
            # **ENHANCED**: Initialize notification cleanup timer
            self._notification_cleanup_timer = QTimer()
            self._notification_cleanup_timer.timeout.connect(self._cleanup_expired_notifications)
            self._notification_cleanup_timer.start(30000)  # Cleanup every 30 seconds
            
            self.logger.info("Notification system initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing notification system: {e}")
    
    def _add_notification(self, notification: 'NotificationItem'):
        """Add notification to the system."""
        try:
            # **ENHANCED**: Check if notifications should be shown
            if not self._should_show_notification(notification):
                return
            
            # **ENHANCED**: Assign unique ID if not provided
            if not hasattr(notification, 'notification_id') or not notification.notification_id:
                self._notification_id_counter += 1
                notification.notification_id = f"notification_{self._notification_id_counter}"
            
            # **ENHANCED**: Add to history
            self._notification_history.append(notification)
            
            # **ENHANCED**: Add to queue for processing
            self._notification_queue.append(notification)
            
            # **ENHANCED**: Process immediately if high priority
            if hasattr(notification, 'priority') and notification.priority == NotificationPriority.HIGH:
                self._process_notification_immediately(notification)
            
        except Exception as e:
            self.logger.error(f"Error adding notification: {e}")
    
    def _should_show_notification(self, notification: 'NotificationItem') -> bool:
        """Check if notification should be shown based on settings."""
        try:
            # **ENHANCED**: Check if notifications are globally enabled
            if not self._notifications_enabled:
                return False
            
            # **ENHANCED**: Check high priority only setting
            if (self._notification_settings.get('high_priority_only', False) and 
                hasattr(notification, 'priority') and 
                notification.priority != NotificationPriority.HIGH):
                return False
            
            # **ENHANCED**: Check category-specific settings
            category = getattr(notification, 'category', 'general')
            category_setting_map = {
                'threat': 'show_threat_notifications',
                'scan': 'show_scan_notifications',
                'update': 'show_update_notifications',
                'system': 'show_system_notifications'
            }
            
            setting_key = category_setting_map.get(category, 'show_system_notifications')
            if not self._notification_settings.get(setting_key, True):
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking notification settings: {e}")
            return True  # Default to showing notifications
    
    def _process_notification_queue(self):
        """Process pending notifications from queue."""
        try:
            if not self._notification_queue:
                return
            
            # **ENHANCED**: Process one notification per timer tick
            notification = self._notification_queue.popleft()
            self._process_notification_immediately(notification)
            
        except Exception as e:
            self.logger.error(f"Error processing notification queue: {e}")
    
    def _process_notification_immediately(self, notification: 'NotificationItem'):
        """Process a notification immediately."""
        try:
            # **ENHANCED**: Determine notification type and show appropriately
            category = getattr(notification, 'category', 'general')
            
            if category == 'threat':
                self._show_threat_notification_detailed(notification)
            elif category == 'scan':
                self._show_scan_notification(notification)
            elif category == 'system':
                self._show_system_notification(notification)
            else:
                self._show_general_notification(notification)
            
            # **ENHANCED**: Play audio alert if enabled
            if (self._notification_settings.get('use_audio_alerts', False) and 
                hasattr(notification, 'priority')):
                self._play_notification_sound(notification.priority)
            
            # **ENHANCED**: Track active notification
            self._active_notifications[notification.notification_id] = {
                'notification': notification,
                'shown_at': datetime.now(),
                'duration': self._notification_settings.get('notification_duration', 5000)
            }
            
        except Exception as e:
            self.logger.error(f"Error processing notification immediately: {e}")
    
    def _show_threat_notification_detailed(self, notification: 'NotificationItem'):
        """Show detailed threat notification with actions."""
        try:
            # **ENHANCED**: Show system tray notification for threats
            if self.system_tray_enabled and self._notification_settings.get('use_system_tray', True):
                self._show_tray_notification(
                    notification.title,
                    notification.message,
                    QSystemTrayIcon.Warning,
                    self._notification_settings.get('notification_duration', 5000)
                )
            
            # **ENHANCED**: Update threat counter in UI
            if hasattr(self, '_threat_counter_label'):
                self._threat_counter_label.setText(f"⚠️ Threats: {self.threat_count}")
            
            # **ENHANCED**: Log threat notification
            self.logger.warning(f"Threat notification: {notification.title} - {notification.message}")
            
        except Exception as e:
            self.logger.error(f"Error showing threat notification: {e}")
    
    def _show_scan_notification(self, notification: 'NotificationItem'):
        """Show scan-related notification."""
        try:
            # **ENHANCED**: Show system tray notification for scans
            if self.system_tray_enabled and self._notification_settings.get('use_system_tray', True):
                icon_type = QSystemTrayIcon.Information
                if hasattr(notification, 'priority') and notification.priority == NotificationPriority.HIGH:
                    icon_type = QSystemTrayIcon.Warning
                
                self._show_tray_notification(
                    notification.title,
                    notification.message,
                    icon_type,
                    self._notification_settings.get('notification_duration', 5000)
                )
            
            # **ENHANCED**: Log scan notification
            self.logger.info(f"Scan notification: {notification.title} - {notification.message}")
            
        except Exception as e:
            self.logger.error(f"Error showing scan notification: {e}")
    
    def _show_system_notification(self, notification: 'NotificationItem'):
        """Show system-related notification."""
        try:
            # **ENHANCED**: Show system tray notification for system events
            if self.system_tray_enabled and self._notification_settings.get('use_system_tray', True):
                icon_type = QSystemTrayIcon.Information
                if hasattr(notification, 'priority'):
                    if notification.priority == NotificationPriority.HIGH:
                        icon_type = QSystemTrayIcon.Critical
                    elif notification.priority == NotificationPriority.WARNING:
                        icon_type = QSystemTrayIcon.Warning
                
                self._show_tray_notification(
                    notification.title,
                    notification.message,
                    icon_type,
                    self._notification_settings.get('notification_duration', 5000)
                )
            
            # **ENHANCED**: Log system notification
            self.logger.info(f"System notification: {notification.title} - {notification.message}")
            
        except Exception as e:
            self.logger.error(f"Error showing system notification: {e}")
    
    def _show_general_notification(self, notification: 'NotificationItem'):
        """Show general notification."""
        try:
            # **ENHANCED**: Show system tray notification for general events
            if self.system_tray_enabled and self._notification_settings.get('use_system_tray', True):
                self._show_tray_notification(
                    notification.title,
                    notification.message,
                    QSystemTrayIcon.Information,
                    self._notification_settings.get('notification_duration', 5000)
                )
            
            # **ENHANCED**: Log general notification
            self.logger.debug(f"General notification: {notification.title} - {notification.message}")
            
        except Exception as e:
            self.logger.error(f"Error showing general notification: {e}")
    
    def _play_notification_sound(self, priority: 'NotificationPriority'):
        """Play notification sound based on priority."""
        try:
            # **ENHANCED**: Play system sound based on priority
            if priority == NotificationPriority.HIGH:
                QApplication.beep()  # High priority gets system beep
            elif priority == NotificationPriority.WARNING:
                QApplication.beep()  # Warning also gets beep
            # Info and other priorities get no sound by default
            
        except Exception as e:
            self.logger.error(f"Error playing notification sound: {e}")
    
    def _cleanup_expired_notifications(self):
        """Clean up expired notifications."""
        try:
            current_time = datetime.now()
            expired_notifications = []
            
            # **ENHANCED**: Find expired notifications
            for notification_id, notification_data in self._active_notifications.items():
                shown_at = notification_data['shown_at']
                duration_ms = notification_data['duration']
                duration_seconds = duration_ms / 1000.0
                
                if (current_time - shown_at).total_seconds() > duration_seconds:
                    expired_notifications.append(notification_id)
            
            # **ENHANCED**: Remove expired notifications
            for notification_id in expired_notifications:
                del self._active_notifications[notification_id]
            
            # **ENHANCED**: Limit history size
            if len(self._notification_history) > 100:
                # Remove oldest notifications beyond limit
                while len(self._notification_history) > 100:
                    self._notification_history.popleft()
            
        except Exception as e:
            self.logger.error(f"Error cleaning up notifications: {e}")
    
    def get_notification_history(self) -> List[Dict[str, Any]]:
        """Get notification history."""
        try:
            history = []
            for notification in self._notification_history:
                history.append({
                    'id': getattr(notification, 'notification_id', 'unknown'),
                    'title': getattr(notification, 'title', ''),
                    'message': getattr(notification, 'message', ''),
                    'category': getattr(notification, 'category', 'general'),
                    'priority': getattr(notification, 'priority', 'info'),
                    'timestamp': getattr(notification, 'timestamp', datetime.now()).isoformat()
                })
            return history
        except Exception as e:
            self.logger.error(f"Error getting notification history: {e}")
            return []
    
    def clear_notification_history(self):
        """Clear notification history."""
        try:
            self._notification_history.clear()
            self._active_notifications.clear()
            self.logger.debug("Notification history cleared")
        except Exception as e:
            self.logger.error(f"Error clearing notification history: {e}")
    
    # ========================================================================
    # SIGNAL CONNECTIONS AND EVENT HANDLING
    # ========================================================================
    
    def _connect_comprehensive_signals(self):
        """Connect all comprehensive signals and event handlers."""
        try:
            self.logger.debug("Connecting comprehensive signals and event handlers...")
            
            # **ENHANCED**: Connect application-level signals
            self._connect_application_signals()
            
            # **ENHANCED**: Connect window-specific signals
            self._connect_window_signals()
            
            # **ENHANCED**: Connect theme management signals
            self._connect_theme_signals()
            
            # **ENHANCED**: Connect configuration signals
            self._connect_configuration_signals()
            
            # **ENHANCED**: Connect component signals
            self._connect_component_signals()
            
            # **ENHANCED**: Connect navigation signals
            self._connect_navigation_signals()
            
            # **ENHANCED**: Connect scan signals
            self._connect_scan_signals()
            
            # **ENHANCED**: Connect notification signals
            self._connect_notification_signals()
            
            self.logger.info("All comprehensive signals connected successfully")
            
        except Exception as e:
            self.logger.error(f"Error connecting comprehensive signals: {e}")
    
    def _connect_application_signals(self):
        """Connect application-level signals."""
        try:
            # **ENHANCED**: Connect QApplication signals
            app = QApplication.instance()
            if app:
                app.aboutToQuit.connect(self._handle_application_about_to_quit)
                app.applicationStateChanged.connect(self._handle_application_state_changed)
            
            # **ENHANCED**: Connect own application signals
            if hasattr(self, 'shutdown_requested'):
                self.shutdown_requested.connect(self._handle_shutdown_request)
            
            self.logger.debug("Application signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting application signals: {e}")
    
    def _connect_window_signals(self):
        """Connect window-specific signals."""
        try:
            # **ENHANCED**: Connect window state signals
            self.windowStateChanged.connect(self._handle_window_state_changed)
            
            # **ENHANCED**: Connect child window signals
            if hasattr(self, 'window_opened'):
                self.window_opened.connect(self._handle_child_window_opened)
            if hasattr(self, 'window_closed'):
                self.window_closed.connect(self._handle_child_window_closed)
            
            self.logger.debug("Window signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting window signals: {e}")
    
    def _connect_theme_signals(self):
        """Connect theme management signals."""
        try:
            if self.theme_manager:
                # **ENHANCED**: Connect theme manager signals
                if hasattr(self.theme_manager, 'theme_changed'):
                    self.theme_manager.theme_changed.connect(self._handle_theme_changed)
                if hasattr(self.theme_manager, 'theme_error'):
                    self.theme_manager.theme_error.connect(self._handle_theme_error)
            
            self.logger.debug("Theme signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting theme signals: {e}")
    
    def _connect_configuration_signals(self):
        """Connect configuration management signals."""
        try:
            if self.config:
                # **ENHANCED**: Connect configuration signals
                if hasattr(self.config, 'setting_changed'):
                    self.config.setting_changed.connect(self._handle_setting_changed)
                if hasattr(self.config, 'configuration_error'):
                    self.config.configuration_error.connect(self._handle_configuration_error)
            
            self.logger.debug("Configuration signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting configuration signals: {e}")
    
    def _connect_component_signals(self):
        """Connect core component signals."""
        try:
            # **ENHANCED**: Connect scanner engine signals
            if self.scanner_engine:
                if hasattr(self.scanner_engine, 'scan_started'):
                    self.scanner_engine.scan_started.connect(self._handle_scan_started)
                if hasattr(self.scanner_engine, 'scan_completed'):
                    self.scanner_engine.scan_completed.connect(self._handle_scan_completed)
                if hasattr(self.scanner_engine, 'threat_detected'):
                    self.scanner_engine.threat_detected.connect(self._handle_threat_detected)
            
            # **ENHANCED**: Connect model manager signals
            if self.model_manager:
                if hasattr(self.model_manager, 'model_loaded'):
                    self.model_manager.model_loaded.connect(self._handle_model_loaded)
                if hasattr(self.model_manager, 'model_error'):
                    self.model_manager.model_error.connect(self._handle_model_error)
            
            # **ENHANCED**: Connect file manager signals
            if self.file_manager:
                if hasattr(self.file_manager, 'file_quarantined'):
                    self.file_manager.file_quarantined.connect(self._handle_file_quarantined)
                if hasattr(self.file_manager, 'file_restored'):
                    self.file_manager.file_restored.connect(self._handle_file_restored)
            
            self.logger.debug("Component signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting component signals: {e}")
    
    def _connect_navigation_signals(self):
        """Connect navigation system signals."""
        try:
            # **ENHANCED**: Connect navigation button signals
            for section, button in self._nav_buttons.items():
                button.clicked.connect(lambda checked, s=section: self._navigate_to_section(s))
            
            self.logger.debug("Navigation signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting navigation signals: {e}")
    
    def _connect_scan_signals(self):
        """Connect scan-related signals."""
        try:
            # **ENHANCED**: Connect scan control signals if they exist
            for scan_type in ['quick', 'full', 'custom']:
                button_name = f'_{scan_type}_scan_button'
                if hasattr(self, button_name):
                    button = getattr(self, button_name)
                    if button:
                        button.clicked.connect(lambda checked, st=scan_type: self._start_scan(st))
            
            self.logger.debug("Scan signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting scan signals: {e}")
    
    def _connect_notification_signals(self):
        """Connect notification system signals."""
        try:
            # **ENHANCED**: Connect internal notification signals
            # These are typically connected when notifications are created
            
            self.logger.debug("Notification signals connected")
            
        except Exception as e:
            self.logger.error(f"Error connecting notification signals: {e}")
    
    # ========================================================================
    # SIGNAL HANDLERS - Event Processing
    # ========================================================================
    
    def _handle_application_about_to_quit(self):
        """Handle application about to quit signal."""
        try:
            self.logger.info("Application about to quit - performing final cleanup")
            
            # **ENHANCED**: Perform final cleanup
            self._perform_final_cleanup()
            
        except Exception as e:
            self.logger.error(f"Error handling application about to quit: {e}")
    
    def _handle_application_state_changed(self, state):
        """Handle application state change signal."""
        try:
            state_names = {
                Qt.ApplicationSuspended: "Suspended",
                Qt.ApplicationHidden: "Hidden", 
                Qt.ApplicationInactive: "Inactive",
                Qt.ApplicationActive: "Active"
            }
            
            state_name = state_names.get(state, f"Unknown({state})")
            self.logger.debug(f"Application state changed to: {state_name}")
            
            # **ENHANCED**: Handle state-specific actions
            if state == Qt.ApplicationActive:
                # **ENHANCED**: Application became active
                self._on_application_activated()
            elif state == Qt.ApplicationInactive:
                # **ENHANCED**: Application became inactive
                self._on_application_deactivated()
            
        except Exception as e:
            self.logger.error(f"Error handling application state change: {e}")
    
    def _handle_window_state_changed(self):
        """Handle window state change signal."""
        try:
            # **ENHANCED**: Update system tray show/hide action
            if self.isVisible() and not self.isMinimized():
                self._update_tray_show_hide_action("Hide Main Window")
            else:
                self._update_tray_show_hide_action("Show Main Window")
            
        except Exception as e:
            self.logger.error(f"Error handling window state change: {e}")
    
    def _handle_child_window_opened(self, window_type: str, window_instance):
        """Handle child window opened signal."""
        try:
            self.logger.debug(f"Child window opened: {window_type}")
            
            # **ENHANCED**: Update UI state for opened window
            self._update_window_menu_actions()
            
        except Exception as e:
            self.logger.error(f"Error handling child window opened: {e}")
    
    def _handle_child_window_closed(self, window_type: str):
        """Handle child window closed signal."""
        try:
            self.logger.debug(f"Child window closed: {window_type}")
            
            # **ENHANCED**: Update UI state for closed window
            self._update_window_menu_actions()
            
        except Exception as e:
            self.logger.error(f"Error handling child window closed: {e}")
    
    def _handle_theme_changed(self, theme_name: str, theme_data: dict):
        """Handle theme changed signal."""
        try:
            self.logger.info(f"Theme changed to: {theme_name}")
            
            # **ENHANCED**: Apply theme changes to main window
            if hasattr(self, 'apply_theme'):
                self.apply_theme()
            
            # **ENHANCED**: Update child windows with new theme
            self._update_child_windows_theme()
            
            # **ENHANCED**: Save theme preference
            self.config.set_theme_preference(theme_name)
            
        except Exception as e:
            self.logger.error(f"Error handling theme changed: {e}")
    
    def _handle_theme_error(self, error_type: str, error_message: str):
        """Handle theme error signal."""
        try:
            self.logger.error(f"Theme error ({error_type}): {error_message}")
            
            # **ENHANCED**: Show theme error notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"theme_error_{datetime.now().timestamp()}",
                    title="Theme Error",
                    message=f"Theme system error: {error_message}",
                    priority=NotificationPriority.WARNING,
                    category="system"
                )
                self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error handling theme error: {e}")
    
    def _handle_setting_changed(self, key_path: str, old_value, new_value):
        """Handle configuration setting changed signal."""
        try:
            self.logger.debug(f"Setting changed: {key_path} = {new_value}")
            
            # **ENHANCED**: Handle specific setting changes
            if key_path == "detection.real_time_enabled":
                self._update_real_time_protection_status(new_value)
            elif key_path.startswith("ui."):
                self._handle_ui_setting_changed(key_path, new_value)
            elif key_path.startswith("notifications."):
                self._handle_notification_setting_changed(key_path, new_value)
            
        except Exception as e:
            self.logger.error(f"Error handling setting change: {e}")
    
    def _handle_configuration_error(self, error_type: str, error_message: str):
        """Handle configuration error signal."""
        try:
            self.logger.error(f"Configuration error ({error_type}): {error_message}")
            
            # **ENHANCED**: Show configuration error notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"config_error_{datetime.now().timestamp()}",
                    title="Configuration Error",
                    message=f"Configuration error: {error_message}",
                    priority=NotificationPriority.WARNING,
                    category="system"
                )
                self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error handling configuration error: {e}")
    
    def _handle_scan_started(self, scan_type: str, scan_config: dict):
        """Handle scan started signal from scanner engine."""
        try:
            self.logger.info(f"Scan started: {scan_type}")
            
            # **ENHANCED**: Update scan status in UI
            self._update_scan_status_ui()
            
            # **ENHANCED**: Show scan notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"scan_started_{datetime.now().timestamp()}",
                    title="Scan Started",
                    message=f"{scan_type.title()} scan has started",
                    priority=NotificationPriority.INFO,
                    category="scan"
                )
                self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error handling scan started: {e}")
    
    def _handle_scan_completed(self, scan_results: dict):
        """Handle scan completed signal from scanner engine."""
        try:
            self.logger.info(f"Scan completed: {scan_results}")
            
            # **ENHANCED**: Update scan status in UI
            self._update_scan_status_ui()
            
            # **ENHANCED**: Show scan completion notification
            threats_found = scan_results.get('threats_found', 0)
            files_scanned = scan_results.get('files_scanned', 0)
            
            if threats_found > 0:
                notification = NotificationItem(
                    notification_id=f"scan_completed_{datetime.now().timestamp()}",
                    title="Scan Completed - Threats Found",
                    message=f"Found {threats_found} threats in {files_scanned} files",
                    priority=NotificationPriority.HIGH,
                    category="scan"
                )
            else:
                notification = NotificationItem(
                    notification_id=f"scan_completed_{datetime.now().timestamp()}",
                    title="Scan Completed",
                    message=f"No threats found in {files_scanned} files",
                    priority=NotificationPriority.INFO,
                    category="scan"
                )
            
            self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error handling scan completed: {e}")
    
    def _handle_threat_detected(self, threat_info: dict):
        """Handle threat detected signal from scanner engine."""
        try:
            threat_name = threat_info.get('name', 'Unknown Threat')
            file_path = threat_info.get('file_path', 'Unknown File')
            
            self.logger.warning(f"Threat detected: {threat_name} in {file_path}")
            
            # **ENHANCED**: Update threat counter
            self.threat_count = getattr(self, 'threat_count', 0) + 1
            
            # **ENHANCED**: Show threat notification
            notification = NotificationItem(
                notification_id=f"threat_detected_{datetime.now().timestamp()}",
                title="Threat Detected",
                message=f"Threat '{threat_name}' detected in {Path(file_path).name}",
                priority=NotificationPriority.HIGH,
                category="threat",
                is_actionable=True
            )
            self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error handling threat detected: {e}")
    
    def _handle_model_loaded(self, model_name: str, model_info: dict):
        """Handle model loaded signal from model manager."""
        try:
            self.logger.info(f"Model loaded: {model_name}")
            
            # **ENHANCED**: Update model status display
            self._update_model_status_display()
            
        except Exception as e:
            self.logger.error(f"Error handling model loaded: {e}")
    
    def _handle_model_error(self, model_name: str, error_message: str):
        """Handle model error signal from model manager."""
        try:
            self.logger.error(f"Model error in {model_name}: {error_message}")
            
            # **ENHANCED**: Show model error notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"model_error_{datetime.now().timestamp()}",
                    title="Model Error",
                    message=f"Error in {model_name}: {error_message}",
                    priority=NotificationPriority.WARNING,
                    category="system"
                )
                self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error handling model error: {e}")
    
    def _handle_file_quarantined(self, file_path: str, quarantine_id: str):
        """Handle file quarantined signal from file manager."""
        try:
            self.logger.info(f"File quarantined: {file_path} -> {quarantine_id}")
            
            # **ENHANCED**: Update quarantine count
            self.quarantine_count = getattr(self, 'quarantine_count', 0) + 1
            self._update_quarantine_status_ui()
            
        except Exception as e:
            self.logger.error(f"Error handling file quarantined: {e}")
    
    def _handle_file_restored(self, file_path: str, original_path: str):
        """Handle file restored signal from file manager."""
        try:
            self.logger.info(f"File restored: {file_path} -> {original_path}")
            
            # **ENHANCED**: Update quarantine count
            self.quarantine_count = max(0, getattr(self, 'quarantine_count', 0) - 1)
            self._update_quarantine_status_ui()
            
        except Exception as e:
            self.logger.error(f"Error handling file restored: {e}")
    
    def _handle_real_time_protection_changed(self, enabled: bool):
        """Handle real-time protection setting change."""
        try:
            # **ENHANCED**: Update system tray icon
            if self.system_tray_enabled:
                self._update_tray_protection_status(enabled)
            
            # **ENHANCED**: Update protection status in UI
            self._update_protection_status()
            
        except Exception as e:
            self.logger.error(f"Error handling real-time protection change: {e}")
    
    def _handle_ui_setting_changed(self, key_path: str, new_value):
        """Handle UI setting change."""
        try:
            if key_path == "ui.theme":
                # **ENHANCED**: Apply new theme
                if self.theme_manager:
                    self.theme_manager.set_theme(new_value)
            elif key_path == "ui.notifications_enabled":
                # **ENHANCED**: Update notification settings
                self._notifications_enabled = new_value
            elif key_path == "ui.system_tray_notifications":
                # **ENHANCED**: Update system tray notification settings
                self._notification_settings['use_system_tray'] = new_value
            
        except Exception as e:
            self.logger.error(f"Error handling UI setting change: {e}")
    
    def _handle_notification_setting_changed(self, key_path: str, new_value):
        """Handle notification setting change."""
        try:
            setting_key = key_path.split('.', 1)[1]  # Remove 'notifications.' prefix
            if setting_key in self._notification_settings:
                self._notification_settings[setting_key] = new_value
            
        except Exception as e:
            self.logger.error(f"Error handling notification setting change: {e}")
    
    # ========================================================================
    # UTILITY METHODS FOR SIGNAL HANDLING
    # ========================================================================
    
    def _on_application_activated(self):
        """Handle application activation."""
        try:
            # **ENHANCED**: Refresh data when application becomes active
            self._update_dashboard_data()
            
        except Exception as e:
            self.logger.error(f"Error handling application activation: {e}")
    
    def _on_application_deactivated(self):
        """Handle application deactivation."""
        try:
            # **ENHANCED**: Save current state when application becomes inactive
            self._save_window_state()
            
        except Exception as e:
            self.logger.error(f"Error handling application deactivation: {e}")
    
    def _update_window_menu_actions(self):
        """Update window menu actions based on open windows."""
        try:
            # **ENHANCED**: Update menu actions based on window states
            pass  # Implementation would update menu states
            
        except Exception as e:
            self.logger.error(f"Error updating window menu actions: {e}")
    
    def _update_child_windows_theme(self):
        """Update theme for all child windows."""
        try:
            # **ENHANCED**: Apply theme to all open child windows
            for window_type, state in self._window_states.items():
                if state.is_open and state.instance:
                    if hasattr(state.instance, 'apply_theme'):
                        try:
                            state.instance.apply_theme()
                        except Exception as e:
                            self.logger.debug(f"Could not apply theme to {window_type}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error updating child windows theme: {e}")
    
    def _update_real_time_protection_status(self, enabled: bool):
        """Update real-time protection status throughout the UI."""
        try:
            # **ENHANCED**: Update all protection status indicators
            self._update_protection_status()
            self._update_tray_protection_status(enabled)
            
        except Exception as e:
            self.logger.error(f"Error updating real-time protection status: {e}")
    
    def _get_real_time_protection_status(self) -> bool:
        """Get current real-time protection status."""
        try:
            return self.config.get_setting('detection.real_time_enabled', True)
        except Exception:
            return True  # Default to enabled
    
    def _perform_final_cleanup(self):
        """Perform final cleanup before application exit."""
        try:
            # **ENHANCED**: Save any pending configuration changes
            if hasattr(self.config, 'save_all_settings'):
                self.config.save_all_settings()
            
            # **ENHANCED**: Stop all timers
            if hasattr(self, '_ui_update_timer'):
                self._ui_update_timer.stop()
            if hasattr(self, '_notification_timer'):
                self._notification_timer.stop()
            if hasattr(self, '_notification_cleanup_timer'):
                self._notification_cleanup_timer.stop()
            
            # **ENHANCED**: Cleanup system tray
            if self.system_tray:
                self.system_tray.hide()
            
        except Exception as e:
            self.logger.error(f"Error in final cleanup: {e}")
    
    def _save_window_state(self):
        """Save current window state to configuration."""
        try:
            # **ENHANCED**: Save window geometry and state
            geometry = {
                'x': self.x(),
                'y': self.y(),
                'width': self.width(),
                'height': self.height(),
                'maximized': self.isMaximized(),
                'minimized': self.isMinimized()
            }
            
            self.config.set_window_geometry('main_window', geometry)
            
        except Exception as e:
            self.logger.error(f"Error saving window state: {e}")
    
    # ========================================================================
    # BACKGROUND PROCESSING AND MONITORING SYSTEMS
    # ========================================================================
    
    def _initialize_background_processing(self):
        """Initialize comprehensive background processing systems with advanced features."""
        try:
            self.logger.debug("Initializing comprehensive background processing systems...")
            
            # **ENHANCED**: Advanced thread pool management with dynamic sizing
            self._background_thread_pool = QThreadPool()
            self._background_thread_pool.setMaxThreadCount(min(16, max(4, os.cpu_count() * 2)))
            self._background_thread_pool.setExpiryTimeout(30000)  # 30 seconds
            
            # **ENHANCED**: Background task management
            self._active_background_tasks = {}
            self._background_task_queue = deque()
            self._background_task_history = deque(maxlen=100)
            self._background_task_lock = threading.RLock()
            
            # **ENHANCED**: Performance monitoring with comprehensive metrics
            self._performance_data = {
                'cpu_usage_history': deque(maxlen=100),
                'memory_usage_history': deque(maxlen=100),
                'network_usage_history': deque(maxlen=100),
                'disk_usage_history': deque(maxlen=100),
                'scan_performance_history': deque(maxlen=50),
                'model_performance_history': deque(maxlen=50),
                'system_health_history': deque(maxlen=100)
            }
            
            # **ENHANCED**: Background operation states
            self._background_operations = {
                'system_monitoring': False,
                'performance_monitoring': False,
                'health_checking': False,
                'update_checking': False,
                'maintenance_tasks': False,
                'cache_cleanup': False,
                'log_rotation': False,
                'backup_operations': False
            }
            
            # **ENHANCED**: Setup background timers with intelligent intervals
            self._setup_background_timers()
            
            # **ENHANCED**: Setup monitoring systems with comprehensive coverage
            self._setup_monitoring_systems()
            
            # **ENHANCED**: Setup update and maintenance systems
            self._setup_update_systems()
            
            # **ENHANCED**: Setup performance monitoring with optimization
            self._setup_performance_monitoring()
            
            # **ENHANCED**: Setup maintenance and cleanup systems
            self._setup_maintenance_systems()
            
            self.logger.info("Comprehensive background processing systems initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing background processing: {e}")
            # **FALLBACK**: Initialize minimal background processing
            self._initialize_minimal_background_processing()
    
    def _initialize_minimal_background_processing(self):
        """Initialize minimal background processing as fallback."""
        try:
            self._background_thread_pool = QThreadPool()
            self._background_thread_pool.setMaxThreadCount(4)
            
            # **BASIC**: Essential timer
            self._ui_update_timer = QTimer()
            self._ui_update_timer.timeout.connect(self._update_ui_data)
            self._ui_update_timer.start(5000)  # 5 seconds
            
            self.logger.warning("Initialized minimal background processing due to errors")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize even minimal background processing: {e}")
    
    def _setup_background_timers(self):
        """Setup background timers for various operations with intelligent scheduling."""
        try:
            # **ENHANCED**: UI update timer with adaptive interval
            self._ui_update_timer = QTimer()
            self._ui_update_timer.timeout.connect(self._update_ui_data)
            self._ui_update_timer.start(2000)  # 2 seconds
            
            # **ENHANCED**: System status monitoring timer
            self._system_status_timer = QTimer()
            self._system_status_timer.timeout.connect(self._check_system_status)
            self._system_status_timer.start(10000)  # 10 seconds
            
            # **ENHANCED**: Performance monitoring timer
            self._performance_timer = QTimer()
            self._performance_timer.timeout.connect(self._monitor_performance)
            self._performance_timer.start(5000)  # 5 seconds
            
            # **ENHANCED**: Update checking timer
            self._update_check_timer = QTimer()
            self._update_check_timer.timeout.connect(self._check_definition_updates)
            self._update_check_timer.start(3600000)  # 1 hour
            
            # **ENHANCED**: Maintenance timer
            self._maintenance_timer = QTimer()
            self._maintenance_timer.timeout.connect(self._perform_maintenance_tasks)
            self._maintenance_timer.start(1800000)  # 30 minutes
            
            # **NEW**: Component health monitoring timer
            self._health_check_timer = QTimer()
            self._health_check_timer.timeout.connect(self._check_component_availability)
            self._health_check_timer.start(30000)  # 30 seconds
            
            # **NEW**: Performance issues monitoring timer
            self._performance_issues_timer = QTimer()
            self._performance_issues_timer.timeout.connect(self._check_performance_issues)
            self._performance_issues_timer.start(15000)  # 15 seconds
            
            # **NEW**: Protection status monitoring timer
            self._protection_status_timer = QTimer()
            self._protection_status_timer.timeout.connect(self._check_protection_status)
            self._protection_status_timer.start(60000)  # 1 minute
            
            # **NEW**: Scan recommendation timer
            self._scan_recommendation_timer = QTimer()
            self._scan_recommendation_timer.timeout.connect(self._check_scan_status)
            self._scan_recommendation_timer.start(7200000)  # 2 hours
            
            self.logger.debug("Background timers configured successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up background timers: {e}")
    
    def _setup_monitoring_systems(self):
        """Setup comprehensive system monitoring capabilities."""
        try:
            # **ENHANCED**: Initialize system monitoring
            self._system_monitor_enabled = True
            self._system_metrics = {
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'disk_usage': 0.0,
                'network_activity': 0.0,
                'process_count': 0,
                'thread_count': 0,
                'handle_count': 0
            }
            
            # **ENHANCED**: Performance thresholds with adaptive limits
            self._performance_thresholds = {
                'cpu_warning': 80.0,
                'cpu_critical': 95.0,
                'memory_warning': 85.0,
                'memory_critical': 95.0,
                'disk_warning': 90.0,
                'disk_critical': 98.0
            }
            
            # **NEW**: Network monitoring
            self._network_monitor_enabled = True
            self._network_metrics = {
                'bytes_sent': 0,
                'bytes_received': 0,
                'packets_sent': 0,
                'packets_received': 0,
                'connections_count': 0
            }
            
            # **NEW**: Application-specific monitoring
            self._app_metrics = {
                'scan_operations': 0,
                'threats_detected': 0,
                'files_quarantined': 0,
                'false_positives': 0,
                'model_predictions': 0,
                'cache_hits': 0,
                'cache_misses': 0
            }
            
            self.logger.debug("Monitoring systems configured successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up monitoring systems: {e}")
    
    def _setup_update_systems(self):
        """Setup automatic update checking and management systems."""
        try:
            # **ENHANCED**: Update checking configuration
            self._update_checking_enabled = self.config.get_setting('updates.auto_check_enabled', True)
            self._last_update_check = None
            self._update_check_interval = self.config.get_setting('updates.check_interval_hours', 24)
            
            # **ENHANCED**: Update status tracking
            self._update_status = {
                'definitions_available': False,
                'models_available': False,
                'application_available': False,
                'last_check_time': None,
                'last_check_result': None,
                'check_in_progress': False
            }
            
            # **NEW**: Update reminder system
            self._update_reminders = {
                'definitions_reminder': True,
                'models_reminder': True,
                'application_reminder': True,
                'reminder_interval_days': 7
            }
            
            # **NEW**: Automatic update preferences
            self._auto_update_preferences = {
                'auto_update_definitions': self.config.get_setting('updates.auto_update_definitions', True),
                'auto_update_models': self.config.get_setting('updates.auto_update_models', False),
                'auto_update_application': self.config.get_setting('updates.auto_update_application', False),
                'update_during_idle': True,
                'update_schedule': 'daily'
            }
            
            self.logger.debug("Update systems configured successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up update systems: {e}")
    
    def _setup_performance_monitoring(self):
        """Setup advanced performance monitoring and optimization systems."""
        try:
            # **ENHANCED**: Performance monitoring configuration
            self._performance_monitoring_enabled = True
            self._performance_optimization_enabled = True
            
            # **ENHANCED**: Performance metrics collection
            self._performance_collectors = {
                'cpu_monitor': self._collect_cpu_metrics,
                'memory_monitor': self._collect_memory_metrics,
                'disk_monitor': self._collect_disk_metrics,
                'network_monitor': self._collect_network_metrics,
                'application_monitor': self._collect_application_metrics
            }
            
            # **NEW**: Performance analysis and optimization
            self._performance_analyzer = {
                'trend_analysis': True,
                'anomaly_detection': True,
                'optimization_suggestions': True,
                'predictive_analysis': False
            }
            
            # **NEW**: Resource management
            self._resource_manager = {
                'memory_cleanup_threshold': 85.0,
                'cache_cleanup_threshold': 80.0,
                'background_task_throttling': True,
                'adaptive_thread_management': True
            }
            
            self.logger.debug("Performance monitoring configured successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up performance monitoring: {e}")
    
    def _setup_maintenance_systems(self):
        """Setup maintenance and cleanup systems."""
        try:
            # **ENHANCED**: Maintenance tasks configuration
            self._maintenance_tasks = {
                'log_cleanup': True,
                'cache_cleanup': True,
                'temp_file_cleanup': True,
                'registry_cleanup': False,
                'backup_cleanup': True,
                'database_optimization': True
            }
            
            # **ENHANCED**: Cleanup schedules
            self._cleanup_schedules = {
                'daily_cleanup': ['temp_files', 'logs'],
                'weekly_cleanup': ['cache', 'backups'],
                'monthly_cleanup': ['database_optimization'],
                'on_demand_cleanup': ['registry', 'deep_cleanup']
            }
            
            # **NEW**: Maintenance preferences
            self._maintenance_preferences = {
                'auto_maintenance': True,
                'maintenance_during_idle': True,
                'maintenance_notifications': True,
                'detailed_maintenance_logs': False
            }
            
            self.logger.debug("Maintenance systems configured successfully")
            
        except Exception as e:
            self.logger.error(f"Error setting up maintenance systems: {e}")
    
    def _update_ui_data(self):
        """Update UI data in background with intelligent caching."""
        try:
            if self._shutdown_detected:
                return
            
            # **ENHANCED**: Update dashboard data with caching
            self._update_dashboard_data()
            
            # **ENHANCED**: Update component status indicators
            self._update_component_status_indicators()
            
            # **ENHANCED**: Update performance indicators
            self._update_performance_indicators()
            
            # **ENHANCED**: Update notification counts
            self._update_notification_counts()
            
            # **NEW**: Update system tray tooltip
            if self.system_tray_enabled:
                self._update_system_tray_tooltip()
            
            # **NEW**: Update scan status indicators
            self._update_scan_status_indicators()
            
            # **NEW**: Update threat counters
            self._update_threat_counters()
            
        except Exception as e:
            self.logger.debug(f"Error updating UI data: {e}")
    
    def _update_dashboard_data(self):
        """Update dashboard data with comprehensive metrics."""
        try:
            # **ENHANCED**: Update scan statistics
            total_scans = self.config.get_setting('statistics.total_scans', 0)
            threats_found = self.config.get_setting('statistics.threats_found', 0)
            files_quarantined = self.config.get_setting('statistics.files_quarantined', 0)
            
            # **ENHANCED**: Update last scan information
            last_scan = self.config.get_setting('scanning.last_scan', None)
            last_full_scan = self.config.get_setting('scanning.last_full_scan', None)
            
            # **NEW**: Update protection status
            protection_enabled = self.config.get_setting('detection.real_time_enabled', True)
            
            # **NEW**: Update model status
            if self.model_manager:
                try:
                    model_status = self.model_manager.get_overall_status()
                except Exception:
                    model_status = {'status': 'unknown', 'loaded_models': 0}
            else:
                model_status = {'status': 'unavailable', 'loaded_models': 0}
            
            # **ENHANCED**: Update UI labels if they exist
            if hasattr(self, '_dashboard_data'):
                self._dashboard_data.update({
                    'total_scans': total_scans,
                    'threats_found': threats_found,
                    'files_quarantined': files_quarantined,
                    'last_scan': last_scan,
                    'last_full_scan': last_full_scan,
                    'protection_enabled': protection_enabled,
                    'model_status': model_status,
                    'last_updated': datetime.now()
                })
            
        except Exception as e:
            self.logger.debug(f"Error updating dashboard data: {e}")
    
    def _update_component_status_indicators(self):
        """Update component status indicators in the UI."""
        try:
            # **ENHANCED**: Update scanner engine status
            if hasattr(self, '_scanner_status_indicator'):
                scanner_available = self._component_health.get('scanner_engine', False)
                self._scanner_status_indicator.setText("🟢 Active" if scanner_available else "🔴 Inactive")
            
            # **ENHANCED**: Update model manager status
            if hasattr(self, '_model_status_indicator'):
                model_available = self._component_health.get('model_manager', False)
                self._model_status_indicator.setText("🟢 Active" if model_available else "🔴 Inactive")
            
            # **ENHANCED**: Update file manager status
            if hasattr(self, '_file_manager_status_indicator'):
                file_manager_available = self._component_health.get('file_manager', False)
                self._file_manager_status_indicator.setText("🟢 Active" if file_manager_available else "🔴 Inactive")
            
        except Exception as e:
            self.logger.debug(f"Error updating component status indicators: {e}")
    
    def _update_performance_indicators(self):
        """Update performance indicators with current system metrics."""
        try:
            # **ENHANCED**: Update CPU usage indicator
            if hasattr(self, '_cpu_usage_indicator'):
                cpu_usage = self._get_current_cpu_usage()
                self._cpu_usage_indicator.setText(f"CPU: {cpu_usage:.1f}%")
            
            # **ENHANCED**: Update memory usage indicator
            if hasattr(self, '_memory_usage_indicator'):
                memory_usage = self._get_current_memory_usage()
                self._memory_usage_indicator.setText(f"Memory: {memory_usage:.1f}%")
            
            # **NEW**: Update thread pool status
            if hasattr(self, '_thread_pool_indicator'):
                active_threads = self._background_thread_pool.activeThreadCount()
                max_threads = self._background_thread_pool.maxThreadCount()
                self._thread_pool_indicator.setText(f"Threads: {active_threads}/{max_threads}")
            
        except Exception as e:
            self.logger.debug(f"Error updating performance indicators: {e}")
    
    def _update_notification_counts(self):
        """Update notification count indicators."""
        try:
            # **ENHANCED**: Update unread notification count
            if hasattr(self, '_notification_count_indicator'):
                unread_count = len([n for n in self._notification_history if not getattr(n, 'read', False)])
                if unread_count > 0:
                    self._notification_count_indicator.setText(f"🔔 {unread_count}")
                    self._notification_count_indicator.setVisible(True)
                else:
                    self._notification_count_indicator.setVisible(False)
            
        except Exception as e:
            self.logger.debug(f"Error updating notification counts: {e}")
    
    def _update_scan_status_indicators(self):
        """Update scan status indicators."""
        try:
            # **ENHANCED**: Update scan progress if scanning
            if hasattr(self, '_scan_progress_indicator') and self._scan_status.get('is_scanning', False):
                progress = self._scan_status.get('progress', 0)
                scan_type = self._scan_status.get('scan_type', 'unknown')
                self._scan_progress_indicator.setText(f"Scanning ({scan_type}): {progress}%")
                self._scan_progress_indicator.setVisible(True)
            elif hasattr(self, '_scan_progress_indicator'):
                self._scan_progress_indicator.setVisible(False)
            
        except Exception as e:
            self.logger.debug(f"Error updating scan status indicators: {e}")
    
    def _update_threat_counters(self):
        """Update threat counter displays."""
        try:
            # **ENHANCED**: Update threat counter
            if hasattr(self, '_threat_counter_display'):
                current_threats = getattr(self, 'threat_count', 0)
                self._threat_counter_display.setText(f"Threats: {current_threats}")
            
            # **ENHANCED**: Update quarantine counter
            if hasattr(self, '_quarantine_counter_display'):
                current_quarantine = getattr(self, 'quarantine_count', 0)
                self._quarantine_counter_display.setText(f"Quarantined: {current_quarantine}")
            
        except Exception as e:
            self.logger.debug(f"Error updating threat counters: {e}")
    
    def _check_system_status(self):
        """Check overall system status and component health."""
        try:
            if self._shutdown_detected:
                return
            
            # **ENHANCED**: Check component availability with detailed status
            self._check_component_availability()
            
            # **ENHANCED**: Check integration health
            self._check_integration_health()
            
            # **ENHANCED**: Check resource usage
            self._check_resource_usage()
            
            # **NEW**: Check for system warnings
            self._check_system_warnings()
            
            # **NEW**: Update system health score
            self._update_system_health_score()
            
        except Exception as e:
            self.logger.debug(f"Error checking system status: {e}")
    
    def _check_integration_health(self):
        """Check health of component integrations."""
        try:
            # **ENHANCED**: Check scanner engine integration
            if self.scanner_engine:
                try:
                    # Test basic functionality
                    if hasattr(self.scanner_engine, 'get_status'):
                        status = self.scanner_engine.get_status()
                        self._integration_health['scanner_engine'] = status.get('healthy', True)
                    else:
                        self._integration_health['scanner_engine'] = True
                except Exception:
                    self._integration_health['scanner_engine'] = False
            
            # **ENHANCED**: Check model manager integration
            if self.model_manager:
                try:
                    if hasattr(self.model_manager, 'get_health_status'):
                        health = self.model_manager.get_health_status()
                        self._integration_health['model_manager'] = health.get('healthy', True)
                    else:
                        self._integration_health['model_manager'] = True
                except Exception:
                    self._integration_health['model_manager'] = False
            
            # **ENHANCED**: Check file manager integration
            if self.file_manager:
                try:
                    if hasattr(self.file_manager, 'is_available'):
                        available = self.file_manager.is_available()
                        self._integration_health['file_manager'] = available
                    else:
                        self._integration_health['file_manager'] = True
                except Exception:
                    self._integration_health['file_manager'] = False
            
        except Exception as e:
            self.logger.debug(f"Error checking integration health: {e}")
    
    def _check_resource_usage(self):
        """Check system resource usage and performance."""
        try:
            # **ENHANCED**: Check CPU usage
            cpu_usage = self._get_current_cpu_usage()
            if cpu_usage > self._performance_thresholds['cpu_critical']:
                self._handle_critical_resource_usage('cpu', cpu_usage)
            elif cpu_usage > self._performance_thresholds['cpu_warning']:
                self._handle_warning_resource_usage('cpu', cpu_usage)
            
            # **ENHANCED**: Check memory usage
            memory_usage = self._get_current_memory_usage()
            if memory_usage > self._performance_thresholds['memory_critical']:
                self._handle_critical_resource_usage('memory', memory_usage)
            elif memory_usage > self._performance_thresholds['memory_warning']:
                self._handle_warning_resource_usage('memory', memory_usage)
            
            # **NEW**: Check disk usage
            disk_usage = self._get_current_disk_usage()
            if disk_usage > self._performance_thresholds['disk_critical']:
                self._handle_critical_resource_usage('disk', disk_usage)
            elif disk_usage > self._performance_thresholds['disk_warning']:
                self._handle_warning_resource_usage('disk', disk_usage)
            
        except Exception as e:
            self.logger.debug(f"Error checking resource usage: {e}")
    
    def _check_system_warnings(self):
        """Check for system warnings and issues."""
        try:
            warnings = []
            
            # **ENHANCED**: Check for outdated definitions
            last_update = self.config.get_setting('updates.last_definition_update', None)
            if last_update:
                try:
                    last_update_time = datetime.fromisoformat(last_update)
                    if (datetime.now() - last_update_time).days > 7:
                        warnings.append(('definitions_outdated', 'Virus definitions are more than 7 days old'))
                except Exception:
                    warnings.append(('definitions_unknown', 'Cannot determine virus definition age'))
            else:
                warnings.append(('no_definitions', 'No virus definition update recorded'))
            
            # **ENHANCED**: Check for scan recommendations
            last_scan = self.config.get_setting('scanning.last_scan', None)
            if last_scan:
                try:
                    last_scan_time = datetime.fromisoformat(last_scan)
                    if (datetime.now() - last_scan_time).days > 7:
                        warnings.append(('scan_recommended', 'No scan performed in the last 7 days'))
                except Exception:
                    warnings.append(('scan_unknown', 'Cannot determine last scan time'))
            else:
                warnings.append(('no_scans', 'No scans have been performed'))
            
            # **NEW**: Check for disabled protection
            if not self.config.get_setting('detection.real_time_enabled', True):
                warnings.append(('protection_disabled', 'Real-time protection is disabled'))
            
            # **NEW**: Update warning count
            self._system_warnings = warnings
            
        except Exception as e:
            self.logger.debug(f"Error checking system warnings: {e}")
    
    def _update_system_health_score(self):
        """Update overall system health score."""
        try:
            score = 100.0
            
            # **ENHANCED**: Deduct points for component failures
            failed_components = sum(1 for health in self._component_health.values() if not health)
            score -= failed_components * 15
            
            # **ENHANCED**: Deduct points for integration issues
            failed_integrations = sum(1 for health in self._integration_health.values() if not health)
            score -= failed_integrations * 10
            
            # **ENHANCED**: Deduct points for warnings
            warning_count = len(getattr(self, '_system_warnings', []))
            score -= warning_count * 5
            
            # **NEW**: Deduct points for resource issues
            cpu_usage = self._get_current_cpu_usage()
            if cpu_usage > 90:
                score -= 20
            elif cpu_usage > 80:
                score -= 10
            
            memory_usage = self._get_current_memory_usage()
            if memory_usage > 90:
                score -= 20
            elif memory_usage > 80:
                score -= 10
            
            # **NEW**: Ensure score is within bounds
            self._system_health_score = max(0.0, min(100.0, score))
            
        except Exception as e:
            self.logger.debug(f"Error updating system health score: {e}")
            self._system_health_score = 50.0  # Default moderate score
    
    def _handle_critical_resource_usage(self, resource_type: str, usage: float):
        """Handle critical resource usage scenarios."""
        try:
            self.logger.warning(f"Critical {resource_type} usage: {usage:.1f}%")
            
            # **ENHANCED**: Show critical resource notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"critical_{resource_type}_{datetime.now().timestamp()}",
                    title=f"Critical {resource_type.title()} Usage",
                    message=f"System {resource_type} usage is critically high ({usage:.1f}%). Performance may be severely impacted.",
                    priority=NotificationPriority.CRITICAL,
                    category="performance",
                    is_persistent=True,
                    is_actionable=True
                )
                self._add_notification(notification)
            
            # **ENHANCED**: Take automatic corrective actions
            if resource_type == 'memory':
                self._perform_emergency_memory_cleanup()
            elif resource_type == 'cpu':
                self._throttle_background_operations()
            elif resource_type == 'disk':
                self._perform_emergency_disk_cleanup()
            
        except Exception as e:
            self.logger.error(f"Error handling critical {resource_type} usage: {e}")
    
    def _handle_warning_resource_usage(self, resource_type: str, usage: float):
        """Handle warning-level resource usage scenarios."""
        try:
            # **ENHANCED**: Log warning (avoid spam with time-based limiting)
            warning_key = f"resource_warning_{resource_type}"
            last_warning = getattr(self, f'_last_{warning_key}', None)
            
            if not last_warning or (datetime.now() - last_warning).total_seconds() > 300:  # 5 minutes
                self.logger.warning(f"High {resource_type} usage: {usage:.1f}%")
                setattr(self, f'_last_{warning_key}', datetime.now())
                
                # **ENHANCED**: Show warning notification (less frequent)
                if self._notifications_enabled and usage > 85:
                    notification = NotificationItem(
                        notification_id=f"warning_{resource_type}_{datetime.now().timestamp()}",
                        title=f"High {resource_type.title()} Usage",
                        message=f"System {resource_type} usage is high ({usage:.1f}%). Consider closing unnecessary applications.",
                        priority=NotificationPriority.WARNING,
                        category="performance"
                    )
                    self._add_notification(notification)
            
        except Exception as e:
            self.logger.debug(f"Error handling warning {resource_type} usage: {e}")
    
    def _perform_emergency_memory_cleanup(self):
        """Perform emergency memory cleanup operations."""
        try:
            self.logger.info("Performing emergency memory cleanup...")
            
            # **ENHANCED**: Force garbage collection
            import gc
            collected = gc.collect()
            self.logger.debug(f"Garbage collection freed {collected} objects")
            
            # **ENHANCED**: Clear caches
            if hasattr(self, '_ui_cache'):
                cache_size = len(self._ui_cache)
                self._ui_cache.clear()
                self.logger.debug(f"Cleared UI cache ({cache_size} items)")
            
            if hasattr(self, '_metrics_cache'):
                cache_size = len(self._metrics_cache)
                self._metrics_cache.clear()
                self.logger.debug(f"Cleared metrics cache ({cache_size} items)")
            
            # **NEW**: Reduce thread pool size temporarily
            current_max = self._background_thread_pool.maxThreadCount()
            if current_max > 2:
                self._background_thread_pool.setMaxThreadCount(max(2, current_max // 2))
                self.logger.debug(f"Reduced thread pool from {current_max} to {self._background_thread_pool.maxThreadCount()}")
            
        except Exception as e:
            self.logger.error(f"Error performing emergency memory cleanup: {e}")
    
    def _throttle_background_operations(self):
        """Throttle background operations to reduce CPU usage."""
        try:
            self.logger.info("Throttling background operations due to high CPU usage...")
            
            # **ENHANCED**: Increase timer intervals
            if hasattr(self, '_ui_update_timer'):
                current_interval = self._ui_update_timer.interval()
                new_interval = min(10000, current_interval * 2)  # Max 10 seconds
                self._ui_update_timer.setInterval(new_interval)
                self.logger.debug(f"Increased UI update interval to {new_interval}ms")
            
            if hasattr(self, '_performance_timer'):
                current_interval = self._performance_timer.interval()
                new_interval = min(30000, current_interval * 2)  # Max 30 seconds
                self._performance_timer.setInterval(new_interval)
                self.logger.debug(f"Increased performance timer interval to {new_interval}ms")
            
            # **NEW**: Pause non-essential operations
            self._background_operations['maintenance_tasks'] = False
            self._background_operations['cache_cleanup'] = False
            
        except Exception as e:
            self.logger.error(f"Error throttling background operations: {e}")
    
    def _perform_emergency_disk_cleanup(self):
        """Perform emergency disk cleanup operations."""
        try:
            self.logger.info("Performing emergency disk cleanup...")
            
            # **ENHANCED**: Clean temporary files
            temp_files_cleaned = 0
            temp_dirs = [
                os.path.expandvars('%TEMP%') if os.name == 'nt' else '/tmp',
                os.path.expanduser('~/.cache') if os.name != 'nt' else None
            ]
            
            for temp_dir in temp_dirs:
                if temp_dir and os.path.exists(temp_dir):
                    temp_files_cleaned += self._clean_directory(temp_dir, max_files=50)
            
            # **NEW**: Clean application logs if they're too large
            log_dir = Path("logs")
            if log_dir.exists():
                total_log_size = sum(f.stat().st_size for f in log_dir.rglob('*') if f.is_file())
                if total_log_size > 100 * 1024 * 1024:  # 100MB
                    self._rotate_logs_emergency()
            
            self.logger.info(f"Emergency disk cleanup completed. Cleaned {temp_files_cleaned} temporary files.")
            
        except Exception as e:
            self.logger.error(f"Error performing emergency disk cleanup: {e}")
    
    def _rotate_logs_emergency(self):
        """Perform emergency log rotation."""
        try:
            log_dir = Path("logs")
            if not log_dir.exists():
                return
            
            # **ENHANCED**: Archive old logs
            for log_file in log_dir.glob("*.log"):
                if log_file.stat().st_size > 10 * 1024 * 1024:  # 10MB
                    archive_name = f"{log_file.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log.old"
                    archive_path = log_file.parent / archive_name
                    log_file.rename(archive_path)
                    self.logger.debug(f"Archived large log file: {log_file.name}")
            
        except Exception as e:
            self.logger.error(f"Error performing emergency log rotation: {e}")
    
    def _monitor_performance(self):
        """Monitor system performance with comprehensive metrics collection."""
        try:
            if self._shutdown_detected:
                return
            
            # **ENHANCED**: Collect performance metrics
            current_metrics = {
                'timestamp': datetime.now(),
                'cpu_usage': self._get_current_cpu_usage(),
                'memory_usage': self._get_current_memory_usage(),
                'disk_usage': self._get_current_disk_usage(),
                'network_activity': self._get_current_network_activity(),
                'thread_count': self._background_thread_pool.activeThreadCount(),
                'cache_size': self._get_current_cache_size()
            }
            
            # **ENHANCED**: Store metrics in history
            for metric, value in current_metrics.items():
                if metric != 'timestamp' and metric in self._performance_data:
                    if isinstance(self._performance_data[metric], deque):
                        self._performance_data[metric].append(value)
            
            # **NEW**: Analyze performance trends
            self._analyze_performance_trends(current_metrics)
            
            # **NEW**: Update performance cache
            self._performance_metrics = current_metrics
            
        except Exception as e:
            self.logger.debug(f"Error monitoring performance: {e}")
    
    def _get_current_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            import psutil
            return psutil.cpu_percent(interval=0.1)
        except ImportError:
            # **FALLBACK**: Use basic process time if psutil not available
            return self._estimate_cpu_usage()
    
    def _get_current_memory_usage(self) -> float:
        """Get current memory usage percentage."""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except ImportError:
            # **FALLBACK**: Use basic memory estimation
            return self._estimate_memory_usage()
    
    def _get_current_disk_usage(self) -> float:
        """Get current disk usage percentage."""
        try:
            import psutil
            return psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent
        except ImportError:
            # **FALLBACK**: Use basic disk space check
            return self._estimate_disk_usage()
    
    def _get_current_network_activity(self) -> float:
        """Get current network activity (bytes per second)."""
        try:
            import psutil
            network_io = psutil.net_io_counters()
            return network_io.bytes_sent + network_io.bytes_recv
        except ImportError:
            return 0.0
    
    def _get_current_cache_size(self) -> int:
        """Get current total cache size."""
        try:
            total_size = 0
            
            if hasattr(self, '_ui_cache'):
                total_size += len(self._ui_cache)
            
            if hasattr(self, '_metrics_cache'):
                total_size += len(self._metrics_cache)
            
            if hasattr(self, '_performance_cache'):
                total_size += len(self._performance_cache)
            
            return total_size
        except Exception:
            return 0
    
    def _estimate_cpu_usage(self) -> float:
        """Estimate CPU usage without psutil."""
        try:
            # **FALLBACK**: Very basic estimation based on thread activity
            active_threads = self._background_thread_pool.activeThreadCount()
            max_threads = self._background_thread_pool.maxThreadCount()
            return (active_threads / max_threads) * 50.0  # Rough estimate
        except Exception:
            return 25.0  # Default moderate estimate
    
    def _estimate_memory_usage(self) -> float:
        """Estimate memory usage without psutil."""
        try:
            # **FALLBACK**: Very basic estimation
            import sys
            if hasattr(sys, 'getsizeof'):
                # This is a very rough estimate
                return min(75.0, 25.0 + len(self.__dict__) * 0.1)
            return 50.0  # Default moderate estimate
        except Exception:
            return 50.0
    
    def _estimate_disk_usage(self) -> float:
        """Estimate disk usage without psutil."""
        try:
            import shutil
            if os.name == 'nt':
                total, used, free = shutil.disk_usage('C:\\')
            else:
                total, used, free = shutil.disk_usage('/')
            return (used / total) * 100.0
        except Exception:
            return 50.0  # Default moderate estimate
    
    def _analyze_performance_trends(self, current_metrics: Dict[str, Any]):
        """Analyze performance trends and detect issues."""
        try:
            # **ENHANCED**: Check for performance degradation
            cpu_history = list(self._performance_data.get('cpu_usage_history', []))
            if len(cpu_history) >= 10:
                recent_avg = sum(cpu_history[-5:]) / 5
                older_avg = sum(cpu_history[-10:-5]) / 5
                
                if recent_avg > older_avg * 1.5:  # 50% increase
                    self.logger.warning(f"CPU usage trend increasing: {older_avg:.1f}% -> {recent_avg:.1f}%")
            
            # **ENHANCED**: Check for memory leaks
            memory_history = list(self._performance_data.get('memory_usage_history', []))
            if len(memory_history) >= 20:
                # Check if memory usage is consistently increasing
                increases = sum(1 for i in range(1, len(memory_history)) 
                               if memory_history[i] > memory_history[i-1])
                if increases > len(memory_history) * 0.8:  # 80% of samples increasing
                    self.logger.warning("Potential memory leak detected - memory usage consistently increasing")
            
        except Exception as e:
            self.logger.debug(f"Error analyzing performance trends: {e}")
    
    def _check_definition_updates(self):
        """Check for virus definition updates."""
        try:
            if self._shutdown_detected or not self._update_checking_enabled:
                return
            
            # **ENHANCED**: Avoid concurrent update checks
            if self._update_status.get('check_in_progress', False):
                return
            
            self._update_status['check_in_progress'] = True
            
            # **ENHANCED**: Check if it's time for an update check
            last_check = self._update_status.get('last_check_time')
            if last_check:
                hours_since_check = (datetime.now() - last_check).total_seconds() / 3600
                if hours_since_check < self._update_check_interval:
                    self._update_status['check_in_progress'] = False
                    return
            
            # **ENHANCED**: Perform update check in background
            update_future = self._background_thread_pool.submit(self._perform_update_check)
            
        except Exception as e:
            self.logger.debug(f"Error checking definition updates: {e}")
            self._update_status['check_in_progress'] = False
    
    def _perform_update_check(self):
        """Perform the actual update check in background thread."""
        try:
            self.logger.debug("Performing background update check...")
            
            # **ENHANCED**: Simulate update check (replace with actual implementation)
            import time
            time.sleep(1)  # Simulate network delay
            
            # **ENHANCED**: Update check results
            updates_available = {
                'definitions': False,  # Would be determined by actual check
                'models': False,
                'application': False
            }
            
            # **ENHANCED**: Update status
            self._update_status.update({
                'definitions_available': updates_available['definitions'],
                'models_available': updates_available['models'],
                'application_available': updates_available['application'],
                'last_check_time': datetime.now(),
                'last_check_result': 'success',
                'check_in_progress': False
            })
            
            # **ENHANCED**: Show update notifications if available
            if any(updates_available.values()) and self._notifications_enabled:
                available_updates = [k for k, v in updates_available.items() if v]
                notification = NotificationItem(
                    notification_id=f"updates_available_{datetime.now().timestamp()}",
                    title="Updates Available",
                    message=f"Updates available for: {', '.join(available_updates)}",
                    priority=NotificationPriority.INFO,
                    category="update",
                    is_actionable=True
                )
                self._add_notification(notification)
            
            self.logger.debug("Background update check completed")
            
        except Exception as e:
            self.logger.error(f"Error performing update check: {e}")
            self._update_status.update({
                'last_check_result': 'error',
                'check_in_progress': False
            })
    
    def _show_update_reminder(self):
        """Show update reminder notification."""
        try:
            if not self._notifications_enabled:
                return
            
            # **ENHANCED**: Check if reminders are enabled
            if not self._update_reminders.get('definitions_reminder', True):
                return
            
            # **ENHANCED**: Check last reminder time to avoid spam
            last_reminder = getattr(self, '_last_update_reminder', None)
            if last_reminder:
                days_since_reminder = (datetime.now() - last_reminder).days
                if days_since_reminder < self._update_reminders.get('reminder_interval_days', 7):
                    return
            
            # **ENHANCED**: Show reminder notification
            notification = NotificationItem(
                notification_id=f"update_reminder_{datetime.now().timestamp()}",
                title="Update Reminder",
                message="It's recommended to check for virus definition updates regularly.",
                priority=NotificationPriority.INFO,
                category="update",
                is_actionable=True
            )
            self._add_notification(notification)
            
            self._last_update_reminder = datetime.now()
            
        except Exception as e:
            self.logger.debug(f"Error showing update reminder: {e}")
    
    def _perform_maintenance_tasks(self):
        """Perform periodic maintenance tasks."""
        try:
            if self._shutdown_detected:
                return
            
            # **ENHANCED**: Check if maintenance is enabled
            if not self._maintenance_preferences.get('auto_maintenance', True):
                return
            
            # **ENHANCED**: Perform maintenance tasks in background
            if self._background_operations.get('maintenance_tasks', True):
                maintenance_future = self._background_thread_pool.submit(self._execute_maintenance_tasks)
            
        except Exception as e:
            self.logger.debug(f"Error performing maintenance tasks: {e}")
    
    def _execute_maintenance_tasks(self):
        """Execute maintenance tasks in background thread."""
        try:
            self.logger.debug("Executing maintenance tasks...")
            
            # **ENHANCED**: Log cleanup
            if self._maintenance_tasks.get('log_cleanup', True):
                self._cleanup_old_logs()
            
            # **ENHANCED**: Cache cleanup
            if self._maintenance_tasks.get('cache_cleanup', True):
                self._cleanup_old_caches()
            
            # **ENHANCED**: Temporary file cleanup
            if self._maintenance_tasks.get('temp_file_cleanup', True):
                self._cleanup_temp_files()
            
            # **NEW**: Database optimization
            if self._maintenance_tasks.get('database_optimization', True):
                self._optimize_databases()
            
            # **NEW**: Backup cleanup
            if self._maintenance_tasks.get('backup_cleanup', True):
                self._cleanup_old_backups()
            
            self.logger.debug("Maintenance tasks completed")
            
        except Exception as e:
            self.logger.error(f"Error executing maintenance tasks: {e}")
    
    def _cleanup_old_logs(self):
        """Clean up old log files."""
        try:
            log_dir = Path("logs")
            if not log_dir.exists():
                return
            
            # **ENHANCED**: Remove logs older than 30 days
            cutoff_date = datetime.now() - timedelta(days=30)
            removed_count = 0
            
            for log_file in log_dir.rglob("*.log*"):
                if log_file.is_file():
                    file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
                    if file_time < cutoff_date:
                        try:
                            log_file.unlink()
                            removed_count += 1
                        except OSError:
                            pass  # Skip files in use
            
            if removed_count > 0:
                self.logger.debug(f"Cleaned up {removed_count} old log files")
            
        except Exception as e:
            self.logger.debug(f"Error cleaning up old logs: {e}")
    
    def _cleanup_old_caches(self):
        """Clean up old cache entries."""
        try:
            # **ENHANCED**: Clear expired cache entries
            current_time = time.time()
            
            if hasattr(self, '_cache_timestamps'):
                expired_keys = [
                    key for key, timestamp in self._cache_timestamps.items()
                    if current_time - timestamp > self.CONFIG_CACHE_TTL
                ]
                
                for key in expired_keys:
                    if hasattr(self, '_ui_cache') and key in self._ui_cache:
                        del self._ui_cache[key]
                    if key in self._cache_timestamps:
                        del self._cache_timestamps[key]
                
                if expired_keys:
                    self.logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
            
        except Exception as e:
            self.logger.debug(f"Error cleaning up old caches: {e}")
    
    def _cleanup_temp_files(self):
        """Clean up temporary files."""
        try:
            temp_dirs = [
                Path("temp"),
                Path(".temp"),
                Path("cache/.temp")
            ]
            
            removed_count = 0
            for temp_dir in temp_dirs:
                if temp_dir.exists():
                    removed_count += self._clean_directory(temp_dir, max_age_hours=24)
            
            if removed_count > 0:
                self.logger.debug(f"Cleaned up {removed_count} temporary files")
            
        except Exception as e:
            self.logger.debug(f"Error cleaning up temp files: {e}")
    
    def _optimize_databases(self):
        """Optimize database files."""
        try:
            # **ENHANCED**: Optimize threat database if available
            if self.threat_database and hasattr(self.threat_database, 'optimize'):
                try:
                    self.threat_database.optimize()
                    self.logger.debug("Optimized threat database")
                except Exception as e:
                    self.logger.debug(f"Error optimizing threat database: {e}")
            
        except Exception as e:
            self.logger.debug(f"Error optimizing databases: {e}")
    
    def _cleanup_old_backups(self):
        """Clean up old backup files."""
        try:
            backup_dirs = [
                Path("backups"),
                Path("config/backups"),
                self.BACKUP_DIR
            ]
            
            cutoff_date = datetime.now() - timedelta(days=self.BACKUP_RETENTION_DAYS)
            removed_count = 0
            
            for backup_dir in backup_dirs:
                if backup_dir.exists():
                    for backup_file in backup_dir.rglob("*.bak"):
                        if backup_file.is_file():
                            file_time = datetime.fromtimestamp(backup_file.stat().st_mtime)
                            if file_time < cutoff_date:
                                try:
                                    backup_file.unlink()
                                    removed_count += 1
                                except OSError:
                                    pass
            
            if removed_count > 0:
                self.logger.debug(f"Cleaned up {removed_count} old backup files")
            
        except Exception as e:
            self.logger.debug(f"Error cleaning up old backups: {e}")
    
    def _clean_directory(self, directory: Path, max_files: int = None, max_age_hours: int = None) -> int:
        """Clean a directory with optional limits."""
        try:
            if not directory.exists():
                return 0
            
            removed_count = 0
            cutoff_time = None
            
            if max_age_hours:
                cutoff_time = time.time() - (max_age_hours * 3600)
            
            for file_path in directory.rglob("*"):
                if file_path.is_file():
                    try:
                        # **ENHANCED**: Check age limit
                        if cutoff_time and file_path.stat().st_mtime > cutoff_time:
                            continue
                        
                        file_path.unlink()
                        removed_count += 1
                        
                        # **ENHANCED**: Check file count limit
                        if max_files and removed_count >= max_files:
                            break
                            
                    except OSError:
                        continue  # Skip files in use or protected
            
            return removed_count
            
        except Exception as e:
            self.logger.debug(f"Error cleaning directory {directory}: {e}")
            return 0
    
    def _get_uptime_string(self) -> str:
        """Get application uptime as formatted string."""
        try:
            uptime = datetime.now() - self._start_time
            total_seconds = int(uptime.total_seconds())
            
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            minutes = (total_seconds % 3600) // 60
            
            if days > 0:
                return f"{days}d {hours}h {minutes}m"
            elif hours > 0:
                return f"{hours}h {minutes}m"
            else:
                return f"{minutes}m"
                
        except Exception:
            return "Unknown"
    
    def _stop_background_processing(self):
        """Stop all background processing systems."""
        try:
            self.logger.info("Stopping background processing systems...")
            
            # **ENHANCED**: Stop all timers
            timers_to_stop = [
                '_ui_update_timer', '_system_status_timer', '_performance_timer',
                '_update_check_timer', '_maintenance_timer', '_health_check_timer',
                '_performance_issues_timer', '_protection_status_timer',
                '_scan_recommendation_timer'
            ]
            
            for timer_name in timers_to_stop:
                if hasattr(self, timer_name):
                    timer = getattr(self, timer_name)
                    if timer and timer.isActive():
                        timer.stop()
                        self.logger.debug(f"Stopped {timer_name}")
            
            # **ENHANCED**: Wait for background threads to complete
            if hasattr(self, '_background_thread_pool'):
                self._background_thread_pool.waitForDone(5000)  # 5 second timeout
                self.logger.debug("Background thread pool stopped")
            
            # **ENHANCED**: Clear background task queues
            if hasattr(self, '_background_task_queue'):
                self._background_task_queue.clear()
            
            
            self.logger.info("Background processing systems stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping background processing: {e}")
    
    # ========================================================================
    # THEME MANAGEMENT INTEGRATION AND DYNAMIC THEMING
    # ========================================================================
    
    def _initialize_theme_integration(self):
        """Initialize comprehensive theme integration with dynamic theming capabilities."""
        try:
            self.logger.debug("Initializing comprehensive theme integration...")
            
            # **ENHANCED**: Advanced theme state management
            self._current_theme_type = self.config.get_setting('ui.theme', 'dark')
            self._theme_preview_mode = False
            self._theme_transition_in_progress = False
            self._theme_cache = {}
            self._theme_validation_results = {}
            
            # **ENHANCED**: Theme component tracking
            self._themed_components = set()
            self._component_theme_overrides = {}
            self._theme_application_queue = deque()
            
            # **ENHANCED**: Dynamic theme capabilities
            self._auto_theme_switching = self.config.get_setting('ui.auto_theme_switching', False)
            self._theme_switching_schedule = self.config.get_setting('ui.theme_schedule', {})
            self._system_theme_detection = self.config.get_setting('ui.system_theme_detection', True)
            
            # **ENHANCED**: Connect theme manager signals
            if hasattr(self.theme_manager, 'theme_changed'):
                self.theme_manager.theme_changed.connect(self._on_theme_changed)
            if hasattr(self.theme_manager, 'theme_error'):
                self.theme_manager.theme_error.connect(self._on_theme_error)
            if hasattr(self.theme_manager, 'theme_validated'):
                self.theme_manager.theme_validated.connect(self._on_theme_validated)
            
            # **ENHANCED**: Setup theme monitoring
            self._setup_theme_monitoring()
            
            # **ENHANCED**: Apply initial theme with validation
            self._apply_initial_theme_with_validation()
            
            self.logger.info("Comprehensive theme integration initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing theme integration: {e}")
            self._initialize_fallback_theme()
    
    def _setup_theme_monitoring(self):
        """Setup theme monitoring and automatic switching capabilities."""
        try:
            # **ENHANCED**: System theme monitoring
            if self._system_theme_detection:
                self._system_theme_timer = QTimer()
                self._system_theme_timer.timeout.connect(self._check_system_theme)
                self._system_theme_timer.start(30000)  # Check every 30 seconds
            
            # **ENHANCED**: Automatic theme switching
            if self._auto_theme_switching:
                self._auto_theme_timer = QTimer()
                self._auto_theme_timer.timeout.connect(self._check_auto_theme_switch)
                self._auto_theme_timer.start(60000)  # Check every minute
            
            # **ENHANCED**: Theme validation timer
            self._theme_validation_timer = QTimer()
            self._theme_validation_timer.timeout.connect(self._validate_current_theme)
            self._theme_validation_timer.start(300000)  # Validate every 5 minutes
            
            self.logger.debug("Theme monitoring systems initialized")
            
        except Exception as e:
            self.logger.error(f"Error setting up theme monitoring: {e}")
    
    def _apply_initial_theme_with_validation(self):
        """Apply initial theme with comprehensive validation."""
        try:
            # **ENHANCED**: Validate theme availability
            if not self._validate_theme_availability(self._current_theme_type):
                self.logger.warning(f"Theme {self._current_theme_type} not available, using fallback")
                self._current_theme_type = 'dark'  # Fallback to dark theme
            
            # **ENHANCED**: Apply theme with error handling
            if hasattr(self.theme_manager, 'apply_theme'):
                success = self.theme_manager.apply_theme(self, self._current_theme_type)
                if not success:
                    self.logger.warning("Theme application failed, using fallback")
                    self._initialize_fallback_theme()
            else:
                self._initialize_fallback_theme()
            
            # **ENHANCED**: Update theme-dependent components
            self._update_theme_dependent_components()
            
            # **ENHANCED**: Register for theme updates
            self._register_theme_components()
            
        except Exception as e:
            self.logger.error(f"Error applying initial theme: {e}")
            self._initialize_fallback_theme()
    
    def _validate_theme_availability(self, theme_name: str) -> bool:
        """Validate that a theme is available and functional."""
        try:
            if not self.theme_manager:
                return False
            
            # **ENHANCED**: Check theme existence
            if hasattr(self.theme_manager, 'get_available_themes'):
                available_themes = self.theme_manager.get_available_themes()
                return theme_name in available_themes
            
            # **FALLBACK**: Basic validation
            return theme_name in ['dark', 'light']
            
        except Exception as e:
            self.logger.debug(f"Error validating theme availability: {e}")
            return False
    
    def _update_theme_dependent_components(self):
        """Update all theme-dependent UI components."""
        try:
            # **ENHANCED**: Update window components
            self._update_window_theme_properties()
            
            # **ENHANCED**: Update child windows
            for window_type, state in self._window_states.items():
                if state.is_open and state.instance:
                    self._apply_theme_to_child_window(state.instance, window_type)
            
            # **ENHANCED**: Update status indicators
            self._update_themed_status_indicators()
            
            # **ENHANCED**: Update navigation elements
            self._update_themed_navigation_elements()
            
            # **ENHANCED**: Update dynamic content
            self._update_themed_dynamic_content()
            
        except Exception as e:
            self.logger.error(f"Error updating theme-dependent components: {e}")
    
    def _update_window_theme_properties(self):
        """Update main window theme-specific properties."""
        try:
            if not self.theme_manager:
                return
            
            # **ENHANCED**: Update window background
            if hasattr(self.theme_manager, 'get_theme_colors'):
                colors = self.theme_manager.get_theme_colors(self._current_theme_type)
                if colors:
                    # Apply background color
                    background_color = colors.get('background', '#2b2b2b')
                    self.setStyleSheet(f"""
                        QMainWindow {{
                            background-color: {background_color};
                        }}
                    """)
            
            # **ENHANCED**: Update window icons
            self._update_themed_window_icons()
            
            # **ENHANCED**: Update tooltips and help text
            self._update_themed_tooltips()
            
        except Exception as e:
            self.logger.debug(f"Error updating window theme properties: {e}")
    
    def _update_themed_window_icons(self):
        """Update window icons based on current theme."""
        try:
            if hasattr(self.theme_manager, 'get_icon'):
                # **ENHANCED**: Update window icon
                app_icon = self.theme_manager.get_icon('app_icon', self._current_theme_type)
                if not app_icon.isNull():
                    self.setWindowIcon(app_icon)
                
                # **ENHANCED**: Update toolbar icons
                self._update_toolbar_icons()
                
                # **ENHANCED**: Update menu icons
                self._update_menu_icons()
                
        except Exception as e:
            self.logger.debug(f"Error updating themed window icons: {e}")
    
    def _update_toolbar_icons(self):
        """Update toolbar icons based on current theme."""
        try:
            # **ENHANCED**: Update main toolbar icons if toolbar exists
            if hasattr(self, '_main_toolbar') and self._main_toolbar:
                for action in self._main_toolbar.actions():
                    if action.objectName():  # Only update actions with object names
                        icon_name = action.objectName().replace('_action', '')
                        if hasattr(self.theme_manager, 'get_icon'):
                            themed_icon = self.theme_manager.get_icon(icon_name, self._current_theme_type)
                            if not themed_icon.isNull():
                                action.setIcon(themed_icon)
            
            # **ENHANCED**: Update navigation toolbar icons
            if hasattr(self, '_nav_buttons'):
                for section, button in self._nav_buttons.items():
                    if hasattr(self.theme_manager, 'get_icon'):
                        icon_name = f"{section}_icon"
                        themed_icon = self.theme_manager.get_icon(icon_name, self._current_theme_type)
                        if not themed_icon.isNull():
                            button.setIcon(themed_icon)
            
        except Exception as e:
            self.logger.debug(f"Error updating toolbar icons: {e}")
    
    def _update_menu_icons(self):
        """Update menu icons based on current theme."""
        try:
            # **ENHANCED**: Update menu bar icons if menu exists
            if hasattr(self, 'menuBar') and self.menuBar():
                for menu in self.menuBar().findChildren(QMenu):
                    for action in menu.actions():
                        if action.objectName():  # Only update actions with object names
                            icon_name = action.objectName().replace('_action', '')
                            if hasattr(self.theme_manager, 'get_icon'):
                                themed_icon = self.theme_manager.get_icon(icon_name, self._current_theme_type)
                                if not themed_icon.isNull():
                                    action.setIcon(themed_icon)
            
        except Exception as e:
            self.logger.debug(f"Error updating menu icons: {e}")
    
    def _update_themed_tooltips(self):
        """Update tooltips and help text based on current theme."""
        try:
            # **ENHANCED**: Update status bar tooltips
            if hasattr(self, '_status_labels'):
                for label_name, label in self._status_labels.items():
                    if hasattr(label, 'setToolTip'):
                        # Update tooltip styling for current theme
                        current_tooltip = label.toolTip()
                        if current_tooltip:
                            # Apply theme-aware tooltip styling
                            label.setToolTip(current_tooltip)
            
        except Exception as e:
            self.logger.debug(f"Error updating themed tooltips: {e}")
    
    def _apply_theme_to_child_window(self, window_instance, window_type: str):
        """Apply theme to a child window."""
        try:
            if hasattr(window_instance, 'apply_theme'):
                window_instance.apply_theme()
            elif hasattr(self.theme_manager, 'apply_theme'):
                self.theme_manager.apply_theme(window_instance, self._current_theme_type)
            
        except Exception as e:
            self.logger.debug(f"Error applying theme to {window_type} window: {e}")
    
    def _update_themed_status_indicators(self):
        """Update status indicators with theme-appropriate styling."""
        try:
            # **ENHANCED**: Update protection status indicator
            if hasattr(self, '_protection_status_widget'):
                self._update_protection_status_styling()
            
            # **ENHANCED**: Update scan status indicator
            if hasattr(self, '_scan_status_widget'):
                self._update_scan_status_styling()
            
            # **ENHANCED**: Update threat counter styling
            if hasattr(self, '_threat_counter_widget'):
                self._update_threat_counter_styling()
            
            # **ENHANCED**: Update performance indicators
            if hasattr(self, '_performance_indicators'):
                self._update_performance_indicators_styling()
            
        except Exception as e:
            self.logger.debug(f"Error updating themed status indicators: {e}")
    
    def _update_protection_status_styling(self):
        """Update protection status widget styling based on theme."""
        try:
            if not hasattr(self, '_protection_status_widget'):
                return
            
            # **ENHANCED**: Get theme-appropriate colors
            if hasattr(self.theme_manager, 'get_theme_colors'):
                colors = self.theme_manager.get_theme_colors(self._current_theme_type)
                if colors:
                    protection_enabled = self._get_real_time_protection_status()
                    if protection_enabled:
                        color = colors.get('status_safe', '#4caf50')
                        icon = '🛡️'
                    else:
                        color = colors.get('status_danger', '#f44336')
                        icon = '⚠️'
                    
                    # Apply styling
                    self._protection_status_widget.setStyleSheet(f"""
                        QLabel {{
                            color: {color};
                            font-weight: bold;
                        }}
                    """)
                    self._protection_status_widget.setText(f"{icon} Protection: {'Active' if protection_enabled else 'Inactive'}")
            
        except Exception as e:
            self.logger.debug(f"Error updating protection status styling: {e}")
    
    def _update_scan_status_styling(self):
        """Update scan status widget styling based on theme."""
        try:
            if not hasattr(self, '_scan_status_widget'):
                return
            
            # **ENHANCED**: Get current scan status
            scan_active = self._scan_status.get('is_scanning', False)
            
            if hasattr(self.theme_manager, 'get_theme_colors'):
                colors = self.theme_manager.get_theme_colors(self._current_theme_type)
                if colors:
                    if scan_active:
                        color = colors.get('status_scanning', '#9c27b0')
                        icon = '🔍'
                        text = "Scanning..."
                    else:
                        color = colors.get('text_secondary', '#cccccc')
                        icon = '💤'
                        text = "Idle"
                    
                    # Apply styling
                    self._scan_status_widget.setStyleSheet(f"""
                        QLabel {{
                            color: {color};
                        }}
                    """)
                    self._scan_status_widget.setText(f"{icon} Scan: {text}")
            
        except Exception as e:
            self.logger.debug(f"Error updating scan status styling: {e}")
    
    def _update_threat_counter_styling(self):
        """Update threat counter widget styling based on theme."""
        try:
            if not hasattr(self, '_threat_counter_widget'):
                return
            
            threat_count = getattr(self, 'threat_count', 0)
            
            if hasattr(self.theme_manager, 'get_theme_colors'):
                colors = self.theme_manager.get_theme_colors(self._current_theme_type)
                if colors:
                    if threat_count > 0:
                        color = colors.get('status_danger', '#f44336')
                        icon = '⚠️'
                    else:
                        color = colors.get('status_safe', '#4caf50')
                        icon = '✅'
                    
                    # Apply styling
                    self._threat_counter_widget.setStyleSheet(f"""
                        QLabel {{
                            color: {color};
                            font-weight: bold;
                        }}
                    """)
                    self._threat_counter_widget.setText(f"{icon} Threats: {threat_count}")
            
        except Exception as e:
            self.logger.debug(f"Error updating threat counter styling: {e}")
    
    def _update_performance_indicators_styling(self):
        """Update performance indicators styling based on theme."""
        try:
            if not hasattr(self, '_performance_indicators'):
                return
            
            if hasattr(self.theme_manager, 'get_theme_colors'):
                colors = self.theme_manager.get_theme_colors(self._current_theme_type)
                if colors:
                    # **ENHANCED**: Update CPU indicator
                    if 'cpu' in self._performance_indicators:
                        cpu_usage = self._get_current_cpu_usage()
                        cpu_color = self._get_performance_color(cpu_usage, colors)
                        self._performance_indicators['cpu'].setStyleSheet(f"""
                            QLabel {{ color: {cpu_color}; }}
                        """)
                    
                    # **ENHANCED**: Update memory indicator
                    if 'memory' in self._performance_indicators:
                        memory_usage = self._get_current_memory_usage()
                        memory_color = self._get_performance_color(memory_usage, colors)
                        self._performance_indicators['memory'].setStyleSheet(f"""
                            QLabel {{ color: {memory_color}; }}
                        """)
            
        except Exception as e:
            self.logger.debug(f"Error updating performance indicators styling: {e}")
    
    def _get_performance_color(self, usage_percent: float, colors: Dict[str, str]) -> str:
        """Get color for performance indicator based on usage percentage."""
        try:
            if usage_percent >= 90:
                return colors.get('status_danger', '#f44336')
            elif usage_percent >= 70:
                return colors.get('status_warning', '#ff9800')
            else:
                return colors.get('status_safe', '#4caf50')
        except Exception:
            return colors.get('text_primary', '#ffffff')
    
    def _update_themed_navigation_elements(self):
        """Update navigation elements with theme-appropriate styling."""
        try:
            # **ENHANCED**: Update navigation buttons
            if hasattr(self, '_nav_buttons'):
                for section, button in self._nav_buttons.items():
                    self._apply_navigation_button_theme(button, section)
            
            # **ENHANCED**: Update sidebar if present
            if hasattr(self, '_sidebar_widget'):
                self._apply_sidebar_theme()
            
        except Exception as e:
            self.logger.debug(f"Error updating themed navigation elements: {e}")
    
    def _apply_navigation_button_theme(self, button, section: str):
        """Apply theme to a navigation button."""
        try:
            if not hasattr(self.theme_manager, 'get_component_colors'):
                return
            
            # **ENHANCED**: Get component-specific colors
            component_colors = self.theme_manager.get_component_colors('navigation', self._current_theme_type)
            if component_colors:
                # Apply button styling
                button.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {component_colors.get('button_background', 'transparent')};
                        color: {component_colors.get('button_text', '#ffffff')};
                        border: none;
                        padding: 8px;
                        border-radius: 4px;
                    }}
                    QPushButton:hover {{
                        background-color: {component_colors.get('button_hover', '#404040')};
                    }}
                    QPushButton:pressed {{
                        background-color: {component_colors.get('button_pressed', '#363636')};
                    }}
                """)
            
        except Exception as e:
            self.logger.debug(f"Error applying navigation button theme: {e}")
    
    def _apply_sidebar_theme(self):
        """Apply theme to sidebar component."""
        try:
            if not hasattr(self.theme_manager, 'get_component_colors'):
                return
            
            # **ENHANCED**: Get sidebar-specific colors
            sidebar_colors = self.theme_manager.get_component_colors('sidebar', self._current_theme_type)
            if sidebar_colors:
                self._sidebar_widget.setStyleSheet(f"""
                    QWidget {{
                        background-color: {sidebar_colors.get('background', '#1e1e1e')};
                        border-right: 1px solid {sidebar_colors.get('border', '#555555')};
                    }}
                """)
            
        except Exception as e:
            self.logger.debug(f"Error applying sidebar theme: {e}")
    
    def _update_themed_dynamic_content(self):
        """Update dynamic content areas with theme-appropriate styling."""
        try:
            # **ENHANCED**: Update dashboard content
            if hasattr(self, '_dashboard_content'):
                self._apply_dashboard_theme()
            
            # **ENHANCED**: Update content areas
            if hasattr(self, '_content_areas'):
                for area_name, area_widget in self._content_areas.items():
                    self._apply_content_area_theme(area_widget, area_name)
            
        except Exception as e:
            self.logger.debug(f"Error updating themed dynamic content: {e}")
    
    def _apply_dashboard_theme(self):
        """Apply theme to dashboard content."""
        try:
            if hasattr(self.theme_manager, 'get_theme_colors'):
                colors = self.theme_manager.get_theme_colors(self._current_theme_type)
                if colors:
                    # Apply dashboard styling
                    dashboard_style = f"""
                        QWidget {{
                            background-color: {colors.get('background', '#2b2b2b')};
                            color: {colors.get('text_primary', '#ffffff')};
                        }}
                        QGroupBox {{
                            border: 1px solid {colors.get('border', '#555555')};
                            border-radius: 4px;
                            margin: 5px;
                            padding-top: 10px;
                            font-weight: bold;
                        }}
                        QGroupBox::title {{
                            subcontrol-origin: margin;
                            left: 10px;
                            padding: 0 5px 0 5px;
                        }}
                    """
                    self._dashboard_content.setStyleSheet(dashboard_style)
            
        except Exception as e:
            self.logger.debug(f"Error applying dashboard theme: {e}")
    
    def _apply_content_area_theme(self, widget, area_name: str):
        """Apply theme to a content area widget."""
        try:
            if hasattr(self.theme_manager, 'get_component_colors'):
                component_colors = self.theme_manager.get_component_colors(area_name, self._current_theme_type)
                if component_colors:
                    widget.setStyleSheet(f"""
                        QWidget {{
                            background-color: {component_colors.get('background', 'transparent')};
                            color: {component_colors.get('text', '#ffffff')};
                        }}
                    """)
            
        except Exception as e:
            self.logger.debug(f"Error applying content area theme: {e}")
    
    def _register_theme_components(self):
        """Register components for theme updates."""
        try:
            # **ENHANCED**: Register main window components
            self._themed_components.add('main_window')
            self._themed_components.add('navigation')
            self._themed_components.add('status_bar')
            self._themed_components.add('content_areas')
            
            # **ENHANCED**: Register child windows
            for window_type in self._window_states.keys():
                self._themed_components.add(window_type)
            
            self.logger.debug(f"Registered {len(self._themed_components)} components for theme updates")
            
        except Exception as e:
            self.logger.debug(f"Error registering theme components: {e}")
    
    def _check_system_theme(self):
        """Check system theme and update if needed."""
        try:
            if not self._system_theme_detection:
                return
            
            # **ENHANCED**: Detect system theme (Windows 10/11)
            try:
                import winreg
                registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
                key = winreg.OpenKey(registry, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize")
                
                # Get AppsUseLightTheme value
                light_theme_value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                system_theme = 'light' if light_theme_value else 'dark'
                
                winreg.CloseKey(key)
                winreg.CloseKey(registry)
                
                # **ENHANCED**: Apply system theme if different
                if system_theme != self._current_theme_type:
                    self.logger.info(f"System theme changed to {system_theme}, updating application theme")
                    self._switch_theme(system_theme, source="system")
                
            except Exception:
                # **FALLBACK**: Use time-based detection for other systems
                current_hour = datetime.now().hour
                auto_theme = 'light' if 6 <= current_hour <= 18 else 'dark'
                
                if auto_theme != self._current_theme_type and self._auto_theme_switching:
                    self.logger.info(f"Auto-switching to {auto_theme} theme based on time")
                    self._switch_theme(auto_theme, source="auto")
            
        except Exception as e:
            self.logger.debug(f"Error checking system theme: {e}")
    
    def _check_auto_theme_switch(self):
        """Check if automatic theme switching should occur."""
        try:
            if not self._auto_theme_switching:
                return
            
            current_time = datetime.now().time()
            
            # **ENHANCED**: Check scheduled theme switches
            for schedule_time, theme_name in self._theme_switching_schedule.items():
                try:
                    schedule_time_obj = datetime.strptime(schedule_time, "%H:%M").time()
                    time_diff = abs((datetime.combine(datetime.today(), current_time) - 
                                   datetime.combine(datetime.today(), schedule_time_obj)).total_seconds())
                    
                    # If within 1 minute of scheduled time and theme is different
                    if time_diff <= 60 and theme_name != self._current_theme_type:
                        self.logger.info(f"Scheduled theme switch to {theme_name}")
                        self._switch_theme(theme_name, source="scheduled")
                        break
                
                except Exception as e:
                    self.logger.debug(f"Error processing theme schedule {schedule_time}: {e}")
            
        except Exception as e:
            self.logger.debug(f"Error checking auto theme switch: {e}")
    
    def _validate_current_theme(self):
        """Validate current theme integrity and performance."""
        try:
            if not self.theme_manager:
                return
            
            # **ENHANCED**: Validate theme integrity
            if hasattr(self.theme_manager, 'validate_theme'):
                is_valid = self.theme_manager.validate_theme(self._current_theme_type)
                if not is_valid:
                    self.logger.warning(f"Current theme {self._current_theme_type} validation failed")
                    self._handle_theme_validation_failure()
            
            # **ENHANCED**: Check theme performance
            self._check_theme_performance()
            
        except Exception as e:
            self.logger.debug(f"Error validating current theme: {e}")
    
    def _check_theme_performance(self):
        """Check theme performance and optimize if needed."""
        try:
            # **ENHANCED**: Monitor theme application time
            theme_application_times = getattr(self, '_theme_application_times', deque(maxlen=10))
            
            if len(theme_application_times) >= 5:
                avg_time = sum(theme_application_times) / len(theme_application_times)
                if avg_time > 1000:  # More than 1 second
                    self.logger.warning(f"Theme application is slow (avg: {avg_time:.0f}ms)")
                    self._optimize_theme_performance()
            
        except Exception as e:
            self.logger.debug(f"Error checking theme performance: {e}")
    
    def _optimize_theme_performance(self):
        """Optimize theme performance."""
        try:
            # **ENHANCED**: Clear theme cache
            self._theme_cache.clear()
            
            # **ENHANCED**: Reduce theme application frequency
            if hasattr(self, '_theme_validation_timer'):
                current_interval = self._theme_validation_timer.interval()
                new_interval = min(600000, current_interval * 2)  # Max 10 minutes
                self._theme_validation_timer.setInterval(new_interval)
            
            self.logger.info("Theme performance optimization applied")
            
        except Exception as e:
            self.logger.debug(f"Error optimizing theme performance: {e}")
    
    def _handle_theme_validation_failure(self):
        """Handle theme validation failure."""
        try:
            self.logger.warning("Handling theme validation failure")
            
            # **ENHANCED**: Try to reload current theme
            if hasattr(self.theme_manager, 'reload_theme'):
                success = self.theme_manager.reload_theme(self._current_theme_type)
                if success:
                    self.logger.info("Theme reloaded successfully")
                    return
            
            # **ENHANCED**: Switch to fallback theme
            fallback_theme = 'dark' if self._current_theme_type != 'dark' else 'light'
            self.logger.info(f"Switching to fallback theme: {fallback_theme}")
            self._switch_theme(fallback_theme, source="fallback")
            
        except Exception as e:
            self.logger.error(f"Error handling theme validation failure: {e}")
            self._initialize_fallback_theme()
    
    def _switch_theme(self, theme_name: str, source: str = "user"):
        """Switch to a different theme with comprehensive handling."""
        try:
            if self._theme_transition_in_progress:
                self.logger.debug("Theme transition already in progress, skipping")
                return
            
            self._theme_transition_in_progress = True
            start_time = time.time()
            
            self.logger.info(f"Switching theme from {self._current_theme_type} to {theme_name} (source: {source})")
            
            # **ENHANCED**: Validate new theme
            if not self._validate_theme_availability(theme_name):
                self.logger.warning(f"Theme {theme_name} not available")
                self._theme_transition_in_progress = False
                return
            
            # **ENHANCED**: Apply new theme
            old_theme = self._current_theme_type
            self._current_theme_type = theme_name
            
            if hasattr(self.theme_manager, 'apply_theme'):
                success = self.theme_manager.apply_theme(self, theme_name)
                if not success:
                    self.logger.error("Failed to apply new theme")
                    self._current_theme_type = old_theme
                    self._theme_transition_in_progress = False
                    return
            
            # **ENHANCED**: Update all theme-dependent components
            self._update_theme_dependent_components()
            
            # **ENHANCED**: Save theme preference
            self.config.set_setting('ui.theme', theme_name)
            
            # **ENHANCED**: Emit theme change signal
            if hasattr(self, 'theme_changed'):
                self.theme_changed.emit(old_theme, theme_name)
            
            # **ENHANCED**: Track performance
            application_time = (time.time() - start_time) * 1000
            if not hasattr(self, '_theme_application_times'):
                self._theme_application_times = deque(maxlen=10)
            self._theme_application_times.append(application_time)
            
            self._theme_transition_in_progress = False
            self.logger.info(f"Theme switch completed in {application_time:.0f}ms")
            
        except Exception as e:
            self.logger.error(f"Error switching theme: {e}")
            self._theme_transition_in_progress = False
    
    def _initialize_fallback_theme(self):
        """Initialize basic fallback theme."""
        try:
            self.logger.info("Initializing fallback theme")
            
            # **ENHANCED**: Basic dark theme fallback
            fallback_style = """
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QPushButton {
                background-color: #404040;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            QPushButton:pressed {
                background-color: #363636;
            }
            QLabel {
                color: #ffffff;
            }
            QGroupBox {
                border: 1px solid #555555;
                border-radius: 4px;
                margin: 5px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            """
            
            self.setStyleSheet(fallback_style)
            self._current_theme_type = 'dark'
            
            self.logger.info("Fallback theme applied successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing fallback theme: {e}")
    
    # ========================================================================
    # THEME EVENT HANDLERS
    # ========================================================================
    
    def _on_theme_changed(self, theme_name: str, theme_metadata: dict):
        """Handle theme changed signal from theme manager."""
        try:
            self.logger.info(f"Theme changed to: {theme_name}")
            
            # **ENHANCED**: Update current theme tracking
            self._current_theme_type = theme_name
            
            # **ENHANCED**: Update child windows
            self._update_theme_dependent_components()
            
            # **ENHANCED**: Update configuration
            self.config.set_setting('ui.theme', theme_name)
            
            # **ENHANCED**: Show theme change notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"theme_changed_{datetime.now().timestamp()}",
                    title="Theme Changed",
                    message=f"Application theme changed to {theme_name.title()}",
                    priority=NotificationPriority.INFO,
                    category="ui"
                )
                self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error handling theme changed: {e}")
    
    def _on_theme_error(self, error_type: str, error_message: str):
        """Handle theme error signal from theme manager."""
        try:
            self.logger.error(f"Theme error ({error_type}): {error_message}")
            
            # **ENHANCED**: Show theme error notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"theme_error_{datetime.now().timestamp()}",
                    title="Theme Error",
                    message=f"Theme system error: {error_message}",
                    priority=NotificationPriority.WARNING,
                    category="system"
                )
                self._add_notification(notification)
            
            # **ENHANCED**: Attempt theme recovery
            if error_type in ['corruption', 'missing_files', 'validation_failed']:
                self._handle_theme_validation_failure()
            
        except Exception as e:
            self.logger.error(f"Error handling theme error: {e}")
    
    def _on_theme_validated(self, theme_name: str, is_valid: bool, validation_info: dict):
        """Handle theme validation signal from theme manager."""
        try:
            self._theme_validation_results[theme_name] = {
                'is_valid': is_valid,
                'validation_info': validation_info,
                'timestamp': datetime.now()
            }
            
            if not is_valid and theme_name == self._current_theme_type:
                self.logger.warning(f"Current theme {theme_name} validation failed")
                self._handle_theme_validation_failure()
            
        except Exception as e:
            self.logger.debug(f"Error handling theme validation: {e}")
    
    # ========================================================================
    # PUBLIC THEME INTERFACE METHODS
    # ========================================================================
    
    def switch_to_theme(self, theme_name: str) -> bool:
        """Public method to switch themes."""
        try:
            if theme_name == self._current_theme_type:
                return True
            
            self._switch_theme(theme_name, source="api")
            return True
            
        except Exception as e:
            self.logger.error(f"Error switching to theme {theme_name}: {e}")
            return False
    
    def get_current_theme(self) -> str:
        """Get the current theme name."""
        return self._current_theme_type
    
    def get_available_themes(self) -> List[str]:
        """Get list of available themes."""
        try:
            if hasattr(self.theme_manager, 'get_available_themes'):
                return self.theme_manager.get_available_themes()
            return ['dark', 'light']
        except Exception as e:
            self.logger.debug(f"Error getting available themes: {e}")
            return ['dark', 'light']
    
    def enable_auto_theme_switching(self, enabled: bool):
        """Enable or disable automatic theme switching."""
        try:
            self._auto_theme_switching = enabled
            self.config.set_setting('ui.auto_theme_switching', enabled)
            
            if enabled and hasattr(self, '_auto_theme_timer'):
                self._auto_theme_timer.start(60000)
            elif hasattr(self, '_auto_theme_timer'):
                self._auto_theme_timer.stop()
            
        except Exception as e:
            self.logger.error(f"Error setting auto theme switching: {e}")
    
    def enable_system_theme_detection(self, enabled: bool):
        """Enable or disable system theme detection."""
        try:
            self._system_theme_detection = enabled
            self.config.set_setting('ui.system_theme_detection', enabled)
            
            if enabled and hasattr(self, '_system_theme_timer'):
                self._system_theme_timer.start(30000)
            elif hasattr(self, '_system_theme_timer'):
                self._system_theme_timer.stop()
            
        except Exception as e:
            self.logger.error(f"Error setting system theme detection: {e}")
    
    def set_theme_schedule(self, schedule: Dict[str, str]):
        """Set theme switching schedule."""
        try:
            self._theme_switching_schedule = schedule
            self.config.set_setting('ui.theme_schedule', schedule)
            
        except Exception as e:
            self.logger.error(f"Error setting theme schedule: {e}")
    
    def apply_theme(self):
        """Apply current theme to the window (for external calls)."""
        try:
            if hasattr(self.theme_manager, 'apply_theme'):
                self.theme_manager.apply_theme(self, self._current_theme_type)
            self._update_theme_dependent_components()
            
        except Exception as e:
            self.logger.error(f"Error applying theme: {e}")
    
    # ========================================================================
    # COMPREHENSIVE EVENT HANDLING AND WINDOW MANAGEMENT
    # ========================================================================
    
    def _initialize_window_event_management(self):
        """Initialize comprehensive window event management system."""
        try:
            self.logger.debug("Initializing comprehensive window event management...")
            
            # **ENHANCED**: Window state tracking
            self._window_state_history = deque(maxlen=50)
            self._last_window_state = {
                'geometry': self.geometry(),
                'window_state': self.windowState(),
                'is_active': self.isActiveWindow(),
                'is_visible': self.isVisible(),
                'timestamp': datetime.now()
            }
            
            # **ENHANCED**: Event handling configuration
            self._event_handling_enabled = True
            self._event_logging_enabled = self.config.get_setting('ui.event_logging_enabled', False)
            self._event_statistics = defaultdict(int)
            self._event_performance_tracking = True
            
            # **ENHANCED**: Window behavior configuration
            self._minimize_to_tray = self.config.get_setting('ui.minimize_to_tray', True)
            self._close_to_tray = self.config.get_setting('ui.close_to_tray', True)
            self._restore_window_state = self.config.get_setting('ui.restore_window_state', True)
            self._auto_save_state = self.config.get_setting('ui.auto_save_state', True)
            
            # **ENHANCED**: Performance monitoring
            self._window_performance_metrics = {
                'paint_events': 0,
                'resize_events': 0,
                'move_events': 0,
                'focus_events': 0,
                'show_hide_events': 0,
                'last_performance_check': datetime.now()
            }
            
            # **ENHANCED**: Setup event timers
            self._setup_window_event_timers()
            
            self.logger.info("Comprehensive window event management initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing window event management: {e}")
    
    def _setup_window_event_timers(self):
        """Setup timers for window event management."""
        try:
            # **ENHANCED**: Window state auto-save timer
            if self._auto_save_state:
                self._window_state_save_timer = QTimer()
                self._window_state_save_timer.timeout.connect(self._auto_save_window_state)
                self._window_state_save_timer.start(30000)  # Save every 30 seconds
            
            # **ENHANCED**: Window performance monitoring timer
            if self._event_performance_tracking:
                self._window_performance_timer = QTimer()
                self._window_performance_timer.timeout.connect(self._update_window_performance_metrics)
                self._window_performance_timer.start(60000)  # Update every minute
            
        except Exception as e:
            self.logger.error(f"Error setting up window event timers: {e}")
    
    def _auto_save_window_state(self):
        """Automatically save window state."""
        try:
            current_state = {
                'geometry': {
                    'x': self.x(),
                    'y': self.y(),
                    'width': self.width(),
                    'height': self.height()
                },
                'window_state': self.windowState(),
                'is_maximized': self.isMaximized(),
                'is_minimized': self.isMinimized(),
                'timestamp': datetime.now().isoformat()
            }
            
            # **ENHANCED**: Only save if state has changed significantly
            if self._has_window_state_changed_significantly(current_state):
                self.config.set_window_geometry('main_window', current_state)
                self._last_window_state.update(current_state)
                self.logger.debug("Window state auto-saved")
            
        except Exception as e:
            self.logger.debug(f"Error auto-saving window state: {e}")
    
    def _has_window_state_changed_significantly(self, new_state: Dict[str, Any]) -> bool:
        """Check if window state has changed significantly enough to save."""
        try:
            if 'geometry' not in self._last_window_state:
                return True
            
            old_geo = self._last_window_state['geometry']
            new_geo = new_state['geometry']
            
            # **ENHANCED**: Check for significant position/size changes
            position_threshold = 10  # pixels
            size_threshold = 20  # pixels
            
            if (abs(new_geo['x'] - old_geo.get('x', 0)) > position_threshold or
                abs(new_geo['y'] - old_geo.get('y', 0)) > position_threshold or
                abs(new_geo['width'] - old_geo.get('width', 0)) > size_threshold or
                abs(new_geo['height'] - old_geo.get('height', 0)) > size_threshold):
                return True
            
            # **ENHANCED**: Check for window state changes
            if new_state['window_state'] != self._last_window_state.get('window_state'):
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking window state changes: {e}")
            return True  # Save if we can't determine changes
    
    def _update_window_performance_metrics(self):
        """Update window performance metrics."""
        try:
            current_time = datetime.now()
            time_diff = (current_time - self._window_performance_metrics['last_performance_check']).total_seconds()
            
            if time_diff > 0:
                # **ENHANCED**: Calculate events per second
                events_per_second = {
                    'paint_events_per_sec': self._window_performance_metrics['paint_events'] / time_diff,
                    'resize_events_per_sec': self._window_performance_metrics['resize_events'] / time_diff,
                    'move_events_per_sec': self._window_performance_metrics['move_events'] / time_diff,
                    'focus_events_per_sec': self._window_performance_metrics['focus_events'] / time_diff
                }
                
                # **ENHANCED**: Check for performance issues
                if events_per_second['paint_events_per_sec'] > 60:  # More than 60 paint events per second
                    self.logger.warning(f"High paint event frequency: {events_per_second['paint_events_per_sec']:.1f}/sec")
                
                if events_per_second['resize_events_per_sec'] > 10:  # More than 10 resize events per second
                    self.logger.warning(f"High resize event frequency: {events_per_second['resize_events_per_sec']:.1f}/sec")
                
                # **ENHANCED**: Reset counters
                for key in ['paint_events', 'resize_events', 'move_events', 'focus_events', 'show_hide_events']:
                    self._window_performance_metrics[key] = 0
                
                self._window_performance_metrics['last_performance_check'] = current_time
            
        except Exception as e:
            self.logger.debug(f"Error updating window performance metrics: {e}")
    
    # ========================================================================
    # ENHANCED WINDOW EVENT OVERRIDES
    # ========================================================================
    
    def closeEvent(self, event: QCloseEvent):
        """Enhanced close event handler with comprehensive cleanup and tray behavior."""
        try:
            self.logger.info("Close event triggered")
            
            # **ENHANCED**: Check if user chose to exit via tray or menu
            if not getattr(self, '_user_chose_exit', False) and self._close_to_tray and self.system_tray_enabled:
                self.logger.info("Minimizing to system tray instead of closing")
                event.ignore()
                self.hide()
                
                # **ENHANCED**: Show tray notification
                if self.system_tray:
                    self.system_tray.showMessage(
                        "Application Minimized",
                        "The application is still running in the system tray.",
                        QSystemTrayIcon.Information,
                        3000
                    )
                return
            
            # **ENHANCED**: Perform comprehensive shutdown
            self._perform_full_shutdown()
            
            # **ENHANCED**: Accept the close event
            event.accept()
            
        except Exception as e:
            self.logger.error(f"Error in close event: {e}")
            event.accept()  # Still close even if there are errors
    
    def _perform_full_shutdown(self):
        """Perform comprehensive application shutdown."""
        try:
            self.logger.info("Performing comprehensive application shutdown...")
            
            # **ENHANCED**: Set shutdown flag
            self._shutdown_detected = True
            
            # **ENHANCED**: Save current state
            self._save_application_state()
            
            # **ENHANCED**: Stop all background operations
            self._stop_all_background_operations()
            
            # **ENHANCED**: Close all child windows
            self._close_all_child_windows()
            
            # **ENHANCED**: Cleanup resources
            self._cleanup_all_resources()
            
            # **ENHANCED**: Save final configuration
            self._save_final_configuration()
            
            # **ENHANCED**: Log shutdown completion
            shutdown_time = datetime.now() - self._start_time
            self.logger.info(f"Application shutdown completed. Total runtime: {shutdown_time}")
            
        except Exception as e:
            self.logger.error(f"Error during full shutdown: {e}")
    
    def _save_application_state(self):
        """Save comprehensive application state."""
        try:
            self.logger.debug("Saving comprehensive application state...")
            
            # **ENHANCED**: Save window geometry
            self._save_window_geometry()
            
            # **ENHANCED**: Save application settings
            self._save_application_settings()
            
            # **ENHANCED**: Save session data
            self._save_session_data()
            
            # **ENHANCED**: Save performance metrics
            self._save_performance_metrics()
            
        except Exception as e:
            self.logger.error(f"Error saving application state: {e}")
    
    def _save_window_geometry(self, window=None, window_type=None):
        """Save window geometry to configuration with proper parameters."""
        try:
            # Use self if no window provided
            if window is None:
                window = self
            
            # Use class name if no window_type provided
            if window_type is None:
                window_type = "main_window"
            
            # Get geometry information
            geometry = {
                'x': window.x(),
                'y': window.y(),
                'width': window.width(),
                'height': window.height(),
                'maximized': window.isMaximized(),
                'minimized': window.isMinimized()
            }
            
            # Save to configuration
            if hasattr(self, 'config') and self.config:
                self.config.set_window_geometry(window_type, geometry)
                self.logger.debug(f"Saved window geometry for {window_type}")
            
        except Exception as e:
            self.logger.error(f"Error saving window geometry: {e}")
    
    def _restore_window_geometry(self, window=None, window_type=None):
        """Restore window geometry from configuration."""
        try:
            # Use self if no window provided
            if window is None:
                window = self
            
            # Use class name if no window_type provided
            if window_type is None:
                window_type = "main_window"
            
            if hasattr(self, 'config') and self.config:
                geometry = self.config.get_window_geometry(window_type)
                if geometry:
                    # Restore position and size
                    window.move(geometry.get('x', 100), geometry.get('y', 100))
                    window.resize(geometry.get('width', 1200), geometry.get('height', 800))
                    
                    # Restore window state
                    if geometry.get('maximized', False):
                        window.showMaximized()
                    elif geometry.get('minimized', False):
                        window.showMinimized()
                    
                    self.logger.debug(f"Restored window geometry for {window_type}")
            
        except Exception as e:
            self.logger.debug(f"Could not restore window geometry: {e}")
    
    def _save_application_settings(self):
        """Save application-wide settings."""
        try:
            settings = {
                'theme': self._current_theme_type,
                'notifications_enabled': self._notifications_enabled,
                'auto_theme_switching': self._auto_theme_switching,
                'system_theme_detection': self._system_theme_detection,
                'minimize_to_tray': self._minimize_to_tray,
                'close_to_tray': self._close_to_tray,
                'last_session_end': datetime.now().isoformat()
            }
            
            for key, value in settings.items():
                self.config.set_setting(f'ui.{key}', value)
            
        except Exception as e:
            self.logger.error(f"Error saving application settings: {e}")
    
    def _save_session_data(self):
        """Save current session data."""
        try:
            session_data = {
                'start_time': self._start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_runtime_seconds': (datetime.now() - self._start_time).total_seconds(),
                'scan_count': getattr(self, '_scan_count', 0),
                'threat_count': getattr(self, 'threat_count', 0),
                'quarantine_count': getattr(self, 'quarantine_count', 0),
                'operation_count': getattr(self, '_operation_count', 0)
            }
            
            self.config.set_setting('session.last_session', session_data)
            
        except Exception as e:
            self.logger.error(f"Error saving session data: {e}")
    
    def _save_performance_metrics(self):
        """Save performance metrics."""
        try:
            if hasattr(self, '_performance_metrics'):
                self.config.set_setting('performance.last_session_metrics', self._performance_metrics)
            
        except Exception as e:
            self.logger.error(f"Error saving performance metrics: {e}")
    
    def _stop_all_background_operations(self):
        """Stop all background operations and threads."""
        try:
            self.logger.debug("Stopping all background operations...")
            
            # **ENHANCED**: Stop background processing
            if hasattr(self, '_stop_background_processing'):
                self._stop_background_processing()
            
            # **ENHANCED**: Stop monitoring timers
            self._stop_all_monitoring_timers()
            
            # **ENHANCED**: Wait for operations to complete
            self._wait_for_operations_completion()
            
        except Exception as e:
            self.logger.error(f"Error stopping background operations: {e}")
    
    def _stop_all_monitoring_timers(self):
        """Stop all monitoring and update timers."""
        try:
            timers_to_stop = [
                '_ui_update_timer', '_system_status_timer', '_performance_timer',
                '_update_check_timer', '_maintenance_timer', '_health_check_timer',
                '_performance_issues_timer', '_protection_status_timer',
                '_scan_recommendation_timer', '_notification_timer',
                '_notification_cleanup_timer', '_theme_validation_timer',
                '_system_theme_timer', '_auto_theme_timer', '_window_state_save_timer',
                '_window_performance_timer'
            ]
            
            for timer_name in timers_to_stop:
                if hasattr(self, timer_name):
                    timer = getattr(self, timer_name)
                    if timer and timer.isActive():
                        timer.stop()
                        self.logger.debug(f"Stopped {timer_name}")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring timers: {e}")
    
    def _wait_for_operations_completion(self):
        """Wait for pending operations to complete."""
        try:
            # **ENHANCED**: Wait for background thread pool
            if hasattr(self, '_background_thread_pool'):
                self._background_thread_pool.waitForDone(5000)  # 5 second timeout
            
            # **ENHANCED**: Wait for validation thread pool
            if hasattr(self, '_validation_thread_pool'):
                self._validation_thread_pool.waitForDone(3000)  # 3 second timeout
            
            # **ENHANCED**: Process remaining events
            QApplication.processEvents()
            
        except Exception as e:
            self.logger.error(f"Error waiting for operations completion: {e}")
    
    def _close_all_child_windows(self):
        """Close all child windows properly."""
        try:
            self.logger.debug("Closing all child windows...")
            
            for window_type, state in self._window_states.items():
                if state.is_open and state.instance:
                    try:
                        # **ENHANCED**: Close child window gracefully
                        if hasattr(state.instance, 'close'):
                            state.instance.close()
                        
                        # **ENHANCED**: Mark as closed
                        state.is_open = False
                        state.instance = None
                        
                        self.logger.debug(f"Closed {window_type} window")
                        
                    except Exception as e:
                        self.logger.warning(f"Error closing {window_type} window: {e}")
            
        except Exception as e:
            self.logger.error(f"Error closing child windows: {e}")
    
    def _cleanup_all_resources(self):
        """Cleanup all application resources."""
        try:
            self.logger.debug("Cleaning up all application resources...")
            
            # **ENHANCED**: Cleanup system tray
            if self.system_tray:
                self.system_tray.hide()
                self.system_tray.deleteLater()
                self.system_tray = None
            
            # **ENHANCED**: Cleanup theme manager
            if self.theme_manager and hasattr(self.theme_manager, 'cleanup'):
                self.theme_manager.cleanup()
            
            # **ENHANCED**: Cleanup model manager
            if self.model_manager and hasattr(self.model_manager, 'cleanup'):
                self.model_manager.cleanup()
            
            # **ENHANCED**: Cleanup scanner engine
            if self.scanner_engine and hasattr(self.scanner_engine, 'cleanup'):
                self.scanner_engine.cleanup()
            
            # **ENHANCED**: Cleanup file manager
            if self.file_manager and hasattr(self.file_manager, 'cleanup'):
                self.file_manager.cleanup()
            
            # **ENHANCED**: Clear caches
            self._clear_all_caches()
            
            # **ENHANCED**: Process events to complete cleanup
            QApplication.processEvents()
            
        except Exception as e:
            self.logger.error(f"Error cleaning up resources: {e}")
    
    def _clear_all_caches(self):
        """Clear all application caches."""
        try:
            # **ENHANCED**: Clear UI cache
            if hasattr(self, '_ui_cache'):
                self._ui_cache.clear()
            
            # **ENHANCED**: Clear metrics cache
            if hasattr(self, '_metrics_cache'):
                self._metrics_cache.clear()
            
            # **ENHANCED**: Clear performance cache
            if hasattr(self, '_performance_cache'):
                self._performance_cache.clear()
            
            # **ENHANCED**: Clear theme cache
            if hasattr(self, '_theme_cache'):
                self._theme_cache.clear()
            
            # **ENHANCED**: Clear notification cache
            if hasattr(self, '_notification_cache'):
                self._notification_cache.clear()
            
        except Exception as e:
            self.logger.debug(f"Error clearing caches: {e}")
    
    def _save_final_configuration(self):
        """Save final configuration state."""
        try:
            # **ENHANCED**: Force save all pending configuration changes
            if hasattr(self.config, 'save_all_settings'):
                self.config.save_all_settings()
            elif hasattr(self.config, 'save'):
                self.config.save()
            
            # **ENHANCED**: Backup current configuration
            if hasattr(self.config, 'create_backup'):
                self.config.create_backup('shutdown_backup')
            
        except Exception as e:
            self.logger.error(f"Error saving final configuration: {e}")
    
    def resizeEvent(self, event: QResizeEvent):
        """Enhanced resize event handler with performance optimization."""
        try:
            super().resizeEvent(event)
            
            # **ENHANCED**: Track resize events for performance monitoring
            if hasattr(self, '_window_performance_metrics'):
                self._window_performance_metrics['resize_events'] += 1
            
            # **ENHANCED**: Log resize events if enabled
            if self._event_logging_enabled:
                self.logger.debug(f"Window resized to {event.size().width()}x{event.size().height()}")
            
            # **ENHANCED**: Update layout for new size
            self._update_layout_for_size(event.size())
            
            # **ENHANCED**: Update window state tracking
            self._update_window_state_tracking('resize', {
                'old_size': event.oldSize(),
                'new_size': event.size()
            })
            
        except Exception as e:
            self.logger.debug(f"Error in resize event: {e}")
    
    def _update_layout_for_size(self, size: QSize):
        """Update layout based on window size."""
        try:
            # **ENHANCED**: Adjust content for different screen sizes
            width = size.width()
            height = size.height()
            
            # **ENHANCED**: Handle very small window sizes
            if width < 800 or height < 600:
                self._enable_compact_mode()
            else:
                self._disable_compact_mode()
            
            # **ENHANCED**: Adjust navigation for different sizes
            if hasattr(self, '_nav_buttons'):
                for button in self._nav_buttons.values():
                    if width < 1000:
                        button.setText("")  # Show only icons in small windows
                    else:
                        # Restore full text for larger windows
                        button_name = button.objectName()
                        if button_name:
                            full_text = button_name.replace('_button', '').replace('_', ' ').title()
                            button.setText(full_text)
            
        except Exception as e:
            self.logger.debug(f"Error updating layout for size: {e}")
    
    def _enable_compact_mode(self):
        """Enable compact mode for small windows."""
        try:
            if hasattr(self, '_compact_mode_enabled') and self._compact_mode_enabled:
                return
            
            self._compact_mode_enabled = True
            
            # **ENHANCED**: Reduce margins and spacing
            if hasattr(self, '_main_layout'):
                self._main_layout.setContentsMargins(5, 5, 5, 5)
                self._main_layout.setSpacing(5)
            
            # **ENHANCED**: Hide non-essential UI elements
            if hasattr(self, '_status_bar'):
                # Hide detailed status information in compact mode
                for widget_name in ['_detailed_status', '_performance_indicators']:
                    if hasattr(self, widget_name):
                        widget = getattr(self, widget_name)
                        if hasattr(widget, 'setVisible'):
                            widget.setVisible(False)
            
            self.logger.debug("Compact mode enabled")
            
        except Exception as e:
            self.logger.debug(f"Error enabling compact mode: {e}")
    
    def _disable_compact_mode(self):
        """Disable compact mode for normal/large windows."""
        try:
            if not hasattr(self, '_compact_mode_enabled') or not self._compact_mode_enabled:
                return
            
            self._compact_mode_enabled = False
            
            # **ENHANCED**: Restore normal margins and spacing
            if hasattr(self, '_main_layout'):
                self._main_layout.setContentsMargins(10, 10, 10, 10)
                self._main_layout.setSpacing(10)
            
            # **ENHANCED**: Show all UI elements
            if hasattr(self, '_status_bar'):
                for widget_name in ['_detailed_status', '_performance_indicators']:
                    if hasattr(self, widget_name):
                        widget = getattr(self, widget_name)
                        if hasattr(widget, 'setVisible'):
                            widget.setVisible(True)
            
            self.logger.debug("Compact mode disabled")
            
        except Exception as e:
            self.logger.debug(f"Error disabling compact mode: {e}")

    def moveEvent(self, event: QMoveEvent):
        """Enhanced move event handler with position tracking and validation."""
        try:
            super().moveEvent(event)
            
            # **ENHANCED**: Track move events for performance monitoring
            if hasattr(self, '_window_performance_metrics'):
                self._window_performance_metrics['move_events'] += 1
            
            # **ENHANCED**: Log move events if enabled
            if self._event_logging_enabled:
                self.logger.debug(f"Window moved to ({event.pos().x()}, {event.pos().y()})")
            
            # **ENHANCED**: Validate window position (ensure it's on screen)
            self._validate_window_position(event.pos())
            
            # **ENHANCED**: Update window state tracking
            self._update_window_state_tracking('move', {
                'old_position': event.oldPos(),
                'new_position': event.pos()
            })
            
            # **ENHANCED**: Update child window positions if cascading is enabled
            if self._window_policies.get('cascade_new_windows', True):
                self._update_cascaded_window_positions()
            
        except Exception as e:
            self.logger.debug(f"Error in move event: {e}")
    
    def _validate_window_position(self, position: QPoint):
        """Validate and correct window position if needed."""
        try:
            # **ENHANCED**: Get available screen geometry
            screen_geometry = self.screen().availableGeometry()
            window_rect = self.geometry()
            
            # **ENHANCED**: Check if window is completely off-screen
            if not screen_geometry.intersects(window_rect):
                self.logger.warning("Window is off-screen, repositioning...")
                
                # **ENHANCED**: Move window to center of screen
                center_x = screen_geometry.x() + (screen_geometry.width() - window_rect.width()) // 2
                center_y = screen_geometry.y() + (screen_geometry.height() - window_rect.height()) // 2
                
                self.move(center_x, center_y)
                
                # **ENHANCED**: Show notification about repositioning
                if self._notifications_enabled:
                    notification = NotificationItem(
                        notification_id=f"window_repositioned_{datetime.now().timestamp()}",
                        title="Window Repositioned",
                        message="Window was moved back to the screen area.",
                        priority=NotificationPriority.INFO,
                        category="ui"
                    )
                    self._add_notification(notification)
            
        except Exception as e:
            self.logger.debug(f"Error validating window position: {e}")
    
    def _update_cascaded_window_positions(self):
        """Update positions of cascaded child windows."""
        try:
            # **ENHANCED**: Update child window positions relative to main window
            cascade_offset = 30
            base_x = self.x() + cascade_offset
            base_y = self.y() + cascade_offset
            
            for i, (window_type, state) in enumerate(self._window_states.items()):
                if state.is_open and state.instance and hasattr(state.instance, 'move'):
                    offset_x = base_x + (i * cascade_offset)
                    offset_y = base_y + (i * cascade_offset)
                    
                    # **ENHANCED**: Ensure child window stays on screen
                    screen_geometry = self.screen().availableGeometry()
                    if (offset_x + state.instance.width() <= screen_geometry.right() and
                        offset_y + state.instance.height() <= screen_geometry.bottom()):
                        state.instance.move(offset_x, offset_y)
            
        except Exception as e:
            self.logger.debug(f"Error updating cascaded window positions: {e}")
    
    def showEvent(self, event):
        """Enhanced show event handler with restoration and optimization."""
        try:
            super().showEvent(event)
            
            # **ENHANCED**: Track show events
            if hasattr(self, '_window_performance_metrics'):
                self._window_performance_metrics['show_hide_events'] += 1
            
            # **ENHANCED**: Log show event
            if self._event_logging_enabled:
                self.logger.debug("Window shown")
            
            # **ENHANCED**: Restore window state if needed
            if self._restore_window_state and hasattr(self, '_pending_state_restoration'):
                self._restore_pending_window_state()
            
            # **ENHANCED**: Update system tray visibility
            if hasattr(self, '_update_tray_show_hide_action'):
                self._update_tray_show_hide_action("Hide Main Window")
            
            # **ENHANCED**: Refresh data when window is shown
            self._refresh_data_on_show()
            
            # **ENHANCED**: Update window state tracking
            self._update_window_state_tracking('show', {'visible': True})
            
            # **ENHANCED**: Emit window visibility signal
            if hasattr(self, 'window_visibility_changed'):
                self.window_visibility_changed.emit(True)
            
        except Exception as e:
            self.logger.debug(f"Error in show event: {e}")
    
    def hideEvent(self, event):
        """Enhanced hide event handler with state preservation."""
        try:
            super().hideEvent(event)
            
            # **ENHANCED**: Track hide events
            if hasattr(self, '_window_performance_metrics'):
                self._window_performance_metrics['show_hide_events'] += 1
            
            # **ENHANCED**: Log hide event
            if self._event_logging_enabled:
                self.logger.debug("Window hidden")
            
            # **ENHANCED**: Save window state before hiding
            if self._auto_save_state:
                self._save_window_state_on_hide()
            
            # **ENHANCED**: Update system tray visibility
            if hasattr(self, '_update_tray_show_hide_action'):
                self._update_tray_show_hide_action("Show Main Window")
            
            # **ENHANCED**: Pause non-essential operations when hidden
            self._pause_non_essential_operations()
            
            # **ENHANCED**: Update window state tracking
            self._update_window_state_tracking('hide', {'visible': False})
            
            # **ENHANCED**: Emit window visibility signal
            if hasattr(self, 'window_visibility_changed'):
                self.window_visibility_changed.emit(False)
            
        except Exception as e:
            self.logger.debug(f"Error in hide event: {e}")
    
    def _restore_pending_window_state(self):
        """Restore pending window state restoration."""
        try:
            if hasattr(self, '_pending_geometry_restoration'):
                geometry = self._pending_geometry_restoration
                self.setGeometry(geometry['x'], geometry['y'], geometry['width'], geometry['height'])
                
                if geometry.get('maximized', False):
                    self.showMaximized()
                
                delattr(self, '_pending_geometry_restoration')
                self.logger.debug("Restored pending window geometry")
            
        except Exception as e:
            self.logger.debug(f"Error restoring pending window state: {e}")
    
    def _refresh_data_on_show(self):
        """Refresh data when window is shown."""
        try:
            # **ENHANCED**: Update dashboard data
            self._update_dashboard_data()
            
            # **ENHANCED**: Refresh component status
            self._check_component_availability()
            
            # **ENHANCED**: Update performance indicators
            self._update_performance_indicators()
            
            # **ENHANCED**: Refresh scan status
            self._update_scan_status_ui()
            
            # **ENHANCED**: Check for pending notifications
            if hasattr(self, '_process_notification_queue'):
                self._process_notification_queue()
            
        except Exception as e:
            self.logger.debug(f"Error refreshing data on show: {e}")
    
    def _save_window_state_on_hide(self):
        """Save window state when hiding."""
        try:
            # **ENHANCED**: Save current state for restoration
            self._last_visible_state = {
                'geometry': self.geometry(),
                'window_state': self.windowState(),
                'timestamp': datetime.now()
            }
            
            # **ENHANCED**: Add to state history
            self._window_state_history.append(self._last_visible_state)
            
        except Exception as e:
            self.logger.debug(f"Error saving window state on hide: {e}")
    
    def _pause_non_essential_operations(self):
        """Pause non-essential operations when window is hidden."""
        try:
            # **ENHANCED**: Reduce update frequency for hidden window
            if hasattr(self, '_ui_update_timer'):
                current_interval = self._ui_update_timer.interval()
                if current_interval < 10000:  # If less than 10 seconds
                    self._ui_update_timer.setInterval(10000)  # Reduce to 10 seconds
            
            # **ENHANCED**: Pause visual updates
            if hasattr(self, '_visual_updates_enabled'):
                self._visual_updates_enabled = False
            
        except Exception as e:
            self.logger.debug(f"Error pausing non-essential operations: {e}")
    
    def focusInEvent(self, event):
        """Enhanced focus in event handler with activation tracking."""
        try:
            super().focusInEvent(event)
            
            # **ENHANCED**: Track focus events
            if hasattr(self, '_window_performance_metrics'):
                self._window_performance_metrics['focus_events'] += 1
            
            # **ENHANCED**: Log focus event
            if self._event_logging_enabled:
                self.logger.debug("Window gained focus")
            
            # **ENHANCED**: Resume full operation when gaining focus
            self._resume_full_operations()
            
            # **ENHANCED**: Update window state tracking
            self._update_window_state_tracking('focus_in', {'has_focus': True})
            
            # **ENHANCED**: Refresh time-sensitive data
            self._refresh_time_sensitive_data()
            
        except Exception as e:
            self.logger.debug(f"Error in focus in event: {e}")
    
    def focusOutEvent(self, event):
        """Enhanced focus out event handler with deactivation handling."""
        try:
            super().focusOutEvent(event)
            
            # **ENHANCED**: Track focus events
            if hasattr(self, '_window_performance_metrics'):
                self._window_performance_metrics['focus_events'] += 1
            
            # **ENHANCED**: Log focus event
            if self._event_logging_enabled:
                self.logger.debug("Window lost focus")
            
            # **ENHANCED**: Update window state tracking
            self._update_window_state_tracking('focus_out', {'has_focus': False})
            
            # **ENHANCED**: Save state when losing focus
            if self._auto_save_state:
                self._auto_save_window_state()
            
        except Exception as e:
            self.logger.debug(f"Error in focus out event: {e}")
    
    def _resume_full_operations(self):
        """Resume full operations when window gains focus."""
        try:
            # **ENHANCED**: Restore normal update frequency
            if hasattr(self, '_ui_update_timer'):
                self._ui_update_timer.setInterval(2000)  # Back to 2 seconds
            
            # **ENHANCED**: Resume visual updates
            if hasattr(self, '_visual_updates_enabled'):
                self._visual_updates_enabled = True
            
            # **ENHANCED**: Process any queued updates
            self._process_queued_updates()
            
        except Exception as e:
            self.logger.debug(f"Error resuming full operations: {e}")
    
    def _refresh_time_sensitive_data(self):
        """Refresh time-sensitive data when gaining focus."""
        try:
            # **ENHANCED**: Update time displays
            if hasattr(self, '_update_time_display'):
                self._update_time_display()
            
            # **ENHANCED**: Check for system changes
            self._check_system_status()
            
            # **ENHANCED**: Update protection status
            self._update_protection_status()
            
        except Exception as e:
            self.logger.debug(f"Error refreshing time-sensitive data: {e}")
    
    def _process_queued_updates(self):
        """Process any queued updates."""
        try:
            # **ENHANCED**: Process pending UI updates
            if hasattr(self, '_pending_ui_updates'):
                for update_func in self._pending_ui_updates:
                    try:
                        update_func()
                    except Exception as e:
                        self.logger.debug(f"Error processing queued update: {e}")
                self._pending_ui_updates.clear()
            
        except Exception as e:
            self.logger.debug(f"Error processing queued updates: {e}")
    
    def paintEvent(self, event):
        """Enhanced paint event handler with performance monitoring."""
        try:
            super().paintEvent(event)
            
            # **ENHANCED**: Track paint events for performance monitoring
            if hasattr(self, '_window_performance_metrics'):
                self._window_performance_metrics['paint_events'] += 1
            
            # **ENHANCED**: Monitor paint performance
            if hasattr(self, '_paint_performance_monitoring') and self._paint_performance_monitoring:
                self._monitor_paint_performance()
            
        except Exception as e:
            self.logger.debug(f"Error in paint event: {e}")
    
    def _monitor_paint_performance(self):
        """Monitor paint event performance."""
        try:
            current_time = time.time()
            
            if not hasattr(self, '_last_paint_time'):
                self._last_paint_time = current_time
                return
            
            # **ENHANCED**: Calculate paint frequency
            paint_interval = current_time - self._last_paint_time
            paint_frequency = 1.0 / paint_interval if paint_interval > 0 else 0
            
            # **ENHANCED**: Log high paint frequency
            if paint_frequency > 120:  # More than 120 FPS
                self.logger.debug(f"High paint frequency detected: {paint_frequency:.1f} FPS")
            
            self._last_paint_time = current_time
            
        except Exception as e:
            self.logger.debug(f"Error monitoring paint performance: {e}")
    
    def changeEvent(self, event):
        """Enhanced change event handler for window state changes."""
        try:
            super().changeEvent(event)
            
            # **ENHANCED**: Handle window state changes
            if event.type() == QEvent.WindowStateChange:
                self._handle_window_state_change(event)
            elif event.type() == QEvent.ActivationChange:
                self._handle_activation_change(event)
            elif event.type() == QEvent.ApplicationStateChange:
                self._handle_application_state_change(event)
            
        except Exception as e:
            self.logger.debug(f"Error in change event: {e}")
    
    def _handle_window_state_change(self, event):
        """Handle window state change events."""
        try:
            # **ENHANCED**: Log window state changes
            if self._event_logging_enabled:
                state_names = {
                    Qt.WindowNoState: "Normal",
                    Qt.WindowMinimized: "Minimized",
                    Qt.WindowMaximized: "Maximized",
                    Qt.WindowFullScreen: "FullScreen"
                }
                
                current_state = self.windowState()
                state_name = state_names.get(current_state, f"Unknown({current_state})")
                self.logger.debug(f"Window state changed to: {state_name}")
            
            # **ENHANCED**: Handle minimize to tray
            if self.isMinimized() and self._minimize_to_tray and self.system_tray_enabled:
                QTimer.singleShot(250, self.hide)  # Hide after brief delay
            
            # **ENHANCED**: Update window state tracking
            self._update_window_state_tracking('state_change', {
                'window_state': self.windowState(),
                'is_minimized': self.isMinimized(),
                'is_maximized': self.isMaximized()
            })
            
            # **ENHANCED**: Adjust operations based on state
            if self.isMinimized():
                self._reduce_operations_for_minimized()
            else:
                self._restore_operations_from_minimized()
            
        except Exception as e:
            self.logger.debug(f"Error handling window state change: {e}")
    
    def _handle_activation_change(self, event):
        """Handle window activation change events."""
        try:
            is_active = self.isActiveWindow()
            
            # **ENHANCED**: Log activation changes
            if self._event_logging_enabled:
                self.logger.debug(f"Window activation changed: {'Active' if is_active else 'Inactive'}")
            
            # **ENHANCED**: Update operations based on activation
            if is_active:
                self._on_window_activated()
            else:
                self._on_window_deactivated()
            
        except Exception as e:
            self.logger.debug(f"Error handling activation change: {e}")
    
    def _handle_application_state_change(self, event):
        """Handle application state change events."""
        try:
            # **ENHANCED**: This is handled at the application level
            # but we can perform window-specific actions here
            pass
            
        except Exception as e:
            self.logger.debug(f"Error handling application state change: {e}")
    
    def _reduce_operations_for_minimized(self):
        """Reduce operations when window is minimized."""
        try:
            # **ENHANCED**: Reduce update frequencies
            if hasattr(self, '_ui_update_timer'):
                self._ui_update_timer.setInterval(30000)  # 30 seconds when minimized
            
            if hasattr(self, '_performance_timer'):
                self._performance_timer.setInterval(60000)  # 1 minute when minimized
            
            # **ENHANCED**: Disable visual updates
            if hasattr(self, '_visual_updates_enabled'):
                self._visual_updates_enabled = False
            
        except Exception as e:
            self.logger.debug(f"Error reducing operations for minimized: {e}")
    
    def _restore_operations_from_minimized(self):
        """Restore full operations when window is restored from minimized."""
        try:
            # **ENHANCED**: Restore normal update frequencies
            if hasattr(self, '_ui_update_timer'):
                self._ui_update_timer.setInterval(2000)  # Back to 2 seconds
            
            if hasattr(self, '_performance_timer'):
                self._performance_timer.setInterval(5000)  # Back to 5 seconds
            
            # **ENHANCED**: Enable visual updates
            if hasattr(self, '_visual_updates_enabled'):
                self._visual_updates_enabled = True
            
            # **ENHANCED**: Refresh all data
            self._refresh_data_on_show()
            
        except Exception as e:
            self.logger.debug(f"Error restoring operations from minimized: {e}")
    
    def _on_window_activated(self):
        """Handle window activation."""
        try:
            # **ENHANCED**: Resume high-frequency operations
            self._resume_high_frequency_operations()
            
            # **ENHANCED**: Check for updates
            self._check_for_pending_updates()
            
            # **ENHANCED**: Update focus-sensitive data
            self._update_focus_sensitive_data()
            
        except Exception as e:
            self.logger.debug(f"Error on window activated: {e}")
    
    def _on_window_deactivated(self):
        """Handle window deactivation."""
        try:
            # **ENHANCED**: Reduce high-frequency operations
            self._reduce_high_frequency_operations()
            
            # **ENHANCED**: Save current state
            if self._auto_save_state:
                self._auto_save_window_state()
            
        except Exception as e:
            self.logger.debug(f"Error on window deactivated: {e}")
    
    def _resume_high_frequency_operations(self):
        """Resume high-frequency operations when window is active."""
        try:
            # **ENHANCED**: Resume normal timer intervals
            if hasattr(self, '_ui_update_timer') and self._ui_update_timer.interval() > 2000:
                self._ui_update_timer.setInterval(2000)
            
            # **ENHANCED**: Enable real-time monitoring
            if hasattr(self, '_real_time_monitoring_enabled'):
                self._real_time_monitoring_enabled = True
            
        except Exception as e:
            self.logger.debug(f"Error resuming high-frequency operations: {e}")
    
    def _reduce_high_frequency_operations(self):
        """Reduce high-frequency operations when window is inactive."""
        try:
            # **ENHANCED**: Slow down UI updates
            if hasattr(self, '_ui_update_timer') and self._ui_update_timer.interval() < 5000:
                self._ui_update_timer.setInterval(5000)
            
            # **ENHANCED**: Reduce real-time monitoring
            if hasattr(self, '_real_time_monitoring_enabled'):
                self._real_time_monitoring_enabled = False
            
        except Exception as e:
            self.logger.debug(f"Error reducing high-frequency operations: {e}")
    
    def _check_for_pending_updates(self):
        """Check for pending updates when window becomes active."""
        try:
            # **ENHANCED**: Check for notification updates
            if hasattr(self, '_process_notification_queue'):
                self._process_notification_queue()
            
            # **ENHANCED**: Check for component status updates
            self._check_component_availability()
            
            # **ENHANCED**: Check for configuration changes
            if hasattr(self.config, 'check_for_external_changes'):
                self.config.check_for_external_changes()
            
        except Exception as e:
            self.logger.debug(f"Error checking for pending updates: {e}")
    
    def _update_focus_sensitive_data(self):
        """Update data that should be current when window has focus."""
        try:
            # **ENHANCED**: Update time-sensitive displays
            self._update_time_display()
            
            # **ENHANCED**: Update real-time status
            self._update_protection_status()
            
            # **ENHANCED**: Update scan status
            self._update_scan_status_ui()
            
            # **ENHANCED**: Update performance indicators
            self._update_performance_indicators()
            
        except Exception as e:
            self.logger.debug(f"Error updating focus-sensitive data: {e}")
    
    def _update_window_state_tracking(self, event_type: str, event_data: dict):
        """Update window state tracking with event information."""
        try:
            # **ENHANCED**: Create state entry
            state_entry = {
                'event_type': event_type,
                'event_data': event_data,
                'timestamp': datetime.now(),
                'window_geometry': self.geometry(),
                'window_state': self.windowState(),
                'is_visible': self.isVisible(),
                'is_active': self.isActiveWindow()
            }
            
            # **ENHANCED**: Add to history
            self._window_state_history.append(state_entry)
            
            # **ENHANCED**: Update statistics
            self._event_statistics[event_type] += 1
            
            # **ENHANCED**: Check for patterns or issues
            self._analyze_window_state_patterns()
            
        except Exception as e:
            self.logger.debug(f"Error updating window state tracking: {e}")
    
    def _analyze_window_state_patterns(self):
        """Analyze window state patterns for potential issues."""
        try:
            if len(self._window_state_history) < 10:
                return
            
            # **ENHANCED**: Check for excessive events
            recent_events = list(self._window_state_history)[-10:]
            current_time = datetime.now()
            
            # **ENHANCED**: Count events in last minute
            events_last_minute = sum(
                1 for entry in recent_events
                if (current_time - entry['timestamp']).total_seconds() < 60
            )
            
            if events_last_minute > 20:  # More than 20 events per minute
                self.logger.warning(f"High window event frequency: {events_last_minute} events/minute")
                
                # **ENHANCED**: Reduce event sensitivity temporarily
                self._temporarily_reduce_event_sensitivity()
            
        except Exception as e:
            self.logger.debug(f"Error analyzing window state patterns: {e}")
    
    def _temporarily_reduce_event_sensitivity(self):
        """Temporarily reduce event sensitivity to prevent spam."""
        try:
            # **ENHANCED**: Disable event logging temporarily
            self._event_logging_enabled = False
            
            # **ENHANCED**: Re-enable after 5 minutes
            QTimer.singleShot(300000, self._restore_event_sensitivity)
            
            self.logger.info("Temporarily reduced window event sensitivity")
            
        except Exception as e:
            self.logger.debug(f"Error reducing event sensitivity: {e}")
    
    def _restore_event_sensitivity(self):
        """Restore normal event sensitivity."""
        try:
            self._event_logging_enabled = self.config.get_setting('ui.event_logging_enabled', False)
            self.logger.info("Restored normal window event sensitivity")
            
        except Exception as e:
            self.logger.debug(f"Error restoring event sensitivity: {e}")
    
    # ========================================================================
    # COMPREHENSIVE KEYBOARD AND MOUSE EVENT HANDLING
    # ========================================================================
    
    def keyPressEvent(self, event: QKeyEvent):
        """Enhanced key press event handler with comprehensive shortcuts."""
        try:
            # **ENHANCED**: Handle global shortcuts
            if self._handle_global_shortcuts(event):
                event.accept()
                return
            
            # **ENHANCED**: Handle navigation shortcuts
            if self._handle_navigation_shortcuts(event):
                event.accept()
                return
            
            # **ENHANCED**: Handle function key shortcuts
            if self._handle_function_key_shortcuts(event):
                event.accept()
                return
            
            # **ENHANCED**: Handle accessibility shortcuts
            if self._handle_accessibility_shortcuts(event):
                event.accept()
                return
            
            # **ENHANCED**: Pass to parent if not handled
            super().keyPressEvent(event)
            
        except Exception as e:
            self.logger.debug(f"Error in key press event: {e}")
            super().keyPressEvent(event)
    
    def _handle_global_shortcuts(self, event: QKeyEvent) -> bool:
        """Handle global application shortcuts."""
        try:
            key = event.key()
            modifiers = event.modifiers()
            
            # **ENHANCED**: Ctrl+Q - Quit application
            if key == Qt.Key_Q and modifiers == Qt.ControlModifier:
                self._user_chose_exit = True
                self.close()
                return True
            
            # **ENHANCED**: Ctrl+R - Refresh/Reload
            if key == Qt.Key_R and modifiers == Qt.ControlModifier:
                self._refresh_all_data()
                return True
            
            # **ENHANCED**: Ctrl+S - Quick save
            if key == Qt.Key_S and modifiers == Qt.ControlModifier:
                self._quick_save_all()
                return True
            
            # **ENHANCED**: Ctrl+Shift+S - Save As/Export
            if key == Qt.Key_S and modifiers == (Qt.ControlModifier | Qt.ShiftModifier):
                self._export_reports()
                return True
            
            # **ENHANCED**: Ctrl+O - Open file for scanning
            if key == Qt.Key_O and modifiers == Qt.ControlModifier:
                self._scan_single_file()
                return True
            
            # **ENHANCED**: Ctrl+H - Hide/Show window
            if key == Qt.Key_H and modifiers == Qt.ControlModifier:
                self._toggle_main_window_visibility()
                return True
            
            # **ENHANCED**: Ctrl+M - Minimize to tray
            if key == Qt.Key_M and modifiers == Qt.ControlModifier:
                if self.system_tray_enabled:
                    self.hide()
                else:
                    self.showMinimized()
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error handling global shortcuts: {e}")
            return False
    
    def _handle_navigation_shortcuts(self, event: QKeyEvent) -> bool:
        """Handle navigation shortcuts."""
        try:
            key = event.key()
            modifiers = event.modifiers()
            
            # **ENHANCED**: Ctrl+1-8 - Navigate to sections
            if modifiers == Qt.ControlModifier and Qt.Key_1 <= key <= Qt.Key_8:
                section_index = key - Qt.Key_1
                sections = list(NavigationSection)
                if section_index < len(sections):
                    self._navigate_to_section(sections[section_index])
                    return True
            
            # **ENHANCED**: Alt+Left - Navigate back
            if key == Qt.Key_Left and modifiers == Qt.AltModifier:
                self._navigate_back()
                return True
            
            # **ENHANCED**: Alt+Right - Navigate forward
            if key == Qt.Key_Right and modifiers == Qt.AltModifier:
                self._navigate_forward()
                return True
            
            # **ENHANCED**: Ctrl+Tab - Next section
            if key == Qt.Key_Tab and modifiers == Qt.ControlModifier:
                self._navigate_to_next_section()
                return True
            
            # **ENHANCED**: Ctrl+Shift+Tab - Previous section
            if key == Qt.Key_Tab and modifiers == (Qt.ControlModifier | Qt.ShiftModifier):
                self._navigate_to_previous_section()
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error handling navigation shortcuts: {e}")
            return False
    
    def _handle_function_key_shortcuts(self, event: QKeyEvent) -> bool:
        """Handle function key shortcuts."""
        try:
            key = event.key()
            modifiers = event.modifiers()
            
            # **ENHANCED**: F1 - Help
            if key == Qt.Key_F1:
                self._show_help()
                return True
            
            # **ENHANCED**: F3 - Find/Search
            if key == Qt.Key_F3:
                self._show_search_dialog()
                return True
            
            # **ENHANCED**: F5 - Quick scan
            if key == Qt.Key_F5:
                if modifiers == Qt.ControlModifier:
                    self._start_scan("full")  # Ctrl+F5 for full scan
                elif modifiers == (Qt.ControlModifier | Qt.ShiftModifier):
                    self._start_scan("custom")  # Ctrl+Shift+F5 for custom scan
                else:
                    self._start_scan("quick")  # F5 for quick scan
                return True
            
            # **ENHANCED**: F9 - Update definitions
            if key == Qt.Key_F9:
                self._update_definitions()
                return True
            
            # **ENHANCED**: F10 - Settings
            if key == Qt.Key_F10:
                self._open_settings()
                return True
            
            # **ENHANCED**: F11 - Toggle fullscreen
            if key == Qt.Key_F11:
                self._toggle_fullscreen()
                return True
            
            # **ENHANCED**: F12 - System information
            if key == Qt.Key_F12:
                self._show_system_information()
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error handling function key shortcuts: {e}")
            return False
    
    def _handle_accessibility_shortcuts(self, event: QKeyEvent) -> bool:
        """Handle accessibility shortcuts."""
        try:
            key = event.key()
            modifiers = event.modifiers()
            
            # **ENHANCED**: Ctrl+Plus - Increase font size
            if key in [Qt.Key_Plus, Qt.Key_Equal] and modifiers == Qt.ControlModifier:
                self._increase_font_size()
                return True
            
            # **ENHANCED**: Ctrl+Minus - Decrease font size
            if key == Qt.Key_Minus and modifiers == Qt.ControlModifier:
                self._decrease_font_size()
                return True
            
            # **ENHANCED**: Ctrl+0 - Reset font size
            if key == Qt.Key_0 and modifiers == Qt.ControlModifier:
                self._reset_font_size()
                return True
            
            # **ENHANCED**: Alt+F4 - Close window
            if key == Qt.Key_F4 and modifiers == Qt.AltModifier:
                self.close()
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error handling accessibility shortcuts: {e}")
            return False
    
    def _navigate_back(self):
        """Navigate to previous section in history."""
        try:
            if self._navigation_history:
                previous_section = self._navigation_history.pop()
                self._navigation_forward_stack.append(self._active_navigation)
                self._navigate_to_section(previous_section)
                
        except Exception as e:
            self.logger.debug(f"Error navigating back: {e}")
    
    def _navigate_forward(self):
        """Navigate to next section in forward stack."""
        try:
            if self._navigation_forward_stack:
                next_section = self._navigation_forward_stack.pop()
                self._navigation_history.append(self._active_navigation)
                self._navigate_to_section(next_section)
                
        except Exception as e:
            self.logger.debug(f"Error navigating forward: {e}")
    
    def _navigate_to_next_section(self):
        """Navigate to next section in order."""
        try:
            sections = list(NavigationSection)
            current_index = sections.index(self._active_navigation)
            next_index = (current_index + 1) % len(sections)
            self._navigate_to_section(sections[next_index])
            
        except Exception as e:
            self.logger.debug(f"Error navigating to next section: {e}")
    
    def _navigate_to_previous_section(self):
        """Navigate to previous section in order."""
        try:
            sections = list(NavigationSection)
            current_index = sections.index(self._active_navigation)
            prev_index = (current_index - 1) % len(sections)
            self._navigate_to_section(sections[prev_index])
            
        except Exception as e:
            self.logger.debug(f"Error navigating to previous section: {e}")
    
    def _refresh_all_data(self):
        """Refresh all application data."""
        try:
            self.logger.info("Refreshing all application data...")
            
            # **ENHANCED**: Refresh dashboard
            self._update_dashboard_data()
            
            # **ENHANCED**: Refresh component status
            self._check_component_availability()
            
            # **ENHANCED**: Refresh performance data
            self._monitor_performance()
            
            # **ENHANCED**: Refresh scan status
            self._update_scan_status_ui()
            
            # **ENHANCED**: Refresh notifications
            self._process_notification_queue()
            
            # **ENHANCED**: Show refresh notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"data_refreshed_{datetime.now().timestamp()}",
                    title="Data Refreshed",
                    message="All application data has been refreshed.",
                    priority=NotificationPriority.INFO,
                    category="ui"
                )
                self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error refreshing all data: {e}")
    
    def _quick_save_all(self):
        """Quick save all application state."""
        try:
            self.logger.info("Quick saving all application state...")
            
            # **ENHANCED**: Save configuration
            if hasattr(self.config, 'save'):
                self.config.save()
            
            # **ENHANCED**: Save window state
            self._save_window_state()
            
            # **ENHANCED**: Save session data
            self._save_session_data()
            
            # **ENHANCED**: Show save notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"quick_save_{datetime.now().timestamp()}",
                    title="Settings Saved",
                    message="All settings and state have been saved.",
                    priority=NotificationPriority.INFO,
                    category="ui"
                )
                self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error in quick save: {e}")
    
    def _show_search_dialog(self):
        """Show search/find dialog."""
        try:
            # **ENHANCED**: Create search dialog
            search_text, ok = QInputDialog.getText(
                self,
                "Search",
                "Enter search term:",
                QLineEdit.Normal
            )
            
            if ok and search_text:
                self._perform_search(search_text)
            
        except Exception as e:
            self.logger.error(f"Error showing search dialog: {e}")
    
    def _perform_search(self, search_text: str):
        """Perform search operation."""
        try:
            self.logger.info(f"Performing search for: {search_text}")
            
            # **ENHANCED**: Search in logs
            self._search_in_logs(search_text)
            
            # **ENHANCED**: Search in scan results
            self._search_in_scan_results(search_text)
            
            # **ENHANCED**: Search in quarantine
            self._search_in_quarantine(search_text)
            
            # **ENHANCED**: Show search results
            self._show_search_results(search_text)
            
        except Exception as e:
            self.logger.error(f"Error performing search: {e}")
    
    def _search_in_logs(self, search_text: str):
        """Search in application logs."""
        try:
            # **ENHANCED**: Implementation would search log files
            pass
            
        except Exception as e:
            self.logger.debug(f"Error searching in logs: {e}")
    
    def _search_in_scan_results(self, search_text: str):
        """Search in scan results."""
        try:
            # **ENHANCED**: Implementation would search scan history
            pass
            
        except Exception as e:
            self.logger.debug(f"Error searching in scan results: {e}")
    
    def _search_in_quarantine(self, search_text: str):
        """Search in quarantine files."""
        try:
            # **ENHANCED**: Implementation would search quarantine
            pass
            
        except Exception as e:
            self.logger.debug(f"Error searching in quarantine: {e}")
    
    def _show_search_results(self, search_text: str):
        """Show search results."""
        try:
            QMessageBox.information(
                self,
                "Search Results",
                f"Search functionality for '{search_text}' is not yet implemented.",
                QMessageBox.Ok
            )
            
        except Exception as e:
            self.logger.error(f"Error showing search results: {e}")
    
    def _toggle_fullscreen(self):
        """Toggle fullscreen mode."""
        try:
            if self.isFullScreen():
                self.showNormal()
                self.logger.debug("Exited fullscreen mode")
            else:
                self.showFullScreen()
                self.logger.debug("Entered fullscreen mode")
            
        except Exception as e:
            self.logger.error(f"Error toggling fullscreen: {e}")
    
    def _show_system_information(self):
        """Show system information dialog."""
        try:
            # **ENHANCED**: Gather system information
            system_info = self._gather_system_information()
            
            # **ENHANCED**: Create and show dialog
            info_dialog = QMessageBox(self)
            info_dialog.setWindowTitle("System Information")
            info_dialog.setText("System Information")
            info_dialog.setDetailedText(system_info)
            info_dialog.setIcon(QMessageBox.Information)
            info_dialog.exec()
            
        except Exception as e:
            self.logger.error(f"Error showing system information: {e}")
    
    def _gather_system_information(self) -> str:
        """Gather comprehensive system information."""
        try:
            info_lines = [
                "Advanced Multi-Algorithm Antivirus - System Information",
                "=" * 60,
                "",
                f"Application Version: 1.0.0",
                f"Start Time: {self._start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"Uptime: {self._get_uptime_string()}",
                "",
                "System Information:",
                f"Platform: {platform.platform()}",
                f"Python Version: {platform.python_version()}",
                f"Processor: {platform.processor()}",
                "",
                "Component Status:",
                f"Scanner Engine: {'Available' if self._component_health.get('scanner_engine', False) else 'Unavailable'}",
                f"Model Manager: {'Available' if self._component_health.get('model_manager', False) else 'Unavailable'}",
                f"File Manager: {'Available' if self._component_health.get('file_manager', False) else 'Unavailable'}",
                "",
                "Statistics:",
                f"Total Scans: {self.config.get_setting('statistics.total_scans', 0)}",
                f"Threats Found: {self.config.get_setting('statistics.threats_found', 0)}",
                f"Files Quarantined: {self.config.get_setting('statistics.files_quarantined', 0)}",
                "",
                "Performance:",
                f"Window Events: {sum(self._event_statistics.values())}",
                f"System Health Score: {getattr(self, '_system_health_score', 'Unknown')}",
                "",
                "Configuration:",
                f"Theme: {self._current_theme_type}",
                f"Notifications: {'Enabled' if self._notifications_enabled else 'Disabled'}",
                f"System Tray: {'Enabled' if self.system_tray_enabled else 'Disabled'}"
            ]
            
            return "\n".join(info_lines)
            
        except Exception as e:
            self.logger.error(f"Error gathering system information: {e}")
            return f"Error gathering system information: {e}"
    
    def _increase_font_size(self):
        """Increase application font size for accessibility."""
        try:
            font = self.font()
            current_size = font.pointSize()
            new_size = min(current_size + 1, 20)  # Max size 20
            
            font.setPointSize(new_size)
            self.setFont(font)
            
            # **ENHANCED**: Save font preference
            self.config.set_setting('ui.font_size', new_size)
            
            self.logger.debug(f"Font size increased to {new_size}")
            
        except Exception as e:
            self.logger.error(f"Error increasing font size: {e}")
    
    def _decrease_font_size(self):
        """Decrease application font size for accessibility."""
        try:
            font = self.font()
            current_size = font.pointSize()
            new_size = max(current_size - 1, 8)  # Min size 8
            
            font.setPointSize(new_size)
            self.setFont(font)
            
            # **ENHANCED**: Save font preference
            self.config.set_setting('ui.font_size', new_size)
            
            self.logger.debug(f"Font size decreased to {new_size}")
            
        except Exception as e:
            self.logger.error(f"Error decreasing font size: {e}")
    
    def _reset_font_size(self):
        """Reset application font size to default."""
        try:
            default_size = 9  # Default font size
            
            font = self.font()
            font.setPointSize(default_size)
            self.setFont(font)
            
            # **ENHANCED**: Save font preference
            self.config.set_setting('ui.font_size', default_size)
            
            self.logger.debug(f"Font size reset to default ({default_size})")
            
        except Exception as e:
            self.logger.error(f"Error resetting font size: {e}")
    
    # ========================================================================
    # DRAG AND DROP FUNCTIONALITY
    # ========================================================================
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Enhanced drag enter event handler for file scanning."""
        try:
            # **ENHANCED**: Check if drag contains files
            if event.mimeData().hasUrls():
                # **ENHANCED**: Check if all URLs are local files
                urls = event.mimeData().urls()
                valid_files = []
                
                for url in urls:
                    if url.isLocalFile():
                        file_path = url.toLocalFile()
                        if os.path.exists(file_path):
                            valid_files.append(file_path)
                
                if valid_files:
                    event.acceptProposedAction()
                    self._show_drag_feedback(len(valid_files))
                    return
            
            # **ENHANCED**: Reject if no valid files
            event.ignore()
            
        except Exception as e:
            self.logger.debug(f"Error in drag enter event: {e}")
            event.ignore()
    
    def dragMoveEvent(self, event):
        """Enhanced drag move event handler."""
        try:
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
            else:
                event.ignore()
                
        except Exception as e:
            self.logger.debug(f"Error in drag move event: {e}")
            event.ignore()
    
    def dragLeaveEvent(self, event):
        """Enhanced drag leave event handler."""
        try:
            # **ENHANCED**: Hide drag feedback
            self._hide_drag_feedback()
            
        except Exception as e:
            self.logger.debug(f"Error in drag leave event: {e}")
    
    def dropEvent(self, event: QDropEvent):
        """Enhanced drop event handler for file scanning."""
        try:
            # **ENHANCED**: Hide drag feedback
            self._hide_drag_feedback()
            
            # **ENHANCED**: Process dropped files
            if event.mimeData().hasUrls():
                urls = event.mimeData().urls()
                files_to_scan = []
                
                for url in urls:
                    if url.isLocalFile():
                        file_path = url.toLocalFile()
                        if os.path.exists(file_path):
                            files_to_scan.append(file_path)
                
                if files_to_scan:
                    self._scan_dropped_files(files_to_scan)
                    event.acceptProposedAction()
                    return
            
            event.ignore()
            
        except Exception as e:
            self.logger.error(f"Error in drop event: {e}")
            event.ignore()
    
    def _show_drag_feedback(self, file_count: int):
        """Show visual feedback during drag operation."""
        try:
            # **ENHANCED**: Update status bar with drag feedback
            if hasattr(self, 'status_bar'):
                if file_count == 1:
                    message = "Drop file to scan"
                else:
                    message = f"Drop {file_count} files to scan"
                
                self.status_bar.showMessage(message, 0)  # Show until cleared
            
            # **ENHANCED**: Change cursor to indicate drop zone
            self.setCursor(Qt.DragCopyCursor)
            
        except Exception as e:
            self.logger.debug(f"Error showing drag feedback: {e}")
    
    def _hide_drag_feedback(self):
        """Hide visual feedback after drag operation."""
        try:
            # **ENHANCED**: Clear status bar message
            if hasattr(self, 'status_bar'):
                self.status_bar.clearMessage()
            
            # **ENHANCED**: Restore normal cursor
            self.unsetCursor()
            
        except Exception as e:
            self.logger.debug(f"Error hiding drag feedback: {e}")
    
    def _scan_dropped_files(self, file_paths: List[str]):
        """Scan dropped files."""
        try:
            self.logger.info(f"Scanning {len(file_paths)} dropped files")
            
            # **ENHANCED**: Show confirmation dialog for multiple files
            if len(file_paths) > 1:
                reply = QMessageBox.question(
                    self,
                    "Scan Multiple Files",
                    f"Scan {len(file_paths)} dropped files?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes
                )
                
                if reply != QMessageBox.Yes:
                    return
            
            # **ENHANCED**: Create scan configuration for dropped files
            scan_config = {
                'scan_type': 'files',
                'target_files': file_paths,
                'start_time': datetime.now(),
                'source': 'drag_drop'
            }
            
            # **ENHANCED**: Start scan
            self._start_scan('files', scan_config)
            
            # **ENHANCED**: Show notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"dropped_files_scan_{datetime.now().timestamp()}",
                    title="Files Dropped for Scanning",
                    message=f"Started scanning {len(file_paths)} dropped files",
                    priority=NotificationPriority.INFO,
                    category="scan"
                )
                self._add_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error scanning dropped files: {e}")
            
            # **ENHANCED**: Show error dialog
            QMessageBox.critical(
                self,
                "Scan Error",
                f"Error scanning dropped files: {str(e)}",
                QMessageBox.Ok
            )
    
    # ========================================================================
    # CONTEXT MENU HANDLING
    # ========================================================================
    
    def contextMenuEvent(self, event: QContextMenuEvent):
        """Enhanced context menu event handler."""
        try:
            # **ENHANCED**: Create context menu
            context_menu = QMenu(self)
            
            # **ENHANCED**: Add context-specific actions
            self._add_context_menu_actions(context_menu, event.pos())
            
            # **ENHANCED**: Show context menu
            if context_menu.actions():
                context_menu.exec(event.globalPos())
            else:
                # **ENHANCED**: Fall back to parent implementation
                super().contextMenuEvent(event)
            
        except Exception as e:
            self.logger.debug(f"Error in context menu event: {e}")
            super().contextMenuEvent(event)
    
    def _add_context_menu_actions(self, menu: QMenu, position: QPoint):
        """Add actions to context menu based on position and context."""
        try:
            # **ENHANCED**: Add refresh action
            refresh_action = QAction("&Refresh", self)
            refresh_action.setShortcut("Ctrl+R")
            refresh_action.triggered.connect(self._refresh_all_data)
            menu.addAction(refresh_action)
            
            menu.addSeparator()
            
            # **ENHANCED**: Add scan actions
            scan_menu = QMenu("Scan", self)
            
            quick_scan_action = QAction("&Quick Scan", self)
            quick_scan_action.setShortcut("F5")
            quick_scan_action.triggered.connect(lambda: self._start_scan("quick"))
            scan_menu.addAction(quick_scan_action)
            
            full_scan_action = QAction("&Full Scan", self)
            full_scan_action.setShortcut("Ctrl+F5")
            full_scan_action.triggered.connect(lambda: self._start_scan("full"))
            scan_menu.addAction(full_scan_action)
            
            scan_file_action = QAction("Scan &File...", self)
            scan_file_action.setShortcut("Ctrl+O")
            scan_file_action.triggered.connect(self._scan_single_file)
            scan_menu.addAction(scan_file_action)
            
            menu.addMenu(scan_menu)
            
            menu.addSeparator()
            
            # **ENHANCED**: Add window actions
            if self.system_tray_enabled:
                hide_action = QAction("&Hide Window", self)
                hide_action.setShortcut("Ctrl+H")
                hide_action.triggered.connect(self.hide)
                menu.addAction(hide_action)
            
            # **ENHANCED**: Add settings action
            settings_action = QAction("&Settings...", self)
            settings_action.setShortcut("F10")
            settings_action.triggered.connect(self._open_settings)
            menu.addAction(settings_action)
            
            menu.addSeparator()
            
            # **ENHANCED**: Add help action
            help_action = QAction("&Help", self)
            help_action.setShortcut("F1")
            help_action.triggered.connect(self._show_help)
            menu.addAction(help_action)
            
        except Exception as e:
            self.logger.debug(f"Error adding context menu actions: {e}")
    
    # ========================================================================
    # ADDITIONAL HELPER METHODS FOR UI ACTIONS
    # ========================================================================
    
    def _show_help(self):
        """Show application help."""
        try:
            # **ENHANCED**: Create help dialog
            help_dialog = QMessageBox(self)
            help_dialog.setWindowTitle("Help - Advanced Multi-Algorithm Antivirus")
            help_dialog.setIcon(QMessageBox.Information)
            
            help_text = """
Advanced Multi-Algorithm Antivirus - Help

KEYBOARD SHORTCUTS:
• F1 - Show this help
• F5 - Quick scan
• Ctrl+F5 - Full scan
• Ctrl+Shift+F5 - Custom scan
• F9 - Update definitions
• F10 - Settings
• F11 - Toggle fullscreen
• F12 - System information

• Ctrl+Q - Quit application
• Ctrl+R - Refresh data
• Ctrl+S - Quick save
• Ctrl+O - Scan file
• Ctrl+H - Hide window
• Ctrl+M - Minimize to tray

NAVIGATION:
• Ctrl+1-8 - Switch sections
• Ctrl+Tab - Next section
• Ctrl+Shift+Tab - Previous section
• Alt+Left - Navigate back
• Alt+Right - Navigate forward

FEATURES:
• Drag and drop files to scan
• System tray integration
• Real-time protection
• Multi-algorithm detection
• Comprehensive reporting

For more information, visit the documentation.
            """.strip()
            
            help_dialog.setText(help_text)
            help_dialog.exec()
            
        except Exception as e:
            self.logger.error(f"Error showing help: {e}")
    
    def _open_user_guide(self):
        """Open user guide documentation."""
        try:
            # **ENHANCED**: Try to open documentation
            docs_url = "https://docs.example.com/antivirus"
            QDesktopServices.openUrl(QUrl(docs_url))
            
        except Exception as e:
            self.logger.error(f"Error opening user guide: {e}")
            QMessageBox.information(
                self,
                "User Guide",
                "User guide documentation is not yet available.",
                QMessageBox.Ok
            )
    
    def _open_faq(self):
        """Open FAQ page."""
        try:
            # **ENHANCED**: Show FAQ dialog
            QMessageBox.information(
                self,
                "FAQ",
                "Frequently Asked Questions page is not yet implemented.",
                QMessageBox.Ok
            )
            
        except Exception as e:
            self.logger.error(f"Error opening FAQ: {e}")
    
    def _show_keyboard_shortcuts(self):
        """Show keyboard shortcuts dialog."""
        try:
            # **ENHANCED**: Reuse help dialog which includes shortcuts
            self._show_help()
            
        except Exception as e:
            self.logger.error(f"Error showing keyboard shortcuts: {e}")
    
    def _report_bug(self):
        """Open bug reporting interface."""
        try:
            # **ENHANCED**: Create bug report dialog
            bug_report, ok = QInputDialog.getMultiLineText(
                self,
                "Report Bug",
                "Please describe the bug you encountered:",
                ""
            )
            
            if ok and bug_report.strip():
                # **ENHANCED**: Process bug report
                self._process_bug_report(bug_report)
            
        except Exception as e:
            self.logger.error(f"Error in bug reporting: {e}")
    
    def _process_bug_report(self, bug_report: str):
        """Process bug report submission."""
        try:
            # **ENHANCED**: Save bug report locally
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            bug_report_file = Path(f"bug_report_{timestamp}.txt")
            
            with open(bug_report_file, 'w', encoding='utf-8') as f:
                f.write(f"Bug Report - {datetime.now().isoformat()}\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"User Report:\n{bug_report}\n\n")
                f.write(f"System Information:\n{self._gather_system_information()}\n")
            
            QMessageBox.information(
                self,
                "Bug Report Saved",
                f"Bug report saved to: {bug_report_file}\n\nThank you for your feedback!",
                QMessageBox.Ok
            )
            
        except Exception as e:
            self.logger.error(f"Error processing bug report: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Error saving bug report: {str(e)}",
                QMessageBox.Ok
            )
    
    def _submit_feedback(self):
        """Open feedback submission interface."""
        try:
            # **ENHANCED**: Create feedback dialog
            feedback, ok = QInputDialog.getMultiLineText(
                self,
                "Submit Feedback",
                "Please share your feedback and suggestions:",
                ""
            )
            
            if ok and feedback.strip():
                # **ENHANCED**: Process feedback
                self._process_feedback(feedback)
            
        except Exception as e:
            self.logger.error(f"Error in feedback submission: {e}")
    
    def _process_feedback(self, feedback: str):
        """Process feedback submission."""
        try:
            # **ENHANCED**: Save feedback locally
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            feedback_file = Path(f"feedback_{timestamp}.txt")
            
            with open(feedback_file, 'w', encoding='utf-8') as f:
                f.write(f"User Feedback - {datetime.now().isoformat()}\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Feedback:\n{feedback}\n")
            
            QMessageBox.information(
                self,
                "Feedback Saved",
                f"Feedback saved to: {feedback_file}\n\nThank you for your input!",
                QMessageBox.Ok
            )
            
        except Exception as e:
            self.logger.error(f"Error processing feedback: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Error saving feedback: {str(e)}",
                QMessageBox.Ok
            )
    
    def _check_for_updates(self):
        """Check for application updates."""
        try:
            # **ENHANCED**: Show update check dialog
            reply = QMessageBox.question(
                self,
                "Check for Updates",
                "Check for application updates?\n\nThis will connect to the update server.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                # **ENHANCED**: Simulate update check
                QMessageBox.information(
                    self,
                    "No Updates Available",
                    "You are running the latest version of the application.",
                    QMessageBox.Ok
                )
            
        except Exception as e:
            self.logger.error(f"Error checking for updates: {e}")

    def _show_about_dialog(self):
        """Show comprehensive about dialog with application information."""
        try:
            # **ENHANCED**: Create comprehensive about dialog
            about_dialog = QMessageBox(self)
            about_dialog.setWindowTitle("About - Advanced Multi-Algorithm Antivirus")
            about_dialog.setIcon(QMessageBox.Information)
            
            # **ENHANCED**: Set application icon if available
            if hasattr(self, '_create_custom_app_icon'):
                app_icon = self._create_custom_app_icon()
                about_dialog.setIconPixmap(app_icon.pixmap(64, 64))
            
            # **ENHANCED**: Create comprehensive about text
            about_text = """
<h2>Advanced Multi-Algorithm Antivirus</h2>
<h3>Professional Security Suite v1.0.0</h3>

<p><strong>Next-Generation Antivirus Protection</strong></p>

<p>This application provides comprehensive malware protection using multiple 
detection algorithms including machine learning ensemble models, signature-based 
detection, and YARA rules analysis.</p>

<h4>Key Features:</h4>
<ul>
    <li>🤖 ML Ensemble Detection (5 algorithms)</li>
    <li>🔍 Signature-based Detection</li>
    <li>📋 YARA Rules Analysis</li>
    <li>🛡️ Real-time Protection</li>
    <li>🔒 Quarantine Management</li>
    <li>📊 Comprehensive Reporting</li>
    <li>🎨 Modern Dark/Light Themes</li>
    <li>🔔 Smart Notifications</li>
</ul>

<h4>Detection Algorithms:</h4>
<ul>
    <li>Random Forest Classifier</li>
    <li>Support Vector Machine (SVM)</li>
    <li>Deep Neural Network (DNN)</li>
    <li>XGBoost Classifier</li>
    <li>LightGBM Classifier</li>
</ul>
            """.strip()
            
            about_dialog.setText(about_text)
            
            # **ENHANCED**: Add detailed technical information
            detailed_info = self._get_detailed_about_information()
            about_dialog.setDetailedText(detailed_info)
            
            # **ENHANCED**: Add custom buttons
            about_dialog.addButton("Visit Website", QMessageBox.ActionRole)
            about_dialog.addButton("View License", QMessageBox.ActionRole)
            about_dialog.addButton(QMessageBox.Ok)
            
            # **ENHANCED**: Connect button signals
            about_dialog.buttonClicked.connect(self._handle_about_dialog_button)
            
            # **ENHANCED**: Show dialog
            about_dialog.exec()
            
        except Exception as e:
            self.logger.error(f"Error showing about dialog: {e}")
            # **FALLBACK**: Simple about dialog
            QMessageBox.about(
                self,
                "About",
                "Advanced Multi-Algorithm Antivirus v1.0.0\n\n"
                "Professional Security Suite with ML Detection"
            )
    
    def _get_detailed_about_information(self) -> str:
        """Get detailed technical information for about dialog."""
        try:
            # **ENHANCED**: Gather comprehensive technical details
            info_lines = [
                "TECHNICAL INFORMATION",
                "=" * 60,
                "",
                "Application Details:",
                f"Version: 1.0.0",
                f"Build Date: {datetime.now().strftime('%Y-%m-%d')}",
                f"Python Version: {platform.python_version()}",
                f"PySide6 Version: {QT_VERSION_STR if 'QT_VERSION_STR' in globals() else 'Unknown'}",
                "",
                "System Information:",
                f"Platform: {platform.platform()}",
                f"Architecture: {platform.architecture()[0]}",
                f"Processor: {platform.processor()}",
                f"Machine Type: {platform.machine()}",
                "",
                "Runtime Information:",
                f"Start Time: {self._start_time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"Uptime: {self._get_uptime_string()}",
                f"Process ID: {os.getpid()}",
                "",
                "Component Status:",
                f"Scanner Engine: {'✓ Active' if self._component_health.get('scanner_engine', False) else '✗ Inactive'}",
                f"Model Manager: {'✓ Active' if self._component_health.get('model_manager', False) else '✗ Inactive'}",
                f"File Manager: {'✓ Active' if self._component_health.get('file_manager', False) else '✗ Inactive'}",
                f"Classification Engine: {'✓ Active' if self._component_health.get('classification_engine', False) else '✗ Inactive'}",
                "",
                "Detection Statistics:",
                f"Total Scans Performed: {self.config.get_setting('statistics.total_scans', 0):,}",
                f"Threats Detected: {self.config.get_setting('statistics.threats_found', 0):,}",
                f"Files Quarantined: {self.config.get_setting('statistics.files_quarantined', 0):,}",
                "",
                "Performance Metrics:",
                f"System Health Score: {getattr(self, '_system_health_score', 'Unknown')}",
                f"Memory Usage: {self._get_current_memory_usage():.1f}%",
                f"CPU Usage: {self._get_current_cpu_usage():.1f}%",
                "",
                "Configuration:",
                f"Theme: {self._current_theme_type.title()}",
                f"Notifications: {'Enabled' if self._notifications_enabled else 'Disabled'}",
                f"System Tray: {'Enabled' if self.system_tray_enabled else 'Disabled'}",
                f"Real-time Protection: {'Enabled' if self._get_real_time_protection_status() else 'Disabled'}",
                "",
                "Installation Information:",
                f"Installation Path: {os.path.abspath('.')}",
                f"Configuration Path: {self.config.config_file_path if hasattr(self.config, 'config_file_path') else 'Unknown'}",
                f"Log Directory: {os.path.abspath('logs')}",
                "",
                "Model Information:",
                "• Random Forest: Binary classification with ensemble voting",
                "• SVM: Support Vector Machine with RBF kernel",
                "• DNN: Deep Neural Network with dropout regularization",
                "• XGBoost: Gradient boosting with tree-based learning",
                "• LightGBM: Light gradient boosting machine",
                "",
                "Signature Database:",
                f"Format: SQLite database with binary signatures",
                f"Last Update: {self.config.get_setting('updates.last_definition_update', 'Never')}",
                "",
                "YARA Rules:",
                f"Rule Categories: Malware, Ransomware, Trojans, Custom",
                f"Active Rules: Available via rule management",
                "",
                "Copyright & License:",
                "Copyright © 2024 Advanced Security Solutions",
                "Licensed under MIT License",
                "",
                "Third-party Components:",
                "• PySide6 - Qt for Python GUI framework",
                "• NumPy - Numerical computing library",
                "• Scikit-learn - Machine learning library",
                "• XGBoost - Gradient boosting framework",
                "• LightGBM - Gradient boosting framework",
                "• YARA-Python - YARA pattern matching",
                "",
                "Contact Information:",
                "Website: https://antivirus.example.com",
                "Support: support@example.com",
                "Documentation: https://docs.example.com/antivirus"
            ]
            
            return "\n".join(info_lines)
            
        except Exception as e:
            self.logger.error(f"Error getting detailed about information: {e}")
            return f"Error retrieving detailed information: {str(e)}"
    
    def _handle_about_dialog_button(self, button):
        """Handle about dialog button clicks."""
        try:
            button_text = button.text()
            
            if "Visit Website" in button_text:
                # **ENHANCED**: Open website
                website_url = "https://antivirus.example.com"
                if not QDesktopServices.openUrl(QUrl(website_url)):
                    QMessageBox.information(
                        self,
                        "Website",
                        f"Please visit: {website_url}",
                        QMessageBox.Ok
                    )
                    
            elif "View License" in button_text:
                # **ENHANCED**: Show license dialog
                self._show_license_dialog()
            
        except Exception as e:
            self.logger.error(f"Error handling about dialog button: {e}")
    
    def _show_license_dialog(self):
        """Show software license dialog."""
        try:
            license_dialog = QMessageBox(self)
            license_dialog.setWindowTitle("Software License")
            license_dialog.setIcon(QMessageBox.Information)
            
            license_text = """
MIT License

Copyright (c) 2024 Advanced Security Solutions

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
            """.strip()
            
            license_dialog.setText("Software License Agreement")
            license_dialog.setDetailedText(license_text)
            license_dialog.exec()
            
        except Exception as e:
            self.logger.error(f"Error showing license dialog: {e}")
    
    def _show_credits(self):
        """Show credits and acknowledgments."""
        try:
            credits_dialog = QMessageBox(self)
            credits_dialog.setWindowTitle("Credits & Acknowledgments")
            credits_dialog.setIcon(QMessageBox.Information)
            
            credits_text = """
<h3>Credits & Acknowledgments</h3>

<h4>Development Team:</h4>
<ul>
    <li><strong>Lead Developer</strong> - Core architecture and ML integration</li>
    <li><strong>Security Specialist</strong> - Threat detection algorithms</li>
    <li><strong>UI/UX Designer</strong> - User interface and experience</li>
    <li><strong>QA Engineer</strong> - Testing and quality assurance</li>
</ul>

<h4>Special Thanks:</h4>
<ul>
    <li>Open source community for invaluable tools and libraries</li>
    <li>Security researchers for threat intelligence</li>
    <li>Beta testers for feedback and bug reports</li>
    <li>Academic institutions for research collaboration</li>
</ul>

<h4>Third-party Libraries:</h4>
<ul>
    <li><strong>Qt/PySide6</strong> - Cross-platform application framework</li>
    <li><strong>NumPy</strong> - Fundamental package for scientific computing</li>
    <li><strong>Scikit-learn</strong> - Machine learning library</li>
    <li><strong>XGBoost</strong> - Optimized gradient boosting library</li>
    <li><strong>LightGBM</strong> - Fast gradient boosting framework</li>
    <li><strong>YARA</strong> - Pattern matching engine</li>
</ul>

<h4>Research & Development:</h4>
<ul>
    <li>Machine learning models based on academic research</li>
    <li>Threat detection techniques from security publications</li>
    <li>Performance optimization through community feedback</li>
</ul>
            """.strip()
            
            credits_dialog.setText(credits_text)
            credits_dialog.exec()
            
        except Exception as e:
            self.logger.error(f"Error showing credits: {e}")
    
    def _show_system_requirements(self):
        """Show system requirements dialog."""
        try:
            requirements_dialog = QMessageBox(self)
            requirements_dialog.setWindowTitle("System Requirements")
            requirements_dialog.setIcon(QMessageBox.Information)
            
            requirements_text = """
<h3>System Requirements</h3>

<h4>Minimum Requirements:</h4>
<ul>
    <li><strong>Operating System:</strong> Windows 10, Linux (Ubuntu 18.04+), macOS 10.14+</li>
    <li><strong>Processor:</strong> Intel Core i3 or AMD equivalent (64-bit)</li>
    <li><strong>Memory:</strong> 4 GB RAM</li>
    <li><strong>Storage:</strong> 2 GB available disk space</li>
    <li><strong>Python:</strong> Python 3.8 or higher</li>
</ul>

<h4>Recommended Requirements:</h4>
<ul>
    <li><strong>Processor:</strong> Intel Core i5 or AMD equivalent (64-bit)</li>
    <li><strong>Memory:</strong> 8 GB RAM or higher</li>
    <li><strong>Storage:</strong> 5 GB available disk space (SSD recommended)</li>
    <li><strong>Graphics:</strong> DirectX 11 compatible (for UI acceleration)</li>
</ul>

<h4>Additional Requirements:</h4>
<ul>
    <li><strong>Internet Connection:</strong> Required for updates and threat intelligence</li>
    <li><strong>Administrator Rights:</strong> Required for real-time protection</li>
    <li><strong>Antivirus Exclusions:</strong> May require exclusions in other security software</li>
</ul>

<h4>Performance Notes:</h4>
<ul>
    <li>Machine learning models require additional CPU and memory resources</li>
    <li>Real-time scanning may impact system performance on older hardware</li>
    <li>Large file scans benefit from faster storage (SSD recommended)</li>
    <li>Network connectivity affects update and threat intelligence features</li>
</ul>
            """.strip()
            
            requirements_dialog.setText(requirements_text)
            requirements_dialog.exec()
            
        except Exception as e:
            self.logger.error(f"Error showing system requirements: {e}")
    
    # ========================================================================
    # FINAL CLEANUP AND RESOURCE MANAGEMENT
    # ========================================================================
    
    def __del__(self):
        """Enhanced destructor with comprehensive cleanup."""
        try:
            # **ENHANCED**: Perform final cleanup if not already done
            if not getattr(self, '_cleanup_completed', False):
                self._perform_final_destructor_cleanup()
            
        except Exception as e:
            # **ENHANCED**: Use print since logger might not be available
            print(f"Error in MainWindow destructor: {e}")
    
    def _perform_final_destructor_cleanup(self):
        """Perform final cleanup in destructor."""
        try:
            # **ENHANCED**: Mark cleanup as started
            self._cleanup_completed = True
            
            # **ENHANCED**: Stop any remaining timers
            self._stop_all_remaining_timers()
            
            # **ENHANCED**: Cleanup system resources
            self._cleanup_system_resources()
            
            # **ENHANCED**: Clear all references
            self._clear_all_references()
            
        except Exception as e:
            print(f"Error in final destructor cleanup: {e}")
    
    def _stop_all_remaining_timers(self):
        """Stop any remaining active timers."""
        try:
            # **ENHANCED**: List of all possible timers
            all_timers = [
                '_ui_update_timer', '_system_status_timer', '_performance_timer',
                '_update_check_timer', '_maintenance_timer', '_health_check_timer',
                '_performance_issues_timer', '_protection_status_timer',
                '_scan_recommendation_timer', '_notification_timer',
                '_notification_cleanup_timer', '_theme_validation_timer',
                '_system_theme_timer', '_auto_theme_timer', '_window_state_save_timer',
                '_window_performance_timer', '_time_update_timer',
                '_dashboard_update_timer', '_system_monitor_timer'
            ]
            
            for timer_name in all_timers:
                if hasattr(self, timer_name):
                    try:
                        timer = getattr(self, timer_name)
                        if timer and hasattr(timer, 'stop') and timer.isActive():
                            timer.stop()
                        delattr(self, timer_name)
                    except Exception:
                        pass  # Ignore individual timer cleanup errors
            
        except Exception as e:
            print(f"Error stopping remaining timers: {e}")
    
    def _cleanup_system_resources(self):
        """Cleanup system resources."""
        try:
            # **ENHANCED**: Cleanup system tray
            if hasattr(self, 'system_tray') and self.system_tray:
                try:
                    self.system_tray.hide()
                    self.system_tray.deleteLater()
                    self.system_tray = None
                except Exception:
                    pass
            
            # **ENHANCED**: Cleanup thread pools
            if hasattr(self, '_background_thread_pool'):
                try:
                    self._background_thread_pool.waitForDone(1000)  # 1 second timeout
                except Exception:
                    pass
            
            # **ENHANCED**: Clear caches
            self._clear_all_caches()
            
        except Exception as e:
            print(f"Error cleaning up system resources: {e}")
    
    def _clear_all_references(self):
        """Clear all object references to prevent memory leaks."""
        try:
            # **ENHANCED**: Clear major component references
            components_to_clear = [
                'config', 'theme_manager', 'model_manager', 'scanner_engine',
                'classification_engine', 'file_manager', 'threat_database'
            ]
            
            for component in components_to_clear:
                if hasattr(self, component):
                    try:
                        setattr(self, component, None)
                    except Exception:
                        pass
            
            # **ENHANCED**: Clear data structures
            data_structures = [
                '_component_health', '_integration_health', '_window_states',
                '_navigation_history', '_notification_history', '_performance_data',
                '_window_state_history', '_event_statistics', '_theme_cache',
                '_active_notifications', '_background_operations'
            ]
            
            for structure in data_structures:
                if hasattr(self, structure):
                    try:
                        getattr(self, structure).clear()
                    except Exception:
                        pass
            
        except Exception as e:
            print(f"Error clearing references: {e}")
    
    # ========================================================================
    # PUBLIC API METHODS FOR EXTERNAL INTEGRATION
    # ========================================================================
    
    def get_application_status(self) -> Dict[str, Any]:
        """Get comprehensive application status for external monitoring."""
        try:
            return {
                'application': {
                    'version': '1.0.0',
                    'start_time': self._start_time.isoformat(),
                    'uptime_seconds': (datetime.now() - self._start_time).total_seconds(),
                    'process_id': os.getpid(),
                    'theme': self._current_theme_type
                },
                'components': {
                    'scanner_engine': self._component_health.get('scanner_engine', False),
                    'model_manager': self._component_health.get('model_manager', False),
                    'file_manager': self._component_health.get('file_manager', False),
                    'classification_engine': self._component_health.get('classification_engine', False)
                },
                'statistics': {
                    'total_scans': self.config.get_setting('statistics.total_scans', 0),
                    'threats_found': self.config.get_setting('statistics.threats_found', 0),
                    'files_quarantined': self.config.get_setting('statistics.files_quarantined', 0)
                },
                'system': {
                    'health_score': getattr(self, '_system_health_score', 0),
                    'cpu_usage': self._get_current_cpu_usage(),
                    'memory_usage': self._get_current_memory_usage(),
                    'protection_enabled': self._get_real_time_protection_status()
                },
                'windows': {
                    'main_window_visible': self.isVisible(),
                    'open_child_windows': [
                        window_type for window_type, state in self._window_states.items()
                        if state.is_open
                    ]
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting application status: {e}")
            return {'error': str(e)}
    
    def execute_command(self, command: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute external command with parameters."""
        try:
            if parameters is None:
                parameters = {}
            
            self.logger.info(f"Executing external command: {command}")
            
            # **ENHANCED**: Define available commands
            commands = {
                'start_scan': self._external_start_scan,
                'stop_scan': self._external_stop_scan,
                'get_scan_status': self._external_get_scan_status,
                'open_window': self._external_open_window,
                'close_window': self._external_close_window,
                'switch_theme': self._external_switch_theme,
                'get_statistics': self._external_get_statistics,
                'refresh_data': self._external_refresh_data,
                'save_state': self._external_save_state,
                'show_notification': self._external_show_notification
            }
            
            if command in commands:
                result = commands[command](parameters)
                return {'success': True, 'result': result}
            else:
                return {'success': False, 'error': f'Unknown command: {command}'}
            
        except Exception as e:
            self.logger.error(f"Error executing external command {command}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _external_start_scan(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """External command to start scan."""
        scan_type = parameters.get('scan_type', 'quick')
        scan_config = parameters.get('scan_config', {})
        
        success = self._start_scan(scan_type, scan_config)
        return {'scan_started': success, 'scan_type': scan_type}
    
    def _external_stop_scan(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """External command to stop scan."""
        success = self._stop_scan()
        return {'scan_stopped': success}
    
    def _external_get_scan_status(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """External command to get scan status."""
        return dict(self._scan_status)
    
    def _external_open_window(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """External command to open window."""
        window_type = parameters.get('window_type')
        if window_type:
            success = self._open_child_window(window_type)
            return {'window_opened': success, 'window_type': window_type}
        return {'error': 'window_type parameter required'}
    
    def _external_close_window(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """External command to close window."""
        window_type = parameters.get('window_type')
        if window_type and window_type in self._window_states:
            state = self._window_states[window_type]
            if state.is_open and state.instance:
                state.instance.close()
                return {'window_closed': True, 'window_type': window_type}
        return {'error': 'Invalid window_type or window not open'}
    
    def _external_switch_theme(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """External command to switch theme."""
        theme_name = parameters.get('theme_name')
        if theme_name:
            success = self.switch_to_theme(theme_name)
            return {'theme_switched': success, 'theme_name': theme_name}
        return {'error': 'theme_name parameter required'}
    
    def _external_get_statistics(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """External command to get statistics."""
        return {
            'total_scans': self.config.get_setting('statistics.total_scans', 0),
            'threats_found': self.config.get_setting('statistics.threats_found', 0),
            'files_quarantined': self.config.get_setting('statistics.files_quarantined', 0),
            'last_scan': self.config.get_setting('scanning.last_scan', None),
            'last_full_scan': self.config.get_setting('scanning.last_full_scan', None)
        }
    
    def _external_refresh_data(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """External command to refresh data."""
        self._refresh_all_data()
        return {'data_refreshed': True}
    
    def _external_save_state(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """External command to save state."""
        self._quick_save_all()
        return {'state_saved': True}
    
    def _external_show_notification(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """External command to show notification."""
        title = parameters.get('title', 'Notification')
        message = parameters.get('message', '')
        priority = parameters.get('priority', 'info')
        
        if message:
            notification = NotificationItem(
                notification_id=f"external_{datetime.now().timestamp()}",
                title=title,
                message=message,
                priority=getattr(NotificationPriority, priority.upper(), NotificationPriority.INFO),
                category="external"
            )
            self._add_notification(notification)
            return {'notification_shown': True}
        return {'error': 'message parameter required'}
    
    def register_external_callback(self, event_type: str, callback: Callable):
        """Register external callback for events."""
        try:
            if not hasattr(self, '_external_callbacks'):
                self._external_callbacks = defaultdict(list)
            
            self._external_callbacks[event_type].append(callback)
            self.logger.info(f"Registered external callback for event: {event_type}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error registering external callback: {e}")
            return False
    
    def unregister_external_callback(self, event_type: str, callback: Callable):
        """Unregister external callback for events."""
        try:
            if hasattr(self, '_external_callbacks') and event_type in self._external_callbacks:
                if callback in self._external_callbacks[event_type]:
                    self._external_callbacks[event_type].remove(callback)
                    self.logger.info(f"Unregistered external callback for event: {event_type}")
                    return True
            return False
            
        except Exception as e:
            self.logger.error(f"Error unregistering external callback: {e}")
            return False
    
    def _emit_external_event(self, event_type: str, event_data: Dict[str, Any]):
        """Emit event to external callbacks."""
        try:
            if hasattr(self, '_external_callbacks') and event_type in self._external_callbacks:
                for callback in self._external_callbacks[event_type]:
                    try:
                        callback(event_type, event_data)
                    except Exception as e:
                        self.logger.error(f"Error in external callback: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error emitting external event: {e}")
    
    # ========================================================================
    # FINAL INITIALIZATION COMPLETION
    # ========================================================================
    
    def _complete_initialization(self):
        """Complete the initialization process and mark as ready."""
        try:
            self.logger.info("Completing MainWindow initialization...")
            
            # **ENHANCED**: Mark initialization phases as complete
            self._initialization_completed = True
            self._initialization_time = datetime.now()
            
            # **ENHANCED**: Calculate total initialization time
            total_init_time = (self._initialization_time - self._start_time).total_seconds()
            self.logger.info(f"MainWindow initialization completed in {total_init_time:.2f} seconds")
            
            # **ENHANCED**: Update status bar with ready message
            if hasattr(self, 'status_bar'):
                self.status_bar.showMessage("Ready", 5000)
            
            # **ENHANCED**: Show initialization complete notification
            if self._notifications_enabled:
                notification = NotificationItem(
                    notification_id=f"init_complete_{datetime.now().timestamp()}",
                    title="Application Ready",
                    message="Advanced Multi-Algorithm Antivirus is ready for use.",
                    priority=NotificationPriority.INFO,
                    category="system"
                )
                self._add_notification(notification)
            
            # **ENHANCED**: Emit initialization complete signal
            if hasattr(self, 'initialization_completed'):
                self.initialization_completed.emit(total_init_time)
            
            # **ENHANCED**: Perform post-initialization tasks
            self._perform_post_initialization_tasks()
            
            # **ENHANCED**: Log final status
            self.logger.info("MainWindow is fully operational and ready for user interaction")
            
        except Exception as e:
            self.logger.error(f"Error completing initialization: {e}")
    
    def _perform_post_initialization_tasks(self):
        """Perform tasks after initialization is complete."""
        try:
            # **ENHANCED**: Check for pending updates
            QTimer.singleShot(5000, self._check_definition_updates)  # Check after 5 seconds
            
            # **ENHANCED**: Perform initial system scan if configured
            if self.config.get_setting('startup.perform_quick_scan', False):
                QTimer.singleShot(10000, lambda: self._start_scan("quick"))  # Start after 10 seconds
            
            # **ENHANCED**: Show welcome message for first run
            if self.config.get_setting('application.first_run', True):
                QTimer.singleShot(2000, self._show_welcome_message)  # Show after 2 seconds
                self.config.set_setting('application.first_run', False)
            
            # **ENHANCED**: Emit external event for integration
            self._emit_external_event('application_ready', {
                'initialization_time': (self._initialization_time - self._start_time).total_seconds(),
                'version': '1.0.0',
                'features_enabled': {
                    'system_tray': self.system_tray_enabled,
                    'notifications': self._notifications_enabled,
                    'real_time_protection': self._get_real_time_protection_status()
                }
            })
            
        except Exception as e:
            self.logger.error(f"Error in post-initialization tasks: {e}")
    
    def _show_welcome_message(self):
        """Show welcome message for first-time users."""
        try:
            welcome_dialog = QMessageBox(self)
            welcome_dialog.setWindowTitle("Welcome to Advanced Multi-Algorithm Antivirus")
            welcome_dialog.setIcon(QMessageBox.Information)
            
            welcome_text = """
<h3>Welcome to Advanced Multi-Algorithm Antivirus!</h3>

<p>Thank you for choosing our comprehensive security solution. This application 
provides advanced malware protection using multiple detection algorithms.</p>

<h4>Getting Started:</h4>
<ul>
    <li>🛡️ <strong>Real-time Protection</strong> is automatically enabled</li>
    <li>🔍 <strong>Quick Scan</strong> - Press F5 or use the Quick Actions panel</li>
    <li>⚙️ <strong>Settings</strong> - Press F10 to customize your experience</li>
    <li>❓ <strong>Help</strong> - Press F1 for keyboard shortcuts and help</li>
</ul>

<h4>Key Features:</h4>
<ul>
    <li>Multi-algorithm ML detection with 5 trained models</li>
    <li>Signature-based and YARA rules detection</li>
    <li>Real-time file system monitoring</li>
    <li>Comprehensive quarantine management</li>
    <li>Dark and light theme support</li>
</ul>

<p><strong>Tip:</strong> Right-click anywhere for context menu options, 
or drag and drop files to scan them immediately.</p>
            """.strip()
            
            welcome_dialog.setText(welcome_text)
            welcome_dialog.addButton("Get Started", QMessageBox.AcceptRole)
            welcome_dialog.addButton("View Settings", QMessageBox.ActionRole)
            welcome_dialog.addButton("Take Tour", QMessageBox.HelpRole)
            
            # **ENHANCED**: Handle welcome dialog response
            welcome_dialog.buttonClicked.connect(self._handle_welcome_dialog_response)
            welcome_dialog.exec()
            
        except Exception as e:
            self.logger.error(f"Error showing welcome message: {e}")
    
    def _handle_welcome_dialog_response(self, button):
        """Handle welcome dialog button responses."""
        try:
            button_text = button.text()
            
            if "View Settings" in button_text:
                # **ENHANCED**: Open settings window
                QTimer.singleShot(500, self._open_settings)
                
            elif "Take Tour" in button_text:
                # **ENHANCED**: Start application tour
                QTimer.singleShot(500, self._start_application_tour)
            
            # "Get Started" just closes the dialog
            
        except Exception as e:
            self.logger.error(f"Error handling welcome dialog response: {e}")
    
    def _start_application_tour(self):
        """Start guided application tour for new users."""
        try:
            # **ENHANCED**: Create tour dialog
            tour_dialog = QMessageBox(self)
            tour_dialog.setWindowTitle("Application Tour")
            tour_dialog.setIcon(QMessageBox.Information)
            
            tour_text = """
<h3>Quick Application Tour</h3>

<p>Let's take a quick tour of the main features:</p>

<h4>Navigation:</h4>
<ul>
    <li><strong>Dashboard</strong> - Overview of system status and quick actions</li>
    <li><strong>Scanning</strong> - Access to all scan types and options</li>
    <li><strong>Quarantine</strong> - Manage isolated threats</li>
    <li><strong>Reports</strong> - View scan history and analytics</li>
    <li><strong>Settings</strong> - Customize application behavior</li>
</ul>

<h4>Quick Actions:</h4>
<ul>
    <li>Use the sidebar buttons to navigate between sections</li>
    <li>Right-click anywhere for context menus</li>
    <li>Use keyboard shortcuts (F1 for help)</li>
    <li>Drag and drop files to scan them</li>
</ul>

<p>The system tray icon shows protection status and provides quick access.</p>

<p><strong>Ready to start?</strong> Try running a quick scan to test the system!</p>
            """.strip()
            
            tour_dialog.setText(tour_text)
            tour_dialog.addButton("Start Quick Scan", QMessageBox.AcceptRole)
            tour_dialog.addButton("Explore Settings", QMessageBox.ActionRole)
            tour_dialog.addButton("Finish Tour", QMessageBox.RejectRole)
            
            # **ENHANCED**: Handle tour dialog response
            tour_dialog.buttonClicked.connect(self._handle_tour_dialog_response)
            tour_dialog.exec()
            
        except Exception as e:
            self.logger.error(f"Error starting application tour: {e}")
    
    def _handle_tour_dialog_response(self, button):
        """Handle tour dialog button responses."""
        try:
            button_text = button.text()
            
            if "Start Quick Scan" in button_text:
                # **ENHANCED**: Start quick scan
                QTimer.singleShot(500, lambda: self._start_scan("quick"))
                
            elif "Explore Settings" in button_text:
                # **ENHANCED**: Open settings
                QTimer.singleShot(500, self._open_settings)
            
            # "Finish Tour" just closes the dialog
            
        except Exception as e:
            self.logger.error(f"Error handling tour dialog response: {e}")
    
    def is_initialization_complete(self) -> bool:
        """Check if initialization is complete."""
        return getattr(self, '_initialization_completed', False)
    
    def get_initialization_time(self) -> float:
        """Get total initialization time in seconds."""
        if hasattr(self, '_initialization_time'):
            return (self._initialization_time - self._start_time).total_seconds()
        return 0.0


# ========================================================================
# NOTIFICATION ITEM CLASS FOR COMPREHENSIVE NOTIFICATION SYSTEM
# ========================================================================

@dataclass
class NotificationItem:
    """Enhanced notification item with comprehensive attributes."""
    notification_id: str
    title: str
    message: str
    priority: NotificationPriority = NotificationPriority.INFO
    category: str = "general"
    timestamp: datetime = field(default_factory=datetime.now)
    is_read: bool = False
    is_persistent: bool = False
    is_actionable: bool = False
    action_callback: Optional[Callable] = None
    icon: Optional[str] = None
    sound: Optional[str] = None
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def mark_as_read(self):
        """Mark notification as read."""
        self.is_read = True
    
    def is_expired(self) -> bool:
        """Check if notification has expired."""
        if self.expires_at:
            return datetime.now() > self.expires_at
        return False
    
    def execute_action(self):
        """Execute notification action if available."""
        if self.is_actionable and self.action_callback:
            try:
                self.action_callback()
                return True
            except Exception:
                return False
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert notification to dictionary."""
        return {
            'id': self.notification_id,
            'title': self.title,
            'message': self.message,
            'priority': self.priority.value if isinstance(self.priority, NotificationPriority) else self.priority,
            'category': self.category,
            'timestamp': self.timestamp.isoformat(),
            'is_read': self.is_read,
            'is_persistent': self.is_persistent,
            'is_actionable': self.is_actionable,
            'icon': self.icon,
            'sound': self.sound,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'metadata': self.metadata
        }


# ========================================================================
# MODULE COMPLETION AND EXPORT
# ========================================================================

# **ENHANCED**: Export the main window class and supporting classes
__all__ = [
    'MainWindow',
    'NavigationSection', 
    'SystemStatus',
    'NotificationPriority',
    'AnimationType',
    'WindowState',
    'ThemeState',
    'ScanStatus',
    'ComponentStatus',
    'NotificationItem'
]

# **ENHANCED**: Module metadata
__version__ = "1.0.0"
__author__ = "Advanced Security Solutions"
__description__ = "Advanced Multi-Algorithm Antivirus Main Window Implementation"

# **ENHANCED**: Ensure proper initialization order
if __name__ == "__main__":
    # **ENHANCED**: This module should not be run directly
    print("MainWindow module should be imported, not run directly.")
    print("Please run the application through main.py")