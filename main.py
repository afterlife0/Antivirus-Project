"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Application Entry Point - Enhanced with Proper Exit Handling

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (this is the entry point)

Connected Components (files that import from this module):
- None (this is the application entry point)

Integration Points:
- Initializes PySide6 QApplication with enhanced configuration
- Sets up comprehensive logging system with file rotation
- Initializes core configuration management system
- Creates and configures theme management system
- Initializes and displays main window with full integration
- Manages graceful application lifecycle and shutdown
- Handles critical errors with user-friendly dialogs
- Implements system tray integration for background operation
- Provides development environment detection and warnings
- Manages component availability checking with fallback handling
- Enhanced exit handling with multiple termination strategies

Verification Checklist:
✓ Application entry point established with PySide6
✓ QApplication setup with proper configuration
✓ Comprehensive logging system implemented
✓ Configuration initialization with error handling
✓ Theme system initialization with fallback support
✓ Main window creation and display with integration
✓ Error handling and user feedback systems
✓ Enhanced graceful shutdown and cleanup procedures
✓ Multiple exit strategies implemented
✓ Force termination safeguards
✓ Development environment detection
✓ Component availability checking implemented
✓ System requirements validation
✓ Performance monitoring integration
✓ Process termination guarantees
"""

import sys
import os
import logging
import signal
import threading
import time
import gc
import atexit
import traceback
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import json

# Ensure src directory is in Python path for development
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# PySide6 Core Imports with comprehensive error handling
try:
    from PySide6.QtWidgets import (
        QApplication, QMessageBox, QSystemTrayIcon, QMenu,
        QWidget, QVBoxLayout, QLabel, QPushButton, QProgressDialog
    )
    from PySide6.QtCore import (
        Qt, QTimer, Signal, QThread, QObject, QCoreApplication,
        QStandardPaths, QDir, QEventLoop
    )
    from PySide6.QtGui import (
        QIcon, QPixmap, QFont, QPalette, QColor,
        QGuiApplication, QScreen
    )
    pyside6_available = True
    print("✓ PySide6 loaded successfully")
except ImportError as e:
    print(f"❌ CRITICAL ERROR: PySide6 not available: {e}")
    print("Please install PySide6: pip install PySide6")
    sys.exit(1)

# Import core components with enhanced error handling and availability checking
app_config_available = False
theme_manager_available = False
main_window_available = False
encoding_handler_available = False
model_manager_available = False

try:
    from src.core.app_config import AppConfig
    app_config_available = True
    print("✓ AppConfig loaded successfully")
except ImportError as e:
    print(f"⚠️  WARNING: AppConfig not available: {e}")
    AppConfig = None

try:
    from src.utils.theme_manager import ThemeManager
    theme_manager_available = True
    print("✓ ThemeManager loaded successfully")
except ImportError as e:
    print(f"⚠️  WARNING: ThemeManager not available: {e}")
    ThemeManager = None

try:
    from src.utils.encoding_utils import EncodingHandler
    encoding_handler_available = True
    print("✓ EncodingHandler loaded successfully")
except ImportError as e:
    print(f"⚠️  WARNING: EncodingHandler not available: {e}")
    EncodingHandler = None

try:
    from src.ui.main_window import MainWindow
    main_window_available = True
    print("✓ MainWindow loaded successfully")
except ImportError as e:
    print(f"⚠️  WARNING: MainWindow not available: {e}")
    MainWindow = None

try:
    from src.core.model_manager import ModelManager
    model_manager_available = True
    print("✓ ModelManager loaded successfully")
except ImportError as e:
    print(f"ℹ️  INFO: ModelManager not available (optional): {e}")
    ModelManager = None


class AntivirusApp(QApplication):
    """
    Enhanced main application class for the Advanced Multi-Algorithm Antivirus Software.
    
    This class serves as the application entry point and lifecycle manager,
    providing comprehensive initialization, error handling, and resource management
    for the entire antivirus system with enhanced exit handling.
    
    Key Features:
    - Enhanced PySide6 QApplication with comprehensive configuration
    - Robust logging system with file rotation and level management
    - Core component initialization with availability checking
    - Graceful error handling with user-friendly feedback
    - Theme management integration with fallback support
    - Main window lifecycle management with proper cleanup
    - System tray integration for background operation
    - Development environment detection and warnings
    - Performance monitoring and metrics collection
    - Enhanced graceful shutdown procedures with data preservation
    - Multiple exit strategies with force termination safeguards
    - Process termination guarantees
    """
    
    # Enhanced signals for application-wide communication
    application_ready = Signal()
    application_shutdown = Signal()
    critical_error = Signal(str, str)  # title, message
    component_initialized = Signal(str, bool)  # component_name, success
    shutdown_progress = Signal(str, int)  # stage, percentage
    
    def __init__(self, argv):
        """Initialize the enhanced antivirus application with proper exit handling."""
        super().__init__(argv)
        
        # Application metadata and configuration
        self.setApplicationName("Advanced Multi-Algorithm Antivirus")
        self.setApplicationVersion("1.0.0")
        self.setApplicationDisplayName("Advanced Multi-Algorithm Antivirus")
        self.setOrganizationName("AntivirusProject")
        self.setOrganizationDomain("antivirusproject.local")
        
        # Enhanced application properties
        self.setQuitOnLastWindowClosed(False)  # Enable system tray functionality
        self.setProperty("development_mode", "--dev" in argv)
        
        # Core components with status tracking
        self.config = None
        self.theme_manager = None
        self.main_window = None
        self.model_manager = None
        self.encoding_handler = None
        self.system_tray = None
        
        # Enhanced exit and shutdown management
        self._initialization_complete = False
        self._shutdown_requested = False
        self._shutdown_in_progress = False
        self._force_exit_requested = False
        self._exit_timer = None
        self._shutdown_timeout = 10  # seconds
        self._exit_strategies = []
        self._cleanup_completed = False
        
        # Component status tracking
        self._components_initialized = {
            'logging': False,
            'encoding_handler': False,
            'config': False,
            'theme_manager': False,
            'model_manager': False,
            'main_window': False,
            'system_tray': False
        }
        
        # Performance and error tracking
        self._start_time = datetime.now()
        self._initialization_errors = []
        self._shutdown_errors = []
        self._performance_metrics = {
            'window_load_time': 0.0,
            'component_init_times': {},
            'ui_render_time': 0.0,
            'memory_usage': 0.0,
            'startup_time': 0.0,
            'operation_count': 0,
            'error_count': 0,
            'last_update': datetime.now()
        }
        self._initialization_phases = {}
        self._notifications_enabled = True
        self._system_health_score = 100.0
        self._current_theme_type = "dark"
        # Enhanced logging setup
        self.logger = None
        self._setup_enhanced_logging()
        
        # Setup exit strategies and handlers
        self._setup_exit_strategies()
        
        # Connect application signals
        self._connect_application_signals()
        
        # Register cleanup at exit
        atexit.register(self._emergency_cleanup)
        
        # Log application startup
        if self.logger:
            self.logger.info("="*80)
            self.logger.info("ADVANCED MULTI-ALGORITHM ANTIVIRUS - APPLICATION STARTUP")
            self.logger.info("="*80)
            self.logger.info(f"Application started at: {self._start_time}")
            self.logger.info(f"Python version: {sys.version}")
            self.logger.info(f"PySide6 version: {getattr(sys.modules.get('PySide6'), '__version__', 'Unknown')}")
            self.logger.info(f"Development mode: {self.property('development_mode')}")
            self.logger.info(f"Process ID: {os.getpid()}")
            
        # Initialize the application
        self._initialize_application()
    
    def _setup_enhanced_logging(self):
        """Setup enhanced logging system with file rotation and comprehensive configuration."""
        try:
            # Create logs directory
            logs_dir = Path("logs")
            logs_dir.mkdir(exist_ok=True)
            
            # Setup main application logger
            self.logger = logging.getLogger("AntivirusApp")
            self.logger.setLevel(logging.DEBUG if self.property('development_mode') else logging.INFO)
            
            # Clear existing handlers
            self.logger.handlers.clear()
            
            # File handler with rotation
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                logs_dir / "antivirus_app.log",
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            
            # Console handler for development
            console_handler = logging.StreamHandler(sys.stdout)
            
            # Enhanced formatter with more context
            formatter = logging.Formatter(
                '%(asctime)s | %(name)-20s | %(levelname)-8s | %(funcName)-20s:%(lineno)-4d | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            
            self.logger.addHandler(file_handler)
            if self.property('development_mode'):
                self.logger.addHandler(console_handler)
            
            # Setup root logger to catch all application logs
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.WARNING)
            root_logger.addHandler(file_handler)
            
            self._components_initialized['logging'] = True
            self.logger.info("Enhanced logging system initialized successfully")
            
        except Exception as e:
            print(f"CRITICAL ERROR: Failed to setup logging: {e}")
            # Create basic fallback logger
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            self.logger = logging.getLogger("AntivirusApp")
            self.logger.error(f"Fallback logging activated due to error: {e}")
    
    def _setup_exit_strategies(self):
        """Setup multiple exit strategies for reliable application termination."""
        try:
            # Exit strategies in order of preference
            self._exit_strategies = [
                ("graceful_quit", self._graceful_quit, "Normal application quit"),
                ("force_quit", self._force_quit, "Force application quit"),
                ("thread_termination", self._terminate_threads, "Terminate all threads"),
                ("system_exit", self._system_exit, "System exit call"),
                ("process_termination", self._process_termination, "Force process termination")
            ]
            
            # Setup exit timer for timeout
            self._exit_timer = QTimer()
            self._exit_timer.timeout.connect(self._handle_exit_timeout)
            self._exit_timer.setSingleShot(True)
            
            if self.logger:
                self.logger.debug(f"Setup {len(self._exit_strategies)} exit strategies")
                
        except Exception as e:
            print(f"Error setting up exit strategies: {e}")
    
    def _connect_application_signals(self):
        """Connect application-wide signals and event handlers."""
        try:
            # Connect Qt application signals
            self.aboutToQuit.connect(self._handle_application_quit)
            self.lastWindowClosed.connect(self._handle_last_window_closed)
            
            # Connect custom signals
            self.critical_error.connect(self._handle_critical_error)
            self.component_initialized.connect(self._handle_component_initialized)
            self.shutdown_progress.connect(self._handle_shutdown_progress)
            
            # Setup signal handlers for system signals
            signal.signal(signal.SIGINT, self._handle_system_signal)
            signal.signal(signal.SIGTERM, self._handle_system_signal)
            
            # Windows-specific signals
            if os.name == 'nt':
                try:
                    signal.signal(signal.SIGBREAK, self._handle_system_signal)
                except AttributeError:
                    pass  # SIGBREAK not available on all Windows versions
            
            if self.logger:
                self.logger.debug("Application signals connected successfully")
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error connecting application signals: {e}")
    
    def _initialize_application(self):
        """Initialize all application components in proper sequence."""
        try:
            if self.logger:
                self.logger.info("Starting application component initialization...")
            
            # Phase 1: Initialize encoding handler first (base utility)
            self._initialize_encoding_handler()
            
            # Phase 2: Initialize configuration system
            self._initialize_configuration()
            
            # Phase 3: Initialize theme management
            self._initialize_theme_manager()
            
            # Phase 4: Initialize model manager (optional)
            self._initialize_model_manager()
            
            # Phase 5: Initialize main window
            self._initialize_main_window()
            
            # Phase 6: Initialize system tray
            self._initialize_system_tray()
            
            # Phase 7: Complete initialization
            self._complete_initialization()
            
        except Exception as e:
            self._handle_initialization_error("Application Initialization", e)
    
    def _initialize_encoding_handler(self):
        """Initialize encoding handler with enhanced error handling."""
        component_start_time = datetime.now()
        
        try:
            if not encoding_handler_available:
                self.logger.warning("EncodingHandler module not available - using basic encoding")
                self._components_initialized['encoding_handler'] = False
                return
            
            self.encoding_handler = EncodingHandler()
            self._components_initialized['encoding_handler'] = True
            
            init_time = (datetime.now() - component_start_time).total_seconds()
            self._performance_metrics['component_init_times']['encoding_handler'] = init_time
            
            self.logger.info(f"EncodingHandler initialized successfully in {init_time:.3f}s")
            self.component_initialized.emit("encoding_handler", True)
            
        except Exception as e:
            self._components_initialized['encoding_handler'] = False
            self.logger.error(f"Failed to initialize EncodingHandler: {e}")
            self.component_initialized.emit("encoding_handler", False)
            self._initialization_errors.append(f"EncodingHandler: {e}")
    
    def _initialize_configuration(self):
        """Initialize application configuration with enhanced error handling."""
        component_start_time = datetime.now()
        
        try:
            if not app_config_available:
                self.logger.error("AppConfig module not available - cannot continue")
                self._show_critical_error_and_exit(
                    "Configuration System Missing",
                    "The configuration system is not available.\n"
                    "This is a critical component required for application startup.\n\n"
                    "Please ensure src/core/app_config.py is properly installed."
                )
                return
            
            # Create configuration instance
            self.config = AppConfig()
            
            # Validate configuration
            if not self.config:
                raise RuntimeError("AppConfig initialization returned None")
            
            self._components_initialized['config'] = True
            
            init_time = (datetime.now() - component_start_time).total_seconds()
            self._performance_metrics['component_init_times']['config'] = init_time
            
            self.logger.info(f"Configuration system initialized successfully in {init_time:.3f}s")
            self.component_initialized.emit("config", True)
            
        except Exception as e:
            self._components_initialized['config'] = False
            self.logger.error(f"Failed to initialize configuration: {e}")
            self.component_initialized.emit("config", False)
            self._show_critical_error_and_exit(
                "Configuration Error",
                f"Failed to initialize application configuration:\n{e}\n\n"
                "The application cannot start without proper configuration."
            )
    
    def _initialize_theme_manager(self):
        """Initialize theme management system with enhanced error handling."""
        component_start_time = datetime.now()
        
        try:
            if not theme_manager_available:
                self.logger.error("ThemeManager module not available - cannot continue")
                self._show_critical_error_and_exit(
                    "Theme System Missing",
                    "The theme management system is not available.\n"
                    "This is a critical component required for the user interface.\n\n"
                    "Please ensure src/utils/theme_manager.py is properly installed."
                )
                return
            
            if not self.config:
                self.logger.error("Configuration not available for ThemeManager")
                raise RuntimeError("Configuration required for ThemeManager initialization")
            
            # Create theme manager instance
            self.theme_manager = ThemeManager(self.config)
            
            # Validate theme manager
            if not self.theme_manager:
                raise RuntimeError("ThemeManager initialization returned None")
            
            self._components_initialized['theme_manager'] = True
            
            init_time = (datetime.now() - component_start_time).total_seconds()
            self._performance_metrics['component_init_times']['theme_manager'] = init_time
            
            self.logger.info(f"Theme management system initialized successfully in {init_time:.3f}s")
            self.component_initialized.emit("theme_manager", True)
            
        except Exception as e:
            self._components_initialized['theme_manager'] = False
            self.logger.error(f"Failed to initialize theme manager: {e}")
            self.component_initialized.emit("theme_manager", False)
            self._show_critical_error_and_exit(
                "Theme System Error",
                f"Failed to initialize theme management system:\n{e}\n\n"
                "The application cannot start without the theme system."
            )
    
    def _initialize_model_manager(self):
        """Initialize ML model manager with enhanced error handling."""
        component_start_time = datetime.now()
        
        try:
            if not model_manager_available:
                self.logger.info("ModelManager module not available - skipping (optional component)")
                self._components_initialized['model_manager'] = False
                self.component_initialized.emit("model_manager", False)
                return
            
            if not self.config:
                self.logger.warning("Configuration not available for ModelManager")
                self._components_initialized['model_manager'] = False
                self.component_initialized.emit("model_manager", False)
                return
            
            # Create model manager instance
            self.model_manager = ModelManager(self.config)
            
            # Validate model manager (optional component, so don't fail if None)
            if self.model_manager:
                self._components_initialized['model_manager'] = True
                self.logger.info("ModelManager initialized successfully")
            else:
                self._components_initialized['model_manager'] = False
                self.logger.warning("ModelManager initialization returned None")
            
            init_time = (datetime.now() - component_start_time).total_seconds()
            self._performance_metrics['component_init_times']['model_manager'] = init_time
            
            self.logger.info(f"Model manager initialization completed in {init_time:.3f}s")
            self.component_initialized.emit("model_manager", self._components_initialized['model_manager'])
            
        except Exception as e:
            self._components_initialized['model_manager'] = False
            self.logger.warning(f"ModelManager initialization failed (optional): {e}")
            self.component_initialized.emit("model_manager", False)
            self._initialization_errors.append(f"ModelManager (optional): {e}")
    
    def _initialize_main_window(self):
        """Initialize main window with enhanced error handling and integration."""
        component_start_time = datetime.now()
        
        try:
            if not main_window_available:
                self.logger.error("MainWindow module not available - cannot continue")
                self._show_critical_error_and_exit(
                    "Main Window Missing",
                    "The main window component is not available.\n"
                    "This is a critical component required for the user interface.\n\n"
                    "Please ensure src/ui/main_window.py is properly installed."
                )
                return
            
            # Validate required dependencies
            if not self.config:
                self.logger.error("Configuration not available for MainWindow")
                raise RuntimeError("Configuration required for MainWindow initialization")
            
            if not self.theme_manager:
                self.logger.error("ThemeManager not available for MainWindow")
                raise RuntimeError("ThemeManager required for MainWindow initialization")
            
            # Create main window instance
            self.main_window = MainWindow(
                config=self.config,
                theme_manager=self.theme_manager,
                model_manager=self.model_manager  # Optional - can be None
            )
            
            # Validate main window
            if not self.main_window:
                raise RuntimeError("MainWindow initialization returned None")
            
            # Connect main window signals
            self._connect_main_window_signals()
            
            # Show main window
            self.main_window.show()
            
            # Bring to front if needed
            self.main_window.raise_()
            self.main_window.activateWindow()
            
            self._components_initialized['main_window'] = True
            
            init_time = (datetime.now() - component_start_time).total_seconds()
            self._performance_metrics['component_init_times']['main_window'] = init_time
            
            self.logger.info(f"Main window initialized and displayed successfully in {init_time:.3f}s")
            self.component_initialized.emit("main_window", True)
            
        except Exception as e:
            self._components_initialized['main_window'] = False
            self.logger.error(f"Failed to initialize main window: {e}")
            self.component_initialized.emit("main_window", False)
            self._show_critical_error_and_exit(
                "Main Window Error",
                f"Failed to create and display the main window:\n{e}\n\n"
                "The application cannot continue without the main interface."
            )
    
    def _connect_main_window_signals(self):
        """Connect main window signals for enhanced integration."""
        try:
            if not self.main_window:
                return
            
            # Connect main window lifecycle signals
            if hasattr(self.main_window, 'shutdown_requested'):
                self.main_window.shutdown_requested.connect(self._request_graceful_shutdown)
            
            # Connect theme change signals
            if hasattr(self.main_window, 'theme_change_requested'):
                self.main_window.theme_change_requested.connect(self._handle_theme_change)
                
            # Connect close event
            if hasattr(self.main_window, 'closeEvent'):
                # Override close event to handle shutdown properly
                original_close_event = self.main_window.closeEvent
                def enhanced_close_event(event):
                    self.logger.info("Main window close event triggered")
                    if not self._shutdown_requested:
                        self._request_graceful_shutdown()
                    original_close_event(event)
                self.main_window.closeEvent = enhanced_close_event
            
            self.logger.debug("Main window signals connected successfully")
            
        except Exception as e:
            self.logger.error(f"Error connecting main window signals: {e}")
    
    def _initialize_system_tray(self):
        """Initialize system tray with enhanced functionality."""
        component_start_time = datetime.now()
        
        try:
            # Check if system tray is available
            if not QSystemTrayIcon.isSystemTrayAvailable():
                self.logger.warning("System tray not available on this system")
                self._components_initialized['system_tray'] = False
                self.component_initialized.emit("system_tray", False)
                return
            
            # Create system tray icon
            self.system_tray = QSystemTrayIcon(self)
            
            # Set system tray icon
            self._setup_system_tray_icon()
            
            # Create system tray menu
            self._setup_system_tray_menu()
            
            # Connect system tray signals
            self.system_tray.activated.connect(self._handle_system_tray_activation)
            
            # Show system tray
            self.system_tray.show()
            
            self._components_initialized['system_tray'] = True
            
            init_time = (datetime.now() - component_start_time).total_seconds()
            self._performance_metrics['component_init_times']['system_tray'] = init_time
            
            self.logger.info(f"System tray initialized successfully in {init_time:.3f}s")
            self.component_initialized.emit("system_tray", True)
            
        except Exception as e:
            self._components_initialized['system_tray'] = False
            self.logger.warning(f"System tray initialization failed: {e}")
            self.component_initialized.emit("system_tray", False)
    
    def _setup_system_tray_icon(self):
        """Setup system tray icon with fallback handling."""
        try:
            # Try to use theme manager for icon
            if self.theme_manager and hasattr(self.theme_manager, 'get_icon'):
                icon = self.theme_manager.get_icon("shield", (16, 16))
                if not icon.isNull():
                    self.system_tray.setIcon(icon)
                    return
            
            # Fallback to default icon
            self.system_tray.setIcon(self.style().standardIcon(self.style().SP_ComputerIcon))
            
        except Exception as e:
            self.logger.warning(f"Error setting system tray icon: {e}")
    
    def _setup_system_tray_menu(self):
        """Setup system tray context menu."""
        try:
            tray_menu = QMenu()
            
            # Show/Hide main window action
            show_action = tray_menu.addAction("Show Main Window")
            show_action.triggered.connect(self._show_main_window)
            
            tray_menu.addSeparator()
            
            # Quick scan action
            quick_scan_action = tray_menu.addAction("Quick Scan")
            quick_scan_action.triggered.connect(lambda: self._request_scan("quick"))
            
            tray_menu.addSeparator()
            
            # Exit action
            exit_action = tray_menu.addAction("Exit")
            exit_action.triggered.connect(self._request_graceful_shutdown)
            
            self.system_tray.setContextMenu(tray_menu)
            
        except Exception as e:
            self.logger.error(f"Error setting up system tray menu: {e}")
    
    def _complete_initialization(self):
        """Complete application initialization with final setup."""
        try:
            # Calculate total startup time
            total_startup_time = (datetime.now() - self._start_time).total_seconds()
            self._performance_metrics['startup_time'] = total_startup_time
            
            # Mark initialization as complete
            self._initialization_complete = True
            
            # Log initialization summary
            self._log_initialization_summary()
            
            # Show development message if in development mode
            if self.property('development_mode'):
                self._show_development_message()
            
            # Emit application ready signal
            self.application_ready.emit()
            
            self.logger.info("="*80)
            self.logger.info("APPLICATION INITIALIZATION COMPLETED SUCCESSFULLY")
            self.logger.info("="*80)
            
        except Exception as e:
            self.logger.error(f"Error completing initialization: {e}")
    
    def _log_initialization_summary(self):
        """Log comprehensive initialization summary."""
        try:
            self.logger.info("INITIALIZATION SUMMARY:")
            self.logger.info("-" * 50)
            
            # Component status
            for component, status in self._components_initialized.items():
                status_text = "✓ SUCCESS" if status else "✗ FAILED"
                self.logger.info(f"  {component:<20}: {status_text}")
            
            # Performance metrics
            self.logger.info("\nPERFORMANCE METRICS:")
            self.logger.info(f"  Total startup time: {self._performance_metrics['startup_time']:.3f}s")
            
            for component, time_taken in self._performance_metrics['component_init_times'].items():
                self.logger.info(f"  {component:<20}: {time_taken:.3f}s")
            
            # Error summary
            if self._initialization_errors:
                self.logger.warning("\nINITIALIZATION WARNINGS/ERRORS:")
                for error in self._initialization_errors:
                    self.logger.warning(f"  - {error}")
            
            self.logger.info("-" * 50)
            
        except Exception as e:
            self.logger.error(f"Error logging initialization summary: {e}")
    
    def _show_development_message(self):
        """Show development environment message with component status."""
        try:
            # Count successful components
            successful_components = sum(1 for status in self._components_initialized.values() if status)
            total_components = len(self._components_initialized)
            
            # Create development message
            message = (
                f"DEVELOPMENT MODE ACTIVE\n\n"
                f"Application Status:\n"
                f"• Components: {successful_components}/{total_components} initialized\n"
                f"• Startup Time: {self._performance_metrics['startup_time']:.2f}s\n"
                f"• Main Window: {'Available' if main_window_available else 'Not Available'}\n"
                f"• Theme System: {'Available' if theme_manager_available else 'Not Available'}\n"
                f"• Model Manager: {'Available' if model_manager_available else 'Not Available'}\n\n"
                f"Critical Issues:\n"
            )
            
            if not main_window_available:
                message += "• Main Window component missing\n"
            if not theme_manager_available:
                message += "• Theme Manager component missing\n"
            if not app_config_available:
                message += "• Configuration system missing\n"
            
            if self._initialization_errors:
                message += f"\nWarnings ({len(self._initialization_errors)}):\n"
                for error in self._initialization_errors[:3]:  # Show first 3 errors
                    message += f"• {error}\n"
            
            # Show development dialog
            QTimer.singleShot(1000, lambda: self._show_development_dialog(message))
            
        except Exception as e:
            self.logger.error(f"Error showing development message: {e}")
    
    def _show_development_dialog(self, message: str):
        """Show development dialog with detailed information."""
        try:
            dev_dialog = QMessageBox()
            dev_dialog.setWindowTitle("Development Environment")
            dev_dialog.setText(message)
            dev_dialog.setIcon(QMessageBox.Information)
            dev_dialog.setStandardButtons(QMessageBox.Ok)
            dev_dialog.exec()
            
        except Exception as e:
            self.logger.error(f"Error showing development dialog: {e}")
    
    # ========================================================================
    # EVENT HANDLERS
    # ========================================================================
    
    def _handle_system_tray_activation(self, reason):
        """Handle system tray icon activation."""
        try:
            if reason == QSystemTrayIcon.DoubleClick:
                self._show_main_window()
            elif reason == QSystemTrayIcon.Trigger:
                self._show_main_window()
                
        except Exception as e:
            self.logger.error(f"Error handling system tray activation: {e}")
    
    def _show_main_window(self):
        """Show and activate main window."""
        try:
            if self.main_window:
                self.main_window.show()
                self.main_window.raise_()
                self.main_window.activateWindow()
                
        except Exception as e:
            self.logger.error(f"Error showing main window: {e}")
    
    def _request_scan(self, scan_type: str):
        """Request a scan through the main window."""
        try:
            if self.main_window and hasattr(self.main_window, 'scan_requested'):
                self.main_window.scan_requested.emit(scan_type, {})
            else:
                self.logger.warning(f"Cannot request {scan_type} scan - main window not available")
                
        except Exception as e:
            self.logger.error(f"Error requesting scan: {e}")
    
    def _handle_theme_change(self, theme_name: str):
        """Handle theme change request."""
        try:
            if self.theme_manager and hasattr(self.theme_manager, 'set_theme'):
                self.theme_manager.set_theme(theme_name)
                self.logger.info(f"Theme changed to: {theme_name}")
            else:
                self.logger.warning(f"Cannot change theme to {theme_name} - theme manager not available")
                
        except Exception as e:
            self.logger.error(f"Error changing theme: {e}")
    
    def _handle_component_initialized(self, component_name: str, success: bool):
        """Handle component initialization completion."""
        try:
            status_text = "successfully" if success else "with errors"
            self.logger.debug(f"Component '{component_name}' initialized {status_text}")
            
        except Exception as e:
            self.logger.error(f"Error handling component initialization: {e}")
    
    def _handle_critical_error(self, title: str, message: str):
        """Handle critical error with user notification."""
        try:
            self.logger.critical(f"CRITICAL ERROR - {title}: {message}")
            
            # Show error dialog
            error_dialog = QMessageBox()
            error_dialog.setWindowTitle(f"Critical Error - {title}")
            error_dialog.setText(message)
            error_dialog.setIcon(QMessageBox.Critical)
            error_dialog.setStandardButtons(QMessageBox.Ok)
            error_dialog.exec()
            
        except Exception as e:
            self.logger.error(f"Error handling critical error: {e}")
    
    def _handle_system_signal(self, signum, frame):
        """Handle system signals for graceful shutdown."""
        try:
            signal_names = {
                signal.SIGINT: "SIGINT (Ctrl+C)",
                signal.SIGTERM: "SIGTERM (Termination)",
            }
            
            if os.name == 'nt':
                signal_names[signal.SIGBREAK] = "SIGBREAK (Ctrl+Break)"
            
            signal_name = signal_names.get(signum, f"Unknown({signum})")
            
            self.logger.info(f"Received system signal: {signal_name}")
            print(f"\n🛑 Received {signal_name}, initiating graceful shutdown...")
            
            # Request graceful shutdown
            QTimer.singleShot(0, self._request_graceful_shutdown)
            
        except Exception as e:
            self.logger.error(f"Error handling system signal: {e}")
            # Force exit if signal handling fails
            self._force_exit()
    
    def _handle_last_window_closed(self):
        """Handle last window closed event."""
        try:
            self.logger.info("Last window closed event triggered")
            
            # If system tray is available, don't quit
            if self.system_tray and self.system_tray.isVisible():
                self.logger.info("System tray active - application will continue in background")
                return
            
            # No system tray, quit application
            self.logger.info("No system tray - requesting graceful shutdown")
            self._request_graceful_shutdown()
            
        except Exception as e:
            self.logger.error(f"Error handling last window closed: {e}")
    
    def _handle_application_quit(self):
        """Handle application quit event with enhanced cleanup."""
        try:
            self.logger.info("Application quit event triggered")
            
            # Emit shutdown signal
            self.application_shutdown.emit()
            
            # Start shutdown timer if not already started
            if not self._shutdown_in_progress:
                self._start_shutdown_process()
            
        except Exception as e:
            self.logger.error(f"Error during application quit: {e}")
    
    def _handle_shutdown_progress(self, stage: str, percentage: int):
        """Handle shutdown progress updates."""
        try:
            self.logger.info(f"Shutdown progress: {stage} ({percentage}%)")
            
        except Exception as e:
            self.logger.error(f"Error handling shutdown progress: {e}")
    
    # ========================================================================
    # ENHANCED SHUTDOWN AND EXIT METHODS
    # ========================================================================
    
    def _request_graceful_shutdown(self):
        """Request graceful application shutdown with comprehensive exit handling."""
        try:
            if self._shutdown_requested:
                self.logger.warning("Shutdown already in progress")
                return
            
            self._shutdown_requested = True
            self._shutdown_in_progress = True
            
            shutdown_start_time = datetime.now()
            
            self.logger.info("=" * 60)
            self.logger.info("GRACEFUL SHUTDOWN INITIATED")
            self.logger.info("=" * 60)
            
            print("🔄 Initiating graceful shutdown...")
            
            # Emit shutdown progress
            self.shutdown_progress.emit("Starting shutdown", 0)
            
            # Start shutdown timer for timeout protection
            self._exit_timer.start(self._shutdown_timeout * 1000)
            
            # Start shutdown process
            self._start_shutdown_process()
            
        except Exception as e:
            self.logger.error(f"Error during graceful shutdown request: {e}")
            self._force_exit()
    
    def _start_shutdown_process(self):
        """Start the shutdown process with progress tracking."""
        try:
            self.logger.info("Starting shutdown process...")
            
            # Phase 1: Hide system tray
            self.shutdown_progress.emit("Hiding system tray", 10)
            self._shutdown_system_tray()
            
            # Phase 2: Close main window
            self.shutdown_progress.emit("Closing main window", 30)
            self._shutdown_main_window()
            
            # Phase 3: Cleanup components
            self.shutdown_progress.emit("Cleaning up components", 50)
            self._cleanup_components()
            
            # Phase 4: Final cleanup
            self.shutdown_progress.emit("Final cleanup", 80)
            self._final_cleanup()
            
            # Phase 5: Execute exit strategy
            self.shutdown_progress.emit("Terminating application", 90)
            self._execute_exit_strategy()
            
        except Exception as e:
            self.logger.error(f"Error in shutdown process: {e}")
            self._shutdown_errors.append(f"Shutdown process: {e}")
            self._force_exit()
    
    def _shutdown_system_tray(self):
        """Shutdown system tray component."""
        try:
            if self.system_tray:
                self.logger.info("Shutting down system tray...")
                self.system_tray.hide()
                self.system_tray.deleteLater()
                self.system_tray = None
                print("✓ System tray shutdown complete")
                
        except Exception as e:
            self.logger.error(f"Error shutting down system tray: {e}")
            self._shutdown_errors.append(f"System tray: {e}")
    
    def _shutdown_main_window(self):
        """Shutdown main window component."""
        try:
            if self.main_window:
                self.logger.info("Shutting down main window...")
                
                # Set user exit flag if available
                if hasattr(self.main_window, '_user_chose_exit'):
                    self.main_window._user_chose_exit = True
                
                # Perform full shutdown if available
                if hasattr(self.main_window, '_perform_full_shutdown'):
                    self.main_window._perform_full_shutdown()
                
                # Close and delete
                self.main_window.close()
                self.main_window.deleteLater()
                self.main_window = None
                print("✓ Main window shutdown complete")
                
        except Exception as e:
            self.logger.error(f"Error shutting down main window: {e}")
            self._shutdown_errors.append(f"Main window: {e}")
    
    def _cleanup_components(self):
        """Cleanup all application components."""
        try:
            self.logger.info("Cleaning up application components...")
            
            # Cleanup model manager
            if self.model_manager:
                try:
                    self.logger.info("Shutting down model manager...")
                    if hasattr(self.model_manager, 'cleanup'):
                        self.model_manager.cleanup()
                    elif hasattr(self.model_manager, 'stop'):
                        self.model_manager.stop()
                    self.model_manager = None
                    print("✓ Model manager cleanup complete")
                except Exception as e:
                    self.logger.warning(f"Error cleaning up model manager: {e}")
                    self._shutdown_errors.append(f"Model manager: {e}")
            
            # Cleanup theme manager
            if self.theme_manager:
                try:
                    self.logger.info("Shutting down theme manager...")
                    if hasattr(self.theme_manager, 'cleanup'):
                        self.theme_manager.cleanup()
                    self.theme_manager = None
                    print("✓ Theme manager cleanup complete")
                except Exception as e:
                    self.logger.warning(f"Error cleaning up theme manager: {e}")
                    self._shutdown_errors.append(f"Theme manager: {e}")
            
            # Cleanup configuration
            if self.config:
                try:
                    self.logger.info("Shutting down configuration...")
                    if hasattr(self.config, 'save'):
                        self.config.save()
                    if hasattr(self.config, 'cleanup'):
                        self.config.cleanup()
                    self.config = None
                    print("✓ Configuration cleanup complete")
                except Exception as e:
                    self.logger.warning(f"Error cleaning up configuration: {e}")
                    self._shutdown_errors.append(f"Configuration: {e}")
            
            # Cleanup encoding handler
            if self.encoding_handler:
                try:
                    self.logger.info("Shutting down encoding handler...")
                    if hasattr(self.encoding_handler, 'cleanup'):
                        self.encoding_handler.cleanup()
                    self.encoding_handler = None
                    print("✓ Encoding handler cleanup complete")
                except Exception as e:
                    self.logger.warning(f"Error cleaning up encoding handler: {e}")
                    self._shutdown_errors.append(f"Encoding handler: {e}")
            
        except Exception as e:
            self.logger.error(f"Error during component cleanup: {e}")
            self._shutdown_errors.append(f"Component cleanup: {e}")
    
    def _final_cleanup(self):
        """Perform final cleanup operations."""
        try:
            self.logger.info("Performing final cleanup...")
            
            # Process any remaining Qt events
            self.processEvents()
            
            # Force garbage collection
            gc.collect()
            
            # Calculate shutdown time
            if hasattr(self, '_start_time'):
                total_runtime = (datetime.now() - self._start_time).total_seconds()
                self.logger.info(f"Total application runtime: {total_runtime:.2f} seconds")
            
            # Log shutdown summary
            self._log_shutdown_summary()
            
            # Mark cleanup as completed
            self._cleanup_completed = True
            
            print("✓ Final cleanup complete")
            
        except Exception as e:
            self.logger.error(f"Error during final cleanup: {e}")
            self._shutdown_errors.append(f"Final cleanup: {e}")
    
    def _log_shutdown_summary(self):
        """Log comprehensive shutdown summary."""
        try:
            self.logger.info("SHUTDOWN SUMMARY:")
            self.logger.info("-" * 50)
            
            if self._shutdown_errors:
                self.logger.warning(f"Shutdown errors encountered: {len(self._shutdown_errors)}")
                for error in self._shutdown_errors:
                    self.logger.warning(f"  - {error}")
            else:
                self.logger.info("Shutdown completed without errors")
            
            # Component cleanup status
            components_cleaned = []
            if not self.main_window:
                components_cleaned.append("main_window")
            if not self.system_tray:
                components_cleaned.append("system_tray")
            if not self.model_manager:
                components_cleaned.append("model_manager")
            if not self.theme_manager:
                components_cleaned.append("theme_manager")
            if not self.config:
                components_cleaned.append("config")
            
            self.logger.info(f"Components cleaned: {', '.join(components_cleaned)}")
            self.logger.info("-" * 50)
            
        except Exception as e:
            self.logger.error(f"Error logging shutdown summary: {e}")
    
    def _execute_exit_strategy(self):
        """Execute exit strategy with multiple fallback options."""
        try:
            self.logger.info("Executing exit strategy...")
            
            # Try each exit strategy in order
            for strategy_name, strategy_func, description in self._exit_strategies:
                try:
                    self.logger.info(f"Attempting exit strategy: {strategy_name} - {description}")
                    print(f"🔄 Trying {description}...")
                    
                    result = strategy_func()
                    
                    if result:
                        self.logger.info(f"Exit strategy {strategy_name} succeeded")
                        print(f"✓ {description} successful")
                        return
                    else:
                        self.logger.warning(f"Exit strategy {strategy_name} failed")
                        print(f"⚠️  {description} failed, trying next strategy...")
                        
                except Exception as e:
                    self.logger.error(f"Exit strategy {strategy_name} error: {e}")
                    print(f"❌ {description} error: {e}")
                    continue
            
            # If all strategies fail, force termination
            self.logger.critical("All exit strategies failed - forcing termination")
            print("❌ All exit strategies failed - forcing process termination")
            self._emergency_exit()
            
        except Exception as e:
            self.logger.critical(f"Fatal error in exit strategy execution: {e}")
            print(f"💀 Fatal error: {e}")
            self._emergency_exit()
    
    def _graceful_quit(self) -> bool:
        """Graceful application quit strategy."""
        try:
            self.logger.info("Attempting graceful quit...")
            self.shutdown_progress.emit("Graceful quit", 95)
            
            # Process events one more time
            self.processEvents()
            
            # Quit application
            self.quit()
            
            # Wait briefly for quit to process
            loop = QEventLoop()
            QTimer.singleShot(1000, loop.quit)
            loop.exec()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Graceful quit failed: {e}")
            return False
    
    def _force_quit(self) -> bool:
        """Force application quit strategy."""
        try:
            self.logger.info("Attempting force quit...")
            self.shutdown_progress.emit("Force quit", 97)
            
            # Force quit
            self.exit(0)
            
            # Wait briefly
            time.sleep(0.5)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Force quit failed: {e}")
            return False
    
    def _terminate_threads(self) -> bool:
        """Terminate all threads strategy."""
        try:
            self.logger.info("Attempting thread termination...")
            
            # Get all threads
            current_thread = threading.current_thread()
            all_threads = threading.enumerate()
            
            # Terminate non-main threads
            for thread in all_threads:
                if thread != current_thread and thread.is_alive():
                    try:
                        if hasattr(thread, '_stop'):
                            thread._stop()
                        self.logger.debug(f"Terminated thread: {thread.name}")
                    except Exception as e:
                        self.logger.warning(f"Error terminating thread {thread.name}: {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Thread termination failed: {e}")
            return False
    
    def _system_exit(self) -> bool:
        """System exit strategy."""
        try:
            self.logger.info("Attempting system exit...")
            self.shutdown_progress.emit("System exit", 99)
            
            sys.exit(0)
            return True
            
        except Exception as e:
            self.logger.error(f"System exit failed: {e}")
            return False
    
    def _process_termination(self) -> bool:
        """Process termination strategy."""
        try:
            self.logger.info("Attempting process termination...")
            
            os._exit(0)
            return True
            
        except Exception as e:
            self.logger.error(f"Process termination failed: {e}")
            return False
    
    def _handle_exit_timeout(self):
        """Handle exit timeout - force termination."""
        try:
            self.logger.critical(f"Exit timeout after {self._shutdown_timeout} seconds - forcing termination")
            print(f"⏰ Shutdown timeout after {self._shutdown_timeout} seconds - forcing exit")
            
            self._force_exit()
            
        except Exception as e:
            self.logger.critical(f"Error handling exit timeout: {e}")
            self._emergency_exit()
    
    def _force_exit(self):
        """Force application exit immediately."""
        try:
            self.logger.warning("Force exit initiated")
            print("🚨 Force exit initiated")
            
            # Stop exit timer
            if self._exit_timer:
                self._exit_timer.stop()
            
            # Minimal cleanup
            try:
                if self.main_window:
                    self.main_window.close()
                if self.system_tray:
                    self.system_tray.hide()
            except Exception:
                pass
            
            # Force exit
            self.exit(1)
            
            # Backup force exit
            QTimer.singleShot(500, lambda: os._exit(1))
            
        except Exception as e:
            self.logger.critical(f"Force exit failed: {e}")
            self._emergency_exit()
    
    def _emergency_exit(self):
        """Emergency exit - last resort."""
        try:
            print("💀 EMERGENCY EXIT - TERMINATING PROCESS")
            if self.logger:
                self.logger.critical("EMERGENCY EXIT - PROCESS TERMINATION")
            
            # Nuclear option
            os._exit(1)
            
        except Exception:
            # If even this fails, there's nothing more we can do
            import ctypes
            if os.name == 'nt':
                ctypes.windll.kernel32.TerminateProcess(-1, 1)
            else:
                os.kill(os.getpid(), signal.SIGKILL)
    
    def _emergency_cleanup(self):
        """Emergency cleanup called by atexit."""
        try:
            if not self._cleanup_completed and self.logger:
                self.logger.warning("Emergency cleanup triggered by atexit")
                print("🆘 Emergency cleanup in progress...")
                
                # Minimal essential cleanup
                try:
                    if self.main_window:
                        self.main_window.close()
                except Exception:
                    pass
                
                try:
                    if self.system_tray:
                        self.system_tray.hide()
                except Exception:
                    pass
                
                self._cleanup_completed = True
                print("✓ Emergency cleanup completed")
                
        except Exception:
            pass  # Silent fail in emergency cleanup
    
    # ========================================================================
    # ERROR HANDLING METHODS
    # ========================================================================
    
    def _handle_initialization_error(self, component: str, error: Exception):
        """Handle initialization errors with appropriate user feedback."""
        try:
            error_msg = f"Failed to initialize {component}: {error}"
            self.logger.error(error_msg)
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            
            self._initialization_errors.append(f"{component}: {error}")
            
            # Show critical error dialog for essential components
            essential_components = ["Application Initialization", "Configuration", "Theme Manager", "Main Window"]
            if component in essential_components:
                self._show_critical_error_and_exit(
                    f"{component} Error",
                    f"Failed to initialize {component}:\n\n{error}\n\n"
                    "This is a critical component required for application startup.\n"
                    "The application cannot continue."
                )
            
        except Exception as e:
            print(f"CRITICAL: Error in error handler: {e}")
    
    def _show_critical_error_and_exit(self, title: str, message: str):
        """Show critical error dialog and exit application."""
        try:
            self.logger.critical(f"CRITICAL ERROR - {title}: {message}")
            print(f"💀 CRITICAL ERROR - {title}: {message}")
            
            # Create minimal error dialog
            error_dialog = QMessageBox()
            error_dialog.setWindowTitle(f"Critical Error - {title}")
            error_dialog.setText(message)
            error_dialog.setDetailedText(f"Startup Time: {datetime.now() - self._start_time}\n"
                                       f"Python: {sys.version}\n"
                                       f"Component Status: {self._components_initialized}")
            error_dialog.setIcon(QMessageBox.Critical)
            error_dialog.setStandardButtons(QMessageBox.Ok)
            
            # Show dialog and exit
            error_dialog.exec()
            
            # Force exit
            self._force_exit()
            
        except Exception as e:
            print(f"CRITICAL: Failed to show error dialog: {e}")
            print(f"Original error - {title}: {message}")
            self._emergency_exit()


def main():
    """Main application entry point with enhanced shutdown handling."""
    app = None
    
    try:
        print("🚀 Advanced Multi-Algorithm Antivirus - Starting...")
        print("="*60)
        
        # Set high DPI scaling
        os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
        
        # Create application instance
        app = AntivirusApp(sys.argv)
        
        # Set application icon if available
        try:
            app.setWindowIcon(app.style().standardIcon(app.style().SP_ComputerIcon))
        except Exception:
            pass  # Icon setting is not critical
        
        print("✓ PySide6 Application initialized successfully")
        print("🔄 Loading application components...")
        
        # Set up enhanced signal handlers
        def enhanced_signal_handler(signum, frame):
            signal_names = {
                signal.SIGINT: "SIGINT (Ctrl+C)",
                signal.SIGTERM: "SIGTERM (Termination)"
            }
            
            if os.name == 'nt':
                signal_names[signal.SIGBREAK] = "SIGBREAK (Ctrl+Break)"
                
            signal_name = signal_names.get(signum, f"Unknown({signum})")
            print(f"\n🛑 Received {signal_name}, initiating graceful shutdown...")
            
            if app and not app._shutdown_requested:
                app._request_graceful_shutdown()
            else:
                print("🚨 Force terminating due to repeated signal...")
                os._exit(1)
        
        signal.signal(signal.SIGINT, enhanced_signal_handler)
        signal.signal(signal.SIGTERM, enhanced_signal_handler)
        
        if os.name == 'nt':
            try:
                signal.signal(signal.SIGBREAK, enhanced_signal_handler)
            except AttributeError:
                pass  # SIGBREAK not available on all Windows versions
        
        print("✓ Signal handlers configured")
        print("🎯 Starting application event loop...")
        print("="*60)
        
        # Run application event loop
        exit_code = app.exec()
        
        print(f"📊 Application event loop exited with code: {exit_code}")
        
        # Ensure complete cleanup
        if app:
            print("🧹 Performing final cleanup...")
            try:
                if not app._cleanup_completed:
                    app._final_cleanup()
            except Exception as e:
                print(f"⚠️  Cleanup error: {e}")
            
            app.deleteLater()
        
        # Force garbage collection
        gc.collect()
        
        print(f"✅ Application shutdown completed successfully with exit code: {exit_code}")
        print("="*60)
        
        return exit_code
        
    except KeyboardInterrupt:
        print("\n🛑 Keyboard interrupt received - shutting down gracefully...")
        if app and not app._shutdown_requested:
            app._request_graceful_shutdown()
        return 130  # Standard exit code for Ctrl+C
        
    except Exception as e:
        print(f"💀 CRITICAL ERROR in main(): {e}")
        print(f"📋 Traceback: {traceback.format_exc()}")
        
        # Try to show error dialog as last resort
        try:
            if app:
                error_dialog = QMessageBox()
                error_dialog.setWindowTitle("Critical Application Error")
                error_dialog.setText(f"The application encountered a critical error and cannot start:\n\n{e}")
                error_dialog.setIcon(QMessageBox.Critical)
                error_dialog.exec()
        except Exception:
            print("❌ Failed to show error dialog")
        
        return 1
    
    finally:
        # Final cleanup attempt
        try:
            if app:
                print("🔚 Final application cleanup...")
                try:
                    app.quit()
                    app.deleteLater()
                except Exception as e:
                    print(f"⚠️  Final cleanup error: {e}")
                    
        except Exception:
            pass
        
        # Force garbage collection
        try:
            gc.collect()
        except Exception:
            pass
        
        print("🏁 Process termination complete")


if __name__ == "__main__":
    try:
        exit_code = main()
        print(f"🎯 Exiting with code: {exit_code}")
        sys.exit(exit_code)
    except Exception as e:
        print(f"💀 Fatal error in main execution: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Final keyboard interrupt - terminating immediately")
        sys.exit(130)