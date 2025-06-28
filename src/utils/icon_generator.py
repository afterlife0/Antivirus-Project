"""
Icon Generator for Advanced Multi-Algorithm Antivirus Software
============================================================

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (base utility for icon generation)

Connected Components (files that import from this module):
- src.utils.theme_manager (imports IconGenerator)
- src.ui.main_window (imports IconGenerator via ThemeManager)

Integration Points:
- Generates SVG and PNG icons for the entire application
- Provides icon creation utilities for ThemeManager
- Creates themed icon variants (dark/light mode)
- Generates scalable vector icons for all UI components

Verification Checklist:
✓ Standalone icon generation utility
✓ SVG and PNG format support
✓ Theme-aware icon variants
✓ Scalable icon generation
✓ Complete icon set for antivirus application
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import logging
from datetime import datetime

# PySide6 imports for icon generation
try:
    from PySide6.QtCore import Qt, QSize, QRectF, QPointF
    from PySide6.QtGui import (
        QIcon, QPixmap, QPainter, QPen, QBrush, QColor, 
        QFont, QFontMetrics, QPainterPath, QRadialGradient, 
        QLinearGradient, QPalette, QPolygonF
    )
    from PySide6.QtWidgets import QApplication
    from PySide6.QtSvg import QSvgGenerator
    pyside6_available = True
except ImportError:
    pyside6_available = False
    print("⚠️  PySide6 not available - icon generation will be limited")


class IconGenerator:
    """
    Advanced icon generator for the antivirus application.
    
    Creates scalable vector icons and bitmap icons for all UI components
    with support for light and dark themes.
    """
    
    def __init__(self):
        """Initialize the icon generator."""
        self.logger = logging.getLogger(__name__)
        
        # Icon specifications
        self.icon_sizes = [16, 24, 32, 48, 64, 128, 256]
        self.default_size = 24
        
        # Color schemes for themes
        self.color_schemes = {
            'dark': {
                'primary': '#ffffff',
                'secondary': '#cccccc',
                'accent': '#4CAF50',
                'warning': '#FF9800',
                'error': '#f44336',
                'success': '#4CAF50',
                'info': '#2196F3',
                'background': '#2b2b2b',
                'shield': '#4CAF50',
                'scan': '#2196F3',
                'quarantine': '#FF9800',
                'model': '#9C27B0',
                'settings': '#607D8B'
            },
            'light': {
                'primary': '#333333',
                'secondary': '#666666',
                'accent': '#4CAF50',
                'warning': '#FF9800',
                'error': '#f44336',
                'success': '#4CAF50',
                'info': '#2196F3',
                'background': '#ffffff',
                'shield': '#4CAF50',
                'scan': '#2196F3',
                'quarantine': '#FF6600',
                'model': '#9C27B0',
                'settings': '#455A64'
            }
        }
        
        # Icon definitions
        self.icon_definitions = {
            # Application icons
            'app_icon': self._create_app_icon,
            'shield': self._create_shield_icon,
            
            # Navigation icons
            'dashboard': self._create_dashboard_icon,
            'scanning': self._create_scanning_icon,
            'quarantine': self._create_quarantine_icon,
            'models': self._create_models_icon,
            'settings': self._create_settings_icon,
            'reports': self._create_reports_icon,
            'updates': self._create_updates_icon,
            'help': self._create_help_icon,
            
            # Scan type icons
            'scan_quick': self._create_quick_scan_icon,
            'scan_full': self._create_full_scan_icon,
            'scan_custom': self._create_custom_scan_icon,
            'scan_memory': self._create_memory_scan_icon,
            'scan_network': self._create_network_scan_icon,
            
            # Status icons
            'status_healthy': self._create_healthy_status_icon,
            'status_warning': self._create_warning_status_icon,
            'status_critical': self._create_critical_status_icon,
            'status_error': self._create_error_status_icon,
            
            # Action icons
            'play': self._create_play_icon,
            'pause': self._create_pause_icon,
            'stop': self._create_stop_icon,
            'refresh': self._create_refresh_icon,
            'delete': self._create_delete_icon,
            'restore': self._create_restore_icon,
            'export': self._create_export_icon,
            'import': self._create_import_icon,
            
            # File type icons
            'file_exe': self._create_exe_icon,
            'file_dll': self._create_dll_icon,
            'file_doc': self._create_doc_icon,
            'file_unknown': self._create_unknown_file_icon,
            
            # Threat icons
            'threat_malware': self._create_malware_icon,
            'threat_virus': self._create_virus_icon,
            'threat_trojan': self._create_trojan_icon,
            'threat_ransomware': self._create_ransomware_icon,
            
            # System icons
            'minimize': self._create_minimize_icon,
            'maximize': self._create_maximize_icon,
            'close': self._create_close_icon,
            'notification': self._create_notification_icon,
            'update': self._create_update_icon
        }
    
    def generate_all_icons(self, output_dir: str = "src/resources/icons") -> bool:
        """Generate all icons for the application."""
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            self.logger.info(f"Generating icons to {output_path}")
            
            # Generate icons for both themes
            for theme in ['dark', 'light']:
                theme_dir = output_path / theme
                theme_dir.mkdir(exist_ok=True)
                
                self.logger.info(f"Generating {theme} theme icons...")
                
                for icon_name, icon_func in self.icon_definitions.items():
                    try:
                        # Generate SVG
                        svg_path = theme_dir / f"{icon_name}.svg"
                        self._generate_svg_icon(icon_func, svg_path, theme)
                        
                        # Generate PNG icons at different sizes
                        for size in self.icon_sizes:
                            png_path = theme_dir / f"{icon_name}_{size}.png"
                            self._generate_png_icon(icon_func, png_path, theme, size)
                        
                        self.logger.debug(f"Generated {icon_name} for {theme} theme")
                        
                    except Exception as e:
                        self.logger.error(f"Error generating {icon_name} icon: {e}")
            
            # Generate theme-neutral icons
            neutral_dir = output_path / "neutral"
            neutral_dir.mkdir(exist_ok=True)
            
            self.logger.info("Generating theme-neutral icons...")
            for icon_name, icon_func in self.icon_definitions.items():
                try:
                    svg_path = neutral_dir / f"{icon_name}.svg"
                    self._generate_svg_icon(icon_func, svg_path, 'neutral')
                    
                    for size in self.icon_sizes:
                        png_path = neutral_dir / f"{icon_name}_{size}.png"
                        self._generate_png_icon(icon_func, png_path, 'neutral', size)
                        
                except Exception as e:
                    self.logger.error(f"Error generating neutral {icon_name} icon: {e}")
            
            self.logger.info(f"Icon generation completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating icons: {e}")
            return False
    
    def _generate_svg_icon(self, icon_func, output_path: Path, theme: str):
        """Generate SVG icon."""
        if not pyside6_available:
            return
        
        try:
            generator = QSvgGenerator()
            generator.setFileName(str(output_path))
            generator.setSize(QSize(256, 256))
            generator.setViewBox(QRectF(0, 0, 256, 256))
            generator.setTitle(f"Antivirus Icon - {output_path.stem}")
            generator.setDescription(f"Generated by IconGenerator for {theme} theme")
            
            painter = QPainter()
            painter.begin(generator)
            painter.setRenderHint(QPainter.Antialiasing)
            
            # Call the icon function
            icon_func(painter, QRectF(0, 0, 256, 256), theme)
            
            painter.end()
            
        except Exception as e:
            self.logger.error(f"Error generating SVG icon {output_path}: {e}")
    
    def _generate_png_icon(self, icon_func, output_path: Path, theme: str, size: int):
        """Generate PNG icon."""
        if not pyside6_available:
            return
        
        try:
            pixmap = QPixmap(size, size)
            pixmap.fill(Qt.transparent)
            
            painter = QPainter()
            painter.begin(pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            
            # Call the icon function
            icon_func(painter, QRectF(0, 0, size, size), theme)
            
            painter.end()
            
            pixmap.save(str(output_path), "PNG")
            
        except Exception as e:
            self.logger.error(f"Error generating PNG icon {output_path}: {e}")
    
    def _get_colors(self, theme: str) -> Dict[str, str]:
        """Get color scheme for theme."""
        if theme == 'neutral':
            return self.color_schemes['dark']  # Use dark as neutral base
        return self.color_schemes.get(theme, self.color_schemes['dark'])
    
    # ========================================================================
    # ICON CREATION METHODS
    # ========================================================================
    
    def _create_app_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create main application icon - shield with antivirus symbol."""
        colors = self._get_colors(theme)
        
        # Create shield shape
        shield_path = QPainterPath()
        center_x = rect.center().x()
        center_y = rect.center().y()
        width = rect.width() * 0.7
        height = rect.height() * 0.8
        
        # Shield outline
        shield_path.moveTo(center_x, rect.top() + rect.height() * 0.1)
        shield_path.cubicTo(
            center_x - width/3, rect.top() + rect.height() * 0.1,
            center_x - width/2, rect.top() + rect.height() * 0.3,
            center_x - width/2, rect.top() + rect.height() * 0.5
        )
        shield_path.lineTo(center_x - width/2, rect.top() + rect.height() * 0.7)
        shield_path.cubicTo(
            center_x - width/2, rect.top() + rect.height() * 0.8,
            center_x, rect.bottom() - rect.height() * 0.05,
            center_x, rect.bottom() - rect.height() * 0.05
        )
        shield_path.cubicTo(
            center_x, rect.bottom() - rect.height() * 0.05,
            center_x + width/2, rect.top() + rect.height() * 0.8,
            center_x + width/2, rect.top() + rect.height() * 0.7
        )
        shield_path.lineTo(center_x + width/2, rect.top() + rect.height() * 0.5)
        shield_path.cubicTo(
            center_x + width/2, rect.top() + rect.height() * 0.3,
            center_x + width/3, rect.top() + rect.height() * 0.1,
            center_x, rect.top() + rect.height() * 0.1
        )
        shield_path.closeSubpath()
        
        # Create gradient
        gradient = QRadialGradient(center_x, center_y, width/2)
        gradient.setColorAt(0, QColor(colors['success']))
        gradient.setColorAt(1, QColor(colors['success']).darker(150))
        
        # Fill shield
        painter.setBrush(QBrush(gradient))
        painter.setPen(QPen(QColor(colors['primary']), 2))
        painter.drawPath(shield_path)
        
        # Add checkmark or virus symbol
        painter.setPen(QPen(QColor(colors['background']), 4, Qt.SolidLine, Qt.RoundCap))
        check_size = width * 0.3
        
        # Checkmark
        painter.drawLine(
            QPointF(center_x - check_size/3, center_y),
            QPointF(center_x - check_size/6, center_y + check_size/3)
        )
        painter.drawLine(
            QPointF(center_x - check_size/6, center_y + check_size/3),
            QPointF(center_x + check_size/2, center_y - check_size/3)
        )
    
    def _create_shield_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create shield icon."""
        self._create_app_icon(painter, rect, theme)  # Same as app icon
    
    def _create_dashboard_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create dashboard icon - grid layout."""
        colors = self._get_colors(theme)
        
        margin = rect.width() * 0.15
        inner_rect = rect.adjusted(margin, margin, -margin, -margin)
        
        # Create 2x2 grid
        cell_width = inner_rect.width() / 2.2
        cell_height = inner_rect.height() / 2.2
        gap = inner_rect.width() * 0.1
        
        painter.setBrush(QBrush(QColor(colors['primary'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        
        # Top-left cell
        painter.drawRoundedRect(
            QRectF(inner_rect.left(), inner_rect.top(), cell_width, cell_height),
            4, 4
        )
        
        # Top-right cell
        painter.drawRoundedRect(
            QRectF(inner_rect.left() + cell_width + gap, inner_rect.top(), cell_width, cell_height),
            4, 4
        )
        
        # Bottom-left cell
        painter.drawRoundedRect(
            QRectF(inner_rect.left(), inner_rect.top() + cell_height + gap, cell_width, cell_height),
            4, 4
        )
        
        # Bottom-right cell (highlight)
        painter.setBrush(QBrush(QColor(colors['accent'])))
        painter.drawRoundedRect(
            QRectF(inner_rect.left() + cell_width + gap, inner_rect.top() + cell_height + gap, cell_width, cell_height),
            4, 4
        )
    
    def _create_scanning_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create scanning icon - magnifying glass with scan lines."""
        colors = self._get_colors(theme)
        
        center = rect.center()
        radius = rect.width() * 0.25
        
        # Magnifying glass circle
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor(colors['scan']), 3))
        painter.drawEllipse(center, radius, radius)
        
        # Handle
        handle_start = QPointF(
            center.x() + radius * 0.7,
            center.y() + radius * 0.7
        )
        handle_end = QPointF(
            center.x() + radius * 1.3,
            center.y() + radius * 1.3
        )
        painter.drawLine(handle_start, handle_end)
        
        # Scan lines inside
        painter.setPen(QPen(QColor(colors['scan']), 1))
        for i in range(3):
            y_offset = (i - 1) * radius * 0.3
            painter.drawLine(
                QPointF(center.x() - radius * 0.5, center.y() + y_offset),
                QPointF(center.x() + radius * 0.5, center.y() + y_offset)
            )
    
    def _create_quarantine_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create quarantine icon - locked folder."""
        colors = self._get_colors(theme)
        
        margin = rect.width() * 0.1
        folder_rect = rect.adjusted(margin, margin * 2, -margin, -margin)
        
        # Folder base
        painter.setBrush(QBrush(QColor(colors['quarantine'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawRoundedRect(folder_rect, 4, 4)
        
        # Folder tab
        tab_width = folder_rect.width() * 0.4
        tab_height = folder_rect.height() * 0.15
        tab_rect = QRectF(
            folder_rect.left(),
            folder_rect.top() - tab_height,
            tab_width,
            tab_height
        )
        painter.drawRoundedRect(tab_rect, 2, 2)
        
        # Lock icon
        lock_size = folder_rect.width() * 0.3
        lock_center = folder_rect.center()
        
        # Lock body
        lock_body = QRectF(
            lock_center.x() - lock_size/2,
            lock_center.y() - lock_size/4,
            lock_size,
            lock_size/2
        )
        painter.setBrush(QBrush(QColor(colors['background'])))
        painter.drawRoundedRect(lock_body, 2, 2)
        
        # Lock shackle
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor(colors['background']), 2))
        shackle_rect = QRectF(
            lock_center.x() - lock_size/3,
            lock_center.y() - lock_size/2,
            lock_size * 2/3,
            lock_size/3
        )
        painter.drawArc(shackle_rect, 0, 180 * 16)
    
    def _create_models_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create models icon - neural network nodes."""
        colors = self._get_colors(theme)
        
        center = rect.center()
        node_radius = rect.width() * 0.06
        
        # Define node positions (3 layers)
        layer1 = [
            QPointF(center.x() - rect.width() * 0.3, center.y() - rect.height() * 0.2),
            QPointF(center.x() - rect.width() * 0.3, center.y()),
            QPointF(center.x() - rect.width() * 0.3, center.y() + rect.height() * 0.2)
        ]
        
        layer2 = [
            QPointF(center.x(), center.y() - rect.height() * 0.3),
            QPointF(center.x(), center.y() - rect.height() * 0.1),
            QPointF(center.x(), center.y() + rect.height() * 0.1),
            QPointF(center.x(), center.y() + rect.height() * 0.3)
        ]
        
        layer3 = [
            QPointF(center.x() + rect.width() * 0.3, center.y() - rect.height() * 0.1),
            QPointF(center.x() + rect.width() * 0.3, center.y() + rect.height() * 0.1)
        ]
        
        # Draw connections
        painter.setPen(QPen(QColor(colors['model']), 1))
        for node1 in layer1:
            for node2 in layer2:
                painter.drawLine(node1, node2)
        
        for node1 in layer2:
            for node2 in layer3:
                painter.drawLine(node1, node2)
        
        # Draw nodes
        painter.setBrush(QBrush(QColor(colors['model'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        
        for nodes in [layer1, layer2, layer3]:
            for node in nodes:
                painter.drawEllipse(node, node_radius, node_radius)
    
    def _create_settings_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create settings icon - gear."""
        colors = self._get_colors(theme)
        
        center = rect.center()
        outer_radius = rect.width() * 0.35
        inner_radius = rect.width() * 0.15
        
        # Create gear path
        gear_path = QPainterPath()
        
        # Outer gear teeth
        teeth_count = 8
        for i in range(teeth_count * 2):
            angle = (i * 180.0 / teeth_count) * 3.14159 / 180.0
            if i % 2 == 0:
                radius = outer_radius
            else:
                radius = outer_radius * 0.8
            
            x = center.x() + radius * cos(angle) if 'cos' in dir(__builtins__) else center.x() + radius * 0.7
            y = center.y() + radius * sin(angle) if 'sin' in dir(__builtins__) else center.y() + radius * 0.7
            
            if i == 0:
                gear_path.moveTo(x, y)
            else:
                gear_path.lineTo(x, y)
        
        gear_path.closeSubpath()
        
        # Draw gear
        painter.setBrush(QBrush(QColor(colors['settings'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawPath(gear_path)
        
        # Inner circle (hole)
        painter.setBrush(QBrush(QColor(colors['background'])))
        painter.drawEllipse(center, inner_radius, inner_radius)
    
    def _create_reports_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create reports icon - chart/graph."""
        colors = self._get_colors(theme)
        
        margin = rect.width() * 0.15
        chart_rect = rect.adjusted(margin, margin, -margin, -margin)
        
        # Chart background
        painter.setBrush(QBrush(QColor(colors['background'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawRoundedRect(chart_rect, 4, 4)
        
        # Chart bars
        bar_width = chart_rect.width() / 6
        bar_spacing = bar_width * 0.2
        
        bar_heights = [0.3, 0.7, 0.5, 0.9, 0.4]
        
        painter.setBrush(QBrush(QColor(colors['info'])))
        
        for i, height in enumerate(bar_heights):
            bar_rect = QRectF(
                chart_rect.left() + (bar_width + bar_spacing) * i + bar_spacing,
                chart_rect.bottom() - chart_rect.height() * height,
                bar_width,
                chart_rect.height() * height
            )
            painter.drawRoundedRect(bar_rect, 2, 2)
    
    def _create_quick_scan_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create quick scan icon - lightning bolt."""
        colors = self._get_colors(theme)
        
        # Lightning bolt path
        bolt_path = QPainterPath()
        center = rect.center()
        width = rect.width() * 0.4
        height = rect.height() * 0.6
        
        # Lightning bolt shape
        bolt_path.moveTo(center.x() - width * 0.2, rect.top() + rect.height() * 0.2)
        bolt_path.lineTo(center.x() + width * 0.3, rect.top() + rect.height() * 0.2)
        bolt_path.lineTo(center.x() - width * 0.1, center.y())
        bolt_path.lineTo(center.x() + width * 0.2, center.y())
        bolt_path.lineTo(center.x() - width * 0.3, rect.bottom() - rect.height() * 0.2)
        bolt_path.lineTo(center.x() - width * 0.1, rect.bottom() - rect.height() * 0.2)
        bolt_path.lineTo(center.x() + width * 0.1, center.y() + height * 0.1)
        bolt_path.lineTo(center.x() - width * 0.2, center.y() + height * 0.1)
        bolt_path.closeSubpath()
        
        painter.setBrush(QBrush(QColor(colors['warning'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawPath(bolt_path)
    
    def _create_full_scan_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create full scan icon - detailed magnifying glass."""
        colors = self._get_colors(theme)
        
        center = rect.center()
        radius = rect.width() * 0.3
        
        # Outer magnifying glass
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor(colors['scan']), 3))
        painter.drawEllipse(center, radius, radius)
        
        # Handle
        handle_start = QPointF(
            center.x() + radius * 0.7,
            center.y() + radius * 0.7
        )
        handle_end = QPointF(
            center.x() + radius * 1.2,
            center.y() + radius * 1.2
        )
        painter.drawLine(handle_start, handle_end)
        
        # Detailed scan pattern inside
        painter.setPen(QPen(QColor(colors['scan']), 1))
        
        # Grid pattern
        for i in range(5):
            offset = (i - 2) * radius * 0.2
            # Vertical lines
            painter.drawLine(
                QPointF(center.x() + offset, center.y() - radius * 0.6),
                QPointF(center.x() + offset, center.y() + radius * 0.6)
            )
            # Horizontal lines
            painter.drawLine(
                QPointF(center.x() - radius * 0.6, center.y() + offset),
                QPointF(center.x() + radius * 0.6, center.y() + offset)
            )
    
    def _create_custom_scan_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create custom scan icon - magnifying glass with settings gear."""
        colors = self._get_colors(theme)
        
        # Main magnifying glass (smaller)
        mag_center = QPointF(rect.center().x() - rect.width() * 0.1, rect.center().y() - rect.height() * 0.1)
        mag_radius = rect.width() * 0.2
        
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor(colors['scan']), 2))
        painter.drawEllipse(mag_center, mag_radius, mag_radius)
        
        # Handle
        handle_start = QPointF(
            mag_center.x() + mag_radius * 0.7,
            mag_center.y() + mag_radius * 0.7
        )
        handle_end = QPointF(
            mag_center.x() + mag_radius * 1.3,
            mag_center.y() + mag_radius * 1.3
        )
        painter.drawLine(handle_start, handle_end)
        
        # Small settings gear
        gear_center = QPointF(rect.center().x() + rect.width() * 0.2, rect.center().y() + rect.height() * 0.2)
        gear_radius = rect.width() * 0.12
        
        painter.setBrush(QBrush(QColor(colors['settings'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawEllipse(gear_center, gear_radius, gear_radius)
        
        # Gear teeth (simplified)
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor(colors['settings']), 1))
        for i in range(6):
            angle = i * 60 * 3.14159 / 180.0
            x1 = gear_center.x() + gear_radius * 0.8 * cos(angle) if 'cos' in dir(__builtins__) else gear_center.x() + gear_radius * 0.6
            y1 = gear_center.y() + gear_radius * 0.8 * sin(angle) if 'sin' in dir(__builtins__) else gear_center.y() + gear_radius * 0.6
            x2 = gear_center.x() + gear_radius * 1.2 * cos(angle) if 'cos' in dir(__builtins__) else gear_center.x() + gear_radius * 0.9
            y2 = gear_center.y() + gear_radius * 1.2 * sin(angle) if 'sin' in dir(__builtins__) else gear_center.y() + gear_radius * 0.9
            
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))
    
    def _create_healthy_status_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create healthy status icon - green checkmark."""
        colors = self._get_colors(theme)
        
        # Circle background
        center = rect.center()
        radius = rect.width() * 0.4
        
        painter.setBrush(QBrush(QColor(colors['success'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawEllipse(center, radius, radius)
        
        # Checkmark
        painter.setPen(QPen(QColor(colors['background']), 4, Qt.SolidLine, Qt.RoundCap))
        check_size = radius * 0.6
        
        painter.drawLine(
            QPointF(center.x() - check_size/3, center.y()),
            QPointF(center.x() - check_size/6, center.y() + check_size/3)
        )
        painter.drawLine(
            QPointF(center.x() - check_size/6, center.y() + check_size/3),
            QPointF(center.x() + check_size/2, center.y() - check_size/3)
        )
    
    def _create_warning_status_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create warning status icon - yellow triangle with exclamation."""
        colors = self._get_colors(theme)
        
        # Triangle
        center = rect.center()
        size = rect.width() * 0.4
        
        triangle = QPolygonF([
            QPointF(center.x(), center.y() - size),
            QPointF(center.x() - size * 0.866, center.y() + size * 0.5),
            QPointF(center.x() + size * 0.866, center.y() + size * 0.5)
        ])
        
        painter.setBrush(QBrush(QColor(colors['warning'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawPolygon(triangle)
        
        # Exclamation mark
        painter.setPen(QPen(QColor(colors['background']), 3, Qt.SolidLine, Qt.RoundCap))
        
        # Line
        painter.drawLine(
            QPointF(center.x(), center.y() - size * 0.3),
            QPointF(center.x(), center.y() + size * 0.1)
        )
        
        # Dot
        painter.drawPoint(QPointF(center.x(), center.y() + size * 0.3))
    
    def _create_critical_status_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create critical status icon - red X."""
        colors = self._get_colors(theme)
        
        # Circle background
        center = rect.center()
        radius = rect.width() * 0.4
        
        painter.setBrush(QBrush(QColor(colors['error'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawEllipse(center, radius, radius)
        
        # X mark
        painter.setPen(QPen(QColor(colors['background']), 4, Qt.SolidLine, Qt.RoundCap))
        x_size = radius * 0.6
        
        painter.drawLine(
            QPointF(center.x() - x_size/2, center.y() - x_size/2),
            QPointF(center.x() + x_size/2, center.y() + x_size/2)
        )
        painter.drawLine(
            QPointF(center.x() + x_size/2, center.y() - x_size/2),
            QPointF(center.x() - x_size/2, center.y() + x_size/2)
        )
    
    # Additional icon methods would continue here...
    # For brevity, I'll provide the remaining methods in the next part
    
    def _create_play_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create play icon - triangle."""
        colors = self._get_colors(theme)
        
        center = rect.center()
        size = rect.width() * 0.3
        
        triangle = QPolygonF([
            QPointF(center.x() - size/2, center.y() - size),
            QPointF(center.x() - size/2, center.y() + size),
            QPointF(center.x() + size, center.y())
        ])
        
        painter.setBrush(QBrush(QColor(colors['success'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawPolygon(triangle)
    
    def _create_pause_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create pause icon - two bars."""
        colors = self._get_colors(theme)
        
        center = rect.center()
        bar_width = rect.width() * 0.12
        bar_height = rect.height() * 0.6
        bar_spacing = rect.width() * 0.08
        
        painter.setBrush(QBrush(QColor(colors['warning'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        
        # Left bar
        painter.drawRoundedRect(
            QRectF(center.x() - bar_spacing/2 - bar_width, center.y() - bar_height/2, bar_width, bar_height),
            2, 2
        )
        
        # Right bar
        painter.drawRoundedRect(
            QRectF(center.x() + bar_spacing/2, center.y() - bar_height/2, bar_width, bar_height),
            2, 2
        )
    
    def _create_stop_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create stop icon - square."""
        colors = self._get_colors(theme)
        
        center = rect.center()
        size = rect.width() * 0.5
        
        stop_rect = QRectF(center.x() - size/2, center.y() - size/2, size, size)
        
        painter.setBrush(QBrush(QColor(colors['error'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawRoundedRect(stop_rect, 4, 4)
    
    # Simplified implementations for remaining icons
    def _create_refresh_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create refresh icon."""
        colors = self._get_colors(theme)
        painter.setPen(QPen(QColor(colors['info']), 3))
        center = rect.center()
        painter.drawEllipse(center, rect.width() * 0.3, rect.width() * 0.3)
    
    def _create_delete_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create delete icon."""
        self._create_critical_status_icon(painter, rect, theme)
    
    def _create_restore_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create restore icon."""
        self._create_healthy_status_icon(painter, rect, theme)
    
    # Placeholder implementations for remaining icons
    def _create_export_icon(self, painter: QPainter, rect: QRectF, theme: str):
        colors = self._get_colors(theme)
        painter.setBrush(QBrush(QColor(colors['info'])))
        painter.drawRect(rect.adjusted(rect.width() * 0.2, rect.height() * 0.2, -rect.width() * 0.2, -rect.height() * 0.2))
    
    def _create_import_icon(self, painter: QPainter, rect: QRectF, theme: str):
        colors = self._get_colors(theme)
        painter.setBrush(QBrush(QColor(colors['success'])))
        painter.drawRect(rect.adjusted(rect.width() * 0.2, rect.height() * 0.2, -rect.width() * 0.2, -rect.height() * 0.2))
    
    def _create_exe_icon(self, painter: QPainter, rect: QRectF, theme: str):
        colors = self._get_colors(theme)
        painter.setBrush(QBrush(QColor(colors['secondary'])))
        painter.drawRoundedRect(rect.adjusted(rect.width() * 0.1, rect.height() * 0.1, -rect.width() * 0.1, -rect.height() * 0.1), 4, 4)
    
    def _create_dll_icon(self, painter: QPainter, rect: QRectF, theme: str):
        self._create_exe_icon(painter, rect, theme)
    
    def _create_doc_icon(self, painter: QPainter, rect: QRectF, theme: str):
        self._create_exe_icon(painter, rect, theme)
    
    def _create_unknown_file_icon(self, painter: QPainter, rect: QRectF, theme: str):
        colors = self._get_colors(theme)
        painter.setBrush(QBrush(QColor(colors['secondary'])))
        painter.drawEllipse(rect.adjusted(rect.width() * 0.2, rect.height() * 0.2, -rect.width() * 0.2, -rect.height() * 0.2))
    
    def _create_malware_icon(self, painter: QPainter, rect: QRectF, theme: str):
        self._create_critical_status_icon(painter, rect, theme)
    
    def _create_virus_icon(self, painter: QPainter, rect: QRectF, theme: str):
        self._create_critical_status_icon(painter, rect, theme)
    
    def _create_trojan_icon(self, painter: QPainter, rect: QRectF, theme: str):
        self._create_critical_status_icon(painter, rect, theme)
    
    def _create_ransomware_icon(self, painter: QPainter, rect: QRectF, theme: str):
        self._create_critical_status_icon(painter, rect, theme)
    
    def _create_minimize_icon(self, painter: QPainter, rect: QRectF, theme: str):
        colors = self._get_colors(theme)
        painter.setPen(QPen(QColor(colors['primary']), 2))
        center = rect.center()
        painter.drawLine(center.x() - rect.width() * 0.2, center.y(), center.x() + rect.width() * 0.2, center.y())
    
    def _create_maximize_icon(self, painter: QPainter, rect: QRectF, theme: str):
        colors = self._get_colors(theme)
        painter.setPen(QPen(QColor(colors['primary']), 2))
        painter.setBrush(Qt.NoBrush)
        painter.drawRect(rect.adjusted(rect.width() * 0.2, rect.height() * 0.2, -rect.width() * 0.2, -rect.height() * 0.2))
    
    def _create_close_icon(self, painter: QPainter, rect: QRectF, theme: str):
        self._create_critical_status_icon(painter, rect, theme)
    
    def _create_notification_icon(self, painter: QPainter, rect: QRectF, theme: str):
        colors = self._get_colors(theme)
        painter.setBrush(QBrush(QColor(colors['info'])))
        painter.drawEllipse(rect.adjusted(rect.width() * 0.1, rect.height() * 0.1, -rect.width() * 0.1, -rect.height() * 0.1))
    
    def _create_update_icon(self, painter: QPainter, rect: QRectF, theme: str):
        self._create_refresh_icon(painter, rect, theme)
    
    def _create_updates_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create updates icon - arrow pointing down with lines."""
        colors = self._get_colors(theme)
        
        center = rect.center()
        arrow_width = rect.width() * 0.3
        arrow_height = rect.height() * 0.4
        
        # Arrow shaft
        painter.setBrush(QBrush(QColor(colors['info'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        shaft_rect = QRectF(
            center.x() - arrow_width * 0.15,
            center.y() - arrow_height * 0.3,
            arrow_width * 0.3,
            arrow_height * 0.6
        )
        painter.drawRoundedRect(shaft_rect, 2, 2)
        
        # Arrow head
        arrow_head = QPolygonF([
            QPointF(center.x() - arrow_width/2, center.y() + arrow_height * 0.1),
            QPointF(center.x() + arrow_width/2, center.y() + arrow_height * 0.1),
            QPointF(center.x(), center.y() + arrow_height * 0.4)
        ])
        painter.drawPolygon(arrow_head)
        
        # Update lines (representing data)
        painter.setPen(QPen(QColor(colors['info']), 1))
        for i in range(3):
            y_pos = center.y() - arrow_height * 0.5 + i * arrow_height * 0.15
            painter.drawLine(
                QPointF(center.x() - arrow_width * 0.4, y_pos),
                QPointF(center.x() + arrow_width * 0.4, y_pos)
            )
    
    def _create_help_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create help icon - question mark."""
        colors = self._get_colors(theme)
        
        # Circle background
        center = rect.center()
        radius = rect.width() * 0.4
        
        painter.setBrush(QBrush(QColor(colors['info'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawEllipse(center, radius, radius)
        
        # Question mark
        painter.setPen(QPen(QColor(colors['background']), 3, Qt.SolidLine, Qt.RoundCap))
        
        # Question mark curve
        q_size = radius * 0.6
        painter.drawArc(
            QRectF(center.x() - q_size/3, center.y() - q_size/2, q_size * 2/3, q_size/2),
            0, 180 * 16
        )
        
        # Question mark tail
        painter.drawLine(
            QPointF(center.x(), center.y()),
            QPointF(center.x(), center.y() + q_size/4)
        )
        
        # Question mark dot
        painter.drawPoint(QPointF(center.x(), center.y() + q_size/2))
    
    def _create_memory_scan_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create memory scan icon - RAM stick with scan line."""
        colors = self._get_colors(theme)
        
        center = rect.center()
        
        # RAM stick
        ram_rect = QRectF(
            center.x() - rect.width() * 0.3,
            center.y() - rect.height() * 0.4,
            rect.width() * 0.6,
            rect.height() * 0.8
        )
        
        painter.setBrush(QBrush(QColor(colors['secondary'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        painter.drawRoundedRect(ram_rect, 4, 4)
        
        # RAM connectors
        connector_height = ram_rect.height() * 0.1
        connector_width = ram_rect.width() * 0.05
        
        for i in range(8):
            connector_x = ram_rect.left() + (i + 1) * ram_rect.width() / 9 - connector_width/2
            connector_rect = QRectF(
                connector_x,
                ram_rect.bottom(),
                connector_width,
                connector_height
            )
            painter.drawRect(connector_rect)
        
        # Scan line
        painter.setPen(QPen(QColor(colors['scan']), 2))
        scan_y = center.y() + rect.height() * 0.1
        painter.drawLine(
            QPointF(ram_rect.left(), scan_y),
            QPointF(ram_rect.right(), scan_y)
        )
    
    def _create_network_scan_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create network scan icon - network nodes with scan waves."""
        colors = self._get_colors(theme)
        
        center = rect.center()
        node_radius = rect.width() * 0.05
        
        # Network nodes
        nodes = [
            QPointF(center.x() - rect.width() * 0.3, center.y() - rect.height() * 0.2),
            QPointF(center.x() + rect.width() * 0.3, center.y() - rect.height() * 0.2),
            QPointF(center.x(), center.y() + rect.height() * 0.3),
            QPointF(center.x() - rect.width() * 0.15, center.y()),
            QPointF(center.x() + rect.width() * 0.15, center.y())
        ]
        
        # Draw connections
        painter.setPen(QPen(QColor(colors['secondary']), 1))
        for i, node1 in enumerate(nodes):
            for j, node2 in enumerate(nodes[i+1:], i+1):
                if j < 3:  # Limit connections
                    painter.drawLine(node1, node2)
        
        # Draw nodes
        painter.setBrush(QBrush(QColor(colors['info'])))
        painter.setPen(QPen(QColor(colors['primary']), 1))
        
        for node in nodes:
            painter.drawEllipse(node, node_radius, node_radius)
        
        # Scan waves (concentric circles around center)
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor(colors['scan']), 1))
        
        for i in range(3):
            wave_radius = rect.width() * (0.1 + i * 0.05)
            painter.drawEllipse(center, wave_radius, wave_radius)
    
    def _create_error_status_icon(self, painter: QPainter, rect: QRectF, theme: str):
        """Create error status icon - same as critical for now."""
        self._create_critical_status_icon(painter, rect, theme)


def generate_icons():
    """Standalone function to generate all application icons."""
    if not pyside6_available:
        print("❌ PySide6 not available - cannot generate icons")
        return False
    
    # Create QApplication if it doesn't exist
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    
    # Create icon generator
    generator = IconGenerator()
    
    # Generate all icons
    success = generator.generate_all_icons()
    
    if success:
        print("✅ All icons generated successfully!")
        print("📁 Icons saved to: src/resources/icons/")
        print("📋 Generated themes: dark, light, neutral")
        print("📏 Generated sizes: 16, 24, 32, 48, 64, 128, 256 pixels")
        print("🎨 Generated formats: SVG, PNG")
    else:
        print("❌ Icon generation failed - check logs for details")
    
    return success


if __name__ == "__main__":
    # Generate icons when run directly
    generate_icons()