from  PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QPushButton, QGraphicsDropShadowEffect, QFrame, QLineEdit,
                             QStackedWidget, QListWidget, QListWidgetItem, QScrollArea, QSizePolicy,
                             QProgressBar, QTextEdit, QMessageBox, QFileDialog,QTabWidget,QDialog)
from PyQt6.QtGui import QFont, QLinearGradient, QColor, QPainter
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import sys
from datetime import datetime
import json
import re  # <-- Ajoutez cette ligne
import os

from scanner_engine import ScannerEngine, HistoryManager, Vulnerability, Severity

# === COMPOSANTS UI AMÉLIORÉS ===
class ModernButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont("Segoe UI", 11, QFont.Weight.Medium))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(0, 4)
        self.setGraphicsEffect(shadow)

class TopNavigationBar(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setMinimumHeight(60)
        self.setMaximumHeight(80)
        self.setStyleSheet("""
            QWidget {
                background: rgba(255, 255, 255, 0.08);
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
        """)
        self.init_ui()
    
    def init_ui(self):
        layout = QHBoxLayout()
        layout.setContentsMargins(20, 10, 20, 10)
        
        # Logo et titre
        logo_title = QHBoxLayout()
        logo_title.setSpacing(12)
        
        logo = QLabel("🔍")
        logo.setStyleSheet("""
            QLabel {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                          stop:0 #00d4ff, stop:1 #0099cc);
                color: white;
                font-size: 16px;
                border-radius: 8px;
                padding: 6px;
            }
        """)
        logo.setFixedSize(40, 40)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)
        
        self.title = QLabel("DVW Secure")
        self.title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.title.setStyleSheet("color: white;")
        
        self.subtitle = QLabel("Security Scanner")
        self.subtitle.setFont(QFont("Segoe UI", 9))
        self.subtitle.setStyleSheet("color: rgba(255, 255, 255, 0.7);")
        
        title_layout.addWidget(self.title)
        title_layout.addWidget(self.subtitle)
        
        logo_title.addWidget(logo)
        logo_title.addLayout(title_layout)
        
        layout.addLayout(logo_title)
        layout.addSpacing(20)
        
        # Boutons de navigation - responsive
        self.nav_buttons_layout = QHBoxLayout()
        self.nav_buttons_layout.setSpacing(8)
        
        self.nav_buttons = []
        nav_items = [
            ("🏠 Accueil", 0),
            ("🔍 Scanner", 1),
            ("📊 Historique", 2),
            ("🔧 Correction IA", 3),
            ("⚙️ Paramètres", 4)
        ]
        
        for text, page_index in nav_items:
            btn = QPushButton(text)
            btn.setFont(QFont("Segoe UI", 10))
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setMinimumHeight(35)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            btn.setStyleSheet("""
                QPushButton {
                    background: transparent;
                    color: rgba(255, 255, 255, 0.8);
                    border: none;
                    border-radius: 6px;
                    padding: 8px 12px;
                    min-width: 80px;
                }
                QPushButton:hover {
                    background: rgba(255, 255, 255, 0.05);
                    color: white;
                }
                QPushButton.active {
                    background: rgba(0, 212, 255, 0.15);
                    color: #00d4ff;
                    font-weight: 600;
                }
            """)
            btn.clicked.connect(lambda checked, idx=page_index: self.main_window.show_page(idx))
            self.nav_buttons.append(btn)
            self.nav_buttons_layout.addWidget(btn)
        
        layout.addLayout(self.nav_buttons_layout)
        layout.addStretch()
        
        # Status - s'adapte à la taille
        status_layout = QVBoxLayout()
        status_layout.setSpacing(2)
        status_layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.status_label = QLabel("● En ligne")
        self.status_label.setFont(QFont("Segoe UI", 9))
        self.status_label.setStyleSheet("color: #00ff00;")
        
        self.version_label = QLabel("v2.1.0")
        self.version_label.setFont(QFont("Segoe UI", 8))
        self.version_label.setStyleSheet("color: rgba(255, 255, 255, 0.5);")
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.version_label)
        
        layout.addLayout(status_layout)
        
        self.setLayout(layout)
    
    def set_active_button(self, page_index):
        for i, btn in enumerate(self.nav_buttons):
            if i == page_index:
                btn.setStyleSheet("""
                    QPushButton {
                        background: rgba(0, 212, 255, 0.15);
                        color: #00d4ff;
                        border: none;
                        border-radius: 6px;
                        padding: 8px 12px;
                        min-width: 80px;
                        font-weight: 600;
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        background: transparent;
                        color: rgba(255, 255, 255, 0.8);
                        border: none;
                        border-radius: 6px;
                        padding: 8px 12px;
                        min-width: 80px;
                    }
                    QPushButton:hover {
                        background: rgba(255, 255, 255, 0.05);
                        color: white;
                    }
                """)

class GradientWidget(QWidget):
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0.0, QColor("#0f2027"))
        gradient.setColorAt(0.5, QColor("#203a43"))
        gradient.setColorAt(1.0, QColor("#2c5364"))
        
        painter.fillRect(self.rect(), gradient)

class ModernCard(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QFrame {
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
            }
        """)
        
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 60))
        shadow.setOffset(0, 4)
        self.setGraphicsEffect(shadow)

class VulnerabilityWidget(QFrame):
    def __init__(self, vulnerability):
        super().__init__()
        self.vulnerability = vulnerability
        self.init_ui()
    
    def init_ui(self):
        self.setStyleSheet(f"""
            QFrame {{
                background: rgba(255, 255, 255, 0.05);
                border-left: 4px solid {self.vulnerability.get_color()};
                border-radius: 8px;
                margin: 5px;
            }}
        """)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(6)
        
        # En-tête avec titre et sévérité
        header_layout = QHBoxLayout()
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)
        
        title_label = QLabel(f"{self.vulnerability.get_icon()} {self.vulnerability.title}")
        title_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title_label.setStyleSheet(f"color: {self.vulnerability.get_color()};")
        
        severity_label = QLabel(f"Sévérité: {self.vulnerability.severity} | CVSS: {self.vulnerability.cvss_score}")
        severity_label.setFont(QFont("Segoe UI", 9))
        severity_label.setStyleSheet("color: rgba(255, 255, 255, 0.7);")
        
        title_layout.addWidget(title_label)
        title_layout.addWidget(severity_label)
        
        header_layout.addLayout(title_layout)
        header_layout.addStretch()
        
        # Description
        desc_label = QLabel(self.vulnerability.description)
        desc_label.setFont(QFont("Segoe UI", 10))
        desc_label.setStyleSheet("color: rgba(255, 255, 255, 0.9);")
        desc_label.setWordWrap(True)
        
        # Localisation
        loc_label = QLabel(f"📍 {self.vulnerability.location}")
        loc_label.setFont(QFont("Segoe UI", 9))
        loc_label.setStyleSheet("color: rgba(255, 255, 255, 0.6);")
        loc_label.setWordWrap(True)
        
        # Recommandation
        rec_label = QLabel(f"💡 {self.vulnerability.recommendation}")
        rec_label.setFont(QFont("Segoe UI", 9))
        rec_label.setStyleSheet("color: #00d4ff;")
        rec_label.setWordWrap(True)
        
        layout.addLayout(header_layout)
        layout.addWidget(desc_label)
        layout.addWidget(loc_label)
        layout.addWidget(rec_label)
        
        self.setLayout(layout)

# === PAGES AVEC SYSTÈME D'ANALYSE INTÉGRÉ ===
class WelcomePage(GradientWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()
    
    def init_ui(self):
        # Scroll area pour le contenu responsive
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        # Widget conteneur principal
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Container central responsive
        container = QWidget()
        container.setStyleSheet("background: transparent;")
        
        content = QVBoxLayout()
        content.setContentsMargins(20, 20, 20, 20)
        content.setSpacing(30)
        
        # Hero section responsive
        hero_layout = QVBoxLayout()
        hero_layout.setSpacing(20)
        
        title = QLabel("DVW Secure Scanner")
        title.setFont(QFont("Segoe UI", 32, QFont.Weight.Bold))
        title.setStyleSheet("color: white;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setWordWrap(True)
        
        subtitle = QLabel("Solution professionnelle d'analyse de vulnérabilités web")
        subtitle.setFont(QFont("Segoe UI", 14))
        subtitle.setStyleSheet("color: rgba(255, 255, 255, 0.8);")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)
        
        # Stats en ligne responsive
        stats_card = ModernCard()
        stats_layout = QHBoxLayout()
        stats_layout.setContentsMargins(20, 15, 20, 15)
        stats_layout.setSpacing(15)
        
        stats = [
            ("🔒", "Analyse", "Sécurité"),
            ("🎯", "Détection", "Vulnérabilités"),
            ("⚡", "Rapport", "Automatique"),
            ("🛡️", "Classification", "Intelligente")
        ]
        
        for icon, value, label in stats:
            stat_widget = QWidget()
            stat_widget.setStyleSheet("background: transparent;")
            stat_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            stat_layout_widget = QHBoxLayout()
            stat_layout_widget.setSpacing(8)
            stat_layout_widget.setContentsMargins(0, 0, 0, 0)
            
            icon_label = QLabel(icon)
            icon_label.setFont(QFont("Segoe UI", 16))
            icon_label.setStyleSheet("background: transparent;")
            icon_label.setFixedSize(30, 30)
            
            text_layout = QVBoxLayout()
            text_layout.setSpacing(2)
            text_layout.setContentsMargins(0, 0, 0, 0)
            
            value_label = QLabel(value)
            value_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
            value_label.setStyleSheet("color: #00d4ff;")
            
            desc_label = QLabel(label)
            desc_label.setFont(QFont("Segoe UI", 10))
            desc_label.setStyleSheet("color: rgba(255, 255, 255, 0.7);")
            
            text_layout.addWidget(value_label)
            text_layout.addWidget(desc_label)
            
            stat_layout_widget.addWidget(icon_label)
            stat_layout_widget.addLayout(text_layout)
            stat_widget.setLayout(stat_layout_widget)
            stats_layout.addWidget(stat_widget)
        
        stats_card.setLayout(stats_layout)
        
        hero_layout.addWidget(title)
        hero_layout.addWidget(subtitle)
        hero_layout.addSpacing(15)
        hero_layout.addWidget(stats_card)
        
        # Section d'actions principales responsive
        actions_label = QLabel("Actions Rapides")
        actions_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        actions_label.setStyleSheet("color: white; margin: 10px 0px;")
        
        # Grille d'actions responsive
        actions_grid = QGridLayout()
        actions_grid.setSpacing(15)
        actions_grid.setContentsMargins(0, 0, 0, 0)
        
        actions = [
            ("🔍 Nouveau Scan", "Lancer une analyse de sécurité", 1, "background: rgba(0, 212, 255, 0.1); color: #00d4ff;"),
            ("📊 Voir Historique", "Consulter les analyses passées", 2, "background: rgba(255, 193, 7, 0.1); color: #ffc107;"),
            ("⚙️ Paramètres", "Configurer les options", 4, "background: rgba(76, 175, 80, 0.1); color: #4caf50;"),
            ("🔧 Correction IA", "Analyser du code source", 3, "background: rgba(156, 39, 176, 0.1); color: #9c27b0;"),
        ]
        
        row, col = 0, 0
        for text, tooltip, page_index, style in actions:
            btn = ModernButton(text)
            btn.setToolTip(tooltip)
            btn.setMinimumHeight(70)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            btn.setStyleSheet(f"""
                QPushButton {{
                    {style}
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 10px;
                    font-weight: 500;
                    font-size: 12px;
                }}
                QPushButton:hover {{
                    background: rgba(255, 255, 255, 0.15);
                }}
            """)
            btn.clicked.connect(lambda checked, idx=page_index: self.main_window.show_page(idx))
            actions_grid.addWidget(btn, row, col)
            
            col += 1
            if col >= 2:
                col = 0
                row += 1
        
        # Section features responsive
        features_label = QLabel("Fonctionnalités")
        features_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        features_label.setStyleSheet("color: white; margin: 20px 0px 10px 0px;")
        
        features_card = ModernCard()
        features_layout = QHBoxLayout()
        features_layout.setContentsMargins(20, 20, 20, 20)
        features_layout.setSpacing(20)
        
        features = [
            ("🌐", "Scan Complet", "Analyse des en-têtes, formulaires et configuration"),
            ("🔐", "Détection Intelligente", "Classification automatique des vulnérabilités"),
            ("📋", "Rapports Détaillés", "Recommandations personnalisées par faille"),
            ("⚡", "Temps Réel", "Résultats en direct pendant l'analyse")
        ]
        
        for icon, title_text, description in features:
            feature_widget = QWidget()
            feature_widget.setStyleSheet("background: transparent;")
            feature_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            feature_layout_inner = QVBoxLayout()
            feature_layout_inner.setSpacing(8)
            feature_layout_inner.setAlignment(Qt.AlignmentFlag.AlignCenter)
            feature_layout_inner.setContentsMargins(0, 0, 0, 0)
            
            icon_label = QLabel(icon)
            icon_label.setFont(QFont("Segoe UI", 24))
            icon_label.setStyleSheet("background: transparent;")
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_label.setFixedHeight(40)
            
            title_label = QLabel(title_text)
            title_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
            title_label.setStyleSheet("color: #00d4ff;")
            title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            title_label.setWordWrap(True)
            
            desc_label = QLabel(description)
            desc_label.setFont(QFont("Segoe UI", 9))
            desc_label.setStyleSheet("color: rgba(255, 255, 255, 0.7);")
            desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            desc_label.setWordWrap(True)
            
            feature_layout_inner.addWidget(icon_label)
            feature_layout_inner.addWidget(title_label)
            feature_layout_inner.addWidget(desc_label)
            feature_widget.setLayout(feature_layout_inner)
            features_layout.addWidget(feature_widget)
        
        features_card.setLayout(features_layout)
        
        # Assemblage
        content.addLayout(hero_layout)
        content.addWidget(actions_label)
        content.addLayout(actions_grid)
        content.addWidget(features_label)
        content.addWidget(features_card)
        content.addStretch()
        
        container.setLayout(content)
        
        # Centrage responsive
        center_layout = QHBoxLayout()
        center_layout.addStretch()
        center_layout.addWidget(container)
        center_layout.addStretch()
        
        main_layout.addLayout(center_layout)
        
        scroll.setWidget(main_widget)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)

class ScannerPage(GradientWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.scanner_engine = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Header
        header = QLabel("🔍 Analyse de Sécurité")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: white;")
        
        # Carte de configuration
        config_card = ModernCard()
        config_layout = QVBoxLayout(config_card)
        config_layout.setContentsMargins(20, 20, 20, 20)
        config_layout.setSpacing(15)
        
        url_label = QLabel("🌐 URL à analyser")
        url_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        url_label.setStyleSheet("color: white;")
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://exemple.com")
        self.url_input.setFont(QFont("Segoe UI", 12))
        self.url_input.setMinimumHeight(45)
        self.url_input.setStyleSheet("""
            QLineEdit {
                background: rgba(255, 255, 255, 0.1);
                border: 2px solid rgba(255, 255, 255, 0.15);
                border-radius: 10px;
                padding: 10px 15px;
                color: white;
            }
            QLineEdit:focus {
                border: 2px solid #00d4ff;
            }
        """)
        
        # Exemples d'URLs de test
        examples_label = QLabel("Exemples de test: http://testphp.vulnweb.com, http://demo.testfire.net")
        examples_label.setFont(QFont("Segoe UI", 9))
        examples_label.setStyleSheet("color: rgba(255, 255, 255, 0.5);")
        
        config_layout.addWidget(url_label)
        config_layout.addWidget(self.url_input)
        config_layout.addWidget(examples_label)
        
        # Barre de progression
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(8)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: rgba(255, 255, 255, 0.1);
                border: none;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                          stop:0 #00d4ff, stop:1 #0099cc);
                border-radius: 4px;
            }
        """)
        self.progress_bar.setVisible(False)
        
        # Label de statut
        self.status_label = QLabel("Prêt à analyser")
        self.status_label.setFont(QFont("Segoe UI", 10))
        self.status_label.setStyleSheet("color: rgba(255, 255, 255, 0.7);")
        
        # Console de logs
        log_card = ModernCard()
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(15, 15, 15, 15)
        
        log_label = QLabel("📝 Journal d'analyse")
        log_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        log_label.setStyleSheet("color: white;")
        
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(120)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setStyleSheet("""
            QTextEdit {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                color: rgba(255, 255, 255, 0.8);
                padding: 8px;
            }
        """)
        self.log_text.setReadOnly(True)
        
        log_layout.addWidget(log_label)
        log_layout.addWidget(self.log_text)
        
        # Boutons
        buttons_layout = QHBoxLayout()
        
        self.btn_scan = ModernButton("🚀 Lancer l'Analyse")
        self.btn_scan.setMinimumHeight(50)
        self.btn_scan.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                          stop:0 #00d4ff, stop:1 #0099cc);
                color: white;
                border: none;
                border-radius: 10px;
                padding: 12px 24px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                          stop:0 #00e5ff, stop:1 #00b8e6);
            }
            QPushButton:disabled {
                background: rgba(255, 255, 255, 0.1);
                color: rgba(255, 255, 255, 0.5);
            }
        """)
        self.btn_scan.clicked.connect(self.start_scan)
        
        self.btn_stop = ModernButton("⏹️ Arrêter")
        self.btn_stop.setMinimumHeight(50)
        self.btn_stop.setStyleSheet("""
            QPushButton {
                background: rgba(244, 67, 54, 0.8);
                color: white;
                border: none;
                border-radius: 10px;
                padding: 12px 24px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: rgba(244, 67, 54, 1.0);
            }
            QPushButton:disabled {
                background: rgba(255, 255, 255, 0.1);
                color: rgba(255, 255, 255, 0.5);
            }
        """)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_stop.setVisible(False)
        
        buttons_layout.addWidget(self.btn_scan)
        buttons_layout.addWidget(self.btn_stop)
        
        # Zone de résultats
        results_label = QLabel("📊 Résultats de l'Analyse")
        results_label.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        results_label.setStyleSheet("color: white; margin: 10px 0px;")
        
        # Statistiques
        self.stats_card = ModernCard()
        self.stats_card.setVisible(False)
        stats_layout = QHBoxLayout(self.stats_card)
        stats_layout.setContentsMargins(20, 15, 20, 15)
        
        self.stats_labels = {}
        severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        
        for severity in severities:
            stat_widget = QWidget()
            stat_layout = QVBoxLayout(stat_widget)
            stat_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            count_label = QLabel("0")
            count_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
            count_label.setStyleSheet(f"color: {Severity.SEVERITY_COLORS[severity]};")
            
            name_label = QLabel(severity)
            name_label.setFont(QFont("Segoe UI", 9))
            name_label.setStyleSheet("color: rgba(255, 255, 255, 0.7);")
            
            stat_layout.addWidget(count_label)
            stat_layout.addWidget(name_label)
            stats_layout.addWidget(stat_widget)
            
            self.stats_labels[severity] = count_label
        
        # Container pour les résultats
        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setSpacing(10)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        
        results_scroll = QScrollArea()
        results_scroll.setWidgetResizable(True)
        results_scroll.setWidget(self.results_container)
        results_scroll.setMinimumHeight(300)
        results_scroll.setStyleSheet("""
            QScrollArea {
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                background: rgba(255, 255, 255, 0.02);
            }
        """)
        
        # Message quand aucun résultat
        self.no_results_label = QLabel("Aucune vulnérabilité trouvée. Lancez une analyse pour commencer.")
        self.no_results_label.setFont(QFont("Segoe UI", 11))
        self.no_results_label.setStyleSheet("color: rgba(255, 255, 255, 0.5);")
        self.no_results_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_layout.addWidget(self.no_results_label)
        
        # Assemblage
        main_layout.addWidget(header)
        main_layout.addWidget(config_card)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.status_label)
        main_layout.addWidget(log_card)
        main_layout.addLayout(buttons_layout)
        main_layout.addWidget(results_label)
        main_layout.addWidget(self.stats_card)
        main_layout.addWidget(results_scroll)
        
        scroll.setWidget(main_widget)
        layout.addWidget(scroll)
    
    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            self.status_label.setText("❌ Veuillez entrer une URL valide")
            return
        
        # Préparer l'interface
        self.btn_scan.setEnabled(False)
        self.btn_stop.setVisible(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("🔄 Initialisation de l'analyse...")
        self.log_text.clear()
        
        # Nettoyer les résultats précédents
        for i in reversed(range(self.results_layout.count())):
            widget = self.results_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
        
        self.no_results_label.setVisible(True)
        self.stats_card.setVisible(False)
        
        # Lancer le scan AVEC le history_manager
        self.scanner_engine = ScannerEngine(url, self.main_window.history_manager)
        self.scanner_engine.progress_updated.connect(self.update_progress)
        self.scanner_engine.vulnerability_found.connect(self.add_vulnerability)
        self.scanner_engine.scan_completed.connect(self.scan_finished)
        self.scanner_engine.status_updated.connect(self.update_status)
        self.scanner_engine.log_message.connect(self.add_log_message)
        self.scanner_engine.start()
    
    def stop_scan(self):
        if self.scanner_engine:
            self.scanner_engine.stop_scan()
        self.scan_finished([])
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def update_status(self, status):
        self.status_label.setText(status)
    
    def add_log_message(self, message):
        self.log_text.append(f"{datetime.now().strftime('%H:%M:%S')} - {message}")
        # Auto-scroll vers le bas
        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum()
        )
    
    def add_vulnerability(self, vulnerability):
        """Ajoute une vulnérabilité à l'affichage"""
        self.no_results_label.setVisible(False)
        vuln_widget = VulnerabilityWidget(vulnerability)
        self.results_layout.addWidget(vuln_widget)
    
    def scan_finished(self, vulnerabilities):
        """Finalise l'analyse et affiche les statistiques"""
        self.btn_scan.setEnabled(True)
        self.btn_stop.setVisible(False)
        self.progress_bar.setVisible(False)
        
        # Calculer les statistiques
        stats = {severity: 0 for severity in Severity.SEVERITY_COLORS.keys()}
        for vuln in vulnerabilities:
            stats[vuln.severity] += 1
        
        # Mettre à jour l'affichage des stats
        for severity, count in stats.items():
            self.stats_labels[severity].setText(str(count))
        
        self.stats_card.setVisible(True)
        
        if vulnerabilities:
            total_vulns = len(vulnerabilities)
            self.status_label.setText(f"✅ Analyse terminée - {total_vulns} vulnérabilité(s) trouvée(s)")
            self.add_log_message(f"✅ Analyse terminée avec {total_vulns} vulnérabilité(s)")
        else:
            self.status_label.setText("✅ Analyse terminée - Aucune vulnérabilité critique trouvée")
            self.add_log_message("✅ Analyse terminée - Aucune vulnérabilité trouvée")

class HistoryPage(GradientWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.history_manager = main_window.history_manager
        self.init_ui()
        self.load_history()
    
    def init_ui(self):
        # Scroll area pour le contenu responsive
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        container = QWidget()
        container.setStyleSheet("background: transparent;")
        
        content = QVBoxLayout()
        content.setContentsMargins(20, 20, 20, 20)
        content.setSpacing(20)
        
        # Header responsive
        header = QWidget()
        header.setStyleSheet("background: transparent;")
        header_layout = QVBoxLayout()
        header_layout.setSpacing(8)
        
        title = QLabel("📊 Historique des Analyses")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: white;")
        title.setWordWrap(True)
        
        subtitle = QLabel("Consultez vos analyses précédentes")
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setStyleSheet("color: rgba(255, 255, 255, 0.7);")
        subtitle.setWordWrap(True)
        
        # Bouton actualiser
        refresh_btn = QPushButton("🔄 Actualiser")
        refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_btn.setFixedSize(120, 35)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background: rgba(0, 212, 255, 0.15);
                color: #00d4ff;
                border: 1px solid rgba(0, 212, 255, 0.3);
                border-radius: 6px;
                font-size: 11px;
            }
            QPushButton:hover {
                background: rgba(0, 212, 255, 0.25);
            }
        """)
        refresh_btn.clicked.connect(self.load_history)
        
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        
        header_buttons = QHBoxLayout()
        header_buttons.addStretch()
        header_buttons.addWidget(refresh_btn)
        
        header_layout.addLayout(header_buttons)
        header.setLayout(header_layout)
        
        # Container pour l'historique
        self.history_container = QWidget()
        self.history_layout = QVBoxLayout(self.history_container)
        self.history_layout.setSpacing(10)
        self.history_layout.setContentsMargins(0, 0, 0, 0)
        
        history_scroll = QScrollArea()
        history_scroll.setWidgetResizable(True)
        history_scroll.setWidget(self.history_container)
        history_scroll.setStyleSheet("""
            QScrollArea {
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                background: rgba(255, 255, 255, 0.02);
            }
        """)
        
        # Message quand aucun historique
        self.no_history_label = QLabel("Aucune analyse dans l'historique. Effectuez une analyse pour commencer.")
        self.no_history_label.setFont(QFont("Segoe UI", 12))
        self.no_history_label.setStyleSheet("color: rgba(255, 255, 255, 0.5);")
        self.no_history_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.no_history_label.setMinimumHeight(200)
        self.history_layout.addWidget(self.no_history_label)
        
        content.addWidget(header)
        content.addSpacing(10)
        content.addWidget(history_scroll)
        
        container.setLayout(content)
        
        # Centrage responsive
        center_layout = QHBoxLayout()
        center_layout.addStretch()
        center_layout.addWidget(container)
        center_layout.addStretch()
        
        layout.addLayout(center_layout)
        scroll.setWidget(main_widget)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)
    
    def load_history(self):
        """Charge et affiche l'historique des analyses"""
        # Nettoyer l'affichage précédent
        for i in reversed(range(self.history_layout.count())):
            widget = self.history_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
        
        # Charger l'historique
        recent_scans = self.history_manager.get_recent_scans(20)
        
        if not recent_scans:
            self.no_history_label.setVisible(True)
            self.history_layout.addWidget(self.no_history_label)
            return
        
        self.no_history_label.setVisible(False)
        
        # Afficher chaque analyse
        for scan in recent_scans:
            item = self.create_history_item(scan)
            self.history_layout.addWidget(item)
        
        self.history_layout.addStretch()
    
    def create_history_item(self, scan_data):
        """Crée un widget pour un élément d'historique"""
        item = QFrame()
        item.setStyleSheet("""
            QFrame {
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 8px;
            }
        """)
        item.setMinimumHeight(80)
        item.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        
        layout = QHBoxLayout()
        layout.setContentsMargins(15, 10, 15, 10)
        layout.setSpacing(10)
        
        # Informations principales
        main_info = QVBoxLayout()
        main_info.setSpacing(4)
        
        # URL
        url_label = QLabel(scan_data['target_url'])
        url_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Medium))
        url_label.setStyleSheet("color: white;")
        url_label.setWordWrap(True)
        
        # Date et durée
        date_duration = QHBoxLayout()
        
        date_label = QLabel(f"📅 {scan_data['timestamp']}")
        date_label.setFont(QFont("Segoe UI", 9))
        date_label.setStyleSheet("color: rgba(255, 255, 255, 0.6);")
        
        duration_label = QLabel(f"⏱️ {scan_data['scan_duration']:.1f}s")
        duration_label.setFont(QFont("Segoe UI", 9))
        duration_label.setStyleSheet("color: rgba(255, 255, 255, 0.6);")
        
        date_duration.addWidget(date_label)
        date_duration.addWidget(duration_label)
        date_duration.addStretch()
        
        main_info.addWidget(url_label)
        main_info.addLayout(date_duration)
        
        # Statistiques des vulnérabilités
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)
        
        vuln_summary = scan_data.get('vulnerabilities', {})
        total_vulns = scan_data['vulnerabilities_count']
        
        # Afficher les counts par sévérité
        for severity, color in Severity.SEVERITY_COLORS.items():
            count = vuln_summary.get(severity, 0)
            if count > 0:
                stat_label = QLabel(f"{count}")
                stat_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
                stat_label.setStyleSheet(f"color: {color}; background: rgba{color}20; padding: 2px 6px; border-radius: 4px;")
                stat_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                stat_label.setToolTip(f"{severity}: {count}")
                stats_layout.addWidget(stat_label)
        
        # Status
        status_label = QLabel(scan_data['status'])
        status_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        status_color = "#00ff88" if scan_data['status'] == "Terminé" else "#ffaa00"
        status_label.setStyleSheet(f"color: {status_color};")
        status_label.setFixedWidth(80)
        
        # Bouton voir détails
        details_btn = QPushButton("📊 Détails")
        details_btn.setFixedSize(100, 35)
        details_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        details_btn.setStyleSheet("""
            QPushButton {
                background: rgba(0, 212, 255, 0.15);
                color: #00d4ff;
                border: 1px solid rgba(0, 212, 255, 0.3);
                border-radius: 6px;
                font-size: 10px;
            }
            QPushButton:hover {
                background: rgba(0, 212, 255, 0.25);
            }
        """)
        details_btn.clicked.connect(lambda: self.show_scan_details(scan_data))
        
        layout.addLayout(main_info)
        layout.addStretch()
        layout.addLayout(stats_layout)
        layout.addWidget(status_label)
        layout.addWidget(details_btn)
        
        item.setLayout(layout)
        return item
    
    def show_scan_details(self, scan_data):
        """Affiche les détails d'une analyse"""
        msg = QMessageBox()
        msg.setWindowTitle(f"Détails de l'analyse - {scan_data['target_url']}")
        
        details_text = f"""
        Analyse du {scan_data['timestamp']}
        
        URL: {scan_data['target_url']}
        Durée: {scan_data['scan_duration']:.1f} secondes
        Statut: {scan_data['status']}
        Total vulnérabilités: {scan_data['vulnerabilities_count']}
        
        Détail par sévérité:
        """
        
        # Ajouter le détail par sévérité
        vuln_summary = scan_data.get('vulnerabilities', {})
        for severity in Severity.SEVERITY_COLORS.keys():
            count = vuln_summary.get(severity, 0)
            if count > 0:
                details_text += f"\n- {severity}: {count}"
        
        msg.setText(details_text)
        msg.exec()

class SettingsPage(GradientWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()
    
    def init_ui(self):
        # Scroll area pour le contenu responsive
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        container = QWidget()
        container.setStyleSheet("background: transparent;")
        
        content = QVBoxLayout()
        content.setContentsMargins(20, 20, 20, 20)
        content.setSpacing(20)
        
        # Header responsive
        header = QWidget()
        header.setStyleSheet("background: transparent;")
        header_layout = QVBoxLayout()
        header_layout.setSpacing(8)
        
        title = QLabel("⚙️ Paramètres")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: white;")
        title.setWordWrap(True)
        
        subtitle = QLabel("Configurez votre analyseur de sécurité")
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setStyleSheet("color: rgba(255, 255, 255, 0.7);")
        subtitle.setWordWrap(True)
        
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header.setLayout(header_layout)
        
        # Paramètres responsive
        settings_card = ModernCard()
        settings_layout = QVBoxLayout()
        settings_layout.setContentsMargins(20, 20, 20, 20)
        settings_layout.setSpacing(15)
        
        settings_title = QLabel("Options de Scan")
        settings_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        settings_title.setStyleSheet("color: white;")
        settings_layout.addWidget(settings_title)
        
        options = [
            ("Scan approfondi", "Analyse complète mais plus lente", True),
            ("Vérification XSS", "Détection des vulnérabilités XSS", True),
            ("Test SQL Injection", "Détection des injections SQL", True),
            ("Scan des headers", "Vérification des en-têtes de sécurité", False)
        ]
        
        for option, description, checked in options:
            settings_layout.addWidget(self.create_setting_option(option, description, checked))
        
        settings_card.setLayout(settings_layout)
        
        content.addWidget(header)
        content.addSpacing(10)
        content.addWidget(settings_card)
        content.addStretch()
        
        container.setLayout(content)
        
        # Centrage responsive
        center_layout = QHBoxLayout()
        center_layout.addStretch()
        center_layout.addWidget(container)
        center_layout.addStretch()
        
        layout.addLayout(center_layout)
        scroll.setWidget(main_widget)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)
    
    def create_setting_option(self, option, description, checked):
        widget = QWidget()
        widget.setStyleSheet("background: transparent;")
        widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        
        checkbox = QPushButton("✓" if checked else "")
        checkbox.setCheckable(True)
        checkbox.setChecked(checked)
        checkbox.setFixedSize(20, 20)
        checkbox.setCursor(Qt.CursorShape.PointingHandCursor)
        checkbox.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 0.1);
                border: 2px solid rgba(255, 255, 255, 0.3);
                border-radius: 4px;
                color: white;
                font-size: 10px;
            }
            QPushButton:checked {
                background: #00d4ff;
                border: 2px solid #00d4ff;
            }
        """)
        
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        text_layout.setContentsMargins(0, 0, 0, 0)
        
        option_label = QLabel(option)
        option_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Medium))
        option_label.setStyleSheet("color: white;")
        
        desc_label = QLabel(description)
        desc_label.setFont(QFont("Segoe UI", 9))
        desc_label.setStyleSheet("color: rgba(255, 255, 255, 0.6);")
        desc_label.setWordWrap(True)
        
        text_layout.addWidget(option_label)
        text_layout.addWidget(desc_label)
        
        layout.addWidget(checkbox)
        layout.addLayout(text_layout)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget

class CodeCorrectionPage(GradientWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.code_files = []
        self.vulnerabilities_found = []
        self.corrected_files = []  # Pour stocker les fichiers corrigés
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Header
        header = QLabel("🤖 Générateur IA de Code Sécurisé")
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        header.setStyleSheet("color: #C527F5;")
        
        # Description
        description = QLabel(
            "Téléchargez vos fichiers source → L'IA analyse les vulnérabilités → "
            "Recevez le code corrigé et sécurisé directement !"
        )
        description.setFont(QFont("Segoe UI", 12))
        description.setStyleSheet("color: rgba(255, 255, 255, 0.8);")
        description.setWordWrap(True)
        
        # Carte de dépôt de fichiers
        drop_card = ModernCard()
        drop_layout = QVBoxLayout(drop_card)
        drop_layout.setContentsMargins(20, 30, 20, 30)
        drop_layout.setSpacing(20)
        
        self.drop_label = QLabel("📁 Déposez vos fichiers de code source ici")
        self.drop_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_label.setAcceptDrops(True)
        self.drop_label.dragEnterEvent = self.drag_enter_event
        self.drop_label.dropEvent = self.drop_event
        self.drop_label.mousePressEvent = self.browse_files
        
        self._update_drop_zone_style()
        
        self.drop_label.setMinimumHeight(200)
        
        drop_layout.addWidget(self.drop_label)
        
        # Bouton parcourir
        browse_btn = ModernButton("📂 Parcourir les fichiers")
        browse_btn.clicked.connect(self.browse_files)
        browse_btn.setMinimumHeight(40)
        
        drop_layout.addWidget(browse_btn)
        
        # Liste des fichiers
        files_label = QLabel("📄 Fichiers chargés:")
        files_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        files_label.setStyleSheet("color: white;")
        
        self.file_list = QListWidget()
        self.file_list.setMaximumHeight(150)
        self.file_list.setStyleSheet("""
            QListWidget {
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                color: white;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            }
            QListWidget::item:selected {
                background: rgba(0, 212, 255, 0.2);
            }
        """)
        
        # Section des vulnérabilités
        vuln_section = QWidget()
        vuln_layout = QVBoxLayout(vuln_section)
        vuln_layout.setContentsMargins(0, 0, 0, 0)
        vuln_layout.setSpacing(10)
        
        vuln_label = QLabel("🎯 Sélectionnez la vulnérabilité à corriger:")
        vuln_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        vuln_label.setStyleSheet("color: white;")
        
        # Boutons pour sélectionner la vulnérabilité
        vuln_buttons_layout = QHBoxLayout()
        
        self.sql_btn = QPushButton("SQL Injection")
        self.xss_btn = QPushButton("XSS")
        self.csrf_btn = QPushButton("CSRF")
        self.all_btn = QPushButton("Toutes")
        
        for btn in [self.sql_btn, self.xss_btn, self.csrf_btn, self.all_btn]:
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setMinimumHeight(35)
            btn.setStyleSheet("""
                QPushButton {
                    background: rgba(197, 39, 245, 0.1);
                    color: #C527F5;
                    border: 1px solid rgba(197, 39, 245, 0.3);
                    border-radius: 6px;
                    padding: 8px 15px;
                }
                QPushButton:checked {
                    background: #C527F5;
                    color: white;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background: rgba(197, 39, 245, 0.2);
                }
            """)
            btn.clicked.connect(self.uncheck_other_buttons)
            vuln_buttons_layout.addWidget(btn)
        
        # Sélection par défaut
        self.sql_btn.setChecked(True)
        self.selected_vulnerability = "SQL Injection"
        
        vuln_layout.addWidget(vuln_label)
        vuln_layout.addLayout(vuln_buttons_layout)
        
        # Boutons d'action
        buttons_layout = QHBoxLayout()
        
        clear_btn = ModernButton("🗑️ Effacer tout")
        clear_btn.clicked.connect(self.clear_files)
        
        self.analyze_btn = ModernButton("🔍 Analyser seulement")
        self.analyze_btn.clicked.connect(self.analyze_files)
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background: #00d4ff;
                color: white;
                font-weight: 600;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: #00c4ef;
            }
            QPushButton:disabled {
                background: rgba(255, 255, 255, 0.1);
                color: rgba(255, 255, 255, 0.5);
            }
        """)
        
        self.generate_btn = ModernButton("🤖 Générer fichiers corrigés")
        self.generate_btn.clicked.connect(self.generate_corrected_files)
        self.generate_btn.setEnabled(False)
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background: #C527F5;
                color: white;
                font-weight: 600;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: #a020d0;
            }
            QPushButton:disabled {
                background: rgba(255, 255, 255, 0.1);
                color: rgba(255, 255, 255, 0.5);
            }
        """)
        
        buttons_layout.addWidget(clear_btn)
        buttons_layout.addStretch()
        buttons_layout.addWidget(self.analyze_btn)
        buttons_layout.addWidget(self.generate_btn)
        
        # Onglets pour les résultats
        self.results_tabs = QTabWidget()
        self.results_tabs.setVisible(False)
        
        # Onglet 1: Suggestions
        self.suggestions_tab = QWidget()
        suggestions_layout = QVBoxLayout(self.suggestions_tab)
        
        self.suggestions_area = QTextEdit()
        self.suggestions_area.setReadOnly(True)
        self.suggestions_area.setStyleSheet("""
            QTextEdit {
                background: rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                color: white;
                padding: 10px;
                font-family: Consolas;
                font-size: 11px;
            }
        """)
        suggestions_layout.addWidget(self.suggestions_area)
        
        # Onglet 2: Code corrigé
        self.corrected_tab = QWidget()
        corrected_layout = QVBoxLayout(self.corrected_tab)
        
        self.corrected_area = QTextEdit()
        self.corrected_area.setReadOnly(True)
        self.corrected_area.setStyleSheet("""
            QTextEdit {
                background: rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                color: #4caf50;
                padding: 10px;
                font-family: Consolas;
                font-size: 11px;
            }
        """)
        corrected_layout.addWidget(self.corrected_area)
        
        # Onglet 3: Téléchargement
        self.download_tab = QWidget()
        download_layout = QVBoxLayout(self.download_tab)
        
        download_label = QLabel("💾 Télécharger les fichiers corrigés")
        download_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        download_label.setStyleSheet("color: white;")
        
        self.download_list = QListWidget()
        self.download_list.setStyleSheet("""
            QListWidget {
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                color: white;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            }
        """)
        
        download_btn_layout = QHBoxLayout()
        
        preview_btn = ModernButton("👁️ Aperçu")
        preview_btn.clicked.connect(self.preview_corrected_file)
        
        download_single_btn = ModernButton("📥 Télécharger sélection")
        download_single_btn.clicked.connect(self.download_selected_file)
        
        download_all_btn = ModernButton("📦 Télécharger tous")
        download_all_btn.clicked.connect(self.download_all_files)
        
        download_btn_layout.addWidget(preview_btn)
        download_btn_layout.addWidget(download_single_btn)
        download_btn_layout.addWidget(download_all_btn)
        
        download_layout.addWidget(download_label)
        download_layout.addWidget(self.download_list)
        download_layout.addLayout(download_btn_layout)
        
        # Ajouter les onglets
        self.results_tabs.addTab(self.suggestions_tab, "🔍 Suggestions")
        self.results_tabs.addTab(self.corrected_tab, "💾 Code corrigé")
        self.results_tabs.addTab(self.download_tab, "📥 Téléchargement")
        
        # Assemblage
        main_layout.addWidget(header)
        main_layout.addWidget(description)
        main_layout.addWidget(drop_card)
        main_layout.addWidget(files_label)
        main_layout.addWidget(self.file_list)
        main_layout.addWidget(vuln_section)
        main_layout.addLayout(buttons_layout)
        main_layout.addWidget(self.results_tabs)
        
        scroll.setWidget(main_widget)
        layout.addWidget(scroll)
    
    def uncheck_other_buttons(self):
        """Décoche les autres boutons quand un est sélectionné"""
        sender = self.sender()
        if sender.isChecked():
            for btn in [self.sql_btn, self.xss_btn, self.csrf_btn, self.all_btn]:
                if btn != sender:
                    btn.setChecked(False)
            self.selected_vulnerability = sender.text()
    
    def _update_drop_zone_style(self, hovering=False):
        style = """
            QLabel {
                background: rgba(197, 39, 245, 0.08);
                border: 2px dashed rgba(197, 39, 245, 0.3);
                border-radius: 12px;
                color: #C527F5;
                font-size: 16px;
                padding: 40px;
            }
        """
        if hovering:
            style = style.replace("rgba(197, 39, 245, 0.3)", "#C527F5")
            style = style.replace("rgba(197, 39, 245, 0.08)", "rgba(197, 39, 245, 0.15)")
        
        self.drop_label.setStyleSheet(style)
    
    def drag_enter_event(self, event):
        if event.mimeData().hasUrls():
            self._update_drop_zone_style(True)
            event.acceptProposedAction()
    
    def drag_leave_event(self, event):
        self._update_drop_zone_style(False)
    
    def drop_event(self, event):
        self._update_drop_zone_style(False)
        for url in event.mimeData().urls():
            self.add_file(url.toLocalFile())
        event.acceptProposedAction()
    
    def browse_files(self, event=None):
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Sélectionnez des fichiers source",
            "",
            "Fichiers source (*.php *.js *.py *.html *.java *.cs *.go *.rb *.ts);;Tous les fichiers (*.*)"
        )
        for file_path in files:
            self.add_file(file_path)
    
    def add_file(self, file_path: str):
        try:
            filename = os.path.basename(file_path)
            
            # Vérifier l'extension
            supported_ext = ['.php', '.js', '.py', '.html', '.java', '.cs', '.go', '.rb', '.ts']
            if not any(filename.lower().endswith(ext) for ext in supported_ext):
                QMessageBox.warning(self, "Format non supporté", 
                                  f"Le format de {filename} n'est pas supporté.")
                return
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Ajouter à la liste des fichiers
            self.code_files.append({
                'path': file_path,
                'filename': filename,
                'content': content,
                'language': self.detect_language(filename),
                'original_content': content  # Sauvegarde du contenu original
            })
            
            # Ajouter à la liste affichée
            lang_icon = self.get_language_icon(self.code_files[-1]['language'])
            item = QListWidgetItem(f"{lang_icon} {filename}")
            self.file_list.addItem(item)
            
            # Activer les boutons
            self.analyze_btn.setEnabled(len(self.code_files) > 0)
            self.generate_btn.setEnabled(len(self.code_files) > 0)
            
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Impossible de lire {file_path}: {str(e)}")
    
    def detect_language(self, filename):
        """Détecte le langage du fichier"""
        ext_map = {
            '.php': 'PHP',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.py': 'Python',
            '.html': 'HTML',
            '.java': 'Java',
            '.cs': 'C#',
            '.go': 'Go',
            '.rb': 'Ruby'
        }
        
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
        return 'Unknown'
    
    def get_language_icon(self, language):
        """Retourne une icône pour le langage"""
        icons = {
            'PHP': '🐘',
            'JavaScript': '📜',
            'TypeScript': '📘',
            'Python': '🐍',
            'HTML': '🌐',
            'Java': '☕',
            'C#': '#️⃣',
            'Go': '🐹',
            'Ruby': '💎'
        }
        return icons.get(language, '📄')
    
    def clear_files(self):
        """Efface tous les fichiers"""
        self.code_files.clear()
        self.corrected_files.clear()
        self.file_list.clear()
        self.download_list.clear()
        self.analyze_btn.setEnabled(False)
        self.generate_btn.setEnabled(False)
        self.suggestions_area.clear()
        self.corrected_area.clear()
        self.results_tabs.setVisible(False)
    
    def analyze_files(self):
        """Analyse les fichiers et montre les suggestions"""
        if not self.code_files:
            return
        
        self.results_tabs.setVisible(True)
        self.results_tabs.setCurrentIndex(0)  # Onglet Suggestions
        self.suggestions_area.clear()
        
        self.suggestions_area.append("🚀 ANALYSE DES FICHIERS...")
        self.suggestions_area.append(f"🎯 Vulnérabilité cible: {self.selected_vulnerability}")
        self.suggestions_area.append(f"📁 Nombre de fichiers: {len(self.code_files)}\n")
        
        total_problems = 0
        
        for file_info in self.code_files:
            filename = file_info['filename']
            language = file_info['language']
            
            self.suggestions_area.append(f"\n{'='*60}")
            self.suggestions_area.append(f"📄 FICHIER: {filename} ({language})")
            
            # Analyser le code
            problems = self.analyze_code_for_vulnerabilities(
                file_info['content'], 
                language, 
                self.selected_vulnerability
            )
            
            if problems:
                total_problems += len(problems)
                self.suggestions_area.append(f"⚠️  {len(problems)} PROBLEME(S) DETECTE(S):")
                
                for i, problem in enumerate(problems, 1):
                    self.suggestions_area.append(f"\n  🔴 Problème {i}:")
                    self.suggestions_area.append(f"     📍 Ligne {problem['line']}:")
                    self.suggestions_area.append(f"        {problem['code'][:80]}...")
                    self.suggestions_area.append(f"     🎯 Type: {problem['type']}")
                    self.suggestions_area.append(f"     📝 Description: {problem['description']}")
                    self.suggestions_area.append(f"     💡 Suggestion: {problem['suggestion']}")
            else:
                self.suggestions_area.append("✅ Aucun problème détecté")
        
        self.suggestions_area.append(f"\n{'='*60}")
        self.suggestions_area.append(f"📊 RESUME: {total_problems} problème(s) trouvé(s) au total")
        self.suggestions_area.append("\n👉 Cliquez sur 'Générer fichiers corrigés' pour obtenir les corrections")
    
    def generate_corrected_files(self):
        """Génère les fichiers corrigés"""
        if not self.code_files:
            return
        
        self.corrected_files.clear()
        self.download_list.clear()
        self.results_tabs.setVisible(True)
        self.results_tabs.setCurrentIndex(1)  # Onglet Code corrigé
        self.corrected_area.clear()
        
        self.corrected_area.append("🤖 GENERATION DES FICHIERS CORRIGES...\n")
        self.corrected_area.append(f"🎯 Vulnérabilité cible: {self.selected_vulnerability}\n")
        
        for file_info in self.code_files:
            filename = file_info['filename']
            language = file_info['language']
            original_content = file_info['content']
            
            self.corrected_area.append(f"\n{'='*60}")
            self.corrected_area.append(f"📄 {filename} ({language})")
            
            # Générer le code corrigé
            corrected_content = self.apply_corrections(original_content, language, self.selected_vulnerability)
            
            # Sauvegarder le fichier corrigé
            corrected_filename = f"corrige_{filename}"
            corrected_file = {
                'original_name': filename,
                'corrected_name': corrected_filename,
                'language': language,
                'content': corrected_content,
                'path': os.path.join(os.path.dirname(file_info['path']), corrected_filename)
            }
            
            self.corrected_files.append(corrected_file)
            
            # Afficher un aperçu
            self.corrected_area.append(f"📝 Fichier généré: {corrected_filename}")
            self.corrected_area.append(f"💾 Taille: {len(corrected_content)} caractères")
            
            # Ajouter à la liste de téléchargement
            item = QListWidgetItem(f"📄 {corrected_filename}")
            self.download_list.addItem(item)
            
            # Afficher un extrait du code corrigé
            self.corrected_area.append("\n📋 Extrait du code corrigé:")
            lines = corrected_content.split('\n')[:5]
            for line in lines:
                self.corrected_area.append(f"   {line}")
            if len(corrected_content.split('\n')) > 5:
                self.corrected_area.append("   ...")
        
        self.corrected_area.append(f"\n{'='*60}")
        self.corrected_area.append(f"✅ {len(self.corrected_files)} fichier(s) corrigé(s) généré(s)")
        self.corrected_area.append("👉 Allez à l'onglet 'Téléchargement' pour récupérer vos fichiers")
        
        # Basculer vers l'onglet téléchargement
        self.results_tabs.setCurrentIndex(2)
    
    # AJOUT DES FONCTIONS DE VULNÉRABILITÉS
    def get_vulnerability_patterns(self, language, vuln_type):
        """Retourne les patterns de recherche pour une vulnérabilité donnée"""
        patterns = {
            'SQL Injection': {
                'PHP': [
                    (r'\$_(GET|POST|REQUEST)\[.*?\].*?\$sql', "Variable utilisateur dans requête SQL"),
                    (r'mysql_query.*?\$', "mysql_query avec variable"),
                    (r'\$sql\s*=\s*["\'].*?\$.*?["\']', "Concaténation SQL dangereuse"),
                ],
                'Python': [
                    (r'cursor\.execute.*?%.*?\$', "Formatage SQL dangereux"),
                    (r'cursor\.execute\(f["\'].*?["\']\)', "f-string dans SQL"),
                ],
                'Java': [
                    (r'Statement\.execute.*?\+\s*request', "Concaténation SQL"),
                    (r'PreparedStatement.*?setString.*?\).*?execute', "Mauvaise utilisation PreparedStatement"),
                ]
            },
            'XSS': {
                'PHP': [
                    (r'echo\s+\$_(GET|POST|REQUEST)', "Écho direct d'input utilisateur"),
                    (r'print\s+\$_(GET|POST|REQUEST)', "Print direct d'input"),
                ],
                'JavaScript': [
                    (r'innerHTML\s*=\s*.*?location', "innerHTML avec URL"),
                    (r'document\.write.*?\)', "document.write non sécurisé"),
                ],
                'HTML': [
                    (r'<script>.*?\$.*?</script>', "Script avec variable"),
                ]
            },
            'CSRF': {
                'HTML': [
                    (r'<form.*?>.*?</form>', "Formulaire sans token CSRF"),
                ]
            }
        }
        
        # Retourne les patterns pour le langage et vulnérabilité spécifiés
        lang_patterns = patterns.get(vuln_type, {}).get(language, [])
        if not lang_patterns:
            # Pattern générique
            lang_patterns = [(r'\$', f"Recherche de variables potentiellement dangereuses pour {vuln_type}")]
        
        return lang_patterns
    
    def generate_correction(self, finding, language):
        """Génère une correction pour une vulnérabilité"""
        corrections = {
            'SQL Injection': {
                'PHP': "Utiliser des requêtes préparées: $stmt = $pdo->prepare('SELECT * FROM table WHERE id = ?'); $stmt->execute([$value]);",
                'Python': "Utiliser des paramètres: cursor.execute('SELECT * FROM table WHERE id = %s', (value,))",
                'Java': "Utiliser PreparedStatement: PreparedStatement ps = conn.prepareStatement('SELECT * FROM table WHERE id = ?'); ps.setString(1, value);"
            },
            'XSS': {
                'PHP': "Échapper les sorties: echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');",
                'JavaScript': "Utiliser textContent au lieu de innerHTML",
                'HTML': "Échapper les caractères spéciaux avec des entités HTML"
            },
            'CSRF': {
                'HTML': "Ajouter un token CSRF: <input type='hidden' name='csrf_token' value='<?php echo $_SESSION[\"csrf_token\"]; ?>'>"
            }
        }
        
        # Récupère la correction spécifique au langage
        correction = corrections.get(finding, {}).get(language, "")
        
        # Si pas de correction spécifique, message générique
        if not correction:
            correction = f"Pour corriger {finding} en {language}, utilisez des pratiques de sécurité standard comme la validation d'entrée et l'échappement de sortie."
        
        return correction
    
    def analyze_code_for_vulnerabilities(self, content, language, vuln_type):
        """Analyse le code pour trouver des vulnérabilités"""
        import re
        
        problems = []
        lines = content.split('\n')
        
        # Si "Toutes" est sélectionné, analyser pour toutes les vulnérabilités
        if vuln_type == "Toutes":
            vuln_types = ['SQL Injection', 'XSS', 'CSRF']
        else:
            vuln_types = [vuln_type]
        
        for current_vuln_type in vuln_types:
            # Récupérer les patterns pour cette vulnérabilité
            patterns = self.get_vulnerability_patterns(language, current_vuln_type)
            
            for line_num, line in enumerate(lines, 1):
                for pattern, description in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Générer une suggestion de correction
                        suggestion = self.generate_correction(current_vuln_type, language)
                        
                        problems.append({
                            'line': line_num,
                            'code': line.strip()[:100],
                            'type': current_vuln_type,
                            'description': description,
                            'suggestion': suggestion
                        })
        
        return problems
    
    def apply_corrections(self, content, language, vuln_type):
        """Applique les corrections au code"""
        import re
        
        corrected_lines = content.split('\n')
        
        # Si "Toutes" est sélectionné, appliquer toutes les corrections
        if vuln_type == "Toutes":
            vuln_types = ['SQL Injection', 'XSS', 'CSRF']
        else:
            vuln_types = [vuln_type]
        
        for i, line in enumerate(corrected_lines):
            for current_vuln_type in vuln_types:
                patterns = self.get_vulnerability_patterns(language, current_vuln_type)
                
                for pattern, description in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Générer une correction
                        correction = self.generate_correction(current_vuln_type, language)
                        
                        # Ajouter un commentaire avec la correction
                        if language in ['PHP', 'JavaScript', 'Java', 'C#']:
                            corrected_lines[i] = f"{line}  // SECURITY: {correction[:60]}..."
                        elif language == 'Python':
                            corrected_lines[i] = f"{line}  # SECURITY: {correction[:60]}..."
                        elif language == 'HTML':
                            corrected_lines[i] = f"{line}  <!-- SECURITY: {correction[:60]}... -->"
                        
                        break  # On applique une seule correction par ligne pour éviter les conflits
        
        return '\n'.join(corrected_lines)
    
    def preview_corrected_file(self):
        """Affiche un aperçu du fichier corrigé sélectionné"""
        selected_items = self.download_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Sélection", "Veuillez sélectionner un fichier à prévisualiser.")
            return
        
        filename = selected_items[0].text().replace("📄 ", "")
        
        # Trouver le fichier correspondant
        for corrected_file in self.corrected_files:
            if corrected_file['corrected_name'] == filename:
                # Créer une fenêtre de prévisualisation
                preview_dialog = QDialog(self)
                preview_dialog.setWindowTitle(f"Aperçu: {filename}")
                preview_dialog.setGeometry(100, 100, 800, 600)
                
                layout = QVBoxLayout(preview_dialog)
                
                header = QLabel(f"📋 Aperçu de: {filename}")
                header.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
                header.setStyleSheet("color: #C527F5;")
                
                text_edit = QTextEdit()
                text_edit.setText(corrected_file['content'])
                text_edit.setReadOnly(True)
                text_edit.setFont(QFont("Consolas", 10))
                text_edit.setStyleSheet("""
                    QTextEdit {
                        background: #1e1e1e;
                        color: #d4d4d4;
                        font-family: Consolas;
                    }
                """)
                
                layout.addWidget(header)
                layout.addWidget(text_edit)
                
                preview_dialog.exec()
                return
    
    def download_selected_file(self):
        """Télécharge le fichier corrigé sélectionné"""
        selected_items = self.download_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Sélection", "Veuillez sélectionner un fichier à télécharger.")
            return
        
        for item in selected_items:
            filename = item.text().replace("📄 ", "")
            
            # Trouver le fichier correspondant
            for corrected_file in self.corrected_files:
                if corrected_file['corrected_name'] == filename:
                    # Demander où sauvegarder
                    save_path, _ = QFileDialog.getSaveFileName(
                        self,
                        f"Sauvegarder {filename}",
                        filename,
                        f"Fichiers (*.{self.get_extension(corrected_file['language'])});;Tous les fichiers (*.*)"
                    )
                    
                    if save_path:
                        try:
                            with open(save_path, 'w', encoding='utf-8') as f:
                                f.write(corrected_file['content'])
                            
                            QMessageBox.information(self, "Succès", 
                                                  f"Fichier sauvegardé:\n{save_path}")
                        except Exception as e:
                            QMessageBox.warning(self, "Erreur", 
                                              f"Impossible de sauvegarder: {str(e)}")
    
    def download_all_files(self):
        """Télécharge tous les fichiers corrigés"""
        if not self.corrected_files:
            QMessageBox.warning(self, "Aucun fichier", "Aucun fichier corrigé à télécharger.")
            return
        
        # Demander un dossier de destination
        folder = QFileDialog.getExistingDirectory(
            self,
            "Sélectionnez un dossier pour sauvegarder les fichiers corrigés"
        )
        
        if folder:
            saved_count = 0
            for corrected_file in self.corrected_files:
                save_path = os.path.join(folder, corrected_file['corrected_name'])
                try:
                    with open(save_path, 'w', encoding='utf-8') as f:
                        f.write(corrected_file['content'])
                    saved_count += 1
                except Exception as e:
                    QMessageBox.warning(self, "Erreur", 
                                      f"Erreur avec {corrected_file['corrected_name']}: {str(e)}")
            
            QMessageBox.information(self, "Succès", 
                                  f"{saved_count}/{len(self.corrected_files)} fichiers sauvegardés dans:\n{folder}")
    
    def get_extension(self, language):
        """Retourne l'extension de fichier pour un langage"""
        extensions = {
            'PHP': 'php',
            'JavaScript': 'js',
            'Python': 'py',
            'HTML': 'html',
            'Java': 'java',
            'C#': 'cs',
            'Go': 'go',
            'Ruby': 'rb'
        }
        return extensions.get(language, 'txt')
class MainApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DVW Secure - Professional Security Scanner")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(800, 600)
        self.setStyleSheet("background: #0f2027;")
        
        # Initialiser le gestionnaire d'historique
        self.history_manager = HistoryManager()
        
        self.init_ui()
    
    def init_ui(self):
        # Layout principal
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setLayout(main_layout)
        
        # Barre de navigation supérieure
        self.top_nav = TopNavigationBar(self)
        main_layout.addWidget(self.top_nav)
        
        # Content area
        self.content_stack = QStackedWidget()
        main_layout.addWidget(self.content_stack)
        
        # Création des pages
        self.create_pages()
        
        # Page par défaut
        self.show_page(0)
    
    def create_pages(self):
        self.welcome_page = WelcomePage(self)
        self.scanner_page = ScannerPage(self)
        self.history_page = HistoryPage(self)
        self.code_correction_page = CodeCorrectionPage(self)
        self.settings_page = SettingsPage(self)
        
        self.content_stack.addWidget(self.welcome_page)
        self.content_stack.addWidget(self.scanner_page)
        self.content_stack.addWidget(self.history_page)
        self.content_stack.addWidget(self.code_correction_page)
        self.content_stack.addWidget(self.settings_page)
    
    def show_page(self, page_index):
        self.content_stack.setCurrentIndex(page_index)
        self.top_nav.set_active_button(page_index)
        
        # Recharger l'historique quand on va sur la page historique
        if page_index == 2:  # Page historique
            self.history_page.load_history()

if __name__ == "__main__":
    # Désactiver les warnings SSL pour les tests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    app = QApplication(sys.argv)
    
    # Police par défaut
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = MainApp()
    window.show()
    
    sys.exit(app.exec())