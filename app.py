from  PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QPushButton, QGraphicsDropShadowEffect, QFrame, QLineEdit,
                             QStackedWidget, QListWidget, QListWidgetItem, QScrollArea, QSizePolicy,
                             QProgressBar, QTextEdit, QMessageBox)
from PyQt6.QtGui import QFont, QLinearGradient, QColor, QPainter
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import sys
from datetime import datetime
import json
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
            ("⚙️ Paramètres", 3)
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
            ("⚙️ Paramètres", "Configurer les options", 3, "background: rgba(76, 175, 80, 0.1); color: #4caf50;"),
            ("📈 Rapports", "Générer des rapports", 2, "background: rgba(156, 39, 176, 0.1); color: #9c27b0;"),
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
        self.settings_page = SettingsPage(self)
        
        self.content_stack.addWidget(self.welcome_page)
        self.content_stack.addWidget(self.scanner_page)
        self.content_stack.addWidget(self.history_page)
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