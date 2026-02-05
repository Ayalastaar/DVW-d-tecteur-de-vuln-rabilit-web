# === MODULE IA POUR CORRECTION DE CODE LOCAL ===
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QPushButton, QGraphicsDropShadowEffect, QFrame, QLineEdit,
                             QStackedWidget, QListWidget, QListWidgetItem, QScrollArea, QSizePolicy,
                             QProgressBar, QTextEdit, QMessageBox, QFileDialog, QDialog, QSplitter, QTabWidget)
from PyQt6.QtGui import QFont, QLinearGradient, QColor, QPainter
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import sys
from datetime import datetime
import json
import os

# Supprimez l'import problématique et définissez les classes nécessaires ici
@dataclass
class Vulnerability:
    """Classe simplifiée pour vulnérabilité"""
    title: str
    severity: str
    description: str
    location: str
    recommendation: str
    cvss_score: float = 0.0
    
    def get_icon(self):
        """Retourne une icône selon la sévérité"""
        icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠", 
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪"
        }
        return icons.get(self.severity.upper(), "⚪")

class Language(Enum):
    """Langages de programmation supportés"""
    PHP = "php"
    JAVASCRIPT = "javascript"
    PYTHON = "python"
    JAVA = "java"
    CSHARP = "csharp"
    GO = "go"
    RUBY = "ruby"
    HTML = "html"
    UNKNOWN = "unknown"

@dataclass
class CodeFile:
    """Représente un fichier de code source"""
    filename: str
    content: str
    language: Language
    path: Optional[str] = None

class VulnerabilityPattern:
    """Patterns de vulnérabilités par langage"""
    
    PATTERNS = {
        Language.PHP: {
            "SQL_INJECTION": [
                (r'\$_(GET|POST|REQUEST|COOKIE)\[.*?\]\s*\.\s*\$', "Concaténation directe dans requête SQL"),
                (r'mysql_query\s*\(', "Fonction mysql_query() non sécurisée"),
                (r'\$sql\s*=\s*["\'].*?\$.*?["\']', "Variables dans chaîne SQL"),
                (r'query\s*\(.*?\$.*?\)', "Variables dans query()"),
            ],
            "XSS": [
                (r'echo\s+\$_(GET|POST|REQUEST)', "Écho direct d'input utilisateur"),
                (r'print\s+\$_(GET|POST|REQUEST)', "Print direct d'input utilisateur"),
                (r'<\?=\s*\$_(GET|POST|REQUEST)', "Short tag avec input utilisateur"),
            ],
            "CSRF": [
                (r'<form[^>]*method=["\']?post["\']?[^>]*>(?!.*csrf)', "Formulaire POST sans CSRF"),
                (r'\$_SERVER\[["\']REQUEST_METHOD["\']\]\s*==\s*["\']POST["\']\s*\{[^}]*\}(?!.*token)', "Traitement POST sans token"),
            ],
            "FILE_INCLUSION": [
                (r'include\s*\(\s*\$_(GET|POST|REQUEST)', "Include avec variable utilisateur"),
                (r'require\s*\(\s*\$_(GET|POST|REQUEST)', "Require avec variable utilisateur"),
            ],
            "SESSION_FIXATION": [
                (r'session_start\s*\(\s*\)\s*;\s*(?!.*session_regenerate_id)', "session_start() sans régénération"),
            ]
        },
        
        Language.JAVASCRIPT: {
            "XSS": [
                (r'\.innerHTML\s*=\s*.*?(location|document\.URL)', "innerHTML avec URL non échappée"),
                (r'eval\s*\(.*?\$', "eval() avec données utilisateur"),
                (r'document\.write\s*\(.*?\)', "document.write() non sécurisé"),
            ],
            "INSECURE_COOKIES": [
                (r'document\.cookie\s*=\s*.*?(?!.*secure.*httponly)', "Cookie sans secure/httponly"),
            ]
        },
        
        Language.PYTHON: {
            "SQL_INJECTION": [
                (r'cursor\.execute\s*\(.*?%\s*.*?\)', "Exécution SQL avec %"),
                (r'cursor\.execute\s*\(f["\'].*?["\']\)', "f-string dans SQL"),
            ],
            "COMMAND_INJECTION": [
                (r'os\.system\s*\(.*?\$', "os.system() avec variables"),
                (r'subprocess\.call\s*\(.*?\$', "subprocess.call() avec variables"),
            ]
        },
        
        Language.HTML: {
            "XSS": [
                (r'<script>.*?\$.*?</script>', "Script avec variables non échappées"),
                (r'on\w+\s*=\s*["\'].*?\$.*?["\']', "Événements avec variables"),
            ]
        }
    }

class CodeAnalyzer:
    """Analyseur de code source local"""
    
    @staticmethod
    def detect_language(filename: str, content: str) -> Language:
        """Détecte le langage du fichier"""
        ext_map = {
            '.php': Language.PHP,
            '.js': Language.JAVASCRIPT,
            '.jsx': Language.JAVASCRIPT,
            '.ts': Language.JAVASCRIPT,
            '.tsx': Language.JAVASCRIPT,
            '.py': Language.PYTHON,
            '.java': Language.JAVA,
            '.cs': Language.CSHARP,
            '.go': Language.GO,
            '.rb': Language.RUBY,
            '.html': Language.HTML,
            '.htm': Language.HTML,
        }
        
        # Par extension
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
        
        # Par shebang
        if content.startswith('#!'):
            if 'python' in content[:50].lower():
                return Language.PYTHON
            elif 'node' in content[:50].lower():
                return Language.JAVASCRIPT
        
        return Language.UNKNOWN
    
    @staticmethod
    def find_vulnerabilities(code_file: CodeFile) -> List[Dict]:
        """Trouve les vulnérabilités dans le code"""
        vulnerabilities = []
        
        if code_file.language not in VulnerabilityPattern.PATTERNS:
            return vulnerabilities
        
        lines = code_file.content.split('\n')
        
        for vuln_type, patterns in VulnerabilityPattern.PATTERNS[code_file.language].items():
            for pattern, description in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': vuln_type,
                            'description': description,
                            'line': line_num,
                            'code': line.strip(),
                            'language': code_file.language.value,
                            'file': code_file.filename
                        })
        
        return vulnerabilities

class CodeFixerAI:
    """IA qui corrige le code source local"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.is_active = api_key is not None
        
        if self.is_active:
            try:
                import openai
                openai.api_key = api_key
            except ImportError:
                self.is_active = False
                print("⚠️ OpenAI non installé. Mode simulation activé.")
    
    def analyze_and_fix(self, code_file: CodeFile, vulnerability: Vulnerability) -> Dict:
        """
        Analyse et corrige une vulnérabilité dans un fichier de code
        """
        # Trouver les vulnérabilités dans le code
        analyzer = CodeAnalyzer()
        code_vulns = analyzer.find_vulnerabilities(code_file)
        
        # Filtrer les vulnérabilités correspondant à celle détectée
        relevant_vulns = self._filter_relevant_vulns(code_vulns, vulnerability)
        
        if not relevant_vulns:
            return self._generate_general_fix(code_file, vulnerability)
        
        # Corriger chaque vulnérabilité trouvée
        fixes = []
        for vuln in relevant_vulns:
            if self.is_active:
                fix = self._generate_ai_fix(code_file, vuln, vulnerability)
            else:
                fix = self._generate_template_fix(code_file, vuln, vulnerability)
            fixes.append(fix)
        
        # Générer un rapport complet
        return {
            'filename': code_file.filename,
            'language': code_file.language.value,
            'vulnerability_title': vulnerability.title,
            'vulnerability_severity': vulnerability.severity,
            'original_code': code_file.content,
            'fixed_code': self._apply_fixes(code_file.content, fixes),
            'fixes_applied': fixes,
            'summary': self._generate_summary(fixes)
        }
    
    def _filter_relevant_vulns(self, code_vulns: List[Dict], vulnerability: Vulnerability) -> List[Dict]:
        """Filtre les vulnérabilités pertinentes"""
        vuln_title = vulnerability.title.lower()
        relevant = []
        
        for vuln in code_vulns:
            vuln_type = vuln['type'].lower()
            
            # Correspondance basée sur les mots-clés
            if ('sql' in vuln_title and 'sql' in vuln_type) or \
               ('xss' in vuln_title and 'xss' in vuln_type) or \
               ('csrf' in vuln_title and 'csrf' in vuln_type) or \
               ('injection' in vuln_title and 'injection' in vuln_type):
                relevant.append(vuln)
        
        return relevant
    
    def _generate_ai_fix(self, code_file: CodeFile, code_vuln: Dict, vulnerability: Vulnerability) -> Dict:
        """Génère une correction avec l'IA"""
        try:
            import openai
            
            prompt = self._build_fix_prompt(code_file, code_vuln, vulnerability)
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "Vous êtes un expert en sécurité et développement. Corrigez cette vulnérabilité dans le code fourni."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )
            
            return self._parse_ai_response(
                response.choices[0].message.content,
                code_vuln,
                code_file.language
            )
            
        except Exception as e:
            print(f"❌ Erreur IA: {e}")
            return self._generate_template_fix(code_file, code_vuln, vulnerability)
    
    def _build_fix_prompt(self, code_file: CodeFile, code_vuln: Dict, vulnerability: Vulnerability) -> str:
        """Construit le prompt pour l'IA"""
        return f"""
        Langage: {code_file.language.value}
        Fichier: {code_file.filename}
        
        VULNÉRABILITÉ À CORRIGER:
        - Type: {code_vuln['type']}
        - Description: {code_vuln['description']}
        - Ligne {code_vuln['line']}: {code_vuln['code']}
        
        CONTEXTE (vulnérabilité détectée par le scanner):
        - Titre: {vulnerability.title}
        - Description: {vulnerability.description}
        - Recommandation: {vulnerability.recommendation}
        
        CODE À CORRIGER (extrait):
        ```
        {self._get_code_context(code_file.content, code_vuln['line'])}
        ```
        
        TÂCHE:
        1. Montrez la ligne problématique EXACTE
        2. Montrez la ligne CORRIGÉE
        3. Expliquez brièvement la correction
        4. Fournissez une version complète si nécessaire
        
        Format de réponse:
        LIGNE_AVANT: [code problématique]
        LIGNE_APRES: [code corrigé]
        EXPLICATION: [explication]
        CODE_COMPLET: [code complet corrigé si nécessaire]
        """
    
    def _get_code_context(self, code: str, line_num: int, context_lines: int = 3) -> str:
        """Extrait le contexte autour d'une ligne"""
        lines = code.split('\n')
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        
        context = []
        for i in range(start, end):
            prefix = '>>> ' if i == line_num - 1 else '    '
            context.append(f"{prefix}{lines[i]}")
        
        return '\n'.join(context)
    
    def _parse_ai_response(self, response: str, code_vuln: Dict, language: Language) -> Dict:
        """Parse la réponse de l'IA"""
        sections = {
            'LIGNE_AVANT': '',
            'LIGNE_APRES': '',
            'EXPLICATION': '',
            'CODE_COMPLET': ''
        }
        
        current_section = None
        for line in response.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            for section in sections.keys():
                if line.startswith(section + ':'):
                    current_section = section
                    sections[section] = line[len(section) + 1:].strip()
                    break
                elif current_section:
                 sections[current_section] += '\n' + line
        
        return {
            'vulnerability': code_vuln['type'],
            'line': code_vuln['line'],
            'before': sections['LIGNE_AVANT'] or code_vuln['code'],
            'after': sections['LIGNE_APRES'],
            'explanation': sections['EXPLICATION'],
            'full_fix': sections['CODE_COMPLET'],
            'ai_generated': True
        }
    
    def _generate_template_fix(self, code_file: CodeFile, code_vuln: Dict, vulnerability: Vulnerability) -> Dict:
        """Génère une correction à partir de templates"""
        fix_templates = {
            Language.PHP: {
                'SQL_INJECTION': {
                    'before': r'(\$sql\s*=\s*["\']SELECT \* FROM users WHERE id = )(\$_(GET|POST|REQUEST)\[.*?\])',
                    'after': r'\1?\'; $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([\2]);',
                    'explanation': "Utilisation de requêtes préparées PDO pour éviter l'injection SQL"
                },
                'XSS': {
                    'before': r'(echo|print)\s+(\$_(GET|POST|REQUEST)\[.*?\])',
                    'after': r'\1 htmlspecialchars(\2, ENT_QUOTES, \'UTF-8\')',
                    'explanation': "Échappement des caractères HTML avec htmlspecialchars()"
                },
                'CSRF': {
                    'before': r'(<form[^>]*method=["\']?post["\']?[^>]*>)',
                    'after': r'\1\n<input type="hidden" name="csrf_token" value="<?php echo $_SESSION[\'csrf_token\']; ?>">',
                    'explanation': "Ajout d'un token CSRF unique par session"
                }
            },
            
            Language.JAVASCRIPT: {
                'XSS': {
                    'before': r'document\.innerHTML\s*=\s*(.*)',
                    'after': r'document.textContent = \1',
                    'explanation': "Utilisation de textContent au lieu de innerHTML pour éviter l'exécution de code"
                }
            },
            
            Language.PYTHON: {
                'SQL_INJECTION': {
                    'before': r'cursor\.execute\s*\(["\']SELECT \* FROM users WHERE id = %s["\']\s*%\s*(.*)\)',
                    'after': r'cursor.execute("SELECT * FROM users WHERE id = %s", (\1,))',
                    'explanation': "Utilisation des paramètres de requête au lieu de la concaténation"
                }
            }
        }
        
        lang_templates = fix_templates.get(code_file.language, {})
        type_template = lang_templates.get(code_vuln['type'], {})
        
        if type_template:
            before_pattern = type_template.get('before', '')
            after_template = type_template.get('after', '')
            
            # Essayer d'appliquer le template
            if before_pattern and after_template:
                import re
                match = re.search(before_pattern, code_vuln['code'])
                if match:
                    after_code = re.sub(before_pattern, after_template, code_vuln['code'])
                    return {
                        'vulnerability': code_vuln['type'],
                        'line': code_vuln['line'],
                        'before': code_vuln['code'],
                        'after': after_code,
                        'explanation': type_template.get('explanation', 'Correction générique'),
                        'ai_generated': False
                    }
        
        # Fallback générique
        return {
            'vulnerability': code_vuln['type'],
            'line': code_vuln['line'],
            'before': code_vuln['code'],
            'after': f"// CORRECTION NÉCESSAIRE: {vulnerability.recommendation}",
            'explanation': vulnerability.recommendation,
            'ai_generated': False
        }
    
    def _apply_fixes(self, original_code: str, fixes: List[Dict]) -> str:
        """Applique les corrections au code"""
        lines = original_code.split('\n')
        
        for fix in fixes:
            line_num = fix['line'] - 1  # Convertir en index 0-based
            if 0 <= line_num < len(lines):
                if fix.get('full_fix'):
                    # Remplacer par le code complet
                    lines[line_num] = fix['full_fix']
                elif fix.get('after'):
                    # Remplacer la ligne spécifique
                    lines[line_num] = fix['after']
        
        return '\n'.join(lines)
    
    def _generate_summary(self, fixes: List[Dict]) -> str:
        """Génère un résumé des corrections"""
        if not fixes:
            return "Aucune correction appliquée."
        
        summary = f"{len(fixes)} correction(s) appliquée(s):\n"
        for i, fix in enumerate(fixes, 1):
            summary += f"\n{i}. Ligne {fix['line']}: {fix['vulnerability']}\n"
            summary += f"   {fix['explanation']}\n"
        
        return summary
    
    def _generate_general_fix(self, code_file: CodeFile, vulnerability: Vulnerability) -> Dict:
        """Génère une correction générale quand aucune vulnérabilité spécifique n'est trouvée"""
        return {
            'filename': code_file.filename,
            'language': code_file.language.value,
            'vulnerability_title': vulnerability.title,
            'vulnerability_severity': vulnerability.severity,
            'original_code': code_file.content,
            'fixed_code': code_file.content,  # Pas de changement
            'fixes_applied': [],
            'summary': f"Aucune instance spécifique de '{vulnerability.title}' trouvée dans {code_file.filename}.\n\nRecommandation générale: {vulnerability.recommendation}",
            'no_specific_fix': True
        }

# === INTERFACE UTILISATEUR POUR LA CORRECTION DE CODE ===
class CodeCorrectionUI(QWidget):
    """Interface pour la correction de code local"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.code_files = []
        self.current_fixes = []
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Zone de dépôt de fichiers
        self.drop_zone = QLabel("📁 Déposez vos fichiers de code source ici")
        self.drop_zone.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_zone.setAcceptDrops(True)
        self.drop_zone.mousePressEvent = self.browse_files
        self.drop_zone.dragEnterEvent = self.drag_enter_event
        self.drop_zone.dropEvent = self.drop_event
        
        self._update_drop_zone_style()
        
        # Liste des fichiers
        self.file_list = QListWidget()
        self.file_list.setMaximumHeight(150)
        self.file_list.itemDoubleClicked.connect(self.view_file_code)
        
        # Boutons d'action
        btn_layout = QHBoxLayout()
        
        self.clear_btn = QPushButton("🗑️ Effacer")
        self.clear_btn.clicked.connect(self.clear_files)
        
        self.analyze_btn = QPushButton("🔍 Analyser le code")
        self.analyze_btn.clicked.connect(self.analyze_code)
        self.analyze_btn.setEnabled(False)
        
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.analyze_btn)
        
        # Résultats
        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setVisible(False)
        
        layout.addWidget(self.drop_zone)
        layout.addWidget(QLabel("Fichiers chargés:"))
        layout.addWidget(self.file_list)
        layout.addLayout(btn_layout)
        layout.addWidget(self.results_area)
    
    def _update_drop_zone_style(self, hovering=False):
        style = """
            QLabel {
                background: rgba(255, 255, 255, 0.05);
                border: 2px dashed rgba(255, 255, 255, 0.2);
                border-radius: 10px;
                padding: 40px;
                color: rgba(255, 255, 255, 0.6);
                font-size: 14px;
            }
        """
        if hovering:
            style = style.replace("rgba(255, 255, 255, 0.2)", "#00d4ff")
            style = style.replace("rgba(255, 255, 255, 0.6)", "#00d4ff")
        
        self.drop_zone.setStyleSheet(style)
    
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
    
    def browse_files(self, event):
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Sélectionnez des fichiers source",
            "",
            "Tous les fichiers supportés (*.php *.js *.py *.html *.java *.cs *.go *.rb *.ts);;Tous les fichiers (*.*)"
        )
        for file_path in files:
            self.add_file(file_path)
    
    def add_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            filename = os.path.basename(file_path)
            language = CodeAnalyzer.detect_language(filename, content)
            
            code_file = CodeFile(
                filename=filename,
                content=content,
                language=language,
                path=file_path
            )
            
            self.code_files.append(code_file)
            
            # Ajouter à la liste
            icon = {
                Language.PHP: "🐘",
                Language.JAVASCRIPT: "📜",
                Language.PYTHON: "🐍",
                Language.JAVA: "☕",
                Language.CSHARP: "#",
                Language.GO: "🐹",
                Language.RUBY: "💎",
                Language.HTML: "🌐"
            }.get(language, "📄")
            
            item = QListWidgetItem(f"{icon} {filename} ({language.value})")
            self.file_list.addItem(item)
            
            self.analyze_btn.setEnabled(len(self.code_files) > 0)
            
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Impossible de lire {file_path}: {str(e)}")
    
    def clear_files(self):
        self.code_files.clear()
        self.file_list.clear()
        self.analyze_btn.setEnabled(False)
        self.results_area.clear()
        self.results_area.setVisible(False)
    
    def view_file_code(self, item):
        """Affiche le contenu d'un fichier"""
        index = self.file_list.row(item)
        if 0 <= index < len(self.code_files):
            code_file = self.code_files[index]
            
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Code: {code_file.filename}")
            dialog.setGeometry(100, 100, 800, 600)
            
            layout = QVBoxLayout(dialog)
            
            text_edit = QTextEdit()
            text_edit.setText(code_file.content)
            text_edit.setReadOnly(True)
            text_edit.setFont(QFont("Consolas", 10))
            
            layout.addWidget(text_edit)
            
            dialog.exec()
    
    def analyze_code(self):
        """Analyse le code pour des vulnérabilités"""
        if not self.code_files:
            return
        
        analyzer = CodeAnalyzer()
        all_vulnerabilities = []
        
        for code_file in self.code_files:
            vulns = analyzer.find_vulnerabilities(code_file)
            all_vulnerabilities.extend(vulns)
        
        if not all_vulnerabilities:
            self.show_results("✅ Aucune vulnérabilité détectée dans le code analysé.")
            return
        
        # Afficher les résultats
        result_text = f"🔍 {len(all_vulnerabilities)} vulnérabilité(s) détectée(s):\n\n"
        
        for i, vuln in enumerate(all_vulnerabilities, 1):
            result_text += f"{i}. {vuln['file']}:{vuln['line']}\n"
            result_text += f"   Type: {vuln['type']}\n"
            result_text += f"   Description: {vuln['description']}\n"
            result_text += f"   Code: {vuln['code'][:100]}...\n"
            result_text += "   " + "-"*40 + "\n"
        
        self.show_results(result_text)
    
    def show_results(self, text: str):
        self.results_area.setText(text)
        self.results_area.setVisible(True)

class VulnerabilityCorrectionDialog(QDialog):
    """Dialogue pour corriger une vulnérabilité avec du code source"""
    
    def __init__(self, vulnerability: Vulnerability, parent=None):
        super().__init__(parent)
        self.vulnerability = vulnerability
        self.code_fixer = CodeFixerAI()  # Mode simulation par défaut
        self.code_files = []
        self.correction_results = []
        
        self.setWindowTitle(f"Correction: {vulnerability.title}")
        self.setMinimumSize(900, 700)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # En-tête
        header = QLabel(f"🔧 Correction de: {self.vulnerability.title}")
        header.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        header.setStyleSheet("color: #00d4ff; padding: 10px;")
        
        # Description de la vulnérabilité
        vuln_info = QLabel(
            f"<b>Sévérité:</b> {self.vulnerability.severity}<br>"
            f"<b>Description:</b> {self.vulnerability.description}<br>"
            f"<b>Recommandation:</b> {self.vulnerability.recommendation}"
        )
        vuln_info.setStyleSheet("""
            QLabel {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 8px;
                padding: 15px;
                color: white;
            }
        """)
        vuln_info.setWordWrap(True)
        
        # Section d'upload de code
        upload_section = self.create_upload_section()
        
        # Résultats
        self.results_tabs = QTabWidget()
        self.results_tabs.setVisible(False)
        
        layout.addWidget(header)
        layout.addWidget(vuln_info)
        layout.addWidget(upload_section)
        layout.addWidget(self.results_tabs)
        layout.addStretch()
    
    def create_upload_section(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(10)
        
        # Zone de dépôt
        drop_label = QLabel("📁 Déposez vos fichiers de code source concernés")
        drop_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        drop_label.setAcceptDrops(True)
        drop_label.mousePressEvent = self.browse_code_files
        drop_label.dragEnterEvent = self.drag_enter_code
        drop_label.dropEvent = self.drop_code
        
        drop_label.setStyleSheet("""
            QLabel {
                background: rgba(0, 212, 255, 0.1);
                border: 2px dashed rgba(0, 212, 255, 0.3);
                border-radius: 10px;
                padding: 30px;
                color: #00d4ff;
                font-size: 14px;
            }
            QLabel:hover {
                background: rgba(0, 212, 255, 0.15);
                border: 2px dashed #00d4ff;
            }
        """)
        
        # Liste des fichiers
        self.code_list = QListWidget()
        self.code_list.setMaximumHeight(120)
        
        # Boutons
        btn_layout = QHBoxLayout()
        
        clear_btn = QPushButton("🗑️ Effacer")
        clear_btn.clicked.connect(self.clear_code_files)
        
        self.correct_btn = QPushButton("🤖 Corriger avec l'IA")
        self.correct_btn.clicked.connect(self.correct_vulnerability)
        self.correct_btn.setEnabled(False)
        self.correct_btn.setStyleSheet("""
            QPushButton {
                background: #00d4ff;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #00c4ef;
            }
            QPushButton:disabled {
                background: rgba(255, 255, 255, 0.1);
                color: rgba(255, 255, 255, 0.5);
            }
        """)
        
        btn_layout.addWidget(clear_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.correct_btn)
        
        layout.addWidget(drop_label)
        layout.addWidget(QLabel("Fichiers à corriger:"))
        layout.addWidget(self.code_list)
        layout.addLayout(btn_layout)
        
        return widget
    
    def browse_code_files(self, event):
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Sélectionnez les fichiers à corriger",
            "",
            "Fichiers source (*.php *.js *.py *.html *.java *.cs *.go *.rb);;Tous les fichiers (*.*)"
        )
        for file_path in files:
            self.add_code_file(file_path)
    
    def drag_enter_code(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def drop_code(self, event):
        for url in event.mimeData().urls():
            self.add_code_file(url.toLocalFile())
        event.acceptProposedAction()
    
    def add_code_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            filename = os.path.basename(file_path)
            language = CodeAnalyzer.detect_language(filename, content)
            
            code_file = CodeFile(
                filename=filename,
                content=content,
                language=language,
                path=file_path
            )
            
            self.code_files.append(code_file)
            
            # Ajouter à la liste
            icon = {
                Language.PHP: "🐘 PHP",
                Language.JAVASCRIPT: "📜 JS",
                Language.PYTHON: "🐍 Python",
                Language.JAVA: "☕ Java",
                Language.CSHARP: "# C#",
                Language.GO: "🐹 Go",
                Language.RUBY: "💎 Ruby",
                Language.HTML: "🌐 HTML"
            }.get(language, "📄 Inconnu")
            
            item = QListWidgetItem(f"{icon} - {filename}")
            self.code_list.addItem(item)
            
            self.correct_btn.setEnabled(len(self.code_files) > 0)
            
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Impossible de lire {file_path}: {str(e)}")
    
    def clear_code_files(self):
        self.code_files.clear()
        self.code_list.clear()
        self.correct_btn.setEnabled(False)
        self.results_tabs.clear()
        self.results_tabs.setVisible(False)
    
    def correct_vulnerability(self):
        """Corrige la vulnérabilité dans les fichiers de code"""
        if not self.code_files:
            return
        
        self.correction_results = []
        
        # Corriger chaque fichier
        for code_file in self.code_files:
            result = self.code_fixer.analyze_and_fix(code_file, self.vulnerability)
            self.correction_results.append(result)
        
        # Afficher les résultats
        self.show_correction_results()
    
    def show_correction_results(self):
        """Affiche les résultats de correction"""
        self.results_tabs.clear()
        
        for result in self.correction_results:
            # Créer un onglet par fichier
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Résumé
            summary = QLabel(f"<h3>📄 {result['filename']} ({result['language']})</h3>")
            summary.setWordWrap(True)
            
            # Différence avant/après
            diff_widget = self.create_diff_view(result)
            
            # Boutons d'action
            action_layout = QHBoxLayout()
            
            copy_btn = QPushButton("📋 Copier le code corrigé")
            copy_btn.clicked.connect(lambda: self.copy_corrected_code(result))
            
            save_btn = QPushButton("💾 Sauvegarder le fichier")
            save_btn.clicked.connect(lambda: self.save_corrected_file(result))
            
            action_layout.addWidget(copy_btn)
            action_layout.addWidget(save_btn)
            action_layout.addStretch()
            
            layout.addWidget(summary)
            layout.addWidget(diff_widget)
            layout.addLayout(action_layout)
            
            self.results_tabs.addTab(tab, result['filename'])
        
        self.results_tabs.setVisible(True)
    
    def create_diff_view(self, result: Dict) -> QWidget:
        """Crée une vue de différence avant/après"""
        widget = QWidget()
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Avant
        before_widget = QWidget()
        before_layout = QVBoxLayout(before_widget)
        before_layout.addWidget(QLabel("<b>Code original:</b>"))
        
        before_text = QTextEdit()
        before_text.setText(result['original_code'])
        before_text.setReadOnly(True)
        before_text.setFont(QFont("Consolas", 10))
        before_text.setStyleSheet("""
            QTextEdit {
                background: rgba(255, 82, 82, 0.05);
                border: 1px solid rgba(255, 82, 82, 0.2);
                color: #ff5252;
            }
        """)
        
        before_layout.addWidget(before_text)
        
        # Après
        after_widget = QWidget()
        after_layout = QVBoxLayout(after_widget)
        after_layout.addWidget(QLabel("<b>Code corrigé:</b>"))
        
        after_text = QTextEdit()
        after_text.setText(result['fixed_code'])
        after_text.setReadOnly(True)
        after_text.setFont(QFont("Consolas", 10))
        after_text.setStyleSheet("""
            QTextEdit {
                background: rgba(76, 175, 80, 0.05);
                border: 1px solid rgba(76, 175, 80, 0.2);
                color: #4caf50;
            }
        """)
        
        after_layout.addWidget(after_text)
        
        splitter.addWidget(before_widget)
        splitter.addWidget(after_widget)
        splitter.setSizes([400, 400])
        
        layout = QVBoxLayout(widget)
        layout.addWidget(splitter)
        
        # Résumé des corrections
        if 'summary' in result:
            summary_label = QLabel(f"<b>Résumé:</b><br>{result['summary']}")
            summary_label.setWordWrap(True)
            summary_label.setStyleSheet("""
                QLabel {
                    background: rgba(255, 255, 255, 0.05);
                    border-radius: 6px;
                    padding: 10px;
                    margin-top: 10px;
                }
            """)
            layout.addWidget(summary_label)
        
        return widget
    
    def copy_corrected_code(self, result: Dict):
        """Copie le code corrigé"""
        QApplication.clipboard().setText(result['fixed_code'])
        QMessageBox.information(self, "Copié", "Le code corrigé a été copié dans le presse-papier.")
    
    def save_corrected_file(self, result: Dict):
        """Sauvegarde le fichier corrigé"""
        if not result.get('path'):
            # Demander où sauvegarder
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Sauvegarder le fichier corrigé",
                f"corrige_{result['filename']}",
                f"Fichiers {result['language']} (*.{result['language']});;Tous les fichiers (*.*)"
            )
            
            if not file_path:
                return
        else:
            file_path = result['path']
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(result['fixed_code'])
            
            QMessageBox.information(self, "Sauvegardé", f"Fichier sauvegardé:\n{file_path}")
            
        except Exception as e:
            QMessageBox.warning(self, "Erreur", f"Impossible de sauvegarder: {str(e)}")

# === FONCTIONS UTILES POUR L'INTÉGRATION ===

def add_ai_correction_button(main_app_instance):
    """Ajoute le bouton de correction IA à l'interface"""
    correction_btn = QPushButton("🔧 Correction IA")
    correction_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    correction_btn.clicked.connect(lambda: open_code_correction(main_app_instance))
    
    return correction_btn

def open_code_correction(main_app_instance):
    """Ouvre l'interface de correction de code"""
    dialog = CodeCorrectionUI(main_app_instance)
    dialog.setWindowTitle("Correcteur IA de code source")
    dialog.setGeometry(100, 100, 800, 600)
    dialog.show()

def show_vulnerability_correction(main_app_instance, vulnerability):
    """Ouvre le dialogue de correction pour une vulnérabilité spécifique"""
    dialog = VulnerabilityCorrectionDialog(vulnerability, main_app_instance)
    dialog.show()

# === FIN DU FICHIER ===