from PyQt6.QtCore import QThread, pyqtSignal
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from datetime import datetime
import json
import os
import time
import ssl
import re

# === MODÈLES ET MOTEUR D'ANALYSE ===
class Severity:
    CRITICAL = "Critique"
    HIGH = "Haute"
    MEDIUM = "Moyenne"
    LOW = "Faible"
    INFO = "Information"
    
    SEVERITY_COLORS = {
        CRITICAL: "#ff4444",
        HIGH: "#ff8800", 
        MEDIUM: "#ffcc00",
        LOW: "#00aa00",
        INFO: "#0099cc"
    }
    
    SEVERITY_ICONS = {
        CRITICAL: "🔴",
        HIGH: "🟠",
        MEDIUM: "🟡", 
        LOW: "🟢",
        INFO: "🔵"
    }

class Vulnerability:
    def __init__(self, title, severity, description, location, recommendation, cvss_score=0.0):
        self.title = title
        self.severity = severity
        self.description = description
        self.location = location
        self.recommendation = recommendation
        self.cvss_score = cvss_score
        self.timestamp = datetime.now()
    
    def get_color(self):
        return Severity.SEVERITY_COLORS.get(self.severity, "#666666")
    
    def get_icon(self):
        return Severity.SEVERITY_ICONS.get(self.severity, "⚪")

class HistoryManager:
    def __init__(self):
        self.history_file = "scan_history.json"
        self.history = self.load_history()
    
    def load_history(self):
        """Charge l'historique depuis le fichier"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"Erreur chargement historique: {e}")
            return []
    
    def save_history(self):
        """Sauvegarde l'historique dans le fichier"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Erreur sauvegarde historique: {e}")
    
    def add_scan_result(self, target_url, vulnerabilities, scan_duration):
        """Ajoute un résultat de scan à l'historique"""
        scan_entry = {
            'id': len(self.history) + 1,
            'target_url': target_url,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'vulnerabilities_count': len(vulnerabilities),
            'scan_duration': scan_duration,
            'status': 'Terminé',
            'vulnerabilities': self._summarize_vulnerabilities(vulnerabilities)
        }
        
        self.history.insert(0, scan_entry)
        self.save_history()
    
    def _summarize_vulnerabilities(self, vulnerabilities):
        """Crée un résumé des vulnérabilités par sévérité"""
        summary = {severity: 0 for severity in Severity.SEVERITY_COLORS.keys()}
        for vuln in vulnerabilities:
            summary[vuln.severity] += 1
        return summary
    
    def get_recent_scans(self, limit=10):
        """Retourne les analyses récentes"""
        return self.history[:limit]

class ScannerEngine(QThread):
    progress_updated = pyqtSignal(int)
    vulnerability_found = pyqtSignal(object)
    scan_completed = pyqtSignal(list)
    status_updated = pyqtSignal(str)
    log_message = pyqtSignal(str)
    
    def __init__(self, target_url, history_manager):
        super().__init__()
        self.target_url = target_url
        self.history_manager = history_manager
        self.vulnerabilities = []
        self.is_running = True
        self.start_time = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def run(self):
        """Lance l'analyse complète du site"""
        self.start_time = datetime.now()
        try:
            self.log_message.emit(f"🚀 Démarrage de l'analyse de {self.target_url}")
            self.status_updated.emit("Initialisation...")
            
            # 1. Vérification de la connectivité
            self.status_updated.emit("Vérification de la connectivité...")
            if not self.check_connectivity():
                return
            self.progress_updated.emit(10)
            
            if not self.is_running:
                return
                
            # 2. Analyse des en-têtes de sécurité
            self.status_updated.emit("Analyse des en-têtes de sécurité...")
            self.check_security_headers()
            self.progress_updated.emit(30)
            
            if not self.is_running:
                return
                
            # 3. Analyse des formulaires
            self.status_updated.emit("Analyse des formulaires...")
            self.check_forms()
            self.progress_updated.emit(50)
            
            if not self.is_running:
                return
                
            # 4. Recherche de fichiers sensibles
            self.status_updated.emit("Recherche de fichiers sensibles...")
            self.check_sensitive_files()
            self.progress_updated.emit(70)
            
            if not self.is_running:
                return
                
            # 5. Analyse de la configuration
            self.status_updated.emit("Analyse de configuration...")
            self.check_server_configuration()
            self.progress_updated.emit(90)
            
            if not self.is_running:
                return
                
            # 6. Analyse des liens et ressources
            self.status_updated.emit("Analyse des liens...")
            self.check_external_resources()
            self.progress_updated.emit(100)
            
            # Sauvegarder dans l'historique
            end_time = datetime.now()
            scan_duration = (end_time - self.start_time).total_seconds()
            
            self.history_manager.add_scan_result(
                self.target_url, 
                self.vulnerabilities, 
                scan_duration
            )
            
            self.log_message.emit(f"✅ Analyse terminée - {len(self.vulnerabilities)} vulnérabilités trouvées")
            self.status_updated.emit("Analyse terminée!")
            self.scan_completed.emit(self.vulnerabilities)
            
        except Exception as e:
            error_msg = f"❌ Erreur lors de l'analyse: {str(e)}"
            self.log_message.emit(error_msg)
            self.status_updated.emit(error_msg)
    
    def stop_scan(self):
        self.is_running = False
        self.log_message.emit("⏹️ Analyse arrêtée par l'utilisateur")
    
    def check_connectivity(self):
        """Vérifie si le site est accessible"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            if response.status_code == 200:
                self.log_message.emit("✅ Site accessible")
                return True
            else:
                self.add_vulnerability(
                    "Site inaccessible",
                    Severity.HIGH,
                    f"Le site retourne le code HTTP {response.status_code}",
                    self.target_url,
                    "Vérifier la disponibilité du site",
                    7.0
                )
                return False
        except Exception as e:
            self.add_vulnerability(
                "Erreur de connexion",
                Severity.HIGH,
                f"Impossible de se connecter au site: {str(e)}",
                self.target_url,
                "Vérifier l'URL et la connectivité réseau",
                8.0
            )
            return False
    
    def check_security_headers(self):
        """Vérifie les en-têtes de sécurité HTTP"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            headers = response.headers
            
            security_checks = [
                ('X-Content-Type-Options', 'nosniff', Severity.MEDIUM, 5.0,
                 "Protection contre le MIME sniffing manquante"),
                ('X-Frame-Options', 'DENY', Severity.MEDIUM, 5.0,
                 "Protection contre le clickjacking manquante"),
                ('X-XSS-Protection', '1; mode=block', Severity.MEDIUM, 5.0,
                 "Protection XSS du navigateur manquante"),
                ('Strict-Transport-Security', None, Severity.HIGH, 7.0,
                 "Forçage HTTPS manquant"),
                ('Content-Security-Policy', None, Severity.MEDIUM, 6.0,
                 "Politique de sécurité de contenu manquante"),
            ]
            
            for header, expected_value, severity, score, description in security_checks:
                if header not in headers:
                    self.add_vulnerability(
                        f"En-tête de sécurité manquant: {header}",
                        severity,
                        description,
                        self.target_url,
                        f"Ajouter l'en-tête {header} avec une valeur appropriée",
                        score
                    )
                elif expected_value and expected_value not in headers[header]:
                    self.add_vulnerability(
                        f"En-tête {header} mal configuré",
                        Severity.LOW,
                        f"Valeur actuelle: {headers[header]}",
                        self.target_url,
                        f"Configurer {header} avec la valeur: {expected_value}",
                        3.0
                    )
                    
            # Vérification spécifique HTTPS
            if not self.target_url.startswith('https'):
                self.add_vulnerability(
                    "Absence de HTTPS",
                    Severity.HIGH,
                    "Le site utilise HTTP non sécurisé",
                    self.target_url,
                    "Implémenter HTTPS avec un certificat SSL valide",
                    7.5
                )
                
        except Exception as e:
            self.log_message.emit(f"⚠️ Erreur lors de la vérification des en-têtes: {e}")
    
    def check_forms(self):
        """Analyse les formulaires pour détecter les vulnérabilités potentielles"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            
            self.log_message.emit(f"🔍 {len(forms)} formulaire(s) trouvé(s)")
            
            for i, form in enumerate(forms):
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                form_id = form.get('id', f"form_{i}")
                
                # Vérifier l'action du formulaire
                full_action_url = urljoin(self.target_url, form_action)
                
                # Vérifier HTTPS pour les formulaires POST
                if form_method == 'post' and not full_action_url.startswith('https'):
                    self.add_vulnerability(
                        "Formulaire sans HTTPS",
                        Severity.HIGH,
                        f"Formulaire {form_id} envoie des données en clair vers {full_action_url}",
                        self.target_url,
                        "Utiliser HTTPS pour tous les formulaires transmettant des données sensibles",
                        6.5
                    )
                
                # Analyser les champs du formulaire
                inputs = form.find_all('input')
                password_fields = []
                
                for input_field in inputs:
                    input_type = input_field.get('type', '').lower()
                    input_name = input_field.get('name', '')
                    
                    if input_type == 'password':
                        password_fields.append(input_name)
                        
                        # Vérifier l'autocomplete
                        autocomplete = input_field.get('autocomplete', '').lower()
                        if autocomplete != 'off':
                            self.add_vulnerability(
                                "Autocomplete activé sur mot de passe",
                                Severity.LOW,
                                f"Le champ {input_name} permet l'autocomplete",
                                self.target_url,
                                "Ajouter autocomplete='off' aux champs sensibles",
                                2.0
                            )
                
                # Détecter les mots de passe en GET
                if password_fields and form_method == 'get':
                    self.add_vulnerability(
                        "Mot de passe transmis en GET",
                        Severity.CRITICAL,
                        f"Champs {', '.join(password_fields)} transmis via URL",
                        self.target_url,
                        "Utiliser la méthode POST pour les formulaires contenant des mots de passe",
                        9.0
                    )
                        
        except Exception as e:
            self.log_message.emit(f"⚠️ Erreur lors de l'analyse des formulaires: {e}")
    
    def check_sensitive_files(self):
        """Recherche des fichiers sensibles accessibles"""
        sensitive_files = [
            ('.env', 'Fichier de configuration environnement', Severity.CRITICAL, 9.0),
            ('.git/config', 'Configuration Git', Severity.HIGH, 7.5),
            ('.htaccess', 'Configuration Apache', Severity.MEDIUM, 5.0),
            ('backup.zip', 'Archive de sauvegarde', Severity.HIGH, 7.0),
            ('admin.php', 'Panel administrateur', Severity.MEDIUM, 6.0),
            ('phpinfo.php', 'Information PHP', Severity.MEDIUM, 6.5),
            ('test.php', 'Fichier de test', Severity.LOW, 3.0),
            ('wp-config.php', 'Configuration WordPress', Severity.CRITICAL, 9.5),
            ('config.json', 'Fichier de configuration', Severity.HIGH, 7.0),
        ]
        
        for file_path, description, severity, score in sensitive_files:
            if not self.is_running:
                return
                
            try:
                test_url = urljoin(self.target_url, file_path)
                response = self.session.get(test_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    # Vérifier que ce n'est pas une page d'erreur
                    content_lower = response.text.lower()
                    error_indicators = ['error', 'not found', '404', 'page not found']
                    
                    if not any(indicator in content_lower for indicator in error_indicators):
                        self.add_vulnerability(
                            f"Fichier sensible accessible: {file_path}",
                            severity,
                            f"{description} accessible publiquement",
                            test_url,
                            "Restreindre l'accès aux fichiers sensibles via .htaccess ou configuration serveur",
                            score
                        )
                        self.log_message.emit(f"⚠️ Fichier sensible trouvé: {file_path}")
                        
            except requests.RequestException:
                continue
    
    def check_server_configuration(self):
        """Vérifie la configuration du serveur"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            # Vérifier la version du serveur dans les headers
            server_header = response.headers.get('Server', '')
            if server_header:
                self.log_message.emit(f"🖥️ Serveur détecté: {server_header}")
                
                # Détecter les versions anciennes ou vulnérables
                old_servers = ['Apache/2.2', 'nginx/1.4', 'IIS/7.0']
                for old_server in old_servers:
                    if old_server in server_header:
                        self.add_vulnerability(
                            "Version de serveur potentiellement vulnérable",
                            Severity.MEDIUM,
                            f"Serveur: {server_header} - pourrait contenir des vulnérabilités connues",
                            self.target_url,
                            "Mettre à jour le serveur vers une version supportée",
                            6.0
                        )
                        break
            
            # Vérifier les méthodes HTTP dangereuses
            try:
                options_response = self.session.options(self.target_url, timeout=5, verify=False)
                allowed_methods = options_response.headers.get('Allow', '')
                dangerous_methods = ['PUT', 'DELETE', 'TRACE']
                
                for method in dangerous_methods:
                    if method in allowed_methods:
                        self.add_vulnerability(
                            f"Méthode HTTP dangereuse autorisée: {method}",
                            Severity.MEDIUM,
                            f"La méthode {method} est activée sur le serveur",
                            self.target_url,
                            f"Désactiver la méthode {method} si non nécessaire",
                            5.5
                        )
            except:
                pass
                
        except Exception as e:
            self.log_message.emit(f"⚠️ Erreur lors de la vérification de configuration: {e}")
    
    def check_external_resources(self):
        """Vérifie les ressources externes"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Compter les liens externes
            external_links = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http') and self.target_url not in href:
                    external_links.append(href)
            
            if len(external_links) > 20:
                self.add_vulnerability(
                    "Nombre élevé de liens externes",
                    Severity.LOW,
                    f"{len(external_links)} liens externes détectés - risque de fuite de données",
                    self.target_url,
                    "Vérifier la légitimité de tous les liens externes",
                    2.5
                )
            
            # Vérifier les scripts externes
            external_scripts = []
            for script in soup.find_all('script', src=True):
                if self.target_url not in script['src']:
                    external_scripts.append(script['src'])
            
            if external_scripts:
                self.log_message.emit(f"📜 {len(external_scripts)} script(s) externe(s) détecté(s)")
                
        except Exception as e:
            self.log_message.emit(f"⚠️ Erreur lors de l'analyse des ressources: {e}")
    
    def add_vulnerability(self, title, severity, description, location, recommendation, cvss_score=0.0):
        """Ajoute une vulnérabilité à la liste"""
        vuln = Vulnerability(title, severity, description, location, recommendation, cvss_score)
        self.vulnerabilities.append(vuln)
        self.vulnerability_found.emit(vuln)
        self.log_message.emit(f"{vuln.get_icon()} {title} - {severity}")

# Fonction pour les tests avancés (optionnelle)
def run_advanced_tests(self):
    """Lance les tests de sécurité avancés"""
    from security_tests import AdvancedSecurityTests
    
    advanced_tester = AdvancedSecurityTests(
        self.session, 
        self.target_url, 
        self.add_vulnerability,
        self.log_message.emit
    )
    advanced_tester.run_all_tests()