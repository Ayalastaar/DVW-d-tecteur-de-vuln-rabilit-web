import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import time

class AdvancedSecurityTests:
    def __init__(self, session, target_url, add_vulnerability_callback, log_callback):
        self.session = session
        self.target_url = target_url
        self.add_vulnerability = add_vulnerability_callback
        self.log = log_callback
        
    # === TESTS SQL INJECTION ===
    def test_sql_injection(self):
        """Teste les vulnérabilités SQL Injection"""
        self.log("🔍 Début des tests SQL Injection...")
        
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Trouver tous les formulaires
            forms = soup.find_all('form')
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                form_url = urljoin(self.target_url, form_action)
                
                # Préparer les payloads SQLi
                sql_payloads = [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "admin'--",
                    "' UNION SELECT 1,2,3--",
                    "' AND 1=1--"
                ]
                
                # Tester chaque champ d'entrée
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text')
                    
                    if input_name and input_type in ['text', 'search', 'email']:
                        for payload in sql_payloads:
                            data = {input_name: payload}
                            
                            try:
                                if form_method == 'post':
                                    resp = self.session.post(form_url, data=data, timeout=5)
                                else:
                                    resp = self.session.get(form_url, params=data, timeout=5)
                                
                                # Vérifier les indicateurs d'injection SQL
                                error_indicators = [
                                    'mysql_fetch_array',
                                    'mysql_num_rows',
                                    'ORA-',
                                    'Microsoft OLE DB Provider',
                                    'SQL syntax',
                                    'mysql_',
                                    'syntax error'
                                ]
                                
                                content_lower = resp.text.lower()
                                if any(indicator in content_lower for indicator in error_indicators):
                                    self.add_vulnerability(
                                        "Vulnérabilité SQL Injection potentielle",
                                        "Critique",
                                        f"Champ '{input_name}' vulnérable à SQL Injection",
                                        form_url,
                                        "Valider et échapper toutes les entrées utilisateur. Utiliser des requêtes paramétrées.",
                                        9.0
                                    )
                                    self.log(f"⚠️ SQL Injection détecté dans le champ {input_name}")
                                    break
                                    
                            except requests.RequestException:
                                continue
                                
        except Exception as e:
            self.log(f"❌ Erreur lors du test SQL Injection: {e}")
    
    # === TESTS XSS (CROSS-SITE SCRIPTING) ===
    def test_xss(self):
        """Teste les vulnérabilités XSS"""
        self.log("🔍 Début des tests XSS...")
        
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            forms = soup.find_all('form')
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "\"><script>alert('XSS')</script>"
            ]
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                form_url = urljoin(self.target_url, form_action)
                
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text')
                    
                    if input_name and input_type in ['text', 'search', 'email', 'url']:
                        for payload in xss_payloads:
                            data = {input_name: payload}
                            
                            try:
                                if form_method == 'post':
                                    resp = self.session.post(form_url, data=data, timeout=5)
                                else:
                                    resp = self.session.get(form_url, params=data, timeout=5)
                                
                                # Vérifier si le payload est réfléchi sans encodage
                                if payload in resp.text:
                                    self.add_vulnerability(
                                        "Vulnérabilité XSS (Cross-Site Scripting)",
                                        "Haute",
                                        f"Champ '{input_name}' vulnérable à XSS",
                                        form_url,
                                        "Encoder toutes les sorties HTML. Utiliser Content Security Policy.",
                                        8.0
                                    )
                                    self.log(f"⚠️ XSS détecté dans le champ {input_name}")
                                    break
                                    
                            except requests.RequestException:
                                continue
                                
        except Exception as e:
            self.log(f"❌ Erreur lors du test XSS: {e}")
    
    # === TESTS CSRF (CROSS-SITE REQUEST FORGERY) ===
    def test_csrf(self):
        """Vérifie la protection CSRF"""
        self.log("🔍 Vérification de la protection CSRF...")
        
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            forms = soup.find_all('form')
            csrf_protected = False
            
            for form in forms:
                form_method = form.get('method', 'get').lower()
                
                # Vérifier les tokens CSRF
                csrf_indicators = [
                    'csrf', 'token', 'nonce', 'authenticity'
                ]
                
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_name = input_field.get('name', '').lower()
                    if any(indicator in input_name for indicator in csrf_indicators):
                        csrf_protected = True
                        break
                
                # Si formulaire POST sans protection CSRF
                if form_method == 'post' and not csrf_protected:
                    self.add_vulnerability(
                        "Absence de protection CSRF",
                        "Moyenne",
                        "Formulaire POST sans token CSRF détecté",
                        self.target_url,
                        "Implémenter des tokens CSRF pour tous les formulaires modifiant des données",
                        6.5
                    )
                    self.log("⚠️ Protection CSRF manquante")
                    break
                    
        except Exception as e:
            self.log(f"❌ Erreur lors du test CSRF: {e}")
    
    # === TESTS INFORMATIONS SENSIBLES DANS LE CODE ===
    def test_sensitive_info_disclosure(self):
        """Recherche des informations sensibles dans le code source"""
        self.log("🔍 Recherche d'informations sensibles...")
        
        try:
            response = self.session.get(self.target_url)
            content = response.text
            
            # Patterns d'informations sensibles
            sensitive_patterns = [
                (r'password\s*=\s*["\']([^"\']+)["\']', "Mot de passe en clair dans le code"),
                (r'api_key\s*=\s*["\']([^"\']+)["\']', "Clé API exposée"),
                (r'secret\s*=\s*["\']([^"\']+)["\']', "Secret exposé"),
                (r'database_password\s*=\s*["\']([^"\']+)["\']', "Mot de passe BDD exposé"),
                (r'aws_secret\s*=\s*["\']([^"\']+)["\']', "Secret AWS exposé"),
            ]
            
            for pattern, description in sensitive_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    self.add_vulnerability(
                        f"Information sensible exposée: {description}",
                        "Haute",
                        f"{description} trouvé dans le code source",
                        self.target_url,
                        "Supprimer les informations sensibles du code source. Utiliser des variables d'environnement.",
                        7.5
                    )
                    self.log(f"⚠️ {description} détecté")
                    
        except Exception as e:
            self.log(f"❌ Erreur lors de la recherche d'informations sensibles: {e}")
    
    # === TESTS DE FORCE BRUTE ===
    def test_brute_force_protection(self):
        """Teste la protection contre les attaques par force brute"""
        self.log("🔍 Test de protection force brute...")
        
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Chercher des formulaires de login
            login_forms = []
            for form in soup.find_all('form'):
                inputs = form.find_all('input')
                has_password = any(input_field.get('type') == 'password' for input_field in inputs)
                if has_password:
                    login_forms.append(form)
            
            if login_forms:
                self.add_vulnerability(
                    "Protection force brute non vérifiée",
                    "Moyenne",
                    "Formulaires de login détectés - protection force brute à vérifier manuellement",
                    self.target_url,
                    "Implémenter un système de rate limiting, CAPTCHA ou verrouillage de compte",
                    5.0
                )
                self.log("ℹ️ Formulaires de login détectés - vérifier manuellement la protection force brute")
                
        except Exception as e:
            self.log(f"❌ Erreur lors du test force brute: {e}")
    
    # === TESTS DE CONFIGURATION SSL/TLS ===
    def test_ssl_tls(self):
        """Teste la configuration SSL/TLS"""
        self.log("🔍 Vérification de la configuration SSL/TLS...")
        
        try:
            if self.target_url.startswith('https://'):
                # Vérifier les protocoles supportés
                import ssl
                import socket
                
                hostname = urlparse(self.target_url).hostname
                
                # Test des protocoles obsolètes
                weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                
                for protocol in weak_protocols:
                    try:
                        context = ssl.SSLContext(getattr(ssl, f'PROTOCOL_{protocol.upper()}'))
                        with socket.create_connection((hostname, 443), timeout=5) as sock:
                            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                                self.add_vulnerability(
                                    f"Protocole {protocol} supporté",
                                    "Moyenne",
                                    f"Le serveur supporte le protocole {protocol} obsolète",
                                    self.target_url,
                                    f"Désactiver le protocole {protocol}",
                                    6.0
                                )
                                self.log(f"⚠️ Protocole {protocol} supporté")
                    except:
                        continue
                        
        except Exception as e:
            self.log(f"❌ Erreur lors du test SSL/TLS: {e}")
    
    # === LANCEUR DE TOUS LES TESTS ===
    def run_all_tests(self):
        """Lance tous les tests de sécurité avancés"""
        self.log("🚀 Démarrage des tests de sécurité avancés...")
        
        tests = [
            self.test_sql_injection,
            self.test_xss,
            self.test_csrf,
            self.test_sensitive_info_disclosure,
            self.test_brute_force_protection,
            self.test_ssl_tls
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                self.log(f"❌ Erreur dans le test {test.__name__}: {e}")
        
        self.log("✅ Tests de sécurité avancés terminés")