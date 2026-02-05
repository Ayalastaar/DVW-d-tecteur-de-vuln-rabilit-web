# DVW-d-tecteur-de-vuln-rabilit-web

**DVW Secure** est une solution complète d'analyse de sécurité web avec interface graphique moderne et fonctionnalités de correction automatique de code

## Fonctionnalités Principales

### 🔍 Scanner de Sécurité Intelligent

- **Analyse complète des sites web** : URL, formulaires, en-têtes, configuration...etc
- **Détection multi-vulnérabilités** : SQL Injection, XSS, CSRF, Headers de sécurité,Fichier Sensibles...etc
- **Classification automatique** : Niveaux de sévérité (Critique, Élevé, Moyen, Faible)
- **Rapports détaillés** : Recommandations personnalisées pour chaque faille
- **Analyse en temps réel** : Barre de progression et logs interactifs

### 🤖 Correcteur de Code IA

- **Analyse de code source** : Support multi-langages (PHP, Python, JavaScript, Java, HTML, C#, Go, Ruby)
- **Détection de vulnérabilités** : Patterns spécifiques par langage
- **Corrections automatiques** : Génération de code sécurisé
- **Suggestions intelligentes** : Recommandations contextuelles
- **Export des corrections** : Fichiers corrigés prêts à l'emploi

### 📊 Interface Utilisateur Avancée 

- **Design moderne** : Interface sombre avec effets visuels

- **Navigation fluide** : Système d'onglets et navigation latérale

- **Responsive** : Adapté à différentes tailles d'écran

- **Expérience utilisateur** : Glisser-déposer, feedback visuel, animations

### 📈 Gestion des Résultats

- **Historique complet**: Sauvegarde de toutes les analyses

- **Statistiques détaillées** : Graphiques et résumés par sévérité

- **Export des rapports** : Formats structurés pour documentation

- **Comparaison temporelle** : Suivi de l'évolution de la sécurité

## 🚀 Installation
 
 ### Prérequis

- Python 3.8+

- Système d'exploitation : Windows 10+, macOS 10.15+, Ubuntu 18.04+

- Mémoire RAM : 4 GB minimum (8 GB recommandé)

- Espace disque : 500 MB libre

## Installation Rapide

 ### 1. Cloner le dépôt
git clone https://github.com/Ayalastaar/DVW-d-tecteur-de-vuln-rabilit-web.git

cd DVW-d-tecteur-de-vuln-rabilit-web

 ### 2. Créer un environnement virtuel (recommandé)
python -m venv venv

### 3. Activer l'environnement

### Sur Windows :
venv\Scripts\activate
#### Sur macOS/Linux :
source venv/bin/activate

### 4. Installer les dépendances
pip install -r requirements.txt

### Dépendances Principales
 
- **PyQt6** : Interface graphique moderne

- **requests** : Communication HTTP/HTTPS

- **beautifulsoup4** : Parsing HTML

- **regex** : Détection de patterns avancés

- **urllib3** : Gestion des connexions réseau

## Guide d'Utilisation

- Lancer avec 
python main.py
 
 ## Page d'Accueil

- **Vue d'ensemble** : Statistiques et état du système

- **Actions rapides** : Accès direct aux principales fonctionnalités

- **Tableau de bord** : Résumé des dernières analyses

## 2. Scanner de Sécurité
- Entrez l'URL à analyser (ex: https://votre-site.com)

- Configurez les options : Profondeur d'analyse, types de tests

- Lancez le scan : Surveillance en temps réel

- Consultez les résultats : Vulnérabilités classées par sévérité

## 3. Correcteur de Code IA

- Importez vos fichiers : Glisser-déposer ou sélection

- Choisissez la vulnérabilité : SQL Injection, XSS, CSRF, ou Toutes

- Analysez le code : Détection automatique des failles

- Générez les corrections : Code sécurisé avec commentaires

- Téléchargez les fichiers : Version corrigée prête à l'emploi

## 4. Historique

- Consultation : Toutes les analyses précédentes

- Filtrage : Par date, URL ou type de vulnérabilité

- Export : Rapports au format JSON ou CSV

- Comparaison : Évolution de la sécurité dans le temps

##  Fonctionnalités Avancées

Détection Multi-Langages

- **PHP** : mysql_query, $_GET, $_POST, injections SQL

- **Python** : cursor.execute, f-strings dangereuses

- **JavaScript** : innerHTML, document.write, XSS

- **Java** : Statement.execute, concaténations SQL

- **HTML** : Formulaires sans CSRF, scripts inline

- Corrections Intelligentes
**python**

# AVANT (vulnérable)
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")

# APRÈS (sécurisé)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
# SECURITY FIX: Utiliser des paramètres au lieu de f-strings
Patterns de Détection
- **SQL Injection** : 15+ patterns spécifiques par langage

- **XSS** : 10+ vecteurs d'attaque détectés

- **CSRF** : Formulaires sans tokens, vérifications manquantes

- **Headers Sécurité** : Configuration serveur optimale

📁 Structure du Projet
├── [__pycache__]
│   ├── ai.cpython-314.pyc
│   ├── scanner_engine.cpython-314.pyc
├── .gitignore
├── ai_backup.py
├── app.py
├── README.md
├── scanner_engine.py
├── scan_history.json
├── security_tests.py

🔧 Configuration
Fichier de Configuration
un fichier scan_history.json à la racine :

json
{
  "scanner": {
    "timeout": 30,
    "user_agent": "DVW-Secure-Scanner/2.1.0",
    "max_depth": 5,
    "threads": 10
  },
  "corrector": {
    "backup_files": true,
    "auto_format": true,
    "language_specific": true
  },
  "ui": {
    "theme": "dark",
    "language": "fr",
    "auto_update": true
  }
}
Options Avancées
Proxy support : Configuration des proxies HTTP/HTTPS

Authentification : Support Basic Auth et tokens

Rate limiting : Contrôle du débit des requêtes

Custom rules : Ajout de règles personnalisées

📊 Exemples de Sortie
Rapport d'Analyse
text
========================================
📊 RAPPORT D'ANALYSE - https://exemple.com
========================================

🔍 Scan terminé en : 2m 15s
📁 Pages analysées : 47
⚠️ Vulnérabilités trouvées : 8

📈 RÉPARTITION PAR SÉVÉRITÉ :
🔴 Critique : 2
🟠 Élevé : 3
🟡 Moyen : 2
🟢 Faible : 1

🎯 VULNÉRABILITÉS DÉTECTÉES :
1. 🔴 SQL Injection - /login.php
   📍 Ligne 42 : $sql = "SELECT * FROM users WHERE login='$user'"
   💡 Correction : Utiliser PDO avec requêtes préparées

2. 🟠 XSS - /contact.php
   📍 Ligne 18 : echo $_POST['message'];
   💡 Correction : htmlspecialchars($_POST['message'], ENT_QUOTES)
## 🛠️ Développement
- Architecture

- **MVC Pattern** : Séparation claire des responsabilités

- **Modulaire** : Composants indépendants et réutilisables

- **Extensible** : Architecture conçue pour les extensions


## Tests
bash
# Lancer les tests unitaires
python -m pytest tests/


## ⚡ Performances
- Fonctionnalité	Temps Moyen	Mémoire Utilisée
- Scan simple	30-60 sec	50-100 MB
- Scan complet	2-5 min	200-500 MB
- Analyse code	1-10 sec	20-50 MB
- Correction	5-15 sec	30-80 MB

## 🔒 Sécurité

- Mesures de Protection

- Validation d'entrée : Toutes les URLs et données utilisateur sont validées

- Limitation de débit : Protection contre les scans agressifs

- Isolation : Environnement séparé pour l'analyse

- Confidentialité : Aucune donnée envoyée à des serveurs externes

## Avertissements
**⚠️ Cet outil est conçu pour des tests légitimes uniquement**

**Utilisez uniquement sur vos propres systèmes**

**Obtenez une autorisation écrite avant de scanner des systèmes tiers**

**Respectez les lois locales et les politiques de sécurité**

📄 Licence
Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

text
MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.


Roadmap
Support des API GraphQL

Intégration CI/CD

Plugins personnalisés

Base de données de vulnérabilités

Rapports automatisés

## 🌟 Fonctionnalités à Venir

### Version 3.0 (Q4 2024)

- Analyse SAST/DAST : Combinaison analyse statique et dynamique

- IA améliorée : Modèles de machine learning pour détection

- Cloud ready : Déploiement SaaS

- API complète : Intégration avec d'autres outils

### Version 2.5 (Q3 2024)

- Support mobile : Application Android/iOS

- Multi-utilisateurs : Gestion d'équipe

- Dashboard web : Interface web supplémentaire

- Plugins marketplace : Extensions communautaires

<div align="center">
⚡ "La sécurité n'est pas un produit, mais un processus" ⚡

</div>
