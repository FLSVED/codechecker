# Code Analyzer

## Description

Ce script Python est conçu pour analyser le code source d'un dépôt GitHub ou d'un répertoire local. Il utilise divers outils d'analyse pour évaluer la qualité du code, détecter des problèmes potentiels, et fournir des suggestions d'amélioration. Les résultats de l'analyse sont générés sous forme de rapports et de prompts pour les outils d'IA.

## Fonctionnalités

- **Clonage de Dépôts GitHub** : Clone un dépôt GitHub pour analyse.
- **Analyse de Code Local** : Analyse les fichiers Python dans un répertoire local.
- **Outils d'Analyse Intégrés** : Utilise `pylint`, `flake8`, `bandit`, `mypy`, `black`, `isort`, `pydocstyle`, `coverage`, `radon`, `vulture`, `safety` et `SonarQube`.
- **Détection de Code Mort** : Identifie les fonctions ou variables inutilisées avec `vulture`.
- **Évaluation de la Sécurité** : Vérifie les dépendances pour des vulnérabilités connues avec `safety`.
- **Génération de Rapports** : Crée des rapports détaillés des résultats de l'analyse.
- **Prompts pour IA** : Génère des prompts basés sur les résultats pour une utilisation dans des outils d'IA.

## Prérequis

- Python 3.x
- Les outils d'analyse listés doivent être installés (`pylint`, `flake8`, etc.).
- Accès à un serveur SonarQube avec les configurations nécessaires.

## Installation

1. Clonez ce dépôt ou téléchargez le fichier script.
2. Assurez-vous d'avoir installé les dépendances requises.
3. Configurez vos informations d'accès SonarQube dans le script (`sonar_url`, `sonar_token`, `project_key`).

## Utilisation

### Analyse d'un Dépôt GitHub

1. Exécutez le script.
2. Entrez `g` pour analyser un dépôt GitHub.
3. Fournissez l'URL du dépôt à analyser.

### Analyse d'un Répertoire Local

1. Exécutez le script.
2. Entrez `l` pour analyser un répertoire local.
3. Fournissez le chemin du répertoire à analyser.

## Exemple d'Exécution

```bash
python code_analyzer.py
```

Suivez les instructions à l'écran pour choisir entre l'analyse d'un dépôt GitHub ou d'un répertoire local.

## Résultats

- **Rapports** : Un fichier `analysis_report_suggestions.txt` contenant les résultats de l'analyse et les suggestions d'amélioration.
- **Structure du Code** : Un fichier `code_and_structure.txt` avec la structure complète du code analysé.
- **Prompts pour IA** : Un fichier `ai_prompts.txt` avec des prompts basés sur l'analyse pour une utilisation dans des outils d'IA.

## Remarques

- Assurez-vous que tous les outils requis sont correctement installés et configurés.
- Les résultats peuvent varier en fonction de la configuration de votre environnement de développement et des versions des outils utilisés.

## Contributions

Les contributions sont les bienvenues. Veuillez soumettre des pull requests pour toute suggestion d'amélioration ou nouvelle fonctionnalité.

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.