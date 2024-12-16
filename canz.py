import os
import subprocess
import tempfile
import git  # Assurez-vous d'installer GitPython avec `pip install GitPython`
from textblob import TextBlob
import requests

def analyser_code(outils, code):
    """Analyse le code avec les outils spécifiés et retourne les résultats."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
        temp_file.write(code.encode())
        temp_file_path = temp_file.name

    results = {}
    for outil in outils:
        try:
            result = subprocess.run(outil + [temp_file_path], capture_output=True, text=True)
            results[outil[0]] = result.stdout
        except Exception as e:
            results[outil[0]] = f"Erreur {outil[0]} : {e}"

    # SonarQube analysis
    try:
        sonar_result = analyser_sonarqube(temp_file_path)
        results['sonarqube'] = sonar_result
    except Exception as e:
        results['sonarqube'] = f"Erreur SonarQube : {e}"

    os.remove(temp_file_path)
    return results

def analyser_sonarqube(file_path):
    """Analyse le code avec SonarQube et retourne les résultats."""
    sonar_url = "http://localhost:9000/api/qualitygates/project_status"
    sonar_token = "your_sonarqube_token"
    project_key = "your_project_key"

    # Assuming SonarQube scanner is configured and running
    subprocess.run(["sonar-scanner", f"-Dsonar.projectKey={project_key}", f"-Dsonar.sources={file_path}"])

    response = requests.get(sonar_url, auth=(sonar_token, ''))
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"SonarQube analysis failed with status code {response.status_code}")

def evaluer_suggestion(code):
    """Évalue le sentiment d'une suggestion de code."""
    blob = TextBlob(code)
    return blob.sentiment.polarity

def evaluer_clarte(code):
    """Évalue la clarté du code en fonction du nombre de lignes."""
    return len(code.splitlines())  # Plus il y a de lignes, moins c'est clair

def evaluer_erreurs(code):
    """Évalue le nombre d'erreurs dans le code."""
    error_count = 0
    if "print" not in code:
        error_count += 1
    return error_count

def generer_suggestions(problemes):
    """Génère des suggestions d'amélioration basées sur les problèmes détectés dans le code."""
    suggestions = []
    if 'E1101' in problemes:  # Erreur Pylint pour utilisation de variable non définie
        suggestions.append("Vérifiez que toutes les variables sont définies avant de les utiliser.")
    if 'F401' in problemes:  # Flake8 pour import inutilisé
        suggestions.append("Supprimez les importations qui ne sont pas utilisées.")
    if 'sonarqube' in problemes:
        suggestions.append("Consultez les résultats de SonarQube pour des suggestions détaillées.")
    return suggestions

def choisir_meilleure_suggestion(suggestions):
    """Choisit la meilleure suggestion parmi celles fournies."""
    scores = {}
    for suggestion in suggestions:
        clarity = evaluer_clarte(suggestion)
        errors = evaluer_erreurs(suggestion)
        sentiment = evaluer_suggestion(suggestion)
        score = sentiment - errors - (clarity / 10)
        scores[suggestion] = score

    meilleur_code = max(scores, key=scores.get)
    return meilleur_code

def lire_code_depuis_fichier(nom_fichier):
    """Lit le code depuis un fichier donné."""
    with open(nom_fichier, 'r') as f:
        return f.read()

def ecrire_resultats_dans_fichier(nom_fichier, resultats):
    """Écrit les résultats d'analyse et les suggestions dans un fichier unique."""
    with open(nom_fichier, 'w') as f:
        f.write("Rapport d'Analyse et Suggestions d'Amélioration\n")
        f.write("=" * 50 + "\n\n")
        for fichier, details in resultats.items():
            f.write(f"Fichier : {fichier}\n")
            f.write("-" * 50 + "\n")
            f.write("Meilleure suggestion :\n")
            f.write(details['meilleure_suggestion'] + "\n\n")
            f.write("Suggestions pour amélioration :\n")
            for suggestion in details['suggestions']:
                f.write("- " + suggestion + "\n")
            f.write("\n")

def sauvegarder_code_et_architecture(path, nom_fichier):
    """Sauvegarde tout le code de tous les modules dans un seul fichier texte avec l'architecture complète."""
    with open(nom_fichier, 'w') as f:
        f.write("Architecture du Code\n")
        f.write("=" * 50 + "\n\n")
        
        for root, dirs, files in os.walk(path):
            for filename in files:
                if filename.endswith('.py'):
                    full_path = os.path.join(root, filename)
                    f.write(f"Module: {full_path}\n")
                    f.write("-" * 50 + "\n")
                    with open(full_path, 'r') as code_file:
                        f.write(code_file.read())
                    f.write("\n\n")

def generer_prompts_pour_copilote(resultats_analyse):
    """Génère un fichier de prompts pour l'IA Copilot basé sur les résultats d'analyse et les suggestions."""
    prompts = []
    for fichier, details in resultats_analyse.items():
        prompts.append(f"Fichier : {fichier}")
        prompts.append("Meilleure suggestion :")
        prompts.append(details['meilleure_suggestion'])
        prompts.append("Suggestions pour amélioration :")
        for suggestion in details['suggestions']:
            prompts.append("- " + suggestion)
        prompts.append("\n")

    chemin_prompts = os.path.join(os.path.dirname(__file__), "prompt.txt")
    with open(chemin_prompts, 'w') as f:
        f.write("\n".join(prompts))
    print(f"Fichier des prompts généré : {chemin_prompts}")

def analyser_modules(path):
    """Analyse tous les fichiers Python dans un répertoire donné et sauvegarde le code et l'architecture."""
    resultats_analyse = {}
    
    if not os.path.isdir(path):
        print(f"Erreur : Le chemin d'accès '{path}' n'est pas un répertoire valide.")
        return

    outils = [
        ['pylint'],
        ['flake8'],
        ['bandit', '-r'],
        ['mypy'],
        ['black', '--check'],
        ['isort', '--check'],
        ['pydocstyle'],
        ['coverage', 'run'],
        ['radon', 'cc']
    ]

    for root, dirs, files in os.walk(path):
        for filename in files:
            if filename.endswith('.py'):
                full_path = os.path.join(root, filename)
                print(f"Analyse du fichier : {full_path}")
                
                try:
                    code_a_corriger = lire_code_depuis_fichier(full_path)

                    # Analyse avec les différents outils
                    results = analyser_code(outils, code_a_corriger)

                    # Générer des suggestions basées sur les problèmes détectés
                    problems_detected = "\n".join(results.values())
                    improvement_suggestions = generer_suggestions(problems_detected)

                    # Choisir la meilleure suggestion
                    meilleure_suggestion = choisir_meilleure_suggestion(results.values())

                    # Stocker les résultats pour ce fichier
                    resultats_analyse[filename] = {
                        'meilleure_suggestion': meilleure_suggestion,
                        'suggestions': improvement_suggestions
                    }
                
                except Exception as e:
                    print(f"Erreur lors de l'analyse du fichier '{full_path}': {e}")

    # Écrire toutes les suggestions globales dans un fichier unique
    if resultats_analyse:
        chemin_rapport = os.path.join(os.path.dirname(__file__), "rapport_analyse_suggestions.txt")
        ecrire_resultats_dans_fichier(chemin_rapport, resultats_analyse)
        print(f"Fichier des suggestions d'amélioration généré : {chemin_rapport}")

        # Générer le fichier de prompts pour Copilot
        generer_prompts_pour_copilote(resultats_analyse)

    # Sauvegarder tout le code et l'architecture dans un fichier unique
    chemin_code_architecture = os.path.join(os.path.dirname(__file__), "code_et_architecture.txt")
    sauvegarder_code_et_architecture(path, chemin_code_architecture)
    print(f"Fichier du code et de l'architecture généré : {chemin_code_architecture}")

def cloner_repository(git_url: str) -> tempfile.TemporaryDirectory | None:
    """Clone le dépôt GitHub dans un répertoire temporaire et retourne l'objet TemporaryDirectory."""
    try:
        # Créer un répertoire temporaire
        temp_dir = tempfile.TemporaryDirectory()
        print(f"Clonage du dépôt à l'adresse : {git_url}")
        # Cloner le dépôt
        git.Repo.clone_from(git_url, temp_dir.name)
        return temp_dir
    except Exception as e:
        print(f"Erreur lors du clonage du dépôt : {e}")
        return None

# Exemple d'utilisation
url_repository = input("Entrez l'URL du dépôt GitHub à analyser : ")
temp_dir_obj = cloner_repository(url_repository)

if temp_dir_obj:
    analyser_modules(temp_dir_obj.name)
    temp_dir_obj.cleanup()  # Clean up the temporary directory after analysis
