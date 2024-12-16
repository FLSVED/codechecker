```python
import os
import subprocess
import tempfile
import git
from textblob import TextBlob
import requests

class CodeAnalyzer:
    def __init__(self, repo_path=None):
        self.repo_path = repo_path
        self.temp_dir = None
        self.tools = [
            ['pylint'],
            ['flake8'],
            ['bandit', '-r'],
            ['mypy'],
            ['black', '--check'],
            ['isort', '--check'],
            ['pydocstyle'],
            ['coverage', 'run'],
            ['radon', 'cc'],
            ['radon', 'mi'],
            ['vulture'],  # Pour détecter le code mort
            ['safety']  # Pour vérifier la sécurité des dépendances
        ]
        self.sonar_url = "http://localhost:9000/api/qualitygates/project_status"
        self.sonar_token = "your_sonarqube_token"
        self.project_key = "your_project_key"

    def clone_repository(self, git_url):
        """Clone the GitHub repository into a temporary directory."""
        try:
            self.temp_dir = tempfile.TemporaryDirectory()
            git.Repo.clone_from(git_url, self.temp_dir.name)
            print(f"Cloned repository to: {self.temp_dir.name}")
        except Exception as e:
            print(f"Error cloning repository: {e}")
            self.cleanup()

    def cleanup(self):
        """Clean up temporary directory."""
        if self.temp_dir:
            self.temp_dir.cleanup()
            print("Temporary directory cleaned up.")

    def analyze_code(self, code):
        """Analyze code with specified tools."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
            temp_file.write(code.encode())
            temp_file_path = temp_file.name

        results = {}
        for tool in self.tools:
            try:
                result = subprocess.run(tool + [temp_file_path], capture_output=True, text=True)
                results[tool[0]] = result.stdout
            except Exception as e:
                results[tool[0]] = f"Error {tool[0]}: {e}"

        # SonarQube analysis
        results['sonarqube'] = self.analyze_sonarqube(temp_file_path)

        os.remove(temp_file_path)
        return results

    def analyze_sonarqube(self, file_path):
        """Analyze code with SonarQube and return results."""
        try:
            subprocess.run(
                ["sonar-scanner", f"-Dsonar.projectKey={self.project_key}", f"-Dsonar.sources={file_path}"]
            )
            response = requests.get(self.sonar_url, auth=(self.sonar_token, ''))
            if response.status_code == 200:
                return response.json()
            else:
                return f"SonarQube analysis failed with status code {response.status_code}"
        except Exception as e:
            return f"Error SonarQube: {e}"

    def evaluate_sentiment(self, suggestion):
        """Evaluate the sentiment of a code suggestion."""
        blob = TextBlob(suggestion)
        return blob.sentiment.polarity

    def evaluate_clarity(self, suggestion):
        """Evaluate the clarity of the suggestion based on the number of lines."""
        return len(suggestion.splitlines())

    def evaluate_errors(self, suggestion):
        """Evaluate the number of errors in a suggestion."""
        error_count = 0
        if "print" not in suggestion:
            error_count += 1
        return error_count

    def generate_suggestions(self, problems):
        """Generate improvement suggestions based on detected problems."""
        suggestions = []
        if 'E1101' in problems:
            suggestions.append("Check that all variables are defined before use.")
        if 'F401' in problems:
            suggestions.append("Remove unused imports.")
        if 'sonarqube' in problems:
            suggestions.append("Refer to SonarQube results for detailed suggestions.")
        if 'complexity' in problems:
            suggestions.append("Consider refactoring complex functions to improve readability and maintainability.")
        if 'dead code' in problems:
            suggestions.append("Remove dead code to improve maintainability.")
        if 'security issues' in problems:
            suggestions.append("Review the security issues found in your dependencies.")

        return suggestions

    def choose_best_suggestion(self, suggestions):
        """Choose the best suggestion among those provided."""
        scores = {}
        for suggestion in suggestions:
            clarity = self.evaluate_clarity(suggestion)
            errors = self.evaluate_errors(suggestion)
            sentiment = self.evaluate_sentiment(suggestion)
            score = sentiment - errors - (clarity / 10)
            scores[suggestion] = score

        best_suggestion = max(scores, key=scores.get)
        return best_suggestion

    def read_code_from_file(self, filename):
        """Read code from a specified file."""
        with open(filename, 'r') as f:
            return f.read()

    def write_results_to_file(self, filename, results):
        """Write analysis results and suggestions to a single file."""
        with open(filename, 'w') as f:
            f.write("Analysis Report and Improvement Suggestions\n")
            f.write("=" * 50 + "\n\n")
            for file, details in results.items():
                f.write(f"File: {file}\n")
                f.write("-" * 50 + "\n")
                f.write("Best Suggestion:\n")
                f.write(details['best_suggestion'] + "\n\n")
                f.write("Improvement Suggestions:\n")
                for suggestion in details['suggestions']:
                    f.write("- " + suggestion + "\n")
                f.write("\n")

    def save_code_and_structure(self, path, filename):
        """Save all the code from all modules into a single text file with complete structure."""
        with open(filename, 'w') as f:
            f.write("Code Structure\n")
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

    def generate_prompts(self, analysis_results):
        """Generate prompts for AI tools based on analysis results."""
        prompts = []
        for filename, details in analysis_results.items():
            prompts.append(f"File: {filename}")
            prompts.append("Best Suggestion:")
            prompts.append(details['best_suggestion'])
            prompts.append("Improvement Suggestions:")
            for suggestion in details['suggestions']:
                prompts.append("- " + suggestion)
            prompts.append("\n")

        prompts_file_path = os.path.join(os.path.dirname(__file__), "ai_prompts.txt")
        with open(prompts_file_path, 'w') as f:
            f.write("\n".join(prompts))
        print(f"AI prompts file generated: {prompts_file_path}")

    def analyze_local_repository(self):
        """Analyze all Python files in the local repository and save the code and structure."""
        analysis_results = {}

        if not os.path.isdir(self.repo_path):
            print(f"Error: The path '{self.repo_path}' is not a valid directory.")
            return

        for root, dirs, files in os.walk(self.repo_path):
            for filename in files:
                if filename.endswith('.py'):
                    full_path = os.path.join(root, filename)
                    print(f"Analyzing file: {full_path}")

                    try:
                        code_to_analyze = self.read_code_from_file(full_path)
                        results = self.analyze_code(code_to_analyze)

                        problems_detected = "\n".join(results.values())
                        improvement_suggestions = self.generate_suggestions(problems_detected)
                        best_suggestion = self.choose_best_suggestion(results.values())

                        analysis_results[filename] = {
                            'best_suggestion': best_suggestion,
                            'suggestions': improvement_suggestions
                        }
                    except Exception as e:
                        print(f"Error analyzing file '{full_path}': {e}")

        if analysis_results:
            report_path = os.path.join(os.path.dirname(__file__), "analysis_report_suggestions.txt")
            self.write_results_to_file(report_path, analysis_results)
            print(f"Improvement suggestions report generated: {report_path}")

            # Generate prompts for AI
            self.generate_prompts(analysis_results)

        code_structure_path = os.path.join(os.path.dirname(__file__), "code_and_structure.txt")
        self.save_code_and_structure(self.repo_path, code_structure_path)
        print(f"Code and structure file generated: {code_structure_path}")

def main():
    choice = input("Do you want to analyze a GitHub repository (enter 'g') or a local directory (enter 'l')? ")
    
    if choice.lower() == 'g':
        url_repository = input("Enter the GitHub repository URL to analyze: ")
        analyzer = CodeAnalyzer()
        analyzer.clone_repository(url_repository)
        analyzer.analyze_local_repository()
        analyzer.cleanup()
    elif choice.lower() == 'l':
        local_path = input("Enter the local directory path to analyze: ")
        analyzer = CodeAnalyzer(repo_path=local_path)
        analyzer.analyze_local_repository()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
```