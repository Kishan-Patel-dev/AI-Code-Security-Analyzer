import os
import re
import json
import uuid
import requests  # Assuming the LLM API requires HTTP requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import zipfile
import tempfile
import shutil
from typing import List, Dict
import subprocess

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'py', 'js', 'java', 'c', 'cpp', 'php', 'rb', 'go'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def identify_language(filename):
    extension = filename.split('.')[-1].lower()
    
    language_map = {
        'py': 'Python',
        'js': 'JavaScript',
        'java': 'Java',
        'c': 'C',
        'cpp': 'C++',
        'php': 'PHP',
        'rb': 'Ruby',
        'go': 'Go'
    }
    
    return language_map.get(extension, 'Unknown')

def analyze_with_llm(code: str, language: str):
    """
    Uses an LLM to analyze the provided code for vulnerabilities.
    """
    # LLM API configuration
    LLM_API_OPTIONS = {
        "openai": {
            "url": "https://api.openai.com/v1/completions",
            "key": "your-openai-api-key-here",
            "model": "gpt-4"
        },
        "anthropic": {
            "url": "https://api.anthropic.com/v1/complete",
            "key": "your-anthropic-api-key-here",
            "model": "claude-v1"
        },
        "huggingface": {
            "url": "https://api-inference.huggingface.co/models/your-model-name",
            "key": "your-huggingface-api-key-here"
        }
    }

    # Select the desired LLM provider
    selected_provider = "openai"  # Change this to "anthropic" or "huggingface" as needed
    config = LLM_API_OPTIONS[selected_provider]

    # Construct the prompt for the LLM
    prompt = f"""
    Analyze the following {language} code for security vulnerabilities. Identify the type of vulnerability, the line number (if possible), a description, severity (Low, Medium, High), and a recommendation to fix it.

    Code:
    {code}

    Provide the output as a JSON array with the following fields:
    - line: Line number where the vulnerability occurs (if extractable)
    - description: Explanation of the issue
    - severity: One of ['Low', 'Medium', 'High']
    - recommendation: Suggested fix or mitigation
    - vuln_type: Type of vulnerability (e.g., 'SQL Injection')
    """

    # Mocked response for demonstration purposes
    mocked_response = [
        {
            "line": 2,
            "description": "Unvalidated input passed to os.system, allowing command injection.",
            "severity": "High",
            "recommendation": "Use subprocess with input sanitization instead of os.system.",
            "vuln_type": "Command Injection"
        }
    ]

    # Uncomment the following lines to use the actual LLM API
    # headers = {
    #     "Authorization": f"Bearer {config['key']}",
    #     "Content-Type": "application/json"
    # }
    # payload = {
    #     "model": config.get("model", ""),
    #     "prompt": prompt,
    #     "max_tokens": 1000,
    #     "temperature": 0
    # }
    # response = requests.post(config["url"], headers=headers, json=payload)
    # if response.status_code == 200:
    #     return response.json().get("choices", [{}])[0].get("text", [])
    # else:
    #     raise Exception(f"LLM API Error: {response.status_code} - {response.text}")

    return mocked_response

def analyze_code(file_path, language):
    """
    Analyze code for vulnerabilities based on language and optionally using LLM.
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        code = file.read()

    vulnerabilities = []

    # Use language-specific analyzers
    analyzers = {
        'Python': analyze_python,
        'JavaScript': analyze_javascript,
        'Java': analyze_java,
        'C': analyze_c,
        'C++': analyze_cpp,
        'PHP': analyze_php,
        'Ruby': analyze_ruby,
        'Go': analyze_go
    }

    if language in analyzers:
        vulnerabilities.extend(analyzers[language](code))

    # Use LLM-based analysis as an additional step
    vulnerabilities.extend(analyze_with_llm(code, language))

    return {
        'source_code': code,
        'language': language,
        'vulnerabilities': vulnerabilities
    }

def generate_code_fix(code: str, language: str, issues: list) -> str:
    """
    Generates a fixed version of the provided code by addressing identified vulnerabilities.

    Parameters:
    - code (str): The original insecure source code.
    - language (str): The programming language of the code.
    - issues (list): A list of identified issues, each containing:
        - `line`: Line number of the issue.
        - `vuln_type`: Type of vulnerability (e.g., 'Hardcoded Secret').
        - `recommendation`: Fix advice.

    Returns:
    - str: The fixed version of the code.
    """
    # Mode selection: Use LLM or Static Rule Mode
    USE_LLM = True  # Set to False to use Static Rule Mode

    if USE_LLM:
        # LLM Mode
        return fix_with_llm(code, language, issues)
    else:
        # Static Rule Mode
        return fix_with_static_rules(code, issues)


def fix_with_llm(code: str, language: str, issues: list) -> str:
    """
    Uses an LLM to generate a secure version of the code.

    Parameters:
    - code (str): The original insecure source code.
    - language (str): The programming language of the code.
    - issues (list): A list of identified issues.

    Returns:
    - str: The fixed version of the code.
    """
    # LLM API configuration
    LLM_API_URL = "https://api.openai.com/v1/completions"
    LLM_API_KEY = "your-openai-api-key-here"

    # Construct the prompt for the LLM
    issues_description = "\n".join(
        [f"- Line {issue['line']}: {issue['vuln_type']} - {issue['recommendation']}" for issue in issues]
    )
    prompt = f"""
    The following {language} code contains security vulnerabilities:

    Code:
    {code}

    Issues:
    {issues_description}

    Please rewrite the code to fix all the vulnerabilities while maintaining its functionality.
    """

    # Mocked response for demonstration purposes
    mocked_fixed_code = "# Fixed code generated by LLM\n" + code.replace("os.system(user_input)", "subprocess.run(user_input, shell=True)")

    # Uncomment the following lines to use the actual LLM API
    # headers = {
    #     "Authorization": f"Bearer {LLM_API_KEY}",
    #     "Content-Type": "application/json"
    # }
    # payload = {
    #     "model": "gpt-4",
    #     "prompt": prompt,
    #     "max_tokens": 2000,
    #     "temperature": 0
    # }
    # response = requests.post(LLM_API_URL, headers=headers, json=payload)
    # if response.status_code == 200:
    #     return response.json().get("choices", [{}])[0].get("text", "").strip()
    # else:
    #     raise Exception(f"LLM API Error: {response.status_code} - {response.text}")

    return mocked_fixed_code


def fix_with_static_rules(code: str, issues: list) -> str:
    """
    Applies static rules to fix common vulnerabilities in the code.

    Parameters:
    - code (str): The original insecure source code.
    - issues (list): A list of identified issues.

    Returns:
    - str: The fixed version of the code.
    """
    lines = code.split("\n")
    for issue in issues:
        line_index = issue["line"] - 1
        if issue["vuln_type"] == "Hardcoded Secret":
            # Replace hardcoded secrets with environment variables
            lines[line_index] = re.sub(
                r'(["\'])(password|secret|key|token|api_key|apikey)\s*=\s*["\'][^"\']+["\']',
                r'\1\2 = os.getenv("\2")',
                lines[line_index]
            )
        elif issue["vuln_type"] == "Command Injection":
            # Replace os.system with subprocess.run
            lines[line_index] = lines[line_index].replace("os.system(", "subprocess.run(")
        elif issue["vuln_type"] == "SQL Injection":
            # Add a comment suggesting parameterized queries
            lines[line_index] += "  # TODO: Use parameterized queries to prevent SQL injection."

    return "\n".join(lines)

# Language-specific analyzers
def analyze_python(code):
    vulnerabilities = []
    
    # Check for command injection vulnerabilities
    lines = code.split('\n')
    for i, line in enumerate(lines):
        # Check for eval/exec with variables
        if re.search(r'eval\s*\(.*?\)', line) or re.search(r'exec\s*\(.*?\)', line):
            if not re.search(r'eval\s*\(\s*[\'"][^\'"]*[\'"]\s*\)', line):  # Ignore hardcoded strings
                vulnerabilities.append({
                    'name': 'Command Injection',
                    'severity': 'high',
                    'line_number': i + 1,
                    'code_snippet': line.strip(),
                    'description': 'Use of eval() or exec() can lead to command injection if user input is involved.',
                    'impact': 'An attacker could execute arbitrary code on the system.',
                    'recommendation': 'Avoid using eval() or exec() with dynamic content. Use safer alternatives.',
                    'references': [
                        {'title': 'OWASP Command Injection', 'url': 'https://owasp.org/www-community/attacks/Command_Injection'}
                    ]
                })
        
        # Check for SQL injection
        if re.search(r'execute\s*\(.*?\+.*?\)', line) or re.search(r'cursor\.execute\s*\(.*?\+.*?\)', line):
            vulnerabilities.append({
                'name': 'SQL Injection',
                'severity': 'high',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'String concatenation in SQL queries can lead to SQL injection vulnerabilities.',
                'impact': 'An attacker could manipulate the database query to access, modify, or delete data.',
                'recommendation': 'Use parameterized queries or an ORM instead of string concatenation.',
                'references': [
                    {'title': 'OWASP SQL Injection', 'url': 'https://owasp.org/www-community/attacks/SQL_Injection'}
                ]
            })
        
        # Check for unsafe deserialization
        if 'pickle.loads' in line or 'pickle.load(' in line:
            vulnerabilities.append({
                'name': 'Insecure Deserialization',
                'severity': 'high',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Unsafe deserialization of pickle data can lead to code execution.',
                'impact': 'An attacker could execute arbitrary code by crafting malicious serialized data.',
                'recommendation': 'Avoid using pickle for untrusted data. Consider using JSON or other safer alternatives.',
                'references': [
                    {'title': 'OWASP Deserialization', 'url': 'https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization'}
                ]
            })
        
        # Check for hardcoded secrets
        if re.search(r'(password|secret|key|token|api_key|apikey)\s*=\s*["\'][^"\']+["\']', line, re.IGNORECASE):
            vulnerabilities.append({
                'name': 'Hardcoded Secret',
                'severity': 'medium',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Hardcoded credentials or API keys were detected in the code.',
                'impact': 'Secrets in source code could be exposed if the code is shared or stored in a repository.',
                'recommendation': 'Use environment variables or secure secret management solutions instead of hardcoded values.',
                'references': [
                    {'title': 'OWASP Sensitive Data Exposure', 'url': 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'}
                ]
            })
        
        # Check for weak cryptography
        if 'md5' in line.lower() or 'sha1' in line.lower():
            vulnerabilities.append({
                'name': 'Weak Cryptography',
                'severity': 'medium',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Use of weak cryptographic algorithms (MD5 or SHA1).',
                'impact': 'Increased risk of cryptographic attacks and hash collisions.',
                'recommendation': 'Use stronger algorithms like SHA-256 or bcrypt for passwords.',
                'references': [
                    {'title': 'OWASP Cryptographic Failures', 'url': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'}
                ]
            })
    
    return vulnerabilities

def analyze_javascript(code):
    vulnerabilities = []
    
    # Check for common JS vulnerabilities
    lines = code.split('\n')
    for i, line in enumerate(lines):
        # Check for XSS vulnerabilities
        if 'innerHTML' in line or 'document.write' in line:
            vulnerabilities.append({
                'name': 'Cross-Site Scripting (XSS)',
                'severity': 'high',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Direct manipulation of HTML with innerHTML or document.write can lead to XSS.',
                'impact': 'Attackers could inject and execute malicious scripts affecting users.',
                'recommendation': 'Use textContent instead of innerHTML when possible, or sanitize user input.',
                'references': [
                    {'title': 'OWASP XSS', 'url': 'https://owasp.org/www-community/attacks/xss/'}
                ]
            })
        
        # Check for eval usage
        if 'eval(' in line or 'new Function(' in line:
            vulnerabilities.append({
                'name': 'Unsafe Code Execution',
                'severity': 'high',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Use of eval() or Function constructor can lead to code injection.',
                'impact': 'Attackers could execute arbitrary JavaScript code.',
                'recommendation': 'Avoid using eval() or new Function(). Use safer alternatives.',
                'references': [
                    {'title': 'OWASP JavaScript Security', 'url': 'https://cheatsheetseries.owasp.org/cheatsheets/JavaScript_Security_Cheat_Sheet.html'}
                ]
            })
        
        # Check for hardcoded secrets
        if re.search(r'(password|secret|key|token|api_key|apikey)\s*=\s*["\'][^"\']+["\']', line, re.IGNORECASE):
            vulnerabilities.append({
                'name': 'Hardcoded Secret',
                'severity': 'medium',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Hardcoded credentials or API keys were detected in the code.',
                'impact': 'Client-side secrets are visible to anyone who can view the source code.',
                'recommendation': 'Never store sensitive values in client-side code. Use server APIs instead.',
                'references': [
                    {'title': 'OWASP Sensitive Data Exposure', 'url': 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'}
                ]
            })
    
    return vulnerabilities

def analyze_java(code):
    vulnerabilities = []
    
    # Check for common Java vulnerabilities
    lines = code.split('\n')
    for i, line in enumerate(lines):
        # Check for SQL injection
        if 'executeQuery(' in line or 'executeUpdate(' in line:
            if '+' in line or 'concat' in line.lower():
                vulnerabilities.append({
                    'name': 'SQL Injection',
                    'severity': 'high',
                    'line_number': i + 1,
                    'code_snippet': line.strip(),
                    'description': 'String concatenation in SQL queries can lead to SQL injection.',
                    'impact': 'Attackers could manipulate database queries to access or modify data.',
                    'recommendation': 'Use PreparedStatement with parameterized queries instead of string concatenation.',
                    'references': [
                        {'title': 'OWASP SQL Injection', 'url': 'https://owasp.org/www-community/attacks/SQL_Injection'}
                    ]
                })
        
        # Check for XSS vulnerabilities
        if '.getParameter(' in line and ('out.print' in line or 'response.getWriter().print' in line):
            vulnerabilities.append({
                'name': 'Cross-Site Scripting (XSS)',
                'severity': 'high',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Directly writing user input to response can lead to XSS.',
                'impact': 'Attackers could inject and execute malicious scripts affecting users.',
                'recommendation': 'Use proper output encoding or escaping for different contexts.',
                'references': [
                    {'title': 'OWASP XSS', 'url': 'https://owasp.org/www-community/attacks/xss/'}
                ]
            })
    
    return vulnerabilities

def analyze_c(code):
    vulnerabilities = []
    
    # Check for common C vulnerabilities
    lines = code.split('\n')
    for i, line in enumerate(lines):
        # Check for buffer overflow vulnerabilities
        if 'strcpy(' in line or 'strcat(' in line or 'gets(' in line:
            vulnerabilities.append({
                'name': 'Buffer Overflow',
                'severity': 'high',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Use of unsafe functions that do not check buffer boundaries.',
                'impact': 'Buffer overflows can lead to crashes, data corruption, or code execution.',
                'recommendation': 'Use safer alternatives like strncpy(), strncat(), or fgets() with proper bounds checking.',
                'references': [
                    {'title': 'OWASP Buffer Overflow', 'url': 'https://owasp.org/www-community/vulnerabilities/Buffer_Overflow'}
                ]
            })
        
        # Check for format string vulnerabilities
        if 'printf(' in line or 'sprintf(' in line:
            if re.search(r'printf\s*\(\s*[^,)]*\)', line) or '...' in line:
                vulnerabilities.append({
                    'name': 'Format String Vulnerability',
                    'severity': 'high',
                    'line_number': i + 1,
                    'code_snippet': line.strip(),
                    'description': 'Potential format string vulnerability due to user-controlled format string.',
                    'impact': 'Attackers could read memory, crash the program, or execute code.',
                    'recommendation': 'Always use a literal format string with proper format specifiers.',
                    'references': [
                        {'title': 'OWASP Format String', 'url': 'https://owasp.org/www-community/attacks/Format_string_attack'}
                    ]
                })
    
    return vulnerabilities

def analyze_cpp(code):
    # C++ analysis includes C vulnerabilities plus C++-specific ones
    vulnerabilities = analyze_c(code)
    
    lines = code.split('\n')
    for i, line in enumerate(lines):
        # Check for use of deprecated functions
        if 'auto_ptr' in line:
            vulnerabilities.append({
                'name': 'Deprecated API Usage',
                'severity': 'low',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Use of deprecated auto_ptr which has been removed in C++17.',
                'impact': 'Code might not compile with newer standards or could have unexpected behavior.',
                'recommendation': 'Use unique_ptr instead of auto_ptr.',
                'references': [
                    {'title': 'C++ Core Guidelines', 'url': 'https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines'}
                ]
            })
    
    return vulnerabilities

def analyze_php(code):
    vulnerabilities = []
    
    lines = code.split('\n')
    for i, line in enumerate(lines):
        # Check for SQL injection
        if re.search(r'mysql_query\s*\(.*\$', line) or re.search(r'mysqli_query\s*\(.*\$', line):
            vulnerabilities.append({
                'name': 'SQL Injection',
                'severity': 'high',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Potential SQL injection due to unparameterized queries.',
                'impact': 'Attackers could manipulate database queries to access or modify data.',
                'recommendation': 'Use prepared statements with mysqli or PDO instead.',
                'references': [
                    {'title': 'OWASP SQL Injection', 'url': 'https://owasp.org/www-community/attacks/SQL_Injection'}
                ]
            })
        
        # Check for XSS vulnerabilities
        if 'echo' in line or 'print' in line:
            if '$_GET' in line or '$_POST' in line or '$_REQUEST' in line:
                if 'htmlspecialchars' not in line and 'htmlentities' not in line:
                    vulnerabilities.append({
                        'name': 'Cross-Site Scripting (XSS)',
                        'severity': 'high',
                        'line_number': i + 1,
                        'code_snippet': line.strip(),
                        'description': 'Potential XSS vulnerability due to unescaped output of user input.',
                        'impact': 'Attackers could inject and execute malicious scripts affecting users.',
                        'recommendation': 'Use htmlspecialchars() or htmlentities() to encode output.',
                        'references': [
                            {'title': 'OWASP XSS', 'url': 'https://owasp.org/www-community/attacks/xss/'}
                        ]
                    })
        
        # Check for command injection
        if 'system(' in line or 'exec(' in line or 'shell_exec(' in line or 'passthru(' in line:
            vulnerabilities.append({
                'name': 'Command Injection',
                'severity': 'high',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Potential command injection vulnerability.',
                'impact': 'Attackers could execute arbitrary system commands.',
                'recommendation': 'Avoid using shell commands. If necessary, use escapeshellarg() or escapeshellcmd().',
                'references': [
                    {'title': 'OWASP Command Injection', 'url': 'https://owasp.org/www-community/attacks/Command_Injection'}
                ]
            })
    
    return vulnerabilities

def analyze_ruby(code):
    vulnerabilities = []
    
    lines = code.split('\n')
    for i, line in enumerate(lines):
        # Check for SQL injection
        if 'execute' in line or 'where' in line:
            if '#{' in line or '+' in line:
                vulnerabilities.append({
                    'name': 'SQL Injection',
                    'severity': 'high',
                    'line_number': i + 1,
                    'code_snippet': line.strip(),
                    'description': 'Potential SQL injection due to string interpolation in queries.',
                    'impact': 'Attackers could manipulate database queries to access or modify data.',
                    'recommendation': 'Use parameterized queries with placeholders (?) or named parameters.',
                    'references': [
                        {'title': 'OWASP SQL Injection', 'url': 'https://owasp.org/www-community/attacks/SQL_Injection'}
                    ]
                })
        
        # Check for command injection
        if '`' in line or 'system(' in line or 'exec(' in line or 'eval(' in line:
            vulnerabilities.append({
                'name': 'Command Injection',
                'severity': 'high',
                'line_number': i + 1,
                'code_snippet': line.strip(),
                'description': 'Potential command injection vulnerability.',
                'impact': 'Attackers could execute arbitrary system commands.',
                'recommendation': 'Avoid using shell commands or eval. If necessary, validate and sanitize inputs.',
                'references': [
                    {'title': 'OWASP Command Injection', 'url': 'https://owasp.org/www-community/attacks/Command_Injection'}
                ]
            })
    
    return vulnerabilities

def analyze_go(code):
    vulnerabilities = []
    
    lines = code.split('\n')
    for i, line in enumerate(lines):
        # Check for SQL injection
        if 'Exec(' in line or 'Query(' in line:
            if '+' in line or 'fmt.Sprintf' in line:
                vulnerabilities.append({
                    'name': 'SQL Injection',
                    'severity': 'high',
                    'line_number': i + 1,
                    'code_snippet': line.strip(),
                    'description': 'Potential SQL injection due to string concatenation in queries.',
                    'impact': 'Attackers could manipulate database queries to access or modify data.',
                    'recommendation': 'Use parameterized queries with the ? placeholder.',
                    'references': [
                        {'title': 'OWASP SQL Injection', 'url': 'https://owasp.org/www-community/attacks/SQL_Injection'}
                    ]
                })
        
        # Check for file path manipulation
        if 'os.Open(' in line or 'ioutil.ReadFile(' in line:
            if '+' in line or 'path.Join' in line:
                vulnerabilities.append({
                    'name': 'Path Traversal',
                    'severity': 'high',
                    'line_number': i + 1,
                    'code_snippet': line.strip(),
                    'description': 'Potential path traversal vulnerability.',
                    'impact': 'Attackers could access files outside the intended directory.',
                    'recommendation': 'Validate and sanitize file paths before using them.',
                    'references': [
                        {'title': 'OWASP Path Traversal', 'url': 'https://owasp.org/www-community/attacks/Path_Traversal'}
                    ]
                })
    
    return vulnerabilities

def extract_and_list_files(zip_path: str) -> List[str]:
    """
    Extracts a zip file to a temporary directory and lists all supported code files.

    Parameters:
    - zip_path (str): Path to the zip file.

    Returns:
    - List[str]: List of full paths to supported code files.
    """
    temp_dir = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        supported_files = []
        for root, dirs, files in os.walk(temp_dir):
            # Skip unnecessary folders
            dirs[:] = [d for d in dirs if d not in {'node_modules', '__pycache__', '.git'}]
            for file in files:
                if allowed_file(file):
                    supported_files.append(os.path.join(root, file))
        return supported_files
    except Exception as e:
        shutil.rmtree(temp_dir)
        raise e


def scan_project(zip_path: str, language: str) -> Dict:
    """
    Scans a zipped project folder for vulnerabilities.

    Parameters:
    - zip_path (str): Path to the zip file.
    - language (str): Programming language of the project.

    Returns:
    - Dict: Consolidated report of vulnerabilities.
    """
    temp_dir = tempfile.mkdtemp()
    try:
        # Extract files
        files = extract_and_list_files(zip_path)

        # Analyze each file
        vulnerabilities_by_file = {}
        summary = {"high": 0, "medium": 0, "low": 0}
        for file_path in files:
            result = analyze_code(file_path, language)
            vulnerabilities_by_file[file_path] = result["vulnerabilities"]

            # Update summary
            for vuln in result["vulnerabilities"]:
                summary[vuln["severity"].lower()] += 1

        return {
            "summary": summary,
            "by_file": vulnerabilities_by_file,
            "files_scanned": len(files)
        }
    finally:
        shutil.rmtree(temp_dir)


def clone_and_scan_repo(git_url: str, language: str) -> Dict:
    """
    Clones a Git repository, scans it for vulnerabilities, and deletes the cloned folder.

    Parameters:
    - git_url (str): URL of the Git repository.
    - language (str): Programming language of the repository.

    Returns:
    - Dict: Consolidated report of vulnerabilities.
    """
    temp_dir = tempfile.mkdtemp()
    try:
        # Clone the repository
        subprocess.run(["git", "clone", git_url, temp_dir], check=True)

        # Create a zip file of the cloned repository
        zip_path = os.path.join(temp_dir, "repo.zip")
        shutil.make_archive(zip_path.replace(".zip", ""), 'zip', temp_dir)

        # Scan the project
        return scan_project(zip_path, language)
    finally:
        shutil.rmtree(temp_dir)

def scan_github_repo(repo_url: str, language: str) -> Dict:
    """
    Downloads a GitHub repository as a ZIP archive, extracts its contents, and scans for vulnerabilities.

    Parameters:
    - repo_url (str): The GitHub repository URL (e.g., https://github.com/user/repo).
    - language (str): Programming language of the repository.

    Returns:
    - Dict: Summary of vulnerabilities and formatted comments for GitHub PR review.
    """
    temp_dir = tempfile.mkdtemp()
    try:
        # Parse the repository URL
        if not repo_url.endswith(".zip"):
            repo_url = repo_url.rstrip("/") + "/archive/refs/heads/main.zip"

        # Download the ZIP archive
        response = requests.get(repo_url, stream=True)
        if response.status_code != 200:
            raise Exception(f"Failed to download repository: {response.status_code} - {response.text}")

        zip_path = os.path.join(temp_dir, "repo.zip")
        with open(zip_path, "wb") as zip_file:
            for chunk in response.iter_content(chunk_size=8192):
                zip_file.write(chunk)

        # Extract the ZIP archive
        extract_dir = os.path.join(temp_dir, "repo")
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_dir)

        # Recursively scan all supported code files
        files = extract_and_list_files(extract_dir)
        vulnerabilities_by_file = {}
        summary = {"high": 0, "medium": 0, "low": 0}
        comments = []

        for file_path in files:
            result = analyze_code(file_path, language)
            vulnerabilities_by_file[file_path] = result["vulnerabilities"]

            # Update summary and format comments
            for vuln in result["vulnerabilities"]:
                summary[vuln["severity"].lower()] += 1
                comments.append({
                    "file": os.path.relpath(file_path, extract_dir),
                    "line": vuln["line_number"],
                    "comment": f"⚠️ {vuln['name']} detected. {vuln['description']} Severity: {vuln['severity']}. Recommendation: {vuln['recommendation']}"
                })

        return {
            "summary": summary,
            "comments": comments
        }
    finally:
        shutil.rmtree(temp_dir)

# API Routes
@app.route('/api/upload', methods=['POST'])
def upload_file():
    # Check if file part exists in request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    # Check if file is selected
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Check if file type is allowed
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    # Generate a unique filename
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    # Save the file
    file.save(file_path)
    
    # Identify the language
    language = identify_language(filename)
    
    # Analyze the code
    result = analyze_code(file_path, language)
    
    return jsonify(result)

@app.route('/api/languages', methods=['GET'])
def get_languages():
    return jsonify({
        'languages': [
            {'name': 'Python', 'extension': 'py'},
            {'name': 'JavaScript', 'extension': 'js'},
            {'name': 'Java', 'extension': 'java'},
            {'name': 'C', 'extension': 'c'},
            {'name': 'C++', 'extension': 'cpp'},
            {'name': 'PHP', 'extension': 'php'},
            {'name': 'Ruby', 'extension': 'rb'},
            {'name': 'Go', 'extension': 'go'}
        ]
    })

@app.route('/api/summary', methods=['GET'])
def get_summary():
    """
    Returns a summary of vulnerabilities detected in the last uploaded file.
    """
    latest_file = max(
        (os.path.join(app.config['UPLOAD_FOLDER'], f) for f in os.listdir(app.config['UPLOAD_FOLDER'])),
        key=os.path.getctime,
        default=None
    )
    if not latest_file:
        return jsonify({'error': 'No files analyzed yet'}), 404

    language = identify_language(latest_file)
    result = analyze_code(latest_file, language)
    summary = {
        'language': result['language'],
        'total_vulnerabilities': len(result['vulnerabilities']),
        'high': sum(1 for v in result['vulnerabilities'] if v['severity'] == 'high'),
        'medium': sum(1 for v in result['vulnerabilities'] if v['severity'] == 'medium'),
        'low': sum(1 for v in result['vulnerabilities'] if v['severity'] == 'low')
    }
    return jsonify(summary)

@app.route('/api/scan-repo', methods=['POST'])
def scan_repo():
    """
    Endpoint to scan a Git repository for vulnerabilities.
    Expects a JSON payload with the Git repository URL.
    """
    data = request.get_json()
    if not data or 'git_url' not in data:
        return jsonify({'error': 'Git repository URL is required'}), 400

    git_url = data['git_url']
    language = data.get('language', 'Unknown')  # Optional: Default to 'Unknown'

    try:
        # Clone and scan the repository
        result = clone_and_scan_repo(git_url, language)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)