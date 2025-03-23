import os
import re
import json
import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

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

def analyze_code(file_path, language):
    """
    Analyze code for vulnerabilities based on language
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        code = file.read()
    
    vulnerabilities = []
    
    # Define analyzers for each language
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
    
    # Call the appropriate analyzer for the language
    if language in analyzers:
        vulnerabilities = analyzers[language](code)
    
    return {
        'source_code': code,
        'language': language,
        'vulnerabilities': vulnerabilities
    }

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

if __name__ == '__main__':
    app.run(debug=True)