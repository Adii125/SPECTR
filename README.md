# SPECTR - Web Vulnerability Scanner

Professional Python CLI-based web vulnerability scanner detecting 7 major security vulnerability types.

```
███████╗██████╗ ███████╗ ██████╗████████╗██████╗ 
██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗
███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝
╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗
███████║██║     ███████╗╚██████╗   ██║   ██║  ██║
╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝
```
### SPECTR - Scanner for Payloads, Endpoints, Configs, Traversals, and Requests

## Features

- **7 Vulnerability Types**: SQLi, XSS, IDOR, Path Traversal, XXE, Command Injection, SSRF
- **Professional Detection**: Error-based, time-based, and response analysis
- **Interactive CLI**: Color-coded output with detailed reporting
- **JSON Reports**: Comprehensive vulnerability reports with recommendations

### 7 Vulnerability Detectors
- **SQL Injection (SQLi)** - Error-based, time-based, boolean-based, and union-based detection
- **Cross-Site Scripting (XSS)** - Reflected, stored, and DOM-based XSS detection
- **Insecure Direct Object Reference (IDOR)** - Numeric, string, and file-based access control bypass
- **Path Traversal** - Directory traversal with encoding bypass techniques
- **Command Injection** - OS command injection with time-based and pattern-based detection
- **XML External Entity (XXE)** - File disclosure and out-of-band XXE detection
- **Server-Side Request Forgery (SSRF)** - Internal network and cloud metadata access


## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Make executable:**
   ```bash
   chmod +x spectr
   ```
3. **Run scanner:**
   ```bash
   ./spectr
   ```


## Example

```bash
🔗 Enter target URL: http://testphp.vulnweb.com/artists.php
📡 HTTP method (GET/POST): GET
📤 Parameters: artist=1
🔍 Verbose mode? (y/n): y
```

## 📜 License
This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## 📞 Support
For questions, issues, or contributions:

GitHub Issues: Report bugs and feature requests.  
Documentation: Comprehensive guides and examples.  
Community: Join discussions and share experiences.   
Remember: Only test applications you own or have explicit permission 
to test.
