# 🔐 Authentication & Password Testing

<div align="center">

![Security](https://img.shields.io/badge/Security-Testing-red?style=for-the-badge&logo=security&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

**A comprehensive collection of authentication and password security testing tools for ethical hackers, penetration testers, and cybersecurity professionals.**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Tool Categories](#-tool-categories)
- [Usage Examples](#-usage-examples)
- [Security Guidelines](#-security-guidelines)
- [Contributing](#-contributing)
- [Legal Disclaimer](#-legal-disclaimer)
- [Resources](#-resources)

---

## 🎯 Overview

This repository contains a curated collection of scripts and tools designed for testing authentication mechanisms and password security. These tools are intended for authorized security testing, vulnerability assessment, and educational purposes in controlled environments.

### 🎪 What's Inside

Our toolkit covers the complete spectrum of authentication testing:

- **Brute Force Attacks** - Dictionary and hybrid attacks against various services
- **Password Analysis** - Strength evaluation and pattern detection
- **Hash Cracking** - Multi-format hash identification and cracking
- **Protocol Testing** - Authentication bypass techniques
- **Token Analysis** - JWT, session token, and API key testing
- **Multi-Factor Authentication** - MFA bypass and weakness detection

---

## ✨ Features

### 🚀 **High-Performance Tools**
- Multi-threaded execution for faster testing
- Optimized algorithms for maximum efficiency
- Resource-aware processing to prevent system overload

### 🎨 **User-Friendly Interface**
- Interactive CLI with progress indicators
- Detailed logging and reporting capabilities
- Customizable output formats (JSON, CSV, HTML)

### 🔧 **Extensive Protocol Support**
- SSH, FTP, HTTP/HTTPS, SMB, RDP
- Database connections (MySQL, PostgreSQL, MSSQL)
- Web application authentication
- API endpoint testing

### 📊 **Advanced Analytics**
- Password pattern analysis
- Success rate statistics
- Time-based attack metrics
- Vulnerability severity scoring

---

## 🛠 Installation

### Prerequisites

```bash
# Python 3.8 or higher
python --version

# pip package manager
pip --version
```

### Quick Start

```bash
# Clone the repository
git clone https://github.com/LilMortal/HackingScriptsCollection.git

# Navigate to Authentication & Password Testing
cd "HackingScriptsCollection/Authentication & Password Testing"

# Install dependencies
pip install -r requirements.txt

# Run setup script
python setup.py
```

### Dependencies

```bash
# Core libraries
pip install requests beautifulsoup4 paramiko
pip install hashlib bcrypt passlib
pip install threading multiprocessing
pip install colorama rich tabulate
```

---

## 🗂 Tool Categories

### 🔨 **Brute Force & Dictionary Attacks**

| Tool | Description | Protocols | Features |
|------|-------------|-----------|----------|
| `ssh_bruteforce.py` | SSH credential testing | SSH | Multi-threading, custom wordlists |
| `ftp_cracker.py` | FTP authentication bypass | FTP/FTPS | Anonymous detection, banner grabbing |
| `web_login_bruteforce.py` | Web form authentication | HTTP/HTTPS | CSRF handling, session management |
| `hydra_wrapper.py` | Hydra automation script | Multi-protocol | 50+ protocols, result parsing |

### 🧬 **Password Analysis & Generation**

| Tool | Description | Input | Output |
|------|-------------|-------|--------|
| `password_analyzer.py` | Strength and pattern analysis | Text/Hash | Detailed report |
| `wordlist_generator.py` | Custom wordlist creation | Rules/Patterns | Dictionary files |
| `hash_identifier.py` | Hash type detection | Hash strings | Algorithm identification |
| `password_policy_checker.py` | Policy compliance testing | Passwords | Compliance report |

### 🔐 **Hash Cracking & Recovery**

| Tool | Algorithm Support | Speed | Features |
|------|------------------|-------|----------|
| `hash_cracker.py` | MD5, SHA1, SHA256, bcrypt | High | GPU acceleration support |
| `rainbow_table.py` | Common algorithms | Ultra-fast | Pre-computed tables |
| `john_wrapper.py` | John the Ripper integration | Variable | Rule-based attacks |
| `hashcat_manager.py` | Hashcat automation | Maximum | Mask and hybrid attacks |

### 🌐 **Protocol-Specific Testing**

```
📁 protocols/
├── 🔒 ssh_testing/
│   ├── key_authentication.py
│   ├── banner_grabbing.py
│   └── vulnerability_scanner.py
├── 🌍 http_testing/
│   ├── basic_auth_bypass.py
│   ├── jwt_analyzer.py
│   └── session_hijacking.py
├── 📊 database_testing/
│   ├── sql_injection_auth.py
│   ├── default_credentials.py
│   └── privilege_escalation.py
└── 🔐 smb_testing/
    ├── null_session.py
    ├── ntlm_relay.py
    └── share_enumeration.py
```

---

## 💡 Usage Examples

### Basic Brute Force Attack

```bash
# SSH brute force with custom wordlist
python ssh_bruteforce.py -t 192.168.1.100 -u admin -w passwords.txt -T 10

# Web login testing
python web_login_bruteforce.py -u http://target.com/login -U users.txt -P passwords.txt
```

### Password Analysis

```bash
# Analyze password strength
python password_analyzer.py -f password_dump.txt -o analysis_report.html

# Generate custom wordlist
python wordlist_generator.py -b company_name -r rules.txt -o custom_wordlist.txt
```

### Hash Cracking

```bash
# Crack MD5 hashes
python hash_cracker.py -f hashes.txt -t md5 -w rockyou.txt -T 8

# Use rainbow tables
python rainbow_table.py -h 5d41402abc4b2a76b9719d911017c592 -t md5
```

### Advanced Protocol Testing

```bash
# JWT token analysis
python jwt_analyzer.py -t "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Database authentication testing
python db_auth_test.py -h mysql://target:3306 -U users.txt -P passwords.txt
```

---

## ⚠️ Security Guidelines

### 🎯 **Responsible Usage**

```markdown
✅ DO:
- Use only on systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Document all testing activities
- Respect rate limits and system resources
- Use in isolated lab environments for learning

❌ DON'T:
- Test against systems without authorization
- Use for malicious purposes
- Ignore system load and stability
- Forget to clean up test artifacts
- Share credentials or sensitive data
```

### 🛡️ **Best Practices**

1. **Authorization First** - Always obtain written permission before testing
2. **Scope Definition** - Clearly define what systems and techniques are authorized
3. **Documentation** - Keep detailed logs of all testing activities
4. **Cleanup** - Remove any test accounts or files created during testing
5. **Reporting** - Provide clear, actionable security recommendations

### 🔒 **Safe Testing Environment**

```bash
# Create isolated test environment
docker run -it --name security-lab ubuntu:latest

# Use VPN or isolated network
sudo openvpn lab-config.ovpn

# Monitor system resources
htop # Keep an eye on CPU/memory usage
```

---

## 🤝 Contributing

We welcome contributions from the cybersecurity community! Here's how you can help improve this toolkit:

### 🎨 **How to Contribute**

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingTool`)
3. **Commit** your changes (`git commit -m 'Add AmazingTool for protocol X'`)
4. **Push** to the branch (`git push origin feature/AmazingTool`)
5. **Open** a Pull Request

### 📝 **Contribution Guidelines**

- **Code Quality**: Follow PEP 8 standards for Python code
- **Documentation**: Include comprehensive docstrings and comments
- **Testing**: Provide test cases and usage examples
- **Security**: Ensure all tools follow ethical hacking principles
- **Performance**: Optimize for speed and resource efficiency

### 👨‍💻 **Project Author**

**LilMortal** - Creator and sole maintainer of this comprehensive authentication testing toolkit.

---

## ⚖️ Legal Disclaimer

```
🚨 IMPORTANT LEGAL NOTICE 🚨

This software is provided for EDUCATIONAL and AUTHORIZED TESTING purposes only.

The tools in this repository are designed for:
✅ Authorized penetration testing
✅ Security research in controlled environments
✅ Educational purposes and learning
✅ Vulnerability assessment with proper authorization

UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS ILLEGAL.

Users are solely responsible for complying with all applicable laws
and regulations. The authors and contributors assume no liability
for misuse of these tools.

Always obtain explicit written permission before testing any system
that you do not own.
```

---

## 📚 Resources

### 📖 **Learning Materials**

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Penetration Testing](https://www.sans.org/cyber-aces/)
- [Ethical Hacking Courses](https://www.cybrary.it/)

### 🛠️ **Related Tools**

- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - Network logon cracker
- [John the Ripper](https://www.openwall.com/john/) - Password cracker
- [Hashcat](https://hashcat.net/hashcat/) - Advanced password recovery
- [Burp Suite](https://portswigger.net/burp) - Web application testing

### 📊 **Wordlists & Dictionaries**

- [SecLists](https://github.com/danielmiessler/SecLists) - Security testing lists
- [RockYou](https://github.com/brannondorsey/naive-hashcat/releases) - Common passwords
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) - Attack patterns
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Useful payloads

---

<div align="center">

## 🌟 **Star History**

If you find this project useful, please consider giving it a star! ⭐

[![Star History Chart](https://api.star-history.com/svg?repos=LilMortal/HackingScriptsCollection&type=Date)](https://star-history.com/#LilMortal/HackingScriptsCollection&Date)

---

**Made with ❤️ by LilMortal**

*Single-handedly crafted for the cybersecurity community*

[🏠 Home](../../README.md) | [📧 Contact](https://github.com/LilMortal) | [🐛 Issues](https://github.com/LilMortal/HackingScriptsCollection/issues) | [💬 Discussions](https://github.com/LilMortal/HackingScriptsCollection/discussions)

</div>
