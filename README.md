# HackingScriptsCollection

## Overview

Welcome to `HackingScriptsCollection`! This repository is a curated and growing collection of various scripts primarily designed for cybersecurity enthusiasts, penetration testers, security researchers, and anyone keen on exploring the practical facets of security vulnerabilities and defense. It serves as a centralized hub for useful scripts that can aid in ethical hacking, system analysis, network security assessments, and general cybersecurity tasks.

---

## Why I Created This Project

I embarked on creating `HackingScriptsCollection` for several key reasons, driven by my own journey and observations in the cybersecurity landscape:

* **A Personal Learning Journey:** Cybersecurity is a vast and ever-evolving field. As I continue to learn and experiment with different techniques and tools, I often find myself writing small scripts to automate tasks, test concepts, or solve specific challenges. This repository serves as a personal knowledge base and a historical record of my practical understanding.
* **Centralizing Scattered Scripts:** Like many in the security community, I've accumulated numerous useful scripts from various sources – online tutorials, personal projects, and community contributions. They were often scattered across different folders, making them hard to find and manage. This project aims to bring them all into one organized, easily accessible location.
* **Bridging the Gap Between Theory and Practice:** While there's an abundance of theoretical knowledge available, hands-on application is crucial for true understanding. These scripts are practical examples that demonstrate how certain vulnerabilities are exploited or how security measures can be tested, helping to solidify theoretical concepts.
* **Sharing and Collaboration:** I believe in the power of community and open-source contributions. By making this collection public, I hope to not only share what I've learned but also to foster collaboration. Others can benefit from these scripts, and their contributions can, in turn, enhance the collection, making it more robust and diverse.
* **Promoting Ethical Hacking:** My primary motivation is to promote responsible and ethical use of these tools. Understanding how attacks work is the first step in building stronger defenses. This repository is intended strictly for legal and authorized activities, emphasizing the importance of permission and ethical conduct in all security assessments.

This project is a continuous work in progress, reflecting my ongoing learning and the dynamic nature of cybersecurity. I invite you to explore, learn, and contribute!

---

## Features

This collection aims to include a diverse set of scripts covering various domains of cybersecurity, such as:

* **Network Scanning & Enumeration**: Scripts to discover hosts, open ports, and services on a network.
* **Vulnerability Assessment**: Tools to identify potential weaknesses in systems and applications.
* **Payload Generation & Encoding**: Utilities for creating and manipulating malicious payloads.
* **Exploitation Helpers**: Scripts to assist in the exploitation phase, often requiring specific target knowledge.
* **Post-Exploitation**: Scripts for maintaining access, escalating privileges, and data exfiltration.
* **Forensics & Analysis**: Tools for analyzing system data, logs, or network traffic.
* **Automation**: Scripts to automate repetitive security tasks.
* **Web Application Security**: Specific scripts targeting common web vulnerabilities (e.g., SQL Injection, XSS).

---

## Repository Structure

The repository is organized into directories, with each directory typically containing scripts related to a specific category or purpose. While the exact subdirectories are not visible from the root URL, a typical structure might look like:

HackingScriptsCollection/
├── reconnaissance/
│   ├── network_scanners/
│   │   ├── port_scanner.py         # Identifies open ports on target hosts.
│   │   ├── ip_sweeper.sh           # Discovers active hosts in an IP range.
│   │   └── subnet_mapper.py        # Maps network topology.
│   ├── enumeration/
│   │   ├── dns_enum.py             # Gathers DNS records and subdomains.
│   │   ├── smb_enum.sh             # Enumerates SMB shares and users.
│   │   └── user_enum.py            # Attempts to enumerate valid usernames.
│   └── osint/
│       ├── email_finder.py         # Scrapes public sources for email addresses.
│       └── social_media_lister.py  # Gathers public social media links.
├── vulnerability_analysis/
│   ├── web_vulnerabilities/
│   │   ├── sql_injector.py         # Detects and exploits SQL injection flaws.
│   │   ├── xss_detector.js         # Scans for Cross-Site Scripting vulnerabilities.
│   │   └── lfi_scanner.py          # Identifies Local File Inclusion vulnerabilities.
│   ├── system_vulnerabilities/
│   │   ├── outdated_software_checker.py # Checks for known vulnerabilities in installed software.
│   │   └── service_version_detector.py  # Identifies versions of running services.
│   └── config_auditors/
│       ├── ssh_config_check.sh     # Audits SSH daemon configurations for security.
│       └── firewall_rule_lister.py # Lists firewall rules for analysis.
├── exploitation/
│   ├── payload_generation/
│   │   ├── reverse_shell_generator.py # Creates various reverse shell payloads.
│   │   ├── base64_encoder.py          # Encodes/decodes data using Base64.
│   │   └── msfvenom_wrapper.sh        # Simplifies Metasploit payload generation.
│   ├── exploit_helpers/
│   │   ├── buffer_overflow_fuzzer.py  # Assists in finding buffer overflow offsets.
│   │   └── exploit_template.py        # Provides a template for developing exploits.
│   └── privilege_escalation/
│       ├── linux_privesc_checker.sh   # Scans Linux systems for common privilege escalation vectors.
│       └── windows_privesc_enum.ps1   # Enumerates Windows privilege escalation opportunities.
├── post_exploitation/
│   ├── persistence/
│   │   ├── backdoor_creator.py     # Creates simple backdoors for continued access.
│   │   └── scheduled_task_creator.ps1 # Establishes persistence via scheduled tasks.
│   ├── data_exfiltration/
│   │   ├── zip_data_exfil.py       # Compresses and exfiltrates files.
│   │   └── dns_tunnel_exfil.py     # Exfiltrates data over DNS.
│   └── lateral_movement/
│       ├── psexec_wrapper.py       # Facilitates execution on remote Windows systems.
│       └── pass_the_hash.py        # Implements pass-the-hash techniques.
├── utilities/
│   ├── hashing_tools/
│   │   ├── hasher.py               # Generates various cryptographic hashes.
│   │   └── hash_cracker.py         # Attempts to crack common hash types (dictionary/brute-force).
│   ├── encoding_decoding/
│   │   ├── url_encoder_decoder.py  # Encodes/decodes URL strings.
│   │   └── hex_converter.py        # Converts between hexadecimal and text.
│   └── miscellaneous/
│       ├── netcat_listener.sh      # Sets up simple Netcat listeners.
│       └── file_type_analyzer.py   # Identifies file types.
└── README.md                       # This file.

🛡️ Cybersecurity Scripts Collection
<div align="center">
Show Image
Show Image
Show Image
Show Image
A comprehensive collection of cybersecurity scripts for educational purposes, penetration testing, and security research
</div>

📋 Table of Contents

Overview
Purpose & Mission
Features
Repository Structure
Getting Started
Script Categories
Usage Examples
Contributing
Legal & Ethical Guidelines
Security Notice
Support
License


🔍 Overview
The Cybersecurity Scripts Collection is a curated repository of security tools and scripts designed specifically for cybersecurity professionals, students, researchers, and ethical hackers. This collection serves as a comprehensive resource for understanding security vulnerabilities, testing defensive measures, and learning practical cybersecurity concepts through hands-on experience.
Key Highlights

🎯 Educational Focus: Scripts designed for learning and understanding security concepts
🔒 Ethical Use: Strict emphasis on authorized and legal security testing
📚 Well-Documented: Each script includes comprehensive documentation and usage examples
🧪 Research-Oriented: Tools for legitimate security research and vulnerability assessment
🤝 Community-Driven: Open to contributions from the cybersecurity community


🎯 Purpose & Mission
Why This Collection Exists
This repository was created to address several critical needs in the cybersecurity education and research community:
🎓 Educational Excellence

Provide practical, hands-on learning tools for cybersecurity concepts
Bridge the gap between theoretical knowledge and real-world application
Offer a structured approach to understanding security vulnerabilities and defenses

🔬 Research & Development

Centralize useful security research tools and methodologies
Enable reproducible security research and testing
Foster innovation in defensive security techniques

🤝 Community Building

Create a collaborative platform for sharing security knowledge
Encourage responsible disclosure and ethical security practices
Build a repository of collectively-maintained security tools

🛡️ Defense Enhancement

Help security professionals understand attack vectors to build better defenses
Provide tools for authorized penetration testing and vulnerability assessment
Support the development of more robust security measures


⚡ Features
Core Capabilities
<table>
<tr>
<td>
🔍 Network Security

Port scanning and enumeration
Network mapping and discovery
Service fingerprinting
Network vulnerability assessment

</td>
<td>
🌐 Web Application Security

SQL injection testing tools
XSS detection and testing
Directory enumeration
Web vulnerability scanners

</td>
</tr>
<tr>
<td>
🔐 Cryptography & Encoding

Hash generation and cracking
Encoding/decoding utilities
Cipher analysis tools
Password security testing

</td>
<td>
📊 Forensics & Analysis

Log analysis tools
Network traffic analysis
System forensics utilities
Evidence collection scripts

</td>
</tr>
</table>
Advanced Features

🤖 Automation Tools: Scripts for automating repetitive security tasks
📈 Reporting: Automated report generation for security assessments
🔧 Utility Scripts: Helper tools for various security operations
📋 Checklists: Security assessment methodologies and checklists

🚀 Getting Started
Prerequisites
Ensure you have the following installed on your system:
Required Software
bash# Python 3.8 or higher
python3 --version

# Git for repository management
git --version

# Basic networking tools (usually pre-installed on security distributions)
nmap --version
curl --version
Recommended Distributions

Kali Linux - Complete penetration testing platform
Parrot Security OS - Security-focused distribution
BlackArch Linux - Penetration testing and security research
Ubuntu/Debian - With security tools manually installed

Installation
Quick Setup
bash# Clone the repository
git clone https://github.com/LilMortal/HackingScriptsCollection.git

# Navigate to the project directory
cd HackingScriptsCollection

# Install Python dependencies
pip3 install -r requirements.txt

# Make shell scripts executable
find . -name "*.sh" -exec chmod +x {} \;
Virtual Environment Setup (Recommended)
bash# Create virtual environment
python3 -m venv cybersec_env

# Activate virtual environment
source cybersec_env/bin/activate  # Linux/Mac
# or
cybersec_env\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
Verification
bash# Test installation with a simple utility
python3 utilities/system_info.py --help

🔧 Script Categories
🌐 Network Security Tools
Port Scanning & Enumeration

Advanced Port Scanner: Multi-threaded port scanning with service detection
Network Discovery: Automated network mapping and host discovery
Service Fingerprinting: Detailed service version detection and analysis

Network Analysis

Traffic Analyzer: Real-time network traffic monitoring and analysis
Vulnerability Scanner: Automated network vulnerability assessment
Protocol Analyzer: Deep packet inspection and protocol analysis

🌍 Web Application Security
Vulnerability Testing

SQL Injection Tester: Comprehensive SQL injection detection and testing
XSS Scanner: Cross-site scripting vulnerability detection
Directory Bruteforcer: Web directory and file enumeration

Web Analysis Tools

Cookie Analyzer: HTTP cookie security assessment
Header Scanner: Security header analysis and recommendations
Form Analyzer: Web form security testing utilities

🔐 Cryptography & Security
Hash & Password Tools

Hash Cracker: Multi-algorithm hash cracking utilities
Password Generator: Secure password generation with custom rules
Cipher Tools: Classical and modern cipher analysis

Encoding & Obfuscation

Base64 Utilities: Advanced Base64 encoding/decoding tools
URL Encoder/Decoder: Web-safe encoding utilities
Hex Tools: Hexadecimal conversion and analysis utilities


💡 Usage Examples
Network Scanning Example
bash# Basic port scan
python3 network_security/port_scanner.py --target 192.168.1.1 --ports 1-1000

# Comprehensive network discovery
./network_security/network_discovery.sh --subnet 192.168.1.0/24 --output results.txt
Web Security Testing
bash# SQL injection testing
python3 web_security/sql_tester.py --url "http://example.com/login" --param username

# XSS vulnerability scanning
python3 web_security/xss_scanner.py --url "http://example.com" --depth 3
Forensics Analysis
bash# Log file analysis
python3 forensics/log_analyzer.py --file /var/log/auth.log --suspicious-only

# Network traffic analysis
python3 forensics/pcap_analyzer.py --file capture.pcap --protocol HTTP

🤝 Contributing
We welcome contributions from the cybersecurity community! Here's how you can contribute:
Contribution Process

🍴 Fork the Repository
bashgit fork https://github.com/LilMortal/HackingScriptsCollection.git

🌿 Create a Feature Branch
bashgit checkout -b feature/new-security-tool

✨ Develop Your Contribution

Add comprehensive documentation
Include usage examples
Ensure ethical use guidelines are followed
Add appropriate error handling


🧪 Test Thoroughly

Test in controlled environments only
Verify functionality across different systems
Ensure no unintended side effects


📝 Document Changes

Update relevant README files
Add inline code comments
Include usage examples


🚀 Submit Pull Request

Provide clear description of changes
Reference any related issues
Ensure code meets project standards



Contribution Guidelines
Code Standards

Python: Follow PEP 8 style guidelines
Shell Scripts: Use proper error handling and input validation
Documentation: Include comprehensive docstrings and comments
Testing: Provide test cases where applicable

Script Requirements

Clear usage instructions and help text
Proper error handling and user feedback
Input validation and sanitization
Ethical use warnings and disclaimers


⚖️ Legal & Ethical Guidelines
🚨 CRITICAL LEGAL NOTICE
This repository is strictly for educational, research, and authorized security testing purposes only.
✅ Authorized Use Cases

Educational Learning: Understanding cybersecurity concepts and techniques
Authorized Penetration Testing: Testing systems you own or have explicit permission to test
Security Research: Academic or professional research with proper authorization
Defensive Development: Building and testing security defenses
Bug Bounty Programs: Testing within scope of authorized bug bounty programs

❌ Prohibited Activities

Unauthorized Access: Testing systems without explicit permission
Malicious Activities: Using tools for illegal or harmful purposes
Data Theft: Accessing or extracting data without authorization
System Damage: Causing harm to systems or networks
Privacy Violations: Accessing personal or confidential information

Legal Responsibility
Users are solely responsible for ensuring their use of these tools complies with:

Local, state, and federal laws
Organizational policies and guidelines
Terms of service of tested systems
Professional ethical standards

Ethical Guidelines

🎯 Get Explicit Permission: Always obtain written authorization before testing
🛡️ Minimize Impact: Use least intrusive methods necessary
📋 Document Everything: Maintain detailed logs of all activities
🚨 Report Responsibly: Follow responsible disclosure practices
🎓 Focus on Learning: Use tools for educational advancement
🤝 Respect Privacy: Never access unauthorized data or systems


🔒 Security Notice
Repository Security

🔍 Regular Updates: Scripts are regularly reviewed and updated
🛡️ Security Scanning: Repository undergoes regular security scans
📋 Vulnerability Reporting: Security issues are addressed promptly
🎯 Code Review: All contributions undergo thorough security review

Usage Security

🔒 Isolated Testing: Always test in isolated, controlled environments
📱 Virtual Machines: Use VMs for testing to prevent system compromise
🌐 Network Isolation: Test on isolated networks when possible
💾 Data Protection: Never use real credentials or sensitive data in testing

Reporting Security Issues
If you discover a security vulnerability in this repository:

Do NOT create a public issue
Email the maintainers directly with details
Allow reasonable time for response and fixing
Follow responsible disclosure practices


📞 Support
Getting Help

📋 Documentation: Check script-specific README files
💬 Issues: Use GitHub Issues for bug reports and feature requests
📧 Contact: Reach out via GitHub for collaboration opportunities
🤝 Community: Join cybersecurity forums and communities for broader support

Troubleshooting
Common Issues

Permission Errors: Ensure proper file permissions (chmod +x script.sh)
Dependency Issues: Install all requirements (pip install -r requirements.txt)
Network Errors: Verify network connectivity and firewall settings
Python Errors: Ensure Python 3.8+ is installed and properly configured

Best Practices

Always read script documentation before use
Test in non-production environments first
Keep tools and dependencies updated
Follow security best practices for your testing environment


📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
License Summary

✅ Commercial Use: Permitted
✅ Modification: Permitted
✅ Distribution: Permitted
✅ Private Use: Permitted
❗ Liability: Not provided
❗ Warranty: Not provided


<div align="center">
🌟 Star this repository if you find it useful!
Made with ❤️ by the Cybersecurity Community
⬆️ Back to Top
</div>

Last Updated: June 2025
