# SSH Connection Testing Tool

A professional Python tool for testing SSH connectivity to authorized systems. This tool helps network administrators and security professionals verify SSH connections, test authentication methods, and diagnose connectivity issues.

## ⚠️ Important Notice

**This tool is designed for testing systems you own or have explicit written permission to test.** Unauthorized access to computer systems is illegal and unethical. Always ensure you have proper authorization before testing any system.

## Features

- **Port Connectivity Testing**: Verify basic TCP connectivity to SSH ports
- **SSH Banner Retrieval**: Get SSH server version and banner information
- **Authentication Method Discovery**: Identify supported authentication methods
- **Password Authentication Testing**: Test username/password combinations
- **Key-based Authentication Testing**: Test SSH key authentication
- **Comprehensive Reporting**: Detailed test results and status reporting
- **Command-line Interface**: Easy-to-use CLI with multiple options
- **Secure Password Handling**: Secure password prompting to avoid command history
- **Verbose Logging**: Optional detailed logging for troubleshooting
- **Timeout Configuration**: Configurable connection timeouts

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Install Dependencies

The script uses standard Python libraries for basic functionality, but requires `paramiko` for advanced SSH testing features:

```bash
# Install paramiko for full SSH functionality
pip install paramiko

# Or install from requirements.txt if provided
pip install -r requirements.txt
```

### Download the Script

Save the script as `ssh_connection_tester.py` and make it executable:

```bash
chmod +x ssh_connection_tester.py
```

## Usage

### Basic Syntax

```bash
python ssh_connection_tester.py -H <hostname> [options]
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-H, --host` | Target hostname or IP address (required) |
| `-p, --port` | SSH port (default: 22) |
| `-u, --username` | Username for authentication testing |
| `-P, --password` | Password for authentication |
| `-k, --key-file` | Private key file path |
| `--key-passphrase` | Passphrase for encrypted private key |
| `-t, --timeout` | Connection timeout in seconds (default: 10) |
| `-v, --verbose` | Enable verbose logging |
| `--prompt-password` | Securely prompt for password |

### Usage Examples

#### Basic Connectivity Test
```bash
# Test basic connectivity to an SSH server
python ssh_connection_tester.py -H 192.168.1.100
```

#### Password Authentication Test
```bash
# Test with username and password (password will be prompted)
python ssh_connection_tester.py -H server.example.com -u admin

# Test with username and password provided
python ssh_connection_tester.py -H 192.168.1.100 -u admin -P mypassword
```

#### Key-based Authentication Test
```bash
# Test with SSH private key
python ssh_connection_tester.py -H server.example.com -u user -k ~/.ssh/id_rsa

# Test with encrypted private key (passphrase will be prompted)
python ssh_connection_tester.py -H 10.0.0.1 -u root --key-file /path/to/encrypted_key
```

#### Advanced Options
```bash
# Custom port with verbose output
python ssh_connection_tester.py -H 192.168.1.100 -p 2222 -u admin -v

# Custom timeout
python ssh_connection_tester.py -H slow-server.com -u user -t 30
```

## Output Interpretation

The tool provides comprehensive test results:

### Status Indicators
- ✅ **SUCCESS**: Full connectivity and authentication successful
- ⚠️ **PARTIAL**: Connected but authentication failed
- 🔗 **CONNECTED**: Basic connectivity successful (no auth tested)
- ❌ **FAILED**: Cannot establish basic connectivity

### Test Results Include
- Port reachability status
- SSH server banner information
- Available authentication methods
- Password authentication results (if tested)
- Key authentication results (if tested)
- Overall connection status

### Example Output
```
============================================================
SSH Connection Test Report for 192.168.1.100:22
============================================================

2024-01-15 10:30:15 - ssh_tester - INFO - Testing TCP connectivity to 192.168.1.100:22
2024-01-15 10:30:15 - ssh_tester - INFO - ✓ Port is reachable
2024-01-15 10:30:15 - ssh_tester - INFO - Testing SSH banner retrieval
2024-01-15 10:30:15 - ssh_tester - INFO - ✓ SSH banner: SSH-2.0-OpenSSH_8.0
2024-01-15 10:30:15 - ssh_tester - INFO - Testing available authentication methods
2024-01-15 10:30:15 - ssh_tester - INFO - ✓ Available auth methods: ['password', 'publickey']
2024-01-15 10:30:15 - ssh_tester - INFO - Testing password authentication for user: admin
2024-01-15 10:30:16 - ssh_tester - INFO - ✓ Password authentication successful

============================================================
TEST SUMMARY
============================================================
Host: 192.168.1.100:22
Port Reachable: ✓
SSH Banner: SSH-2.0-OpenSSH_8.0
Auth Methods: password, publickey
Password Auth: ✓

Overall Status: ✅ SUCCESS
============================================================
```

## Exit Codes

- `0`: Success (connection and/or authentication successful)
- `1`: Failure (connection or authentication failed)
- `130`: Interrupted by user (Ctrl+C)

## Security Considerations

### Best Practices
- **Never test systems without permission**
- Use secure password prompting (avoid `-P` flag in shared environments)
- Store SSH keys securely with appropriate file permissions
- Review logs for any suspicious activity
- Use strong authentication methods

### Limitations
- Tool does not implement rate limiting (be mindful of login attempt policies)
- Does not support all SSH authentication methods (e.g., GSSAPI, keyboard-interactive)
- Basic host key verification (accepts all host keys)

## Troubleshooting

### Common Issues

#### "paramiko not available" Warning
```bash
# Install paramiko
pip install paramiko
```

#### Connection Timeout
- Increase timeout with `-t` option
- Check network connectivity
- Verify target host is running SSH service

#### Authentication Failures
- Verify username and password/key are correct
- Check if account is locked or disabled
- Verify key file permissions (should be 600)

#### Permission Denied
- Ensure SSH key file has correct permissions: `chmod 600 ~/.ssh/id_rsa`
- Verify username exists on target system
- Check SSH server configuration

### Debug Mode
Use `-v` flag for verbose output to help diagnose connection issues.

## Dependencies

### Required
- Python 3.6+
- Standard library modules: `argparse`, `socket`, `sys`, `time`, `logging`, `pathlib`, `typing`, `getpass`

### Optional (for full functionality)
- `paramiko`: SSH client library for Python
  ```bash
  pip install paramiko
  ```

## License

This project is licensed under the MIT License:

```
MIT License

Copyright (c) 2024 SSH Connection Tester

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Contributing

Contributions are welcome! Please ensure any contributions:
- Follow the existing code style
- Include appropriate tests
- Update documentation as needed
- Respect the ethical use guidelines

## Disclaimer

This tool is intended for legitimate network administration and security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

---

**Remember**: Always obtain explicit written permission before testing systems you do not own.
