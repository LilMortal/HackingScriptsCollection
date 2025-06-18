#!/usr/bin/env python3
"""
Basic Intrusion Detection System (IDS)

A simple network and system monitoring tool that detects suspicious activities
and potential security threats through pattern analysis and anomaly detection.

Usage:
    python basic_ids.py --interface eth0 --log-file /var/log/security.log
    python basic_ids.py --monitor-logs --threshold 100
    python basic_ids.py --config config.json --daemon

Author: Security Monitoring Tool
License: MIT
"""

import argparse
import json
import logging
import re
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Third-party imports (install with pip)
try:
    import psutil
except ImportError:
    psutil = None
    print("Warning: psutil not installed. System monitoring features disabled.")

try:
    import scapy.all as scapy
except ImportError:
    scapy = None
    print("Warning: scapy not installed. Network packet capture disabled.")


class SecurityEvent:
    """Represents a security event detected by the IDS."""
    
    def __init__(self, event_type: str, source_ip: str, description: str, 
                 severity: str = "MEDIUM", timestamp: Optional[datetime] = None):
        self.event_type = event_type
        self.source_ip = source_ip
        self.description = description
        self.severity = severity
        self.timestamp = timestamp or datetime.now()
    
    def to_dict(self) -> Dict:
        """Convert event to dictionary format."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'source_ip': self.source_ip,
            'description': self.description,
            'severity': self.severity
        }
    
    def __str__(self) -> str:
        return (f"[{self.timestamp}] {self.severity} - {self.event_type}: "
                f"{self.description} (Source: {self.source_ip})")


class NetworkMonitor:
    """Monitors network traffic for suspicious patterns."""
    
    def __init__(self, interface: str = "eth0", threshold: int = 100):
        self.interface = interface
        self.threshold = threshold
        self.connection_counts = defaultdict(int)
        self.packet_counts = defaultdict(int)
        self.port_scan_detection = defaultdict(set)
        self.ddos_detection = defaultdict(deque)
        self.running = False
        
        # Suspicious ports commonly used by attackers
        self.suspicious_ports = {
            1433, 1521, 3306, 3389, 4444, 5432, 5900, 6379, 
            8080, 8888, 9200, 27017, 50070
        }
        
        # Common attack patterns
        self.attack_patterns = [
            r'union.*select',  # SQL injection
            r'<script.*>',     # XSS
            r'\.\./',          # Directory traversal
            r'cmd\.exe',       # Command injection
            r'/etc/passwd',    # File inclusion
        ]
    
    def start_monitoring(self) -> None:
        """Start network monitoring in a separate thread."""
        if not scapy:
            logging.error("Scapy not available. Cannot start network monitoring.")
            return
        
        self.running = True
        monitor_thread = threading.Thread(target=self._monitor_packets)
        monitor_thread.daemon = True
        monitor_thread.start()
        logging.info(f"Network monitoring started on interface {self.interface}")
    
    def stop_monitoring(self) -> None:
        """Stop network monitoring."""
        self.running = False
        logging.info("Network monitoring stopped")
    
    def _monitor_packets(self) -> None:
        """Monitor network packets for suspicious activity."""
        try:
            scapy.sniff(iface=self.interface, prn=self._analyze_packet, 
                       stop_filter=lambda x: not self.running)
        except Exception as e:
            logging.error(f"Error in packet monitoring: {e}")
    
    def _analyze_packet(self, packet) -> None:
        """Analyze individual network packets."""
        try:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                # Update packet counts
                self.packet_counts[src_ip] += 1
                
                # DDoS detection
                self._detect_ddos(src_ip)
                
                # Port scan detection
                if packet.haslayer(scapy.TCP):
                    dst_port = packet[scapy.TCP].dport
                    self._detect_port_scan(src_ip, dst_port)
                    
                    # Suspicious port access
                    if dst_port in self.suspicious_ports:
                        event = SecurityEvent(
                            "SUSPICIOUS_PORT_ACCESS",
                            src_ip,
                            f"Access to suspicious port {dst_port}",
                            "HIGH"
                        )
                        self._log_event(event)
                
                # Payload analysis for web attacks
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                    self._analyze_payload(src_ip, payload)
                    
        except Exception as e:
            logging.debug(f"Error analyzing packet: {e}")
    
    def _detect_ddos(self, src_ip: str) -> None:
        """Detect potential DDoS attacks based on packet frequency."""
        current_time = time.time()
        
        # Clean old entries (older than 60 seconds)
        while (self.ddos_detection[src_ip] and 
               current_time - self.ddos_detection[src_ip][0] > 60):
            self.ddos_detection[src_ip].popleft()
        
        # Add current timestamp
        self.ddos_detection[src_ip].append(current_time)
        
        # Check if threshold exceeded
        if len(self.ddos_detection[src_ip]) > self.threshold:
            event = SecurityEvent(
                "DDOS_ATTEMPT",
                src_ip,
                f"High packet rate detected: {len(self.ddos_detection[src_ip])} packets/min",
                "CRITICAL"
            )
            self._log_event(event)
            # Clear to avoid spam
            self.ddos_detection[src_ip].clear()
    
    def _detect_port_scan(self, src_ip: str, dst_port: int) -> None:
        """Detect port scanning attempts."""
        self.port_scan_detection[src_ip].add(dst_port)
        
        # If more than 10 different ports accessed, consider it a scan
        if len(self.port_scan_detection[src_ip]) > 10:
            event = SecurityEvent(
                "PORT_SCAN",
                src_ip,
                f"Port scan detected: {len(self.port_scan_detection[src_ip])} ports accessed",
                "HIGH"
            )
            self._log_event(event)
            # Reset to avoid spam
            self.port_scan_detection[src_ip].clear()
    
    def _analyze_payload(self, src_ip: str, payload: str) -> None:
        """Analyze packet payload for attack patterns."""
        payload_lower = payload.lower()
        
        for pattern in self.attack_patterns:
            if re.search(pattern, payload_lower, re.IGNORECASE):
                event = SecurityEvent(
                    "WEB_ATTACK",
                    src_ip,
                    f"Malicious pattern detected: {pattern}",
                    "HIGH"
                )
                self._log_event(event)
                break
    
    def _log_event(self, event: SecurityEvent) -> None:
        """Log security event."""
        logging.warning(f"SECURITY ALERT: {event}")


class LogMonitor:
    """Monitors system logs for suspicious activities."""
    
    def __init__(self, log_files: List[str]):
        self.log_files = log_files
        self.file_positions = {}
        self.running = False
        
        # Suspicious patterns in logs
        self.suspicious_patterns = [
            (r'failed.*login.*from\s+(\d+\.\d+\.\d+\.\d+)', 'FAILED_LOGIN'),
            (r'invalid.*user.*from\s+(\d+\.\d+\.\d+\.\d+)', 'INVALID_USER'),
            (r'refused.*connect.*from\s+(\d+\.\d+\.\d+\.\d+)', 'CONNECTION_REFUSED'),
            (r'authentication.*failure.*rhost=(\d+\.\d+\.\d+\.\d+)', 'AUTH_FAILURE'),
            (r'sudo.*COMMAND.*', 'SUDO_USAGE'),
            (r'su:.*authentication.*failure', 'SU_FAILURE'),
        ]
        
        # Failed login tracking
        self.failed_logins = defaultdict(list)
    
    def start_monitoring(self) -> None:
        """Start log monitoring in a separate thread."""
        self.running = True
        
        # Initialize file positions
        for log_file in self.log_files:
            if Path(log_file).exists():
                with open(log_file, 'r') as f:
                    f.seek(0, 2)  # Go to end of file
                    self.file_positions[log_file] = f.tell()
        
        monitor_thread = threading.Thread(target=self._monitor_logs)
        monitor_thread.daemon = True
        monitor_thread.start()
        logging.info("Log monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop log monitoring."""
        self.running = False
        logging.info("Log monitoring stopped")
    
    def _monitor_logs(self) -> None:
        """Monitor log files for new entries."""
        while self.running:
            try:
                for log_file in self.log_files:
                    self._check_log_file(log_file)
                time.sleep(1)  # Check every second
            except Exception as e:
                logging.error(f"Error in log monitoring: {e}")
    
    def _check_log_file(self, log_file: str) -> None:
        """Check a specific log file for new entries."""
        try:
            if not Path(log_file).exists():
                return
            
            with open(log_file, 'r') as f:
                # Seek to last known position
                current_pos = self.file_positions.get(log_file, 0)
                f.seek(current_pos)
                
                # Read new lines
                new_lines = f.readlines()
                
                # Update position
                self.file_positions[log_file] = f.tell()
                
                # Analyze new lines
                for line in new_lines:
                    self._analyze_log_line(line.strip())
                    
        except Exception as e:
            logging.debug(f"Error reading log file {log_file}: {e}")
    
    def _analyze_log_line(self, line: str) -> None:
        """Analyze a single log line for suspicious patterns."""
        for pattern, event_type in self.suspicious_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                # Extract IP if available
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                source_ip = ip_match.group() if ip_match else "unknown"
                
                # Special handling for failed logins
                if event_type == 'FAILED_LOGIN':
                    self._track_failed_login(source_ip)
                
                event = SecurityEvent(
                    event_type,
                    source_ip,
                    f"Suspicious log entry: {line[:100]}...",
                    "MEDIUM"
                )
                self._log_event(event)
                break
    
    def _track_failed_login(self, ip: str) -> None:
        """Track failed login attempts for brute force detection."""
        current_time = datetime.now()
        
        # Clean old entries (older than 10 minutes)
        self.failed_logins[ip] = [
            timestamp for timestamp in self.failed_logins[ip]
            if current_time - timestamp < timedelta(minutes=10)
        ]
        
        # Add current attempt
        self.failed_logins[ip].append(current_time)
        
        # Check for brute force (5+ failed attempts in 10 minutes)
        if len(self.failed_logins[ip]) >= 5:
            event = SecurityEvent(
                "BRUTE_FORCE_ATTACK",
                ip,
                f"Brute force attack detected: {len(self.failed_logins[ip])} failed attempts",
                "CRITICAL"
            )
            self._log_event(event)
            # Clear to avoid spam
            self.failed_logins[ip].clear()
    
    def _log_event(self, event: SecurityEvent) -> None:
        """Log security event."""
        logging.warning(f"SECURITY ALERT: {event}")


class SystemMonitor:
    """Monitors system resources and processes for anomalies."""
    
    def __init__(self, cpu_threshold: float = 90.0, memory_threshold: float = 90.0):
        self.cpu_threshold = cpu_threshold
        self.memory_threshold = memory_threshold
        self.running = False
        self.baseline_processes = set()
        self.suspicious_processes = [
            'nc', 'netcat', 'ncat', 'socat', 'telnet', 'wget', 'curl',
            'python', 'perl', 'ruby', 'bash', 'sh', 'cmd', 'powershell'
        ]
    
    def start_monitoring(self) -> None:
        """Start system monitoring."""
        if not psutil:
            logging.error("psutil not available. Cannot start system monitoring.")
            return
        
        self.running = True
        # Get baseline processes
        self._update_baseline()
        
        monitor_thread = threading.Thread(target=self._monitor_system)
        monitor_thread.daemon = True
        monitor_thread.start()
        logging.info("System monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop system monitoring."""
        self.running = False
        logging.info("System monitoring stopped")
    
    def _monitor_system(self) -> None:
        """Monitor system resources and processes."""
        while self.running:
            try:
                self._check_resource_usage()
                self._check_new_processes()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logging.error(f"Error in system monitoring: {e}")
    
    def _update_baseline(self) -> None:
        """Update baseline of running processes."""
        try:
            self.baseline_processes = {proc.name() for proc in psutil.process_iter(['name'])}
        except Exception as e:
            logging.debug(f"Error updating baseline: {e}")
    
    def _check_resource_usage(self) -> None:
        """Check system resource usage."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > self.cpu_threshold:
                event = SecurityEvent(
                    "HIGH_CPU_USAGE",
                    "localhost",
                    f"High CPU usage detected: {cpu_percent}%",
                    "MEDIUM"
                )
                self._log_event(event)
            
            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > self.memory_threshold:
                event = SecurityEvent(
                    "HIGH_MEMORY_USAGE",
                    "localhost",
                    f"High memory usage detected: {memory.percent}%",
                    "MEDIUM"
                )
                self._log_event(event)
                
        except Exception as e:
            logging.debug(f"Error checking resource usage: {e}")
    
    def _check_new_processes(self) -> None:
        """Check for new suspicious processes."""
        try:
            current_processes = {proc.name() for proc in psutil.process_iter(['name'])}
            new_processes = current_processes - self.baseline_processes
            
            for proc_name in new_processes:
                if proc_name.lower() in self.suspicious_processes:
                    event = SecurityEvent(
                        "SUSPICIOUS_PROCESS",
                        "localhost",
                        f"Suspicious process started: {proc_name}",
                        "HIGH"
                    )
                    self._log_event(event)
            
            # Update baseline
            self.baseline_processes = current_processes
            
        except Exception as e:
            logging.debug(f"Error checking processes: {e}")
    
    def _log_event(self, event: SecurityEvent) -> None:
        """Log security event."""
        logging.warning(f"SECURITY ALERT: {event}")


class BasicIDS:
    """Main Intrusion Detection System class."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.monitors = []
        self.running = False
        
        # Setup logging
        self._setup_logging()
        
        # Initialize monitors based on configuration
        if config.get('network_monitoring', True):
            network_monitor = NetworkMonitor(
                interface=config.get('interface', 'eth0'),
                threshold=config.get('threshold', 100)
            )
            self.monitors.append(network_monitor)
        
        if config.get('log_monitoring', True):
            log_files = config.get('log_files', ['/var/log/auth.log', '/var/log/syslog'])
            log_monitor = LogMonitor(log_files)
            self.monitors.append(log_monitor)
        
        if config.get('system_monitoring', True):
            system_monitor = SystemMonitor(
                cpu_threshold=config.get('cpu_threshold', 90.0),
                memory_threshold=config.get('memory_threshold', 90.0)
            )
            self.monitors.append(system_monitor)
    
    def _setup_logging(self) -> None:
        """Setup logging configuration."""
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper())
        log_file = self.config.get('log_file', 'ids.log')
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def start(self) -> None:
        """Start the IDS."""
        logging.info("Starting Basic Intrusion Detection System")
        self.running = True
        
        # Start all monitors
        for monitor in self.monitors:
            monitor.start_monitoring()
        
        try:
            # Keep the main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Shutdown requested by user")
            self.stop()
    
    def stop(self) -> None:
        """Stop the IDS."""
        logging.info("Stopping Basic Intrusion Detection System")
        self.running = False
        
        # Stop all monitors
        for monitor in self.monitors:
            monitor.stop_monitoring()


def load_config(config_file: str) -> Dict:
    """Load configuration from JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"Config file {config_file} not found. Using defaults.")
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing config file: {e}")
        sys.exit(1)


def create_default_config(filename: str) -> None:
    """Create a default configuration file."""
    default_config = {
        "network_monitoring": True,
        "log_monitoring": True,
        "system_monitoring": True,
        "interface": "eth0",
        "threshold": 100,
        "log_files": [
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/secure"
        ],
        "cpu_threshold": 90.0,
        "memory_threshold": 90.0,
        "log_level": "INFO",
        "log_file": "ids.log"
    }
    
    with open(filename, 'w') as f:
        json.dump(default_config, f, indent=4)
    
    print(f"Default configuration created: {filename}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Basic Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Start with default settings
    python basic_ids.py
    
    # Use specific network interface
    python basic_ids.py --interface wlan0
    
    # Monitor specific log files
    python basic_ids.py --log-files /var/log/auth.log /var/log/apache2/access.log
    
    # Use configuration file
    python basic_ids.py --config ids_config.json
    
    # Create default configuration file
    python basic_ids.py --create-config my_config.json
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Configuration file path (JSON format)'
    )
    
    parser.add_argument(
        '--interface', '-i',
        default='eth0',
        help='Network interface to monitor (default: eth0)'
    )
    
    parser.add_argument(
        '--log-files', '-l',
        nargs='+',
        default=['/var/log/auth.log', '/var/log/syslog'],
        help='Log files to monitor'
    )
    
    parser.add_argument(
        '--threshold', '-t',
        type=int,
        default=100,
        help='Packet threshold for DDoS detection (default: 100)'
    )
    
    parser.add_argument(
        '--cpu-threshold',
        type=float,
        default=90.0,
        help='CPU usage threshold percentage (default: 90.0)'
    )
    
    parser.add_argument(
        '--memory-threshold',
        type=float,
        default=90.0,
        help='Memory usage threshold percentage (default: 90.0)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--log-file',
        default='ids.log',
        help='Log file path (default: ids.log)'
    )
    
    parser.add_argument(
        '--create-config',
        help='Create default configuration file and exit'
    )
    
    parser.add_argument(
        '--no-network',
        action='store_true',
        help='Disable network monitoring'
    )
    
    parser.add_argument(
        '--no-logs',
        action='store_true',
        help='Disable log monitoring'
    )
    
    parser.add_argument(
        '--no-system',
        action='store_true',
        help='Disable system monitoring'
    )
    
    args = parser.parse_args()
    
    # Create config file if requested
    if args.create_config:
        create_default_config(args.create_config)
        return
    
    # Load configuration
    if args.config:
        config = load_config(args.config)
    else:
        config = {}
    
    # Override config with command line arguments
    config.update({
        'interface': args.interface,
        'log_files': args.log_files,
        'threshold': args.threshold,
        'cpu_threshold': args.cpu_threshold,
        'memory_threshold': args.memory_threshold,
        'log_level': args.log_level,
        'log_file': args.log_file,
        'network_monitoring': not args.no_network,
        'log_monitoring': not args.no_logs,
        'system_monitoring': not args.no_system
    })
    
    # Check if running as root for network monitoring
    if config.get('network_monitoring') and scapy:
        try:
            import os
            if os.geteuid() != 0:
                print("Warning: Network monitoring requires root privileges")
                print("Run with sudo for full functionality")
        except AttributeError:
            pass  # Windows doesn't have geteuid
    
    # Start IDS
    ids = BasicIDS(config)
    ids.start()


if __name__ == "__main__":
    main()
