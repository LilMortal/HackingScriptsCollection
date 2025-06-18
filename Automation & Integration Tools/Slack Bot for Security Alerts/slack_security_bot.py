#!/usr/bin/env python3
"""
Slack Bot for Security Alerts

A Python script that sends security alerts to Slack channels using webhooks.
Supports various alert types including system intrusions, failed logins,
malware detection, and custom security events.

Usage:
    python slack_security_bot.py --webhook-url <url> --alert-type login_failure 
                                 --message "Multiple failed login attempts detected"
    
    python slack_security_bot.py --webhook-url <url> --alert-type intrusion 
                                 --severity critical --source "192.168.1.100"
                                 --message "Unauthorized access attempt detected"

Author: Security Team
License: MIT
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
import os


class SlackSecurityBot:
    """
    A Slack bot for sending security alerts to designated channels.
    
    This bot supports various types of security alerts with different
    severity levels and customizable formatting.
    """
    
    # Color codes for different severity levels
    SEVERITY_COLORS = {
        'low': '#36a64f',      # Green
        'medium': '#ff9500',   # Orange
        'high': '#ff0000',     # Red
        'critical': '#8b0000'  # Dark Red
    }
    
    # Alert type configurations
    ALERT_TYPES = {
        'login_failure': {
            'title': '🔐 Login Failure Alert',
            'emoji': ':warning:',
            'default_severity': 'medium'
        },
        'intrusion': {
            'title': '🚨 Intrusion Detection Alert',
            'emoji': ':rotating_light:',
            'default_severity': 'high'
        },
        'malware': {
            'title': '🦠 Malware Detection Alert',
            'emoji': ':biohazard_sign:',
            'default_severity': 'critical'
        },
        'firewall': {
            'title': '🛡️ Firewall Alert',
            'emoji': ':shield:',
            'default_severity': 'medium'
        },
        'vulnerability': {
            'title': '🔍 Vulnerability Alert',
            'emoji': ':mag:',
            'default_severity': 'high'
        },
        'custom': {
            'title': '⚠️ Security Alert',
            'emoji': ':exclamation:',
            'default_severity': 'medium'
        }
    }
    
    def __init__(self, webhook_url: str, debug: bool = False):
        """
        Initialize the Slack Security Bot.
        
        Args:
            webhook_url (str): Slack webhook URL for sending messages
            debug (bool): Enable debug logging
        """
        self.webhook_url = webhook_url
        self.debug = debug
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging for the bot."""
        log_level = logging.DEBUG if self.debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('slack_security_bot.log', mode='a')
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def validate_webhook_url(self) -> bool:
        """
        Validate the Slack webhook URL format.
        
        Returns:
            bool: True if URL appears valid, False otherwise
        """
        if not self.webhook_url:
            self.logger.error("Webhook URL is required")
            return False
            
        if not self.webhook_url.startswith('https://hooks.slack.com/'):
            self.logger.error("Invalid Slack webhook URL format")
            return False
            
        return True
        
    def create_alert_payload(self, 
                           alert_type: str,
                           message: str,
                           severity: str = 'medium',
                           source: Optional[str] = None,
                           details: Optional[Dict[str, Any]] = None,
                           custom_title: Optional[str] = None) -> Dict[str, Any]:
        """
        Create the Slack message payload for a security alert.
        
        Args:
            alert_type (str): Type of security alert
            message (str): Main alert message
            severity (str): Alert severity level
            source (str, optional): Source of the alert (IP, hostname, etc.)
            details (dict, optional): Additional alert details
            custom_title (str, optional): Custom alert title
            
        Returns:
            dict: Slack message payload
        """
        # Get alert configuration
        alert_config = self.ALERT_TYPES.get(alert_type, self.ALERT_TYPES['custom'])
        
        # Use custom title if provided, otherwise use default
        title = custom_title if custom_title else alert_config['title']
        
        # Create timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Build the attachment fields
        fields = [
            {
                "title": "Severity",
                "value": severity.upper(),
                "short": True
            },
            {
                "title": "Timestamp",
                "value": timestamp,
                "short": True
            }
        ]
        
        # Add source if provided
        if source:
            fields.append({
                "title": "Source",
                "value": source,
                "short": True
            })
            
        # Add additional details if provided
        if details:
            for key, value in details.items():
                fields.append({
                    "title": key.replace('_', ' ').title(),
                    "value": str(value),
                    "short": len(str(value)) < 40
                })
        
        # Create the payload
        payload = {
            "text": f"{alert_config['emoji']} {title}",
            "attachments": [
                {
                    "color": self.SEVERITY_COLORS.get(severity, self.SEVERITY_COLORS['medium']),
                    "title": title,
                    "text": message,
                    "fields": fields,
                    "footer": "Security Alert System",
                    "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                    "ts": int(time.time())
                }
            ]
        }
        
        return payload
        
    def send_alert(self, 
                  alert_type: str,
                  message: str,
                  severity: str = 'medium',
                  source: Optional[str] = None,
                  details: Optional[Dict[str, Any]] = None,
                  custom_title: Optional[str] = None) -> bool:
        """
        Send a security alert to Slack.
        
        Args:
            alert_type (str): Type of security alert
            message (str): Main alert message
            severity (str): Alert severity level
            source (str, optional): Source of the alert
            details (dict, optional): Additional alert details
            custom_title (str, optional): Custom alert title
            
        Returns:
            bool: True if alert sent successfully, False otherwise
        """
        try:
            # Validate inputs
            if not self.validate_inputs(alert_type, message, severity):
                return False
                
            # Create the payload
            payload = self.create_alert_payload(
                alert_type, message, severity, source, details, custom_title
            )
            
            # Convert payload to JSON
            json_payload = json.dumps(payload).encode('utf-8')
            
            # Create the request
            req = urllib.request.Request(
                self.webhook_url,
                data=json_payload,
                headers={'Content-Type': 'application/json'}
            )
            
            # Send the request
            self.logger.info(f"Sending {severity} {alert_type} alert to Slack")
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status == 200:
                    self.logger.info("Alert sent successfully")
                    return True
                else:
                    self.logger.error(f"Failed to send alert. Status: {response.status}")
                    return False
                    
        except urllib.error.URLError as e:
            self.logger.error(f"Network error sending alert: {e}")
            return False
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON encoding error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending alert: {e}")
            return False
            
    def validate_inputs(self, alert_type: str, message: str, severity: str) -> bool:
        """
        Validate input parameters.
        
        Args:
            alert_type (str): Type of security alert
            message (str): Alert message
            severity (str): Alert severity
            
        Returns:
            bool: True if inputs are valid, False otherwise
        """
        # Validate alert type
        if alert_type not in self.ALERT_TYPES:
            self.logger.error(f"Invalid alert type: {alert_type}")
            self.logger.error(f"Valid types: {', '.join(self.ALERT_TYPES.keys())}")
            return False
            
        # Validate message
        if not message or not message.strip():
            self.logger.error("Message cannot be empty")
            return False
            
        # Validate severity
        if severity not in self.SEVERITY_COLORS:
            self.logger.error(f"Invalid severity: {severity}")
            self.logger.error(f"Valid severities: {', '.join(self.SEVERITY_COLORS.keys())}")
            return False
            
        return True
        
    def test_connection(self) -> bool:
        """
        Test the Slack webhook connection with a simple message.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        self.logger.info("Testing Slack webhook connection...")
        return self.send_alert(
            'custom',
            'This is a test message from the Security Alert Bot',
            'low',
            details={'test': 'connection'}
        )


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Send security alerts to Slack via webhook',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --webhook-url https://hooks.slack.com/... --alert-type login_failure \\
           --message "Multiple failed login attempts" --severity high

  %(prog)s --webhook-url https://hooks.slack.com/... --alert-type intrusion \\
           --message "Suspicious activity detected" --source "192.168.1.100" \\
           --severity critical --details '{"user": "admin", "attempts": 5}'

  %(prog)s --test --webhook-url https://hooks.slack.com/...
        """
    )
    
    # Required arguments
    parser.add_argument(
        '--webhook-url',
        required=True,
        help='Slack webhook URL for sending alerts'
    )
    
    # Alert configuration
    parser.add_argument(
        '--alert-type',
        choices=list(SlackSecurityBot.ALERT_TYPES.keys()),
        default='custom',
        help='Type of security alert (default: custom)'
    )
    
    parser.add_argument(
        '--message',
        help='Alert message content'
    )
    
    parser.add_argument(
        '--severity',
        choices=['low', 'medium', 'high', 'critical'],
        default='medium',
        help='Alert severity level (default: medium)'
    )
    
    # Optional alert details
    parser.add_argument(
        '--source',
        help='Source of the alert (IP address, hostname, etc.)'
    )
    
    parser.add_argument(
        '--details',
        help='Additional alert details as JSON string'
    )
    
    parser.add_argument(
        '--custom-title',
        help='Custom title for the alert'
    )
    
    # Utility options
    parser.add_argument(
        '--test',
        action='store_true',
        help='Send a test message to verify webhook connection'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    parser.add_argument(
        '--config-file',
        help='Path to configuration file (JSON format)'
    )
    
    return parser.parse_args()


def load_config_file(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from a JSON file.
    
    Args:
        config_path (str): Path to the configuration file
        
    Returns:
        dict: Configuration dictionary
    """
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"Error: Configuration file not found: {config_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in configuration file: {e}")
        sys.exit(1)


def main():
    """Main function to run the Slack Security Bot."""
    args = parse_arguments()
    
    # Load configuration from file if specified
    if args.config_file:
        config = load_config_file(args.config_file)
        # Override command line args with config file values where applicable
        for key, value in config.items():
            if hasattr(args, key) and getattr(args, key) is None:
                setattr(args, key, value)
    
    # Check for webhook URL in environment if not provided
    if not args.webhook_url:
        args.webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
        
    if not args.webhook_url:
        print("Error: Slack webhook URL is required. Provide via --webhook-url or SLACK_WEBHOOK_URL environment variable.")
        sys.exit(1)
    
    # Initialize the bot
    bot = SlackSecurityBot(args.webhook_url, args.debug)
    
    # Validate webhook URL
    if not bot.validate_webhook_url():
        sys.exit(1)
    
    # Handle test mode
    if args.test:
        success = bot.test_connection()
        sys.exit(0 if success else 1)
    
    # Validate required arguments for alert sending
    if not args.message:
        print("Error: --message is required when not in test mode")
        sys.exit(1)
    
    # Parse additional details if provided
    details = None
    if args.details:
        try:
            details = json.loads(args.details)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in details: {e}")
            sys.exit(1)
    
    # Send the alert
    success = bot.send_alert(
        alert_type=args.alert_type,
        message=args.message,
        severity=args.severity,
        source=args.source,
        details=details,
        custom_title=args.custom_title
    )
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
