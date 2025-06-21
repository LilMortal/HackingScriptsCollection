#!/usr/bin/env python3
"""
Network Protocol Analysis Tool

A comprehensive network packet analyzer that captures and analyzes network traffic
to provide insights into protocol usage, traffic patterns, and network behavior.

Author: Claude AI
License: MIT
Version: 1.0.0

Usage Example:
    python network_protocol_analyzer.py -i eth0 -c 100 --output analysis.json
    python network_protocol_analyzer.py --interface wlan0 --count 50 --filter "tcp port 80"
"""

import argparse
import json
import sys
import time
import socket
import struct
from collections import defaultdict, Counter
from datetime import datetime
import logging

# Try to import scapy for packet capture
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

# Try to import matplotlib for visualization
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class NetworkProtocolAnalyzer:
    """
    Main class for network protocol analysis.
    Captures packets and provides detailed analysis of network traffic.
    """
    
    def __init__(self, interface=None, packet_count=100, packet_filter=None):
        """
        Initialize the network analyzer.
        
        Args:
            interface (str): Network interface to capture from
            packet_count (int): Number of packets to capture
            packet_filter (str): BPF filter string for packet filtering
        """
        self.interface = interface
        self.packet_count = packet_count
        self.packet_filter = packet_filter
        self.packets = []
        self.analysis_results = defaultdict(int)
        self.protocol_stats = Counter()
        self.ip_stats = Counter()
        self.port_stats = Counter()
        self.packet_sizes = []
        self.timestamps = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_interface(self, interface):
        """
        Validate that the specified network interface exists.
        
        Args:
            interface (str): Network interface name
            
        Returns:
            bool: True if interface is valid, False otherwise
        """
        try:
            # Try to get interface information
            import netifaces
            interfaces = netifaces.interfaces()
            return interface in interfaces
        except ImportError:
            # If netifaces not available, assume interface is valid
            self.logger.warning("netifaces not available for interface validation")
            return True
    
    def packet_handler(self, packet):
        """
        Handle captured packets and extract relevant information.
        
        Args:
            packet: Scapy packet object
        """
        try:
            # Store packet for later analysis
            self.packets.append(packet)
            
            # Extract timestamp
            self.timestamps.append(time.time())
            
            # Extract packet size
            self.packet_sizes.append(len(packet))
            
            # Analyze Ethernet layer
            if packet.haslayer(Ether):
                self.protocol_stats['Ethernet'] += 1
            
            # Analyze IP layer
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                self.protocol_stats['IPv4'] += 1
                self.ip_stats[ip_layer.src] += 1
                self.ip_stats[ip_layer.dst] += 1
                
                # Analyze transport layer protocols
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    self.protocol_stats['TCP'] += 1
                    self.port_stats[tcp_layer.sport] += 1
                    self.port_stats[tcp_layer.dport] += 1
                    
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    self.protocol_stats['UDP'] += 1
                    self.port_stats[udp_layer.sport] += 1
                    self.port_stats[udp_layer.dport] += 1
                    
                elif packet.haslayer(ICMP):
                    self.protocol_stats['ICMP'] += 1
            
            # Analyze ARP packets
            if packet.haslayer(ARP):
                self.protocol_stats['ARP'] += 1
            
            # Print progress
            if len(self.packets) % 10 == 0:
                print(f"Captured {len(self.packets)} packets...", end='\r')
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def capture_packets(self):
        """
        Capture network packets using scapy.
        
        Returns:
            bool: True if capture was successful, False otherwise
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy is required for packet capture")
            return False
        
        try:
            self.logger.info(f"Starting packet capture on interface: {self.interface}")
            self.logger.info(f"Capturing {self.packet_count} packets...")
            
            if self.packet_filter:
                self.logger.info(f"Using filter: {self.packet_filter}")
            
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=self.packet_count,
                filter=self.packet_filter,
                timeout=60  # Timeout after 60 seconds
            )
            
            print(f"\nCapture complete! Analyzed {len(self.packets)} packets")
            return True
            
        except PermissionError:
            self.logger.error("Permission denied. Run as administrator/root for packet capture")
            return False
        except Exception as e:
            self.logger.error(f"Error during packet capture: {e}")
            return False
    
    def analyze_traffic_patterns(self):
        """
        Analyze captured packets for traffic patterns and statistics.
        
        Returns:
            dict: Analysis results
        """
        if not self.packets:
            self.logger.warning("No packets to analyze")
            return {}
        
        self.logger.info("Analyzing traffic patterns...")
        
        # Calculate basic statistics
        total_packets = len(self.packets)
        total_bytes = sum(self.packet_sizes)
        avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
        
        # Calculate time span and packet rate
        if len(self.timestamps) > 1:
            time_span = self.timestamps[-1] - self.timestamps[0]
            packet_rate = total_packets / time_span if time_span > 0 else 0
        else:
            time_span = 0
            packet_rate = 0
        
        # Get top IP addresses
        top_ips = dict(self.ip_stats.most_common(10))
        
        # Get top ports
        top_ports = dict(self.port_stats.most_common(10))
        
        # Calculate protocol distribution
        protocol_percentages = {}
        for protocol, count in self.protocol_stats.items():
            protocol_percentages[protocol] = (count / total_packets) * 100
        
        # Compile analysis results
        analysis = {
            'capture_info': {
                'interface': self.interface,
                'filter': self.packet_filter,
                'capture_time': datetime.now().isoformat(),
                'duration_seconds': time_span
            },
            'basic_stats': {
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'average_packet_size': round(avg_packet_size, 2),
                'packets_per_second': round(packet_rate, 2)
            },
            'protocol_distribution': dict(self.protocol_stats),
            'protocol_percentages': {k: round(v, 2) for k, v in protocol_percentages.items()},
            'top_source_destinations': top_ips,
            'top_ports': top_ports,
            'packet_size_stats': {
                'min': min(self.packet_sizes) if self.packet_sizes else 0,
                'max': max(self.packet_sizes) if self.packet_sizes else 0,
                'average': round(avg_packet_size, 2)
            }
        }
        
        return analysis
    
    def generate_report(self, analysis_results):
        """
        Generate a human-readable analysis report.
        
        Args:
            analysis_results (dict): Analysis results from analyze_traffic_patterns
        """
        print("\n" + "="*80)
        print("NETWORK PROTOCOL ANALYSIS REPORT")
        print("="*80)
        
        # Capture Information
        print(f"\nCapture Information:")
        print(f"  Interface: {analysis_results['capture_info']['interface']}")
        print(f"  Filter: {analysis_results['capture_info']['filter'] or 'None'}")
        print(f"  Capture Time: {analysis_results['capture_info']['capture_time']}")
        print(f"  Duration: {analysis_results['capture_info']['duration_seconds']:.2f} seconds")
        
        # Basic Statistics
        stats = analysis_results['basic_stats']
        print(f"\nBasic Statistics:")
        print(f"  Total Packets: {stats['total_packets']:,}")
        print(f"  Total Bytes: {stats['total_bytes']:,}")
        print(f"  Average Packet Size: {stats['average_packet_size']} bytes")
        print(f"  Packets per Second: {stats['packets_per_second']}")
        
        # Protocol Distribution
        print(f"\nProtocol Distribution:")
        for protocol, percentage in analysis_results['protocol_percentages'].items():
            count = analysis_results['protocol_distribution'][protocol]
            print(f"  {protocol}: {count:,} packets ({percentage}%)")
        
        # Top IP Addresses
        if analysis_results['top_source_destinations']:
            print(f"\nTop IP Addresses:")
            for ip, count in list(analysis_results['top_source_destinations'].items())[:5]:
                print(f"  {ip}: {count} packets")
        
        # Top Ports
        if analysis_results['top_ports']:
            print(f"\nTop Ports:")
            for port, count in list(analysis_results['top_ports'].items())[:5]:
                print(f"  Port {port}: {count} packets")
        
        # Packet Size Statistics
        size_stats = analysis_results['packet_size_stats']
        print(f"\nPacket Size Statistics:")
        print(f"  Minimum: {size_stats['min']} bytes")
        print(f"  Maximum: {size_stats['max']} bytes")
        print(f"  Average: {size_stats['average']} bytes")
    
    def save_results(self, analysis_results, output_file):
        """
        Save analysis results to a JSON file.
        
        Args:
            analysis_results (dict): Analysis results
            output_file (str): Output file path
        """
        try:
            with open(output_file, 'w') as f:
                json.dump(analysis_results, f, indent=2, default=str)
            self.logger.info(f"Results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
    
    def create_visualization(self, analysis_results, output_dir="."):
        """
        Create visualizations of the analysis results.
        
        Args:
            analysis_results (dict): Analysis results
            output_dir (str): Directory to save visualizations
        """
        if not MATPLOTLIB_AVAILABLE:
            self.logger.warning("Matplotlib not available for visualization")
            return
        
        try:
            # Protocol distribution pie chart
            protocols = list(analysis_results['protocol_distribution'].keys())
            counts = list(analysis_results['protocol_distribution'].values())
            
            plt.figure(figsize=(10, 8))
            plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
            plt.title('Protocol Distribution')
            plt.axis('equal')
            plt.savefig(f"{output_dir}/protocol_distribution.png")
            plt.close()
            
            # Packet size histogram
            plt.figure(figsize=(10, 6))
            plt.hist(self.packet_sizes, bins=30, alpha=0.7, edgecolor='black')
            plt.xlabel('Packet Size (bytes)')
            plt.ylabel('Frequency')
            plt.title('Packet Size Distribution')
            plt.grid(True, alpha=0.3)
            plt.savefig(f"{output_dir}/packet_size_distribution.png")
            plt.close()
            
            self.logger.info(f"Visualizations saved to {output_dir}/")
            
        except Exception as e:
            self.logger.error(f"Error creating visualizations: {e}")


def main():
    """
    Main function to handle command-line arguments and run the analyzer.
    """
    parser = argparse.ArgumentParser(
        description="Network Protocol Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_protocol_analyzer.py -i eth0 -c 100
  python network_protocol_analyzer.py --interface wlan0 --count 50 --filter "tcp port 80"
  python network_protocol_analyzer.py -i any -c 200 --output analysis.json --visualize
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        type=str,
        default='any',
        help='Network interface to capture from (default: any)'
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=100,
        help='Number of packets to capture (default: 100)'
    )
    
    parser.add_argument(
        '-f', '--filter',
        type=str,
        help='BPF filter string (e.g., "tcp port 80", "host 192.168.1.1")'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file for analysis results (JSON format)'
    )
    
    parser.add_argument(
        '--visualize',
        action='store_true',
        help='Create visualization charts (requires matplotlib)'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='.',
        help='Directory for output files (default: current directory)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate arguments
    if args.count <= 0:
        print("Error: Packet count must be greater than 0")
        sys.exit(1)
    
    # Check if scapy is available
    if not SCAPY_AVAILABLE:
        print("Error: Scapy is required for packet capture")
        print("Install with: pip install scapy")
        sys.exit(1)
    
    # Create analyzer instance
    analyzer = NetworkProtocolAnalyzer(
        interface=args.interface,
        packet_count=args.count,
        packet_filter=args.filter
    )
    
    try:
        # Capture packets
        success = analyzer.capture_packets()
        if not success:
            sys.exit(1)
        
        # Analyze traffic patterns
        analysis_results = analyzer.analyze_traffic_patterns()
        
        # Generate report
        analyzer.generate_report(analysis_results)
        
        # Save results if requested
        if args.output:
            analyzer.save_results(analysis_results, args.output)
        
        # Create visualizations if requested
        if args.visualize:
            analyzer.create_visualization(analysis_results, args.output_dir)
        
    except KeyboardInterrupt:
        print("\nCapture interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
