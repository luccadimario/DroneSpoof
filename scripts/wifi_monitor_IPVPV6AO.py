#!/usr/bin/env python3
from scapy.all import *
import logging
import os
import sys
from datetime import datetime

# Check if running as root
if os.geteuid() != 0:
    print("This script must be run as root (use sudo)")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Counter for statistics
packet_stats = {
    'total': 0,
    'ipv6_nd': 0,
    'multicast': 0,
    'other': 0
}

def packet_handler(pkt):
    try:
        packet_stats['total'] += 1
        
        # Print timestamp for all packets
        print(f"\n--- New Packet Detected at {datetime.now().strftime('%H:%M:%S.%f')[:-3]} ---")

        # Check for IPv6 packets
        if pkt.haslayer(IPv6):
            packet_stats['ipv6_nd'] += 1
            
            # Router Advertisement
            if pkt.haslayer(ICMPv6ND_RA):
                print("Type: IPv6 Router Advertisement")
                print(f"Source: {pkt[IPv6].src}")
                print(f"Destination: {pkt[IPv6].dst}")
                
            # Neighbor Advertisement
            elif pkt.haslayer(ICMPv6ND_NA):
                print("Type: IPv6 Neighbor Advertisement")
                print(f"Source: {pkt[IPv6].src}")
                print(f"Destination: {pkt[IPv6].dst}")
                
            # Multicast Listener Report
            elif pkt.haslayer(ICMPv6MLReport):
                print("Type: IPv6 Multicast Listener Report")
                print(f"Source: {pkt[IPv6].src}")
                print(f"Destination: {pkt[IPv6].dst}")
                packet_stats['multicast'] += 1
            
            else:
                print("Type: Other IPv6 Packet")
                print(f"Source: {pkt[IPv6].src}")
                print(f"Destination: {pkt[IPv6].dst}")
                packet_stats['other'] += 1

        # Show packet summary
        print(f"Raw Packet Summary: {pkt.summary()}")
        
        # Print statistics every 10 packets
        if packet_stats['total'] % 10 == 0:
            print("\n=== Packet Statistics ===")
            print(f"Total Packets: {packet_stats['total']}")
            print(f"IPv6 ND Packets: {packet_stats['ipv6_nd']}")
            print(f"Multicast Packets: {packet_stats['multicast']}")
            print(f"Other Packets: {packet_stats['other']}")
            print("=" * 23 + "\n")

    except Exception as e:
        logging.error(f"Error processing packet: {e}")
        logging.error(f"Packet that caused error: {pkt.summary()}")

def start_monitoring(interface="wlan0"):
    print(f"Starting network monitoring on {interface}")
    print("\nCurrent interface capabilities:")
    os.system(f"iwconfig {interface}")
    
    print("\nWaiting for packets... (Press Ctrl+C to stop)")
    print("Monitoring IPv6 and network discovery packets")
    
    try:
        # Sniff all packets, not just WiFi
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        # Print final statistics
        print("\n=== Final Statistics ===")
        print(f"Total Packets: {packet_stats['total']}")
        print(f"IPv6 ND Packets: {packet_stats['ipv6_nd']}")
        print(f"Multicast Packets: {packet_stats['multicast']}")
        print(f"Other Packets: {packet_stats['other']}")
    except Exception as e:
        print(f"Error starting packet capture: {e}")
        print("\nDebug information:")
        print(f"Interface: {interface}")
        os.system(f"ifconfig {interface}")

if __name__ == "__main__":
    try:
        start_monitoring()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Fatal error: {e}")

