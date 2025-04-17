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
    'data': 0,
    'management': 0,
    'control': 0
}

def decode_packet_type(type_num, subtype_num):
    """Decode packet type and subtype into readable format"""
    types = {
        0: "Management",
        1: "Control",
        2: "Data"
    }
    
    subtypes = {
        0: {  # Management subtypes
            0: "Association Request",
            1: "Association Response",
            4: "Probe Request",
            5: "Probe Response",
            8: "Beacon"
        },
        2: {  # Data subtypes
            0: "Data",
            4: "Null (no data)",
            8: "QoS Data"
        }
    }
    
    type_str = types.get(type_num, "Unknown")
    subtype_str = subtypes.get(type_num, {}).get(subtype_num, "Unknown")
    
    return f"{type_str}/{subtype_str}"

def packet_handler(pkt):
    try:
        packet_stats['total'] += 1
        
        if not pkt.haslayer(Dot11):
            return

        # Get basic packet info
        packet_type = pkt.type
        packet_subtype = pkt.subtype
        
        # Update statistics
        if packet_type == 0:
            packet_stats['management'] += 1
        elif packet_type == 1:
            packet_stats['control'] += 1
        elif packet_type == 2:
            packet_stats['data'] += 1

        # Only show interesting packets (modify these conditions as needed)
        should_print = False
        packet_info = []

        if packet_type == 0 and packet_subtype == 8:  # Beacon frames
            ssid = pkt[Dot11Elt].info.decode() if pkt.haslayer(Dot11Elt) else "Unknown"
            packet_info.extend([
                f"Network: {ssid}",
                f"BSSID: {pkt.addr3 if pkt.addr3 else 'Unknown'}"
            ])
            should_print = True

        elif packet_type == 2:  # Data frames
            packet_info.extend([
                f"Source: {pkt.addr2 if pkt.addr2 else 'Unknown'}",
                f"Destination: {pkt.addr1 if pkt.addr1 else 'Unknown'}",
                f"Data Length: {len(pkt) if pkt.haslayer(Raw) else 0} bytes"
            ])
            should_print = True

        if should_print:
            print("\n--- New Packet Detected ---")
            print(f"Time: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
            print(f"Type: {decode_packet_type(packet_type, packet_subtype)}")
            for info in packet_info:
                print(info)
            
            # Print statistics every 50 packets
            if packet_stats['total'] % 50 == 0:
                print("\n=== Packet Statistics ===")
                print(f"Total Packets: {packet_stats['total']}")
                print(f"Data Packets: {packet_stats['data']}")
                print(f"Management Packets: {packet_stats['management']}")
                print(f"Control Packets: {packet_stats['control']}")
                print("=" * 23 + "\n")

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def start_monitoring(interface="wlan0"):
    print(f"Starting WiFi monitoring on {interface}")
    print("\nCurrent interface capabilities:")
    os.system(f"iwconfig {interface}")
    
    print("\nWaiting for packets... (Press Ctrl+C to stop)")
    print("Only showing Beacon frames and Data packets")
    print("(Will show more packet types with external adapter in monitor mode)")
    
    try:
        # Sniff packets and print what we can see
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        # Print final statistics
        print("\n=== Final Statistics ===")
        print(f"Total Packets: {packet_stats['total']}")
        print(f"Data Packets: {packet_stats['data']}")
        print(f"Management Packets: {packet_stats['management']}")
        print(f"Control Packets: {packet_stats['control']}")
    except Exception as e:
        print(f"Error starting packet capture: {e}")

if __name__ == "__main__":
    try:
        start_monitoring()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Fatal error: {e}")

