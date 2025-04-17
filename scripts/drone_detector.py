#!/usr/bin/env python3
from scapy.all import *
import logging
from datetime import datetime

class DroneDetector:
    def __init__(self):
        self.known_drone_macs = {
            'dji': ['60:60:1f', '48:61:6f'],
            'parrot': ['90:3a:e6', '00:12:1c'],
            'skydio': ['58:97:1e'],
            'autel': ['60:60:1f']
        }
        
        self.known_drone_ssids = [
            'DJI-', 'TELLO-', 'Parrot-', 
            'AUTEL', 'SKYDIO', 'UAV'
        ]
        
    def is_drone_packet(self, pkt):
        """Check if packet is likely from a drone"""
        if not pkt.haslayer(Dot11):
            return False
            
        # Check MAC address
        for vendor, prefixes in self.known_drone_macs.items():
            for prefix in prefixes:
                if pkt.addr2 and pkt.addr2.replace(':', '').lower().startswith(prefix.replace(':', '').lower()):
                    return f"Detected {vendor.upper()} drone (MAC match)"
        
        # Check SSID if it's a beacon
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode()
            for drone_ssid in self.known_drone_ssids:
                if drone_ssid in ssid:
                    return f"Detected drone network: {ssid}"
                    
        return False

def start_drone_detection(interface):
    detector = DroneDetector()
    
    def packet_handler(pkt):
        result = detector.is_drone_packet(pkt)
        if result:
            print(f"\n[{datetime.now()}] {result}")
            print(f"Signal Strength: {pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 'Unknown'}")
            print(f"Channel: {pkt.channel if hasattr(pkt, 'channel') else 'Unknown'}")
            print(f"Data Rate: {pkt.rate if hasattr(pkt, 'rate') else 'Unknown'}")
            
    print(f"Starting drone detection on {interface}")
    print("Waiting for drone signals... (Press Ctrl+C to stop)")
    
    sniff(iface=interface, prn=packet_handler, store=0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)
    
    start_drone_detection(sys.argv[1])

