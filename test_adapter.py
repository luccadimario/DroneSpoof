#!/usr/bin/env python3
from scapy.all import *
import subprocess
import os
import sys
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='logs/adapter_test.log'
)

class WiFiAdapterTester:
    def __init__(self, interface):
        self.interface = interface
        self.original_mode = None
        
    def check_interface(self):
        """Check if interface exists and get its capabilities"""
        try:
            output = subprocess.check_output(['iwconfig', self.interface]).decode()
            logging.info(f"Interface info:\n{output}")
            return True
        except:
            logging.error(f"Interface {self.interface} not found")
            return False
    
    def check_monitor_mode(self):
        """Test if adapter supports monitor mode"""
        try:
            # Try to set monitor mode
            subprocess.run(['airmon-ng', 'start', self.interface], check=True)
            logging.info("Monitor mode test: PASSED")
            return True
        except:
            logging.error("Monitor mode test: FAILED")
            return False
            
    def test_packet_injection(self):
        """Test packet injection capability"""
        try:
            # Create a test packet
            packet = RadioTap() / Dot11(
                type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55"
            )
            # Try to send it
            sendp(packet, iface=self.interface, count=1, verbose=False)
            logging.info("Packet injection test: PASSED")
            return True
        except Exception as e:
            logging.error(f"Packet injection test: FAILED - {e}")
            return False
    
    def scan_networks(self):
        """Scan for nearby networks"""
        print("\nScanning for networks...")
        networks = set()
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode()
                bssid = pkt[Dot11].addr3
                if ssid not in networks:
                    networks.add(ssid)
                    print(f"Network found: {ssid} (BSSID: {bssid})")
        
        sniff(iface=self.interface, prn=packet_handler, timeout=10)
        
    def run_full_test(self):
        """Run all tests"""
        print(f"Testing adapter: {self.interface}")
        
        if not self.check_interface():
            print("❌ Interface not found")
            return
        
        print("\nRunning capability tests:")
        print(f"✓ Interface detected: {self.interface}")
        
        if self.check_monitor_mode():
            print("✓ Monitor mode supported")
        else:
            print("❌ Monitor mode not supported")
            
        if self.test_packet_injection():
            print("✓ Packet injection supported")
        else:
            print("❌ Packet injection not supported")
        
        self.scan_networks()

def main():
    if os.geteuid() != 0:
        print("This script must be run as root (use sudo)")
        sys.exit(1)
    
    # List all wireless interfaces
    print("Available wireless interfaces:")
    os.system("iwconfig 2>/dev/null | grep IEEE")
    
    interface = input("\nEnter interface name to test: ")
    tester = WiFiAdapterTester(interface)
    tester.run_full_test()

if __name__ == "__main__":
    main()

