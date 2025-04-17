from scapy.all import *
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def packet_handler(pkt):
    # Print every packet we can see
    print("\n--- New Packet Detected ---")
    
    if pkt.haslayer(Dot11):
        # Basic WiFi info
        print(f"WiFi Frame Type: {pkt.type}")
        print(f"Source MAC: {pkt.addr2}")
        print(f"Destination MAC: {pkt.addr1}")
        
        # If it's a data packet
        if pkt.type == 2:
            print("Data packet detected")
            if pkt.haslayer(Raw):
                print(f"Data: {pkt[Raw].load}")
    
        # If it's a management frame
        elif pkt.type == 0:
            if pkt.subtype == 8:  # Beacon frame
                if pkt.haslayer(Dot11Beacon):
                    ssid = pkt[Dot11Elt].info.decode()
                    print(f"Network detected: {ssid}")
                    
        # Print raw packet details for learning
        print("\nComplete packet structure:")
        print(pkt.summary())

def start_monitoring(interface="wlan0"):
    print(f"Starting WiFi monitoring on {interface}")
    print("Current interface capabilities:")
    os.system(f"iwconfig {interface}")
    
    print("\nWaiting for packets... (Press Ctrl+C to stop)")
    try:
        # Sniff packets and print what we can see
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    start_monitoring()

