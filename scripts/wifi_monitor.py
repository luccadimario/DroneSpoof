# wifi_monitor.py
from scapy.all import *
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='logs/wifi_monitor.log'
)

def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        # Extract basic WiFi frame info
        logging.info(f"WiFi Frame Type: {pkt.type}")
        logging.info(f"Subtype: {pkt.subtype}")
        
        # If it's a beacon frame
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.haslayer(Dot11Beacon):
                # Extract SSID
                ssid = pkt[Dot11Elt].info.decode()
                bssid = pkt[Dot11].addr3
                logging.info(f"SSID: {ssid}, BSSID: {bssid}")
                
                # Check for drone-related SSIDs
                if any(drone_name in ssid.lower() for drone_name in ['dji', 'parrot', 'yuneec', 'drone']):
                    logging.warning(f"Potential drone detected: {ssid}")

def start_monitoring(interface="wlan0"):
    print(f"Starting WiFi monitoring on {interface}")
    print("Press Ctrl+C to stop")
    
    try:
        # Just sniff packets, we'll add injection capabilities later
        sniff(iface=interface, prn=packet_handler)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
    except Exception as e:
        logging.error(f"Error: {e}")

if __name__ == "__main__":
    start_monitoring()

