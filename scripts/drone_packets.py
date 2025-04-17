# drone_packets.py
from scapy.all import *
import binascii

class DronePacketAnalyzer:
    def __init__(self):
        self.known_vendors = {
            'dji': ['60:60:1f', '48:61:6f', '4c:ef:c0'],
            'parrot': ['90:3a:e6', '00:12:1c', '00:26:7e'],
            'yuneec': ['e0:6f:25']
        }
    
    def create_sample_packets(self):
        """Create sample packets for different drone protocols"""
        # ASTM F3411 Remote ID sample
        astm_packet = (
            RadioTap() /
            Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                  addr2="90:3a:e6:5b:c8:a8", addr3="90:3a:e6:5b:c8:a8") /
            Dot11Beacon() /
            Dot11Elt(ID='SSID', info="DroneID-Sample")
        )
        
        print("Sample ASTM F3411 Packet Structure:")
        astm_packet.show()
        
        # Print hex dump
        print("\nHex dump of packet:")
        hexdump(astm_packet)

    def decode_packet(self, packet_hex):
        """Decode a hex packet string into its components"""
        try:
            packet = Dot11(binascii.unhexlify(packet_hex))
            print("Decoded packet structure:")
            packet.show()
        except Exception as e:
            print(f"Error decoding packet: {e}")

# Example usage
analyzer = DronePacketAnalyzer()
analyzer.create_sample_packets()

