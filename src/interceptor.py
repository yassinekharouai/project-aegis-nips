import sys
from netfilterqueue import NetfilterQueue
from scapy.all import IP
from engine import SecurityEngine
import logging

# Professional Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

class AegisInterceptor:
    def __init__(self, queue_num=1):
        self.queue_num = queue_num
        self.engine = SecurityEngine()

    def packet_callback(self, packet):
        """Callback function for every packet trapped in NFQUEUE."""
        try:
            # Parse packet with Scapy
            raw_data = packet.get_payload()
            scapy_packet = IP(raw_data)
            
            # 1. Extract Features
            features = self.engine.extract_features(scapy_packet)
            
            # 2. Get Decision from Engine
            decision = self.engine.decide(features)
            
            # 3. Take Action
            if decision == "DROP":
                logging.warning(f"ACTION: DROP | Src: {scapy_packet.src} | Proto: {scapy_packet.proto} | Entropy: {features['entropy']:.2f}")
                packet.drop()
            else:
                # logging.info(f"ACTION: ALLOW | Src: {scapy_packet.src}")
                packet.accept()
                
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            packet.accept() # Fail-safe: allow traffic if code crashes

    def start(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(self.queue_num, self.packet_callback)
        logging.info(f"--- Project Aegis NIPS Active on Queue {self.queue_num} ---")
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            logging.info("Shutting down Interceptor...")
            nfqueue.unbind()

if __name__ == "__main__":
    # Ensure script is run as root
    import os
    if os.geteuid() != 0:
        print("Please run as root (sudo)")
        sys.exit(1)
        
    interceptor = AegisInterceptor(queue_num=1)
    interceptor.start()