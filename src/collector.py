import pandas as pd
from scapy.all import IP, sniff
from engine import SecurityEngine
import os
import logging

logging.basicConfig(level=logging.INFO, format='[*] %(message)s')

class DataCollector:
    def __init__(self, output_file="data/attack_log.csv"):
        self.output_file = output_file
        self.engine = SecurityEngine()
        self.data_list = []

    def packet_handler(self, packet):
        """Extracts features and adds them to our dataset."""
        if IP in packet:
            # Use the feature extractor you already built!
            features = self.engine.extract_features(packet)
            
            # Label '0' means 'Normal/Benign' traffic
            features['label'] = 1
            self.data_list.append(features)
            
            if len(self.data_list) % 50 == 0:
                logging.info(f"Captured {len(self.data_list)} packets...")

    def start(self, count=1000):
        logging.info(f"Starting collection of {count} packets. Go browse some websites!")
        # We sniff traffic without the NFQUEUE trap for this part
        sniff(prn=self.packet_handler, count=count)
        
        # Save to CSV
        df = pd.DataFrame(self.data_list)
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        df.to_csv(self.output_file, index=False)
        logging.info(f"Success! Data saved to {self.output_file}")

if __name__ == "__main__":
    collector = DataCollector()
    collector.start(count=1000)