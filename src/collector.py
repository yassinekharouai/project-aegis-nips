import pandas as pd
from scapy.all import IP, sniff, TCP, UDP, ICMP
from engine import SecurityEngine
import os
import logging
import time
from datetime import datetime
import signal
import sys

logging.basicConfig(level=logging.INFO, format='[*] %(message)s')

class DataCollector:
    def __init__(self, output_file="data/attack_log.csv"):
        self.output_file = output_file
        self.engine = SecurityEngine()
        self.data_list = []
        self.packet_count = 0
        self.start_time = None
        self.running = True
        
        # Statistics
        self.stats = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'other': 0
        }
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        logging.info("\n[!] Interrupt received, saving data...")
        self.running = False
        self.save_data()
        sys.exit(0)
    
    def packet_handler(self, packet):
        """Extracts features and adds them to our dataset."""
        if not self.running:
            return
            
        if IP in packet:
            try:
                # Extract features using your engine
                features = self.engine.extract_features(packet)
                
                # Label '1' for attack traffic (as requested)
                features['label'] = 1
                
                # Add timestamp for temporal analysis
                features['timestamp'] = datetime.now().isoformat()
                
                # Add packet size
                features['packet_size'] = len(packet)
                
                # Add protocol type for better classification
                if TCP in packet:
                    features['protocol'] = 'TCP'
                    self.stats['tcp'] += 1
                elif UDP in packet:
                    features['protocol'] = 'UDP'
                    self.stats['udp'] += 1
                elif ICMP in packet:
                    features['protocol'] = 'ICMP'
                    self.stats['icmp'] += 1
                else:
                    features['protocol'] = 'OTHER'
                    self.stats['other'] += 1
                
                # Add flow identifier (src_ip:src_port->dst_ip:dst_port)
                if TCP in packet or UDP in packet:
                    sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
                    dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
                    features['flow'] = f"{packet[IP].src}:{sport}->{packet[IP].dst}:{dport}"
                
                self.data_list.append(features)
                self.packet_count += 1
                
                # Progress reporting
                if self.packet_count % 100 == 0:
                    elapsed = time.time() - self.start_time if self.start_time else 0
                    rate = self.packet_count / elapsed if elapsed > 0 else 0
                    logging.info(f"Captured {self.packet_count} attack packets "
                               f"(TCP: {self.stats['tcp']}, UDP: {self.stats['udp']}, "
                               f"ICMP: {self.stats['icmp']}) - {rate:.1f} pkts/sec")
                
            except Exception as e:
                logging.error(f"Error processing packet: {e}")
    
    def save_data(self):
        """Save collected data to CSV"""
        if not self.data_list:
            logging.warning("No data collected!")
            return
        
        logging.info(f"Saving {len(self.data_list)} packets to {self.output_file}")
        
        # Convert to DataFrame
        df = pd.DataFrame(self.data_list)
        
        # Reorder columns to put label first for easier access
        cols = ['label'] + [col for col in df.columns if col != 'label']
        df = df[cols]
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        
        # Save to CSV
        df.to_csv(self.output_file, index=False)
        
        # Save metadata
        metadata = {
            'total_packets': len(self.data_list),
            'collection_time': datetime.now().isoformat(),
            'packet_stats': self.stats,
            'features': list(df.columns)
        }
        
        meta_file = self.output_file.replace('.csv', '_metadata.json')
        pd.Series(metadata).to_json(meta_file)
        
        logging.info(f"Success! Data saved to {self.output_file}")
        logging.info(f"Metadata saved to {meta_file}")
        
        # Print summary
        print("\n" + "="*50)
        print("COLLECTION SUMMARY")
        print("="*50)
        print(f"Total packets: {len(self.data_list)}")
        print(f"TCP packets: {self.stats['tcp']} ({self.stats['tcp']/len(self.data_list)*100:.1f}%)")
        print(f"UDP packets: {self.stats['udp']} ({self.stats['udp']/len(self.data_list)*100:.1f}%)")
        print(f"ICMP packets: {self.stats['icmp']} ({self.stats['icmp']/len(self.data_list)*100:.1f}%)")
        print(f"Features extracted: {len(df.columns)}")
        print("="*50)
    
    def validate_engine(self):
        """Validate that the SecurityEngine works"""
        try:
            # Create a test packet
            from scapy.all import IP, TCP
            test_packet = IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=12345, dport=80)
            
            # Try to extract features
            features = self.engine.extract_features(test_packet)
            
            if features and len(features) > 0:
                logging.info("SecurityEngine validation successful!")
                logging.info(f"Features extracted: {list(features.keys())}")
                return True
            else:
                logging.error("SecurityEngine returned empty features!")
                return False
                
        except Exception as e:
            logging.error(f"SecurityEngine validation failed: {e}")
            logging.error("Make sure your engine.py has extract_features() method")
            return False
    
    def start(self, duration=None, count=None):
        """Start packet collection
        
        Args:
            duration: Collect for N seconds (if None, collect until count reached)
            count: Collect N packets (if None, collect indefinitely)
        """
        # Validate engine first
        if not self.validate_engine():
            logging.error("Cannot start collector - SecurityEngine issues detected")
            return
        
        self.start_time = time.time()
        
        if duration:
            logging.info(f"Starting collection for {duration} seconds...")
            logging.info("Run the attack script in another terminal NOW!")
            
            # Sniff for specified duration
            sniff(prn=self.packet_handler, timeout=duration, store=False)
            
        elif count:
            logging.info(f"Starting collection of {count} attack packets...")
            logging.info("Run the attack script in another terminal NOW!")
            
            # Sniff until count reached
            sniff(prn=self.packet_handler, count=count, store=False)
            
        else:
            logging.info("Starting indefinite collection (Ctrl+C to stop)...")
            logging.info("Run the attack script in another terminal NOW!")
            
            # Sniff indefinitely
            sniff(prn=self.packet_handler, store=False)
        
        # Save data when done
        self.save_data()
    
    def start_with_attack_sync(self, attack_script=None, count=5000):
        """Synchronize attack generation with collection"""
        import subprocess
        import threading
        
        logging.info(f"Will collect {count} attack packets")
        logging.info("Press Ctrl+C to stop early")
        
        # Start packet collection in background
        collect_thread = threading.Thread(target=self.start, args=(None, count))
        collect_thread.daemon = True
        collect_thread.start()
        
        # Wait a moment for collection to start
        time.sleep(2)
        
        # Run attack script if provided
        if attack_script:
            logging.info(f"Launching attack script: {attack_script}")
            try:
                subprocess.run(['sudo', attack_script], check=True)
            except Exception as e:
                logging.error(f"Attack script error: {e}")
        
        # Wait for collection to complete
        collect_thread.join()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='IPS Training Data Collector')
    parser.add_argument('--count', type=int, default=None, 
                       help='Number of packets to collect')
    parser.add_argument('--duration', type=int, default=None,
                       help='Duration in seconds to collect')
    parser.add_argument('--output', type=str, default="data/attack_log.csv",
                       help='Output CSV file path')
    parser.add_argument('--validate', action='store_true',
                       help='Validate SecurityEngine only')
    parser.add_argument('--with-attacks', type=str, default=None,
                       help='Path to attack script to run simultaneously')
    
    args = parser.parse_args()
    
    collector = DataCollector(output_file=args.output)
    
    if args.validate:
        collector.validate_engine()
    elif args.with_attacks:
        collector.start_with_attack_sync(args.with_attacks, args.count or 5000)
    else:
        collector.start(duration=args.duration, count=args.count)