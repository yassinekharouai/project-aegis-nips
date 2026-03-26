#!/usr/bin/env python3
"""
Aegis Network Intrusion Prevention System (NIPS)
AI-powered packet interceptor using NFQUEUE
"""

import sys
import os
import signal
import logging
import argparse
import json
import time
from datetime import datetime
from collections import defaultdict
import threading
from typing import Dict, List

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP, Raw
from engine import SecurityEngine
import pandas as pd

# Professional Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler('/var/log/aegis.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class AegisInterceptor:
    """
    Main interceptor class that hooks into NFQUEUE and processes packets.
    Features:
        - Real-time packet inspection
        - AI-powered decision making
        - Performance metrics
        - Threat intelligence logging
        - Fail-safe mode
    """
    
    def __init__(self, queue_num: int = 1, model_path: str = None, 
                 log_file: str = "/var/log/aegis_threats.json"):
        """
        Initialize the interceptor.
        
        Args:
            queue_num: NFQUEUE number to bind to
            model_path: Path to trained AI model (optional)
            log_file: Path to threat log file
        """
        self.queue_num = queue_num
        self.engine = SecurityEngine(model_path)
        self.log_file = log_file
        self.running = True
        
        # Statistics tracking
        self.stats = {
            'total_packets': 0,
            'accepted': 0,
            'dropped': 0,
            'errors': 0,
            'start_time': time.time(),
            'packets_per_second': 0,
            'threats': defaultdict(int),
            'recent_decisions': []
        }
        
        # Performance tracking
        self.latency_samples = []
        self.last_stats_time = time.time()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Create log directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    def signal_handler(self, sig, frame):
        """Handle shutdown signals gracefully"""
        logger.info("Shutdown signal received")
        self.running = False
    
    def packet_callback(self, packet):
        """
        Callback function for every packet trapped in NFQUEUE.
        This is where the magic happens!
        """
        if not self.running:
            packet.accept()
            return
        
        start_time = time.time()
        self.stats['total_packets'] += 1
        
        try:
            # Parse packet with Scapy
            raw_data = packet.get_payload()
            scapy_packet = IP(raw_data)
            
            # 1. Extract Features
            features = self.engine.extract_features(scapy_packet)
            
            # 2. Get Decision from Engine
            decision, confidence = self.engine.decide(features)
            
            # 3. Take Action
            if decision == "DROP":
                self.stats['dropped'] += 1
                logger.warning(
                    f"🚫 DROPPED | {scapy_packet.src}:{features.get('sport', '?')} -> "
                    f"{scapy_packet.dst}:{features.get('dport', '?')} | "
                    f"Proto: {features.get('protocol', '?')} | "
                    f"Entropy: {features.get('entropy', 0):.2f} | "
                    f"Score: {features.get('anomaly_score', 0):.2f} | "
                    f"Confidence: {confidence:.2f}"
                )
                packet.drop()
                
                # Log threat details
                self.log_threat(scapy_packet, features, confidence)
                
                # Track threat types
                threat_type = self.classify_threat(features)
                self.stats['threats'][threat_type] += 1
                
            elif decision == "LOG":
                # Log but don't drop
                self.stats['accepted'] += 1
                logger.info(
                    f"⚠️  LOGGED | {scapy_packet.src}:{features.get('sport', '?')} -> "
                    f"{scapy_packet.dst}:{features.get('dport', '?')} | "
                    f"Score: {features.get('anomaly_score', 0):.2f}"
                )
                packet.accept()
                
            else:  # ACCEPT
                self.stats['accepted'] += 1
                # Only log accept for suspicious but allowed packets
                if features.get('anomaly_score', 0) > 0.5:
                    logger.debug(
                        f"✅ ACCEPTED (suspicious) | {scapy_packet.src} -> {scapy_packet.dst} | "
                        f"Score: {features.get('anomaly_score', 0):.2f}"
                    )
                packet.accept()
            
            # Track performance
            latency = (time.time() - start_time) * 1000  # Convert to ms
            self.latency_samples.append(latency)
            if len(self.latency_samples) > 1000:
                self.latency_samples.pop(0)
            
            # Track recent decisions
            self.stats['recent_decisions'].append(decision)
            if len(self.stats['recent_decisions']) > 100:
                self.stats['recent_decisions'].pop(0)
            
            # Update performance metrics periodically
            if time.time() - self.last_stats_time >= 5:  # Every 5 seconds
                self.update_performance_stats()
                self.last_stats_time = time.time()
                
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Error processing packet: {e}", exc_info=True)
            packet.accept()  # Fail-safe: allow traffic if code crashes
    
    def classify_threat(self, features: Dict) -> str:
        """Classify the type of threat based on features"""
        if features.get('suspicious_flags', 0):
            if features.get('syn_flag') and not features.get('ack_flag'):
                return 'SYN_SCAN'
            elif features.get('fin_flag') and features.get('urg_flag') and features.get('psh_flag'):
                return 'XMAS_SCAN'
            elif features.get('flags') == 0:
                return 'NULL_SCAN'
            else:
                return 'FLAG_ANOMALY'
        
        if features.get('entropy', 0) > 7.0:
            if features.get('dport') not in [443, 993, 995]:
                return 'ENCRYPTED_PAYLOAD'
        
        if features.get('port_rate', 0) > 100:
            return 'DOS_ATTACK'
        
        if features.get('packet_rate', 0) > 500:
            return 'FLOOD_ATTACK'
        
        if features.get('payload_size') == 0 and features.get('dport') in [80, 443, 25]:
            return 'NULL_PAYLOAD'
        
        return 'GENERIC_ANOMALY'
    
    def log_threat(self, packet, features: Dict, confidence: float):
        """Log threat details to JSON file for analysis"""
        try:
            threat_log = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': features.get('src_ip', packet.src if hasattr(packet, 'src') else 'unknown'),
                'dst_ip': features.get('dst_ip', packet.dst if hasattr(packet, 'dst') else 'unknown'),
                'src_port': features.get('sport', 0),
                'dst_port': features.get('dport', 0),
                'protocol': features.get('protocol', 0),
                'threat_type': self.classify_threat(features),
                'confidence': confidence,
                'anomaly_score': features.get('anomaly_score', 0),
                'entropy': features.get('entropy', 0),
                'packet_size': features.get('packet_size', 0),
                'flags': features.get('flags', 0),
                'packet_rate': features.get('packet_rate', 0)
            }
            
            # Append to JSON file
            try:
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                logs = []
            
            logs.append(threat_log)
            
            # Keep only last 10,000 logs
            if len(logs) > 10000:
                logs = logs[-10000:]
            
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def update_performance_stats(self):
        """Calculate and log performance metrics"""
        runtime = time.time() - self.stats['start_time']
        pps = self.stats['total_packets'] / runtime if runtime > 0 else 0
        drop_rate = (self.stats['dropped'] / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
        
        avg_latency = sum(self.latency_samples) / len(self.latency_samples) if self.latency_samples else 0
        max_latency = max(self.latency_samples) if self.latency_samples else 0
        
        logger.info(
            f"📊 STATS | Packets: {self.stats['total_packets']} | "
            f"Dropped: {self.stats['dropped']} ({drop_rate:.1f}%) | "
            f"Errors: {self.stats['errors']} | "
            f"PPS: {pps:.0f} | "
            f"Latency: {avg_latency:.2f}ms (max: {max_latency:.2f}ms)"
        )
        
        # Log top threats
        if self.stats['threats']:
            top_threats = sorted(self.stats['threats'].items(), key=lambda x: x[1], reverse=True)[:5]
            logger.info(f"⚠️  TOP THREATS: {', '.join([f'{t}: {c}' for t, c in top_threats])}")
    
    def start(self):
        """Start the interceptor and bind to NFQUEUE"""
        logger.info(f"🚀 Starting Aegis NIPS on Queue {self.queue_num}")
        logger.info(f"📁 Threat log: {self.log_file}")
        logger.info(f"🤖 AI Model: {'Loaded' if self.engine.model else 'Not loaded (Collection mode)'}")
        logger.info("=" * 60)
        
        nfqueue = NetfilterQueue()
        
        try:
            nfqueue.bind(self.queue_num, self.packet_callback)
            logger.info("✅ Successfully bound to NFQUEUE")
            logger.info("🛡️  Aegis is now protecting the system!")
            
            # Start statistics thread
            stats_thread = threading.Thread(target=self.periodic_stats, daemon=True)
            stats_thread.start()
            
            nfqueue.run()
            
        except Exception as e:
            logger.error(f"Failed to start interceptor: {e}")
            logger.error("Make sure to setup iptables rules first:")
            logger.error(f"  sudo iptables -I INPUT -j NFQUEUE --queue-num {self.queue_num}")
            logger.error(f"  sudo iptables -I OUTPUT -j NFQUEUE --queue-num {self.queue_num}")
            sys.exit(1)
            
        finally:
            logger.info("Shutting down...")
            nfqueue.unbind()
            self.print_final_stats()
    
    def periodic_stats(self):
        """Print statistics periodically"""
        while self.running:
            time.sleep(10)
            self.update_performance_stats()
    
    def print_final_stats(self):
        """Print final statistics on shutdown"""
        runtime = time.time() - self.stats['start_time']
        logger.info("=" * 60)
        logger.info("📊 FINAL STATISTICS")
        logger.info(f"   Total Runtime: {runtime:.2f} seconds")
        logger.info(f"   Total Packets: {self.stats['total_packets']}")
        logger.info(f"   Accepted: {self.stats['accepted']}")
        logger.info(f"   Dropped: {self.stats['dropped']}")
        logger.info(f"   Errors: {self.stats['errors']}")
        logger.info(f"   Average PPS: {self.stats['total_packets']/runtime:.1f}")
        
        if self.latency_samples:
            logger.info(f"   Average Latency: {sum(self.latency_samples)/len(self.latency_samples):.2f}ms")
        
        if self.stats['threats']:
            logger.info("\n   Top Threats Detected:")
            for threat, count in sorted(self.stats['threats'].items(), key=lambda x: x[1], reverse=True)[:10]:
                logger.info(f"     - {threat}: {count}")
        
        logger.info("=" * 60)


def setup_iptables(queue_num: int, enable: bool = True):
    """
    Setup or remove iptables rules for NFQUEUE.
    """
    import subprocess
    
    if enable:
        # Forward all traffic to NFQUEUE
        cmd_input = f"iptables -I INPUT -j NFQUEUE --queue-num {queue_num}"
        cmd_output = f"iptables -I OUTPUT -j NFQUEUE --queue-num {queue_num}"
        cmd_forward = f"iptables -I FORWARD -j NFQUEUE --queue-num {queue_num}"
    else:
        # Remove rules
        cmd_input = f"iptables -D INPUT -j NFQUEUE --queue-num {queue_num}"
        cmd_output = f"iptables -D OUTPUT -j NFQUEUE --queue-num {queue_num}"
        cmd_forward = f"iptables -D FORWARD -j NFQUEUE --queue-num {queue_num}"
    
    try:
        subprocess.run(cmd_input.split(), check=True)
        subprocess.run(cmd_output.split(), check=True)
        subprocess.run(cmd_forward.split(), check=True)
        logger.info(f"✅ iptables rules {'added' if enable else 'removed'}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to {'add' if enable else 'remove'} iptables rules: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis NIPS - AI-Powered Network Intrusion Prevention System")
    parser.add_argument('--queue', type=int, default=1, help='NFQUEUE number (default: 1)')
    parser.add_argument('--model', type=str, help='Path to trained AI model (optional)')
    parser.add_argument('--log-file', type=str, default='/var/log/aegis_threats.json', 
                       help='Path to threat log file')
    parser.add_argument('--setup-iptables', action='store_true', 
                       help='Setup iptables rules before starting')
    parser.add_argument('--clean-iptables', action='store_true',
                       help='Remove iptables rules and exit')
    
    args = parser.parse_args()
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("❌ Please run as root (sudo)")
        sys.exit(1)
    
    # Handle iptables cleanup
    if args.clean_iptables:
        setup_iptables(args.queue, enable=False)
        sys.exit(0)
    
    # Setup iptables if requested
    if args.setup_iptables:
        setup_iptables(args.queue, enable=True)
    
    # Start interceptor
    interceptor = AegisInterceptor(
        queue_num=args.queue,
        model_path=args.model,
        log_file=args.log_file
    )
    
    try:
        interceptor.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
    finally:
        # Cleanup iptables if we set them up
        if args.setup_iptables:
            setup_iptables(args.queue, enable=False)