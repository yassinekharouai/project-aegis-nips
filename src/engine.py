import math
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Raw
from collections import defaultdict, deque
import time
import pickle
import os
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)

class SecurityEngine:
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the Security Engine with feature extraction capabilities.
        
        Args:
            model_path: Path to trained AI model (optional, for inference mode)
        """
        # AI Model (to be loaded in Phase 3)
        self.model = None
        self.model_path = model_path
        
        # Stateful tracking for anomaly detection
        self.connection_tracker = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'flags': set(),
            'payload_entropies': []
        })
        
        # Rate limiting detection
        self.rate_tracker = defaultdict(lambda: deque(maxlen=100))
        
        # Known benign patterns (for initial whitelist)
        self.benign_patterns = self._load_benign_patterns()
        
        # Load model if provided
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def _load_benign_patterns(self) -> Dict:
        """Load known benign traffic patterns"""
        return {
            'common_ports': {80, 443, 53, 22, 25, 3306, 5432},
            'common_tcp_flags': {0x02, 0x10, 0x18},  # SYN, ACK, SYN-ACK
            'low_entropy_threshold': 4.5,  # Normal text has entropy < 4.5
            'high_entropy_threshold': 7.5,  # Encrypted/random > 7.5
        }
    
    def calculate_entropy(self, payload: bytes) -> float:
        """
        Calculate Shannon entropy to detect encrypted/malicious payloads.
        Higher entropy suggests encryption, compression, or random data.
        
        Args:
            payload: Raw packet payload bytes
            
        Returns:
            float: Entropy value between 0 and 8
        """
        if not payload or len(payload) < 8:
            return 0.0
        
        entropy = 0.0
        payload_len = len(payload)
        
        # Use byte frequency analysis
        freq = [0] * 256
        for byte in payload:
            freq[byte] += 1
        
        for count in freq:
            if count > 0:
                probability = count / payload_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def extract_features(self, packet) -> Dict:
        """
        Comprehensive feature extraction from network packets.
        Returns a dictionary of features for ML model.
        
        Features extracted:
            - Basic: size, ttl, protocol, entropy
            - TCP-specific: flags, window size, urgent pointer
            - Traffic patterns: packet ratios, rates
            - Security indicators: suspicious flags, unusual combinations
        """
        features = {}
        
        if not packet.haslayer(IP):
            return features
        
        ip_layer = packet[IP]
        
        # === BASIC FEATURES ===
        features['packet_size'] = len(packet)
        features['ttl'] = ip_layer.ttl
        features['protocol'] = ip_layer.proto
        features['ip_id'] = ip_layer.id
        features['ip_flags'] = int(ip_layer.flags) if hasattr(ip_layer, 'flags') else 0
        
        # === PAYLOAD ANALYSIS ===
        payload = bytes(ip_layer.payload) if ip_layer.payload else b''
        features['payload_size'] = len(payload)
        features['entropy'] = self.calculate_entropy(payload)
        
        # === FLOW IDENTIFIER ===
        features['src_ip'] = ip_layer.src
        features['dst_ip'] = ip_layer.dst
        flow_key = f"{ip_layer.src}:{ip_layer.dst}"
        
        # === LAYER-SPECIFIC FEATURES ===
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            features['sport'] = tcp.sport
            features['dport'] = tcp.dport
            features['flags'] = int(tcp.flags)
            features['tcp_window'] = tcp.window
            features['tcp_urgptr'] = tcp.urgptr if hasattr(tcp, 'urgptr') else 0
            features['tcp_options'] = len(tcp.options) if tcp.options else 0
            
            # Flag-based features
            features['syn_flag'] = 1 if tcp.flags & 0x02 else 0
            features['ack_flag'] = 1 if tcp.flags & 0x10 else 0
            features['rst_flag'] = 1 if tcp.flags & 0x04 else 0
            features['fin_flag'] = 1 if tcp.flags & 0x01 else 0
            features['psh_flag'] = 1 if tcp.flags & 0x08 else 0
            features['urg_flag'] = 1 if tcp.flags & 0x20 else 0
            
            # Suspicious flag combinations
            features['suspicious_flags'] = self._check_suspicious_flags(tcp.flags)
            
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            features['sport'] = udp.sport
            features['dport'] = udp.dport
            features['flags'] = 0
            features['tcp_window'] = 0
            features['tcp_urgptr'] = 0
            features['tcp_options'] = 0
            features['syn_flag'] = 0
            features['ack_flag'] = 0
            features['rst_flag'] = 0
            features['fin_flag'] = 0
            features['psh_flag'] = 0
            features['urg_flag'] = 0
            features['suspicious_flags'] = 0
            
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            features['sport'] = 0
            features['dport'] = 0
            features['flags'] = icmp.type
            features['tcp_window'] = 0
            features['tcp_urgptr'] = 0
            features['tcp_options'] = 0
            features['syn_flag'] = 0
            features['ack_flag'] = 0
            features['rst_flag'] = 0
            features['fin_flag'] = 0
            features['psh_flag'] = 0
            features['urg_flag'] = 0
            features['suspicious_flags'] = 0
        else:
            # Default for unknown protocols
            features['sport'] = 0
            features['dport'] = 0
            features['flags'] = 0
            features['tcp_window'] = 0
            features['tcp_urgptr'] = 0
            features['tcp_options'] = 0
            features['syn_flag'] = 0
            features['ack_flag'] = 0
            features['rst_flag'] = 0
            features['fin_flag'] = 0
            features['psh_flag'] = 0
            features['urg_flag'] = 0
            features['suspicious_flags'] = 0
        
        # === STATE-BASED FEATURES ===
        # Update connection tracker
        conn = self.connection_tracker[flow_key]
        conn['packet_count'] += 1
        conn['byte_count'] += len(packet)
        conn['last_seen'] = time.time()
        
        # Add payload entropy to history
        if features['entropy'] > 0:
            conn['payload_entropies'].append(features['entropy'])
            # Keep last 50 entropies
            if len(conn['payload_entropies']) > 50:
                conn['payload_entropies'].pop(0)
        
        # Calculate connection statistics
        time_diff = conn['last_seen'] - conn['first_seen']
        if time_diff > 0:
            features['packet_rate'] = conn['packet_count'] / time_diff
            features['byte_rate'] = conn['byte_count'] / time_diff
        else:
            features['packet_rate'] = 0
            features['byte_rate'] = 0
        
        # Average entropy for this flow
        if conn['payload_entropies']:
            features['avg_entropy'] = sum(conn['payload_entropies']) / len(conn['payload_entropies'])
        else:
            features['avg_entropy'] = 0
        
        # === RATE-BASED ANOMALY DETECTION ===
        # Track packet rates per destination port (for DoS detection)
        port_key = f"{features['dport']}"
        self.rate_tracker[port_key].append(time.time())
        
        # Calculate recent packet rate
        recent_packets = len(self.rate_tracker[port_key])
        if recent_packets > 1:
            time_span = self.rate_tracker[port_key][-1] - self.rate_tracker[port_key][0]
            features['port_rate'] = recent_packets / max(time_span, 0.001)
        else:
            features['port_rate'] = 0
        
        # === SECURITY SCORES ===
        features['anomaly_score'] = self._calculate_anomaly_score(features, conn)
        
        return features
    
    def _check_suspicious_flags(self, flags: int) -> int:
        """
        Check for suspicious TCP flag combinations.
        Returns 1 if suspicious, 0 otherwise.
        """
        # XMAS Tree: FIN + URG + PSH
        xmas = (flags & 0x29) == 0x29  # 0x29 = FIN+URG+PSH
        # NULL: no flags
        null_flag = flags == 0
        # SYN+FIN: impossible combination
        syn_fin = (flags & 0x03) == 0x03
        
        return 1 if (xmas or null_flag or syn_fin) else 0
    
    def _calculate_anomaly_score(self, features: Dict, connection: Dict) -> float:
        """
        Calculate an anomaly score based on various heuristics.
        Higher score = more anomalous.
        """
        score = 0.0
        
        # 1. Entropy anomaly (encrypted in non-encrypted port)
        if features['entropy'] > self.benign_patterns['high_entropy_threshold']:
            if features['dport'] not in {443, 993, 995}:  # Non-encrypted ports
                score += 0.3
        
        # 2. Suspicious flag combinations
        if features.get('suspicious_flags', 0):
            score += 0.5
        
        # 3. Unusual port + protocol combination
        if features['protocol'] == 6:  # TCP
            if features['dport'] < 1024 and features['dport'] not in self.benign_patterns['common_ports']:
                score += 0.2
        
        # 4. High packet rate (potential DoS)
        if features['port_rate'] > 100:  # >100 packets/sec
            score += 0.4
        
        # 5. Very small TTL (potential traceroute or scanning)
        if features['ttl'] < 32:
            score += 0.2
        
        # 6. Empty payload on ports that typically have data
        if features['payload_size'] == 0 and features['dport'] in {80, 443, 25, 110}:
            score += 0.1
        
        # 7. Rapid connection establishment
        if connection['packet_count'] < 5 and (features['syn_flag'] and features['ack_flag']):
            score += 0.1
        
        return min(score, 1.0)  # Cap at 1.0
    
    def decide(self, features: Dict) -> Tuple[str, float]:
        """
        Make a decision on packet based on features.
        
        Returns:
            Tuple: (decision, confidence_score)
            decision: "ACCEPT", "DROP", or "LOG"
            confidence: float between 0 and 1
        """
        # DATA COLLECTION MODE - Accept everything with logging
        # This is for Phase 1-2: Collecting training data
        if not self.model:
            # Log suspicious packets even in collection mode
            if features.get('anomaly_score', 0) > 0.7:
                logger.warning(f"SUSPICIOUS PACKET DETECTED (Score: {features['anomaly_score']:.2f}) - Will be labeled as attack")
                return "ACCEPT", features['anomaly_score']
            return "ACCEPT", 0.0
        
        # INFERENCE MODE - Use AI model (Phase 3+)
        try:
            # Prepare features for model (remove non-numeric)
            model_features = self._prepare_for_model(features)
            
            # Get prediction (0=benign, 1=malicious)
            prediction = self.model.predict([model_features])[0]
            confidence = max(self.model.predict_proba([model_features])[0])
            
            if prediction == 1:  # Malicious
                return "DROP", confidence
            else:
                return "ACCEPT", confidence
                
        except Exception as e:
            logger.error(f"Model inference error: {e}")
            # Fallback to heuristic
            if features.get('anomaly_score', 0) > 0.7:
                return "DROP", features['anomaly_score']
            return "ACCEPT", 0.0
    
    def _prepare_for_model(self, features: Dict) -> List[float]:
        """
        Convert feature dictionary to list format for ML model.
        Excludes non-numeric and IP address fields.
        """
        exclude_fields = {'src_ip', 'dst_ip', 'flow'}
        
        feature_list = []
        for key, value in features.items():
            if key not in exclude_fields and isinstance(value, (int, float)):
                feature_list.append(float(value))
        
        return feature_list
    
    def load_model(self, model_path: str):
        """Load trained AI model from file"""
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            logger.info(f"Model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    def save_model(self, model_path: str):
        """Save trained model to file"""
        if self.model:
            with open(model_path, 'wb') as f:
                pickle.dump(self.model, f)
            logger.info(f"Model saved to {model_path}")
    
    def get_feature_names(self) -> List[str]:
        """Return list of feature names for model training"""
        return [
            'packet_size', 'ttl', 'protocol', 'ip_id', 'ip_flags',
            'payload_size', 'entropy', 'sport', 'dport', 'flags',
            'tcp_window', 'tcp_urgptr', 'tcp_options', 'syn_flag',
            'ack_flag', 'rst_flag', 'fin_flag', 'psh_flag', 'urg_flag',
            'suspicious_flags', 'packet_rate', 'byte_rate', 'avg_entropy',
            'port_rate', 'anomaly_score'
        ]
    
    def reset_state(self):
        """Reset all stateful tracking (useful for testing)"""
        self.connection_tracker.clear()
        self.rate_tracker.clear()