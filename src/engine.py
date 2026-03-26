import math
from scapy.all import IP, TCP, UDP, ICMP

class SecurityEngine:
    def __init__(self):
        # We will load the AI model here in Phase 3
        pass

    def calculate_entropy(self, payload):
        """Calculates Shannon entropy to detect encrypted/malicious payloads."""
        if not payload:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(payload.count(bytes([x]))) / len(payload)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract_features(self, scapy_packet):
        """Converts a packet into a numeric dictionary for the AI."""
        features = {}
        if scapy_packet.haslayer(IP):
            features['size'] = len(scapy_packet)
            features['ttl'] = scapy_packet.ttl
            features['proto'] = scapy_packet.proto
            
            payload = bytes(scapy_packet[IP].payload)
            features['entropy'] = self.calculate_entropy(payload)
            
            # Layer-specific features
            if scapy_packet.haslayer(TCP):
                features['port'] = scapy_packet[TCP].dport
                features['flags'] = int(scapy_packet[TCP].flags)
            elif scapy_packet.haslayer(UDP):
                features['port'] = scapy_packet[UDP].dport
                features['flags'] = 0
            else:
                features['port'] = 0
                features['flags'] = 0
        return features

    def decide(self, features):
        """
        The decision logic. 
        Currently: Basic Symbolic Rules.
        Phase 3: AI Model Prediction.
        """
        # Example rule: Block if entropy is suspiciously high (potential shellcode)
        if features.get('entropy', 0) > 7.0:
            return "DROP"
        
        return "ACCEPT"