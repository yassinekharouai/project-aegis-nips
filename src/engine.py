"""
Aegis NIPS — Security Engine
Core feature extraction, anomaly scoring, and ML-based decision making.

This is the brain of the system. Every packet flows through here to be
analysed before a ACCEPT / DROP / LOG verdict is returned.
"""

import math
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Raw
from collections import defaultdict, deque
import time
import pickle
import json
import os
from typing import Dict, List, Tuple, Optional
import logging

from config import (
    CANONICAL_FEATURES,
    NON_NUMERIC_FIELDS,
    HIGH_ENTROPY_THRESHOLD,
    DOS_RATE_THRESHOLD,
    FLOOD_RATE_THRESHOLD,
    ANOMALY_DROP_THRESHOLD,
    COMMON_PORTS,
    ENCRYPTED_PORTS,
    COMMON_TCP_FLAGS,
    DEFAULT_MODEL_PATH,
    DEFAULT_SCALER_PATH,
    DEFAULT_FEATURE_LIST_PATH,
)

logger = logging.getLogger(__name__)


class SecurityEngine:
    """
    Feature extraction + anomaly scoring + ML inference engine.

    Modes:
        Collection mode (no model loaded) — accept everything, extract features
        Inference mode  (model loaded)    — predict benign/malicious, DROP attacks
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the Security Engine.

        Args:
            model_path: Path to trained model bundle directory.
                        Expected files: aegis_model.pkl, aegis_scaler.pkl,
                        aegis_features.json
        """
        # AI Model
        self.model = None
        self.scaler = None
        self.feature_names: List[str] = list(CANONICAL_FEATURES)
        self.model_path = model_path

        # Stateful tracking for flow-based anomaly detection
        self.connection_tracker = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "first_seen": time.time(),
            "last_seen": time.time(),
            "flags": set(),
            "payload_entropies": [],
        })

        # Rate limiting detection (per-port packet timestamps)
        self.rate_tracker = defaultdict(lambda: deque(maxlen=100))

        # Load model bundle if provided
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

    # =========================================================================
    # FEATURE EXTRACTION
    # =========================================================================

    def calculate_entropy(self, payload: bytes) -> float:
        """
        Calculate Shannon entropy of raw bytes.

        Useful for detecting:
          - Encrypted traffic on plaintext ports (high entropy)
          - Tunnelled / obfuscated payloads
          - Compressed data

        Returns a value between 0.0 (uniform) and 8.0 (perfectly random).
        """
        if not payload or len(payload) < 8:
            return 0.0

        payload_len = len(payload)
        freq = [0] * 256
        for byte in payload:
            freq[byte] += 1

        entropy = 0.0
        for count in freq:
            if count > 0:
                probability = count / payload_len
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def extract_features(self, packet) -> Dict:
        """
        Comprehensive feature extraction from a single network packet.

        Returns a flat dictionary of features.  The keys match
        CANONICAL_FEATURES so the ML model receives them in the same order
        every time.

        Feature categories:
            Basic       — packet_size, ttl, protocol, ip_id, ip_flags
            Payload     — payload_size, entropy
            L4          — sport, dport, flags, tcp_window, tcp_urgptr,
                          tcp_options, syn/ack/rst/fin/psh/urg flags
            Security    — suspicious_flags
            Flow-state  — packet_rate, byte_rate, avg_entropy, port_rate
            Score       — anomaly_score (heuristic composite)
        """
        features: Dict = {}

        if not packet.haslayer(IP):
            return features

        ip_layer = packet[IP]

        # --- Basic IP features ---
        features["packet_size"] = len(packet)
        features["ttl"] = ip_layer.ttl
        features["protocol"] = ip_layer.proto
        features["ip_id"] = ip_layer.id
        features["ip_flags"] = int(ip_layer.flags) if hasattr(ip_layer, "flags") else 0

        # --- Payload analysis ---
        payload = bytes(ip_layer.payload) if ip_layer.payload else b""
        features["payload_size"] = len(payload)
        features["entropy"] = self.calculate_entropy(payload)

        # --- Flow identifiers (metadata — not fed to model) ---
        features["src_ip"] = ip_layer.src
        features["dst_ip"] = ip_layer.dst
        flow_key = f"{ip_layer.src}:{ip_layer.dst}"

        # --- Layer-4 features ---
        self._extract_l4_features(packet, features)

        # --- Stateful / flow-based features ---
        self._extract_flow_features(packet, features, flow_key)

        # --- Composite anomaly score ---
        conn = self.connection_tracker[flow_key]
        features["anomaly_score"] = self._calculate_anomaly_score(features, conn)

        return features

    def _extract_l4_features(self, packet, features: Dict) -> None:
        """Extract transport-layer features into *features* dict in-place."""

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            features["sport"] = tcp.sport
            features["dport"] = tcp.dport
            features["flags"] = int(tcp.flags)
            features["tcp_window"] = tcp.window
            features["tcp_urgptr"] = tcp.urgptr if hasattr(tcp, "urgptr") else 0
            features["tcp_options"] = len(tcp.options) if tcp.options else 0

            # Individual flag bits
            features["syn_flag"] = 1 if tcp.flags & 0x02 else 0
            features["ack_flag"] = 1 if tcp.flags & 0x10 else 0
            features["rst_flag"] = 1 if tcp.flags & 0x04 else 0
            features["fin_flag"] = 1 if tcp.flags & 0x01 else 0
            features["psh_flag"] = 1 if tcp.flags & 0x08 else 0
            features["urg_flag"] = 1 if tcp.flags & 0x20 else 0

            features["suspicious_flags"] = self._check_suspicious_flags(tcp.flags)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            features["sport"] = udp.sport
            features["dport"] = udp.dport
            features.update(self._default_tcp_features())

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            features["sport"] = 0
            features["dport"] = 0
            features["flags"] = icmp.type
            features.update({k: v for k, v in self._default_tcp_features().items() if k != "flags"})

        else:
            features["sport"] = 0
            features["dport"] = 0
            features.update(self._default_tcp_features())

    @staticmethod
    def _default_tcp_features() -> Dict:
        """Return zeroed TCP-specific features for non-TCP packets."""
        return {
            "flags": 0,
            "tcp_window": 0,
            "tcp_urgptr": 0,
            "tcp_options": 0,
            "syn_flag": 0,
            "ack_flag": 0,
            "rst_flag": 0,
            "fin_flag": 0,
            "psh_flag": 0,
            "urg_flag": 0,
            "suspicious_flags": 0,
        }

    def _extract_flow_features(self, packet, features: Dict, flow_key: str) -> None:
        """Update connection tracker and compute rate / flow features."""
        conn = self.connection_tracker[flow_key]
        conn["packet_count"] += 1
        conn["byte_count"] += len(packet)
        conn["last_seen"] = time.time()

        if features["entropy"] > 0:
            conn["payload_entropies"].append(features["entropy"])
            if len(conn["payload_entropies"]) > 50:
                conn["payload_entropies"].pop(0)

        time_diff = conn["last_seen"] - conn["first_seen"]
        if time_diff > 0:
            features["packet_rate"] = round(conn["packet_count"] / time_diff, 4)
            features["byte_rate"] = round(conn["byte_count"] / time_diff, 4)
        else:
            features["packet_rate"] = 0.0
            features["byte_rate"] = 0.0

        if conn["payload_entropies"]:
            features["avg_entropy"] = round(
                sum(conn["payload_entropies"]) / len(conn["payload_entropies"]), 4
            )
        else:
            features["avg_entropy"] = 0.0

        # Per-port rate tracking (for DoS detection)
        port_key = str(features["dport"])
        self.rate_tracker[port_key].append(time.time())
        recent = self.rate_tracker[port_key]
        if len(recent) > 1:
            span = recent[-1] - recent[0]
            features["port_rate"] = round(len(recent) / max(span, 0.001), 4)
        else:
            features["port_rate"] = 0.0

    # =========================================================================
    # ANOMALY HEURISTICS
    # =========================================================================

    @staticmethod
    def _check_suspicious_flags(flags: int) -> int:
        """
        Detect impossible / scan-indicative TCP flag combinations.

        Returns 1 if suspicious, 0 otherwise.
        """
        xmas = (flags & 0x29) == 0x29       # FIN + URG + PSH
        null_flag = flags == 0               # No flags set
        syn_fin = (flags & 0x03) == 0x03     # SYN + FIN (impossible)
        syn_rst = (flags & 0x06) == 0x06     # SYN + RST (impossible)
        return 1 if (xmas or null_flag or syn_fin or syn_rst) else 0

    def _calculate_anomaly_score(self, features: Dict, connection: Dict) -> float:
        """
        Weighted heuristic anomaly score ∈ [0, 1].

        Used as:
          - A standalone feature for the ML model
          - Fallback decision metric when no model is loaded
        """
        score = 0.0

        # High entropy on plaintext port
        if features["entropy"] > HIGH_ENTROPY_THRESHOLD:
            if features["dport"] not in ENCRYPTED_PORTS:
                score += 0.3

        # Suspicious TCP flag combos
        if features.get("suspicious_flags", 0):
            score += 0.5

        # Unusual privileged port
        if features["protocol"] == 6:  # TCP
            if 0 < features["dport"] < 1024 and features["dport"] not in COMMON_PORTS:
                score += 0.2

        # High packet rate → potential DoS
        if features["port_rate"] > DOS_RATE_THRESHOLD:
            score += 0.4

        # Low TTL → traceroute / scanning
        if features["ttl"] < 32:
            score += 0.2

        # Empty payload on data ports
        if features["payload_size"] == 0 and features["dport"] in {80, 443, 25, 110}:
            score += 0.1

        # Rapid connection establishment
        if connection["packet_count"] < 5 and features.get("syn_flag") and features.get("ack_flag"):
            score += 0.1

        return round(min(score, 1.0), 4)

    # =========================================================================
    # DECISION ENGINE
    # =========================================================================

    def decide(self, features: Dict) -> Tuple[str, float]:
        """
        Return a verdict for the packet.

        Returns:
            (decision, confidence)
            decision ∈ {"ACCEPT", "DROP", "LOG"}
        """
        # --- Collection mode (no model) ---
        if self.model is None:
            if features.get("anomaly_score", 0) > ANOMALY_DROP_THRESHOLD:
                logger.warning(
                    "SUSPICIOUS (Score: %.2f) — logged in collection mode",
                    features["anomaly_score"],
                )
                return "LOG", features["anomaly_score"]
            return "ACCEPT", 0.0

        # --- Inference mode ---
        try:
            model_input = self._prepare_for_model(features)
            prediction = self.model.predict([model_input])[0]
            probabilities = self.model.predict_proba([model_input])[0]
            confidence = float(max(probabilities))

            if prediction == 1:  # malicious
                return "DROP", confidence
            return "ACCEPT", confidence

        except Exception as e:
            logger.error("Model inference error: %s", e)
            # Fallback to heuristic
            if features.get("anomaly_score", 0) > ANOMALY_DROP_THRESHOLD:
                return "DROP", features["anomaly_score"]
            return "ACCEPT", 0.0

    def _prepare_for_model(self, features: Dict) -> List[float]:
        """
        Convert feature dict → ordered float list matching the trained model.

        Uses CANONICAL_FEATURES to guarantee the same column order that the
        model was trained on.  Missing features are filled with 0.0.
        If a scaler was saved during training, it is applied here.
        """
        vector = [float(features.get(f, 0.0)) for f in self.feature_names]

        if self.scaler is not None:
            vector = self.scaler.transform([vector])[0].tolist()

        return vector

    # =========================================================================
    # MODEL PERSISTENCE
    # =========================================================================

    def load_model(self, model_path: str) -> None:
        """
        Load trained model bundle.

        Expects either:
          - A single .pkl file (legacy)
          - A directory containing aegis_model.pkl, aegis_scaler.pkl,
            aegis_features.json
        """
        try:
            if os.path.isdir(model_path):
                m_path = os.path.join(model_path, "aegis_model.pkl")
                s_path = os.path.join(model_path, "aegis_scaler.pkl")
                f_path = os.path.join(model_path, "aegis_features.json")
            else:
                # Legacy single-file mode
                m_path = model_path
                s_path = model_path.replace("_model.pkl", "_scaler.pkl")
                f_path = model_path.replace("_model.pkl", "_features.json")

            with open(m_path, "rb") as f:
                self.model = pickle.load(f)
            logger.info("Model loaded from %s", m_path)

            if os.path.exists(s_path):
                with open(s_path, "rb") as f:
                    self.scaler = pickle.load(f)
                logger.info("Scaler loaded from %s", s_path)

            if os.path.exists(f_path):
                with open(f_path, "r") as f:
                    self.feature_names = json.load(f)
                logger.info("Feature list loaded (%d features)", len(self.feature_names))

        except Exception as e:
            logger.error("Failed to load model bundle: %s", e)
            self.model = None

    def save_model(self, model_path: str) -> None:
        """Save trained model to file."""
        if self.model:
            with open(model_path, "wb") as f:
                pickle.dump(self.model, f)
            logger.info("Model saved to %s", model_path)

    # =========================================================================
    # UTILITIES
    # =========================================================================

    def get_feature_names(self) -> List[str]:
        """Return canonical feature name list."""
        return list(self.feature_names)

    def reset_state(self) -> None:
        """Clear all stateful trackers (useful between test runs)."""
        self.connection_tracker.clear()
        self.rate_tracker.clear()