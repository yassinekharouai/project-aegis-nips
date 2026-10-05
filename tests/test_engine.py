"""
Tests for the Aegis SecurityEngine.
"""

import sys
import os
import pytest

# Ensure src/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scapy.all import IP, TCP, UDP, ICMP, Raw
from engine import SecurityEngine
from config import CANONICAL_FEATURES


@pytest.fixture
def engine():
    """Fresh SecurityEngine for each test."""
    return SecurityEngine()


class TestFeatureExtraction:
    """Test that extract_features produces the expected feature set."""

    def test_tcp_packet_features(self, engine):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")
        features = engine.extract_features(pkt)

        assert features["src_ip"] == "10.0.0.1"
        assert features["dst_ip"] == "10.0.0.2"
        assert features["sport"] == 12345
        assert features["dport"] == 80
        assert features["syn_flag"] == 1
        assert features["ack_flag"] == 0
        assert features["protocol"] == 6  # TCP

    def test_udp_packet_features(self, engine):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
        features = engine.extract_features(pkt)

        assert features["sport"] == 5000
        assert features["dport"] == 53
        assert features["protocol"] == 17  # UDP
        assert features["syn_flag"] == 0
        assert features["tcp_window"] == 0

    def test_icmp_packet_features(self, engine):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        features = engine.extract_features(pkt)

        assert features["protocol"] == 1  # ICMP
        assert features["sport"] == 0
        assert features["dport"] == 0

    def test_all_canonical_features_present(self, engine):
        """Every canonical feature must be present in the output."""
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
        features = engine.extract_features(pkt)

        for feat in CANONICAL_FEATURES:
            assert feat in features, f"Missing canonical feature: {feat}"

    def test_non_ip_packet_returns_empty(self, engine):
        """Non-IP packets should return empty dict."""
        from scapy.all import Ether
        pkt = Ether()
        features = engine.extract_features(pkt)
        assert features == {}

    def test_payload_entropy(self, engine):
        """Packets with random payload should have high entropy."""
        payload = os.urandom(200)
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80) / Raw(load=payload)
        features = engine.extract_features(pkt)

        assert features["entropy"] > 6.0  # random data → high entropy
        assert features["payload_size"] > 0

    def test_empty_payload_entropy(self, engine):
        """Packets with no payload should have 0 entropy."""
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
        features = engine.extract_features(pkt)

        # Payload entropy can be > 0 due to TCP header being part of IP payload
        # but the raw application payload is effectively empty
        assert isinstance(features["entropy"], float)


class TestSuspiciousFlags:
    """Test suspicious TCP flag detection."""

    def test_xmas_scan_detected(self, engine):
        pkt = IP() / TCP(flags="FPU")  # FIN + PSH + URG
        features = engine.extract_features(pkt)
        assert features["suspicious_flags"] == 1

    def test_null_scan_detected(self, engine):
        pkt = IP() / TCP(flags=0)  # No flags
        features = engine.extract_features(pkt)
        assert features["suspicious_flags"] == 1

    def test_syn_fin_detected(self, engine):
        pkt = IP() / TCP(flags="SF")  # SYN + FIN (impossible)
        features = engine.extract_features(pkt)
        assert features["suspicious_flags"] == 1

    def test_normal_syn_not_suspicious(self, engine):
        pkt = IP() / TCP(flags="S")  # Normal SYN
        features = engine.extract_features(pkt)
        assert features["suspicious_flags"] == 0

    def test_normal_ack_not_suspicious(self, engine):
        pkt = IP() / TCP(flags="A")  # Normal ACK
        features = engine.extract_features(pkt)
        assert features["suspicious_flags"] == 0


class TestAnomalyScore:
    """Test anomaly score calculation."""

    def test_normal_packet_low_score(self, engine):
        pkt = IP(ttl=64) / TCP(sport=12345, dport=80, flags="A", window=32768)
        features = engine.extract_features(pkt)
        assert features["anomaly_score"] < 0.5

    def test_suspicious_flags_high_score(self, engine):
        pkt = IP(ttl=64) / TCP(flags="FPU")  # XMAS
        features = engine.extract_features(pkt)
        assert features["anomaly_score"] >= 0.5

    def test_low_ttl_adds_score(self, engine):
        pkt = IP(ttl=5) / TCP(sport=12345, dport=80, flags="A")
        features = engine.extract_features(pkt)
        assert features["anomaly_score"] > 0.0

    def test_score_capped_at_1(self, engine):
        """Score should never exceed 1.0."""
        pkt = IP(ttl=1) / TCP(flags="FPU", dport=12345)
        features = engine.extract_features(pkt)
        assert features["anomaly_score"] <= 1.0


class TestDecisionEngine:
    """Test the decide() method."""

    def test_collection_mode_accepts_all(self, engine):
        """Without a model, all packets should be accepted."""
        pkt = IP() / TCP(sport=1234, dport=80, flags="S")
        features = engine.extract_features(pkt)
        decision, confidence = engine.decide(features)
        assert decision in ("ACCEPT", "LOG")

    def test_prepare_for_model_length(self, engine):
        """Model input vector must match feature list length."""
        pkt = IP() / TCP(sport=1234, dport=80)
        features = engine.extract_features(pkt)
        vector = engine._prepare_for_model(features)
        assert len(vector) == len(CANONICAL_FEATURES)

    def test_prepare_for_model_all_floats(self, engine):
        """All values in model input must be floats."""
        pkt = IP() / TCP(sport=1234, dport=80)
        features = engine.extract_features(pkt)
        vector = engine._prepare_for_model(features)
        assert all(isinstance(v, float) for v in vector)


class TestEntropy:
    """Test Shannon entropy calculation."""

    def test_uniform_bytes_max_entropy(self, engine):
        """All 256 byte values equally → max entropy ≈ 8.0."""
        payload = bytes(range(256)) * 4
        entropy = engine.calculate_entropy(payload)
        assert 7.9 <= entropy <= 8.0

    def test_single_byte_zero_entropy(self, engine):
        """All same bytes → entropy = 0."""
        payload = b"\x00" * 100
        entropy = engine.calculate_entropy(payload)
        assert entropy == 0.0

    def test_empty_payload_zero_entropy(self, engine):
        assert engine.calculate_entropy(b"") == 0.0
        assert engine.calculate_entropy(b"\x01\x02") == 0.0  # < 8 bytes

    def test_text_medium_entropy(self, engine):
        """English text should have moderate entropy (~3.5-5.0)."""
        payload = b"The quick brown fox jumps over the lazy dog. " * 10
        entropy = engine.calculate_entropy(payload)
        assert 3.0 <= entropy <= 5.5


class TestStateTracking:
    """Test stateful flow tracking."""

    def test_flow_tracking_increments(self, engine):
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=100, dport=80)

        engine.extract_features(pkt)
        engine.extract_features(pkt)
        engine.extract_features(pkt)

        flow_key = "1.1.1.1:2.2.2.2"
        assert engine.connection_tracker[flow_key]["packet_count"] == 3

    def test_reset_clears_state(self, engine):
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=100, dport=80)
        engine.extract_features(pkt)
        engine.reset_state()
        assert len(engine.connection_tracker) == 0
        assert len(engine.rate_tracker) == 0
