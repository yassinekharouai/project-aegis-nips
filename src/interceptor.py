#!/usr/bin/env python3
"""
Aegis NIPS — Packet Interceptor
Inline packet inspection via NFQUEUE with AI-powered verdicts.

Usage:
    # Start in protection mode (requires trained model + root)
    sudo python interceptor.py --model models/aegis_model.pkl --setup-iptables

    # Start in collection/heuristic mode (no model)
    sudo python interceptor.py --setup-iptables

    # Dry-run mode (no iptables, for testing)
    sudo python interceptor.py --dry-run

    # Cleanup iptables rules
    sudo python interceptor.py --clean-iptables
"""

import sys
import os
import signal
import logging
import argparse
import json
import time
import subprocess
import threading
from datetime import datetime
from collections import defaultdict
from typing import Dict

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP, Raw

from engine import SecurityEngine
from alert_manager import AlertManager
from config import (
    DEFAULT_QUEUE_NUM,
    DEFAULT_THREAT_LOG,
    DEFAULT_SYSTEM_LOG,
    LOG_DIR,
    ensure_directories,
)

# Logging setup
ensure_directories()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(DEFAULT_SYSTEM_LOG),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


class AegisInterceptor:
    """
    Inline NFQUEUE-based packet interceptor.

    Features:
      - Real-time AI-powered packet classification
      - Heuristic fallback when no model is loaded
      - AlertManager integration (rate-limited, severity-classified)
      - Performance tracking (latency, PPS, drop rate)
      - Fail-safe: packets are ACCEPTED if processing errors occur
    """

    def __init__(
        self,
        queue_num: int = DEFAULT_QUEUE_NUM,
        model_path: str = None,
        log_file: str = DEFAULT_THREAT_LOG,
        dry_run: bool = False,
    ):
        self.queue_num = queue_num
        self.engine = SecurityEngine(model_path)
        self.alert_mgr = AlertManager()
        self.log_file = log_file
        self.dry_run = dry_run
        self.running = True

        # Statistics
        self.stats = {
            "total_packets": 0,
            "accepted": 0,
            "dropped": 0,
            "logged": 0,
            "errors": 0,
            "start_time": time.time(),
        }

        # Latency tracking
        self.latency_samples: list = []
        self.last_stats_time = time.time()

        # Signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        ensure_directories()

    def _signal_handler(self, sig, frame):
        logger.info("Shutdown signal received")
        self.running = False

    # =========================================================================
    # PACKET CALLBACK
    # =========================================================================

    def packet_callback(self, packet):
        """
        NFQUEUE callback — called for every intercepted packet.

        Flow: parse → extract features → decide → accept/drop → log
        """
        if not self.running:
            packet.accept()
            return

        t0 = time.time()
        self.stats["total_packets"] += 1

        try:
            raw_data = packet.get_payload()
            scapy_pkt = IP(raw_data)

            # 1. Feature extraction
            features = self.engine.extract_features(scapy_pkt)

            # 2. Decision
            decision, confidence = self.engine.decide(features)

            # 3. Execute verdict
            if decision == "DROP":
                self.stats["dropped"] += 1
                packet.drop()

                logger.warning(
                    "🚫 DROP | %s:%s → %s:%s | Score:%.2f Conf:%.2f",
                    features.get("src_ip", "?"),
                    features.get("sport", "?"),
                    features.get("dst_ip", "?"),
                    features.get("dport", "?"),
                    features.get("anomaly_score", 0),
                    confidence,
                )

                # File alert
                threat_type = self._classify_threat(features)
                self.alert_mgr.alert(
                    src_ip=features.get("src_ip", "unknown"),
                    dst_ip=features.get("dst_ip", "unknown"),
                    src_port=features.get("sport", 0),
                    dst_port=features.get("dport", 0),
                    threat_type=threat_type,
                    confidence=confidence,
                    anomaly_score=features.get("anomaly_score", 0),
                    extra={"entropy": features.get("entropy", 0),
                           "packet_rate": features.get("packet_rate", 0)},
                )

                # Append to threat JSONL
                self._log_threat_jsonl(features, confidence, threat_type)

            elif decision == "LOG":
                self.stats["logged"] += 1
                packet.accept()
                logger.info(
                    "⚠️  LOG | %s → %s | Score:%.2f",
                    features.get("src_ip", "?"),
                    features.get("dst_ip", "?"),
                    features.get("anomaly_score", 0),
                )

            else:  # ACCEPT
                self.stats["accepted"] += 1
                packet.accept()

            # Latency tracking
            latency_ms = (time.time() - t0) * 1000
            self.latency_samples.append(latency_ms)
            if len(self.latency_samples) > 1000:
                self.latency_samples.pop(0)

            # Periodic stats
            if time.time() - self.last_stats_time >= 10:
                self._print_stats()
                self.last_stats_time = time.time()

        except Exception as e:
            self.stats["errors"] += 1
            logger.error("Packet processing error: %s", e)
            packet.accept()  # fail-safe

    # =========================================================================
    # THREAT CLASSIFICATION
    # =========================================================================

    @staticmethod
    def _classify_threat(features: Dict) -> str:
        """Classify threat based on extracted features."""
        if features.get("suspicious_flags", 0):
            f = features.get("flags", 0)
            if (f & 0x29) == 0x29:
                return "XMAS_SCAN"
            if f == 0:
                return "NULL_SCAN"
            if features.get("syn_flag") and not features.get("ack_flag"):
                return "SYN_SCAN"
            return "FLAG_ANOMALY"

        if features.get("entropy", 0) > 7.0:
            if features.get("dport") not in [443, 993, 995]:
                return "ENCRYPTED_PAYLOAD"

        if features.get("port_rate", 0) > 100:
            return "DOS_ATTACK"

        if features.get("packet_rate", 0) > 500:
            return "FLOOD_ATTACK"

        return "GENERIC_ANOMALY"

    # =========================================================================
    # LOGGING (JSONL — append only)
    # =========================================================================

    def _log_threat_jsonl(self, features: Dict, confidence: float, threat_type: str):
        """Append a single threat record to the JSONL log."""
        record = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": features.get("src_ip", "unknown"),
            "dst_ip": features.get("dst_ip", "unknown"),
            "src_port": features.get("sport", 0),
            "dst_port": features.get("dport", 0),
            "protocol": features.get("protocol", 0),
            "threat_type": threat_type,
            "confidence": round(confidence, 4),
            "anomaly_score": round(features.get("anomaly_score", 0), 4),
            "entropy": round(features.get("entropy", 0), 4),
            "packet_size": features.get("packet_size", 0),
        }
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error("Failed to write threat log: %s", e)

    # =========================================================================
    # STATS
    # =========================================================================

    def _print_stats(self):
        """Print periodic performance statistics."""
        runtime = time.time() - self.stats["start_time"]
        total = self.stats["total_packets"]
        pps = total / runtime if runtime > 0 else 0
        drop_pct = (self.stats["dropped"] / total * 100) if total > 0 else 0

        avg_lat = (sum(self.latency_samples) / len(self.latency_samples)) if self.latency_samples else 0
        max_lat = max(self.latency_samples) if self.latency_samples else 0

        logger.info(
            "📊 Packets:%d | Dropped:%d (%.1f%%) | Errors:%d | "
            "PPS:%.0f | Latency:%.2fms (max:%.2fms)",
            total, self.stats["dropped"], drop_pct, self.stats["errors"],
            pps, avg_lat, max_lat,
        )

        # Alert stats
        alert_stats = self.alert_mgr.get_stats()
        if alert_stats["total_alerts"] > 0:
            logger.info(
                "🔔 Alerts:%d | Suppressed:%d | Sources:%d",
                alert_stats["total_alerts"],
                alert_stats["suppressed_alerts"],
                alert_stats["unique_sources"],
            )

    def _print_final_stats(self):
        """Print comprehensive final statistics on shutdown."""
        runtime = time.time() - self.stats["start_time"]
        logger.info("=" * 60)
        logger.info("FINAL STATISTICS")
        logger.info("  Runtime:    %.1f seconds", runtime)
        logger.info("  Total:      %d packets", self.stats["total_packets"])
        logger.info("  Accepted:   %d", self.stats["accepted"])
        logger.info("  Dropped:    %d", self.stats["dropped"])
        logger.info("  Logged:     %d", self.stats["logged"])
        logger.info("  Errors:     %d", self.stats["errors"])

        if self.latency_samples:
            logger.info("  Avg latency: %.2fms", sum(self.latency_samples) / len(self.latency_samples))

        top = self.alert_mgr.get_top_offenders(5)
        if top:
            logger.info("  Top offenders:")
            for ip, count in top:
                logger.info("    %s — %d alerts", ip, count)

        logger.info("=" * 60)

    # =========================================================================
    # START / STOP
    # =========================================================================

    def start(self):
        """Bind to NFQUEUE and start processing packets."""
        mode = "AI" if self.engine.model else "Heuristic"
        logger.info("🚀 Aegis NIPS starting on Queue %d [%s mode]", self.queue_num, mode)
        logger.info("   Threat log: %s", self.log_file)
        logger.info("   Dry-run: %s", self.dry_run)
        logger.info("=" * 60)

        nfqueue = NetfilterQueue()

        try:
            nfqueue.bind(self.queue_num, self.packet_callback)
            logger.info("✅ Bound to NFQUEUE %d — Aegis is protecting!", self.queue_num)
            nfqueue.run()

        except PermissionError:
            logger.error("Permission denied — run with sudo")
            sys.exit(1)
        except Exception as e:
            logger.error("Failed to start: %s", e)
            logger.error("Setup iptables first:")
            logger.error("  sudo iptables -I INPUT -j NFQUEUE --queue-num %d", self.queue_num)
            logger.error("  sudo iptables -I OUTPUT -j NFQUEUE --queue-num %d", self.queue_num)
            sys.exit(1)
        finally:
            logger.info("Shutting down...")
            nfqueue.unbind()
            self._print_final_stats()


# =============================================================================
# IPTABLES HELPER
# =============================================================================

def setup_iptables(queue_num: int, enable: bool = True):
    """Add or remove iptables NFQUEUE rules."""
    action = "-I" if enable else "-D"
    chains = ["INPUT", "OUTPUT", "FORWARD"]

    for chain in chains:
        cmd = f"iptables {action} {chain} -j NFQUEUE --queue-num {queue_num}"
        try:
            subprocess.run(cmd.split(), check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            logger.error("iptables %s %s failed: %s", action, chain, e)

    logger.info("iptables rules %s", "added" if enable else "removed")


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Aegis NIPS — AI-Powered Network Intrusion Prevention",
    )
    parser.add_argument("--queue", type=int, default=DEFAULT_QUEUE_NUM,
                        help="NFQUEUE number")
    parser.add_argument("--model", type=str, default=None,
                        help="Path to trained model (.pkl or directory)")
    parser.add_argument("--log-file", type=str, default=DEFAULT_THREAT_LOG,
                        help="Threat log file path")
    parser.add_argument("--setup-iptables", action="store_true",
                        help="Auto-setup iptables rules")
    parser.add_argument("--clean-iptables", action="store_true",
                        help="Remove iptables rules and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run without iptables (testing)")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("❌ Run with sudo")
        sys.exit(1)

    if args.clean_iptables:
        setup_iptables(args.queue, enable=False)
        sys.exit(0)

    if args.setup_iptables:
        setup_iptables(args.queue, enable=True)

    interceptor = AegisInterceptor(
        queue_num=args.queue,
        model_path=args.model,
        log_file=args.log_file,
        dry_run=args.dry_run,
    )

    try:
        interceptor.start()
    except KeyboardInterrupt:
        logger.info("Interrupted — shutting down")
    finally:
        if args.setup_iptables:
            setup_iptables(args.queue, enable=False)