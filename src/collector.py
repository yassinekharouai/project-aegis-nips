#!/usr/bin/env python3
"""
Aegis NIPS — Packet Collector
Captures live network traffic, extracts features, and saves labelled CSVs
for ML model training.

Usage:
    # Collect normal traffic (label=0)
    sudo python collector.py --label 0 --output data/normal_log.csv --duration 120

    # Collect attack traffic (label=1) — run attack_generator.sh in another terminal
    sudo python collector.py --label 1 --output data/attack_log.csv --duration 120

    # Collect indefinitely until Ctrl+C
    sudo python collector.py --label 0 --output data/normal_log.csv
"""

import os
import sys
import signal
import logging
import time
import argparse
from datetime import datetime

import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP, sniff

from engine import SecurityEngine
from config import DATA_DIR, ensure_directories

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


class DataCollector:
    """
    Sniffs packets, extracts features via SecurityEngine, and writes
    labelled CSV files for model training.
    """

    def __init__(self, output_file: str = "data/normal_log.csv", label: int = 0):
        """
        Args:
            output_file: Where to save the CSV
            label: 0 for normal traffic, 1 for attack traffic
        """
        self.output_file = output_file
        self.label = label
        self.engine = SecurityEngine()
        self.data_list: list = []
        self.packet_count: int = 0
        self.start_time: float = 0.0
        self.running: bool = True

        self.stats = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}

        signal.signal(signal.SIGINT, self._signal_handler)

    # =========================================================================
    # SIGNAL HANDLING
    # =========================================================================

    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully — save data before exiting."""
        logger.info("Interrupt received — saving data...")
        self.running = False
        self.save_data()
        sys.exit(0)

    # =========================================================================
    # PACKET HANDLING
    # =========================================================================

    def packet_handler(self, packet):
        """Extract features from a single packet and append to data_list."""
        if not self.running:
            return

        if IP not in packet:
            return

        try:
            features = self.engine.extract_features(packet)
            features["label"] = self.label
            features["timestamp"] = datetime.now().isoformat()
            features["packet_size"] = len(packet)

            # Protocol name (for readability — excluded from ML)
            if TCP in packet:
                features["protocol_name"] = "TCP"
                self.stats["tcp"] += 1
            elif UDP in packet:
                features["protocol_name"] = "UDP"
                self.stats["udp"] += 1
            elif ICMP in packet:
                features["protocol_name"] = "ICMP"
                self.stats["icmp"] += 1
            else:
                features["protocol_name"] = "OTHER"
                self.stats["other"] += 1

            # Flow identifier
            if TCP in packet or UDP in packet:
                sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
                dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
                features["flow"] = f"{packet[IP].src}:{sport}->{packet[IP].dst}:{dport}"

            self.data_list.append(features)
            self.packet_count += 1

            if self.packet_count % 100 == 0:
                elapsed = time.time() - self.start_time if self.start_time else 0
                rate = self.packet_count / elapsed if elapsed > 0 else 0
                label_name = "ATTACK" if self.label == 1 else "NORMAL"
                logger.info(
                    "Captured %d %s packets "
                    "(TCP:%d UDP:%d ICMP:%d) — %.1f pkt/s",
                    self.packet_count,
                    label_name,
                    self.stats["tcp"],
                    self.stats["udp"],
                    self.stats["icmp"],
                    rate,
                )

        except Exception as e:
            logger.error("Error processing packet: %s", e)

    # =========================================================================
    # PERSISTENCE
    # =========================================================================

    def save_data(self):
        """Save collected features to CSV (append if file exists)."""
        if not self.data_list:
            logger.warning("No data collected!")
            return

        ensure_directories()
        os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)

        df = pd.DataFrame(self.data_list)

        # Reorder: label first
        cols = ["label"] + [c for c in df.columns if c != "label"]
        df = df[cols]

        # Append mode — don't overwrite existing data
        if os.path.exists(self.output_file):
            existing_df = pd.read_csv(self.output_file)
            df = pd.concat([existing_df, df], ignore_index=True)
            logger.info(
                "Appending %d packets to existing %d in %s",
                len(self.data_list),
                len(existing_df),
                self.output_file,
            )

        df.to_csv(self.output_file, index=False)

        # Save metadata
        meta_file = self.output_file.replace(".csv", "_metadata.json")
        metadata = {
            "total_packets": len(df),
            "new_packets": len(self.data_list),
            "label": self.label,
            "collection_time": datetime.now().isoformat(),
            "packet_stats": self.stats,
            "features": list(df.columns),
        }
        pd.Series(metadata).to_json(meta_file)

        logger.info("Saved to %s", self.output_file)
        self._print_summary(df)

    def _print_summary(self, df: pd.DataFrame):
        """Print a collection summary table."""
        total = len(df)
        print("\n" + "=" * 55)
        print("  COLLECTION SUMMARY")
        print("=" * 55)
        print(f"  Output:       {self.output_file}")
        print(f"  Label:        {self.label} ({'ATTACK' if self.label else 'NORMAL'})")
        print(f"  Total rows:   {total}")
        print(f"  TCP packets:  {self.stats['tcp']}")
        print(f"  UDP packets:  {self.stats['udp']}")
        print(f"  ICMP packets: {self.stats['icmp']}")
        print(f"  Features:     {len(df.columns)}")
        print("=" * 55 + "\n")

    # =========================================================================
    # VALIDATION
    # =========================================================================

    def validate_engine(self) -> bool:
        """Verify SecurityEngine works on a crafted packet."""
        try:
            from scapy.all import IP, TCP
            test_pkt = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80)
            features = self.engine.extract_features(test_pkt)

            if features and len(features) > 0:
                logger.info("Engine validation OK — %d features extracted", len(features))
                return True

            logger.error("Engine returned empty features!")
            return False

        except Exception as e:
            logger.error("Engine validation failed: %s", e)
            return False

    # =========================================================================
    # START
    # =========================================================================

    def start(self, duration=None, count=None):
        """
        Start packet collection.

        Args:
            duration: Seconds to capture (None = indefinite)
            count:    Number of packets to capture (None = indefinite)
        """
        if not self.validate_engine():
            logger.error("Cannot start — engine validation failed")
            return

        self.start_time = time.time()
        label_name = "ATTACK" if self.label == 1 else "NORMAL"

        if duration:
            logger.info("Collecting %s traffic for %ds...", label_name, duration)
        elif count:
            logger.info("Collecting %d %s packets...", count, label_name)
        else:
            logger.info("Collecting %s traffic indefinitely (Ctrl+C to stop)...", label_name)

        logger.info("Output: %s", self.output_file)

        sniff(
            prn=self.packet_handler,
            timeout=duration,
            count=count or 0,
            store=False,
        )

        self.save_data()


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis NIPS — Packet Collector")
    parser.add_argument("--label", type=int, default=0, choices=[0, 1],
                        help="Traffic label: 0=normal, 1=attack (default: 0)")
    parser.add_argument("--count", type=int, default=None,
                        help="Number of packets to collect")
    parser.add_argument("--duration", type=int, default=None,
                        help="Duration in seconds")
    parser.add_argument("--output", type=str, default=os.path.join(DATA_DIR, "normal_log.csv"),
                        help="Output CSV file path")
    parser.add_argument("--validate", action="store_true",
                        help="Validate engine only")

    args = parser.parse_args()

    collector = DataCollector(output_file=args.output, label=args.label)

    if args.validate:
        collector.validate_engine()
    else:
        collector.start(duration=args.duration, count=args.count)