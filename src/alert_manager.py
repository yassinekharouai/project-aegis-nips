"""
Aegis NIPS — Alert Manager
Structured threat logging, severity classification, and rate-limited alerting.
"""

import json
import os
import time
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, Optional

from config import (
    DEFAULT_ALERT_LOG,
    ALERT_RATE_LIMIT_SECONDS,
    ALERT_MAX_BUFFER,
    DOS_RATE_THRESHOLD,
    ensure_directories,
)

logger = logging.getLogger(__name__)


class Severity:
    """Alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertManager:
    """
    Manages threat alerts with:
      - Severity classification (LOW → CRITICAL)
      - Rate-limiting per source IP (avoid log flooding)
      - JSON-Lines append-only logging (O(1) per alert)
      - Aggregated statistics for repeat offenders
    """

    def __init__(self, log_path: str = DEFAULT_ALERT_LOG):
        self.log_path = log_path
        ensure_directories()

        # Rate limiting: { src_ip: last_alert_timestamp }
        self._last_alert: Dict[str, float] = {}

        # Aggregated stats: { src_ip: { threat_type: count } }
        self.ip_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        # Session counters
        self.total_alerts = 0
        self.suppressed_alerts = 0

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def alert(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        threat_type: str,
        confidence: float,
        anomaly_score: float,
        extra: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """
        File an alert if not rate-limited.

        Returns the alert dict if it was filed, or None if suppressed.
        """
        # Rate-limit check
        now = time.time()
        if src_ip in self._last_alert:
            elapsed = now - self._last_alert[src_ip]
            if elapsed < ALERT_RATE_LIMIT_SECONDS:
                self.suppressed_alerts += 1
                return None

        self._last_alert[src_ip] = now

        # Classify severity
        severity = self._classify_severity(threat_type, confidence, anomaly_score)

        # Build alert record
        record = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "threat_type": threat_type,
            "confidence": round(confidence, 4),
            "anomaly_score": round(anomaly_score, 4),
        }
        if extra:
            record["details"] = extra

        # Update stats
        self.ip_stats[src_ip][threat_type] += 1
        self.total_alerts += 1

        # Persist
        self._write_alert(record)

        # Log to console
        self._log_to_console(record)

        return record

    def get_top_offenders(self, top_n: int = 10) -> list:
        """Return top N source IPs by total alert count."""
        totals = {
            ip: sum(types.values())
            for ip, types in self.ip_stats.items()
        }
        return sorted(totals.items(), key=lambda x: x[1], reverse=True)[:top_n]

    def get_threat_summary(self) -> Dict[str, int]:
        """Aggregate threat types across all IPs."""
        summary: Dict[str, int] = defaultdict(int)
        for types in self.ip_stats.values():
            for threat_type, count in types.items():
                summary[threat_type] += count
        return dict(summary)

    def get_stats(self) -> Dict:
        """Return session alert statistics."""
        return {
            "total_alerts": self.total_alerts,
            "suppressed_alerts": self.suppressed_alerts,
            "unique_sources": len(self.ip_stats),
            "threat_summary": self.get_threat_summary(),
        }

    # =========================================================================
    # SEVERITY CLASSIFICATION
    # =========================================================================

    @staticmethod
    def _classify_severity(
        threat_type: str,
        confidence: float,
        anomaly_score: float,
    ) -> str:
        """
        Map threat type + confidence into a severity level.

        CRITICAL — active exploitation (XMAS, NULL scans, high-confidence drops)
        HIGH     — DoS / flood attacks, brute force
        MEDIUM   — suspicious patterns, moderate confidence
        LOW      — informational anomalies
        """
        critical_types = {"XMAS_SCAN", "NULL_SCAN", "FLAG_ANOMALY", "SYN_SCAN"}
        high_types = {"DOS_ATTACK", "FLOOD_ATTACK", "ENCRYPTED_PAYLOAD"}

        if threat_type in critical_types and confidence > 0.7:
            return Severity.CRITICAL
        if threat_type in critical_types:
            return Severity.HIGH
        if threat_type in high_types:
            return Severity.HIGH
        if confidence > 0.8 or anomaly_score > 0.8:
            return Severity.HIGH
        if confidence > 0.5 or anomaly_score > 0.5:
            return Severity.MEDIUM
        return Severity.LOW

    # =========================================================================
    # PERSISTENCE (JSON-Lines — append only, O(1) per write)
    # =========================================================================

    def _write_alert(self, record: Dict) -> None:
        """Append a single JSON line to the alert log."""
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error("Failed to write alert: %s", e)

    # =========================================================================
    # CONSOLE OUTPUT
    # =========================================================================

    def _log_to_console(self, record: Dict) -> None:
        """Log alert to console with severity-appropriate level."""
        severity = record["severity"]
        msg = (
            f"[{severity}] {record['threat_type']} | "
            f"{record['src_ip']}:{record['src_port']} → "
            f"{record['dst_ip']}:{record['dst_port']} | "
            f"Confidence: {record['confidence']:.2f}"
        )

        if severity == Severity.CRITICAL:
            logger.critical("🔴 %s", msg)
        elif severity == Severity.HIGH:
            logger.error("🟠 %s", msg)
        elif severity == Severity.MEDIUM:
            logger.warning("🟡 %s", msg)
        else:
            logger.info("🔵 %s", msg)
