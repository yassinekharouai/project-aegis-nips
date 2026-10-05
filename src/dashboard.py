#!/usr/bin/env python3
"""
Aegis NIPS — Real-Time CLI Dashboard
Premium cybersecurity monitoring terminal with live threat visualization.

Usage:
    python dashboard.py
    python dashboard.py --threat-log logs/aegis_threats.jsonl --alert-log logs/aegis_alerts.jsonl
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime
from collections import defaultdict

from config import DEFAULT_THREAT_LOG, DEFAULT_ALERT_LOG, LOG_DIR

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich.columns import Columns
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# =============================================================================
# THEME CONSTANTS
# =============================================================================

BRAND_CYAN = "#00e5ff"
BRAND_MAGENTA = "#ff00e5"
BRAND_GREEN = "#00ff88"
BRAND_RED = "#ff3355"
BRAND_ORANGE = "#ff9933"
BRAND_YELLOW = "#ffdd33"
BRAND_DIM = "#555577"
BRAND_BG = "#0a0a1a"

SEVERITY_STYLES = {
    "CRITICAL": ("bold #ff3355", "🔴", "█", "#ff3355"),
    "HIGH":     ("bold #ff9933", "🟠", "▓", "#ff9933"),
    "MEDIUM":   ("bold #ffdd33", "🟡", "▒", "#ffdd33"),
    "LOW":      ("bold #00e5ff", "🔵", "░", "#00e5ff"),
}

THREAT_ICONS = {
    "SYN_FLOOD":          "⚡",
    "PORT_SCAN":          "🔍",
    "XMAS_SCAN":          "🎄",
    "NULL_SCAN":          "∅ ",
    "DOS_ATTACK":         "💥",
    "FLOOD_ATTACK":       "🌊",
    "ENCRYPTED_PAYLOAD":  "🔐",
    "BRUTE_FORCE":        "🔑",
    "FLAG_ANOMALY":       "🚩",
    "HIGH_ENTROPY":       "🧬",
    "SUSPICIOUS_TRAFFIC": "⚠️ ",
    "UNKNOWN":            "❓",
}

# Sparkline blocks (bottom to top)
SPARK_CHARS = " ▁▂▃▄▅▆▇█"


# =============================================================================
# DASHBOARD CLASS
# =============================================================================

class Dashboard:
    """
    Reads JSONL log files and displays real-time statistics.
    Works with or without the 'rich' library.
    """

    def __init__(self, threat_log: str = DEFAULT_THREAT_LOG,
                 alert_log: str = DEFAULT_ALERT_LOG):
        self.threat_log = threat_log
        self.alert_log = alert_log
        self._frame = 0
        self._history: list[int] = []   # threat-count-per-refresh history for sparkline

    # =========================================================================
    # DATA LOADING
    # =========================================================================

    def _load_jsonl(self, path: str, max_lines: int = 5000) -> list:
        """Load last N lines from a JSONL file."""
        records = []
        if not os.path.exists(path):
            return records
        try:
            with open(path, "r") as f:
                lines = f.readlines()
                for line in lines[-max_lines:]:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except Exception:
            pass
        return records

    def _compute_stats(self, threats: list, alerts: list) -> dict:
        """Compute dashboard statistics from loaded records."""
        stats = {
            "total_threats": len(threats),
            "total_alerts": len(alerts),
            "threat_types": defaultdict(int),
            "severity_counts": defaultdict(int),
            "top_sources": defaultdict(int),
            "recent_threats": threats[-20:] if threats else [],
            "recent_alerts": alerts[-15:] if alerts else [],
        }

        for t in threats:
            stats["threat_types"][t.get("threat_type", "UNKNOWN")] += 1
            stats["top_sources"][t.get("src_ip", "?")] += 1

        for a in alerts:
            stats["severity_counts"][a.get("severity", "UNKNOWN")] += 1

        # Sort top sources
        stats["top_sources"] = dict(
            sorted(stats["top_sources"].items(), key=lambda x: x[1], reverse=True)[:10]
        )

        return stats

    # =========================================================================
    # SPARKLINE GENERATOR
    # =========================================================================

    @staticmethod
    def _sparkline(data: list[int], width: int = 40) -> str:
        """Produce a sparkline string from a list of integers."""
        if not data:
            return SPARK_CHARS[0] * width
        # Pad or trim
        series = data[-width:]
        if len(series) < width:
            series = [0] * (width - len(series)) + series
        max_val = max(series) if max(series) > 0 else 1
        return "".join(
            SPARK_CHARS[min(int(v / max_val * (len(SPARK_CHARS) - 1)), len(SPARK_CHARS) - 1)]
            for v in series
        )

    # =========================================================================
    # SEVERITY GAUGE BAR
    # =========================================================================

    @staticmethod
    def _gauge_bar(value: int, max_val: int, width: int = 25, color: str = "#00e5ff") -> Text:
        """Render a colored proportional bar."""
        if max_val <= 0:
            max_val = 1
        filled = min(int(value / max_val * width), width)
        bar = Text()
        bar.append("█" * filled, style=color)
        bar.append("░" * (width - filled), style="#333344")
        return bar

    # =========================================================================
    # ANIMATED HEADER
    # =========================================================================

    def _make_header(self) -> Panel:
        """Build the animated header banner."""
        self._frame += 1

        # Cycle accent color for a subtle pulse effect
        pulse_colors = [BRAND_CYAN, "#33eeff", "#66f0ff", "#33eeff"]
        accent = pulse_colors[self._frame % len(pulse_colors)]

        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

        title = Text()
        title.append("  ◢◤ ", style=f"bold {accent}")
        title.append("A E G I S", style=f"bold {accent}")
        title.append("  N I P S", style=f"bold {BRAND_MAGENTA}")
        title.append("  ◥◣  ", style=f"bold {accent}")

        subtitle = Text()
        subtitle.append("  AI-Powered Network Intrusion Prevention  │  ", style=f"dim {BRAND_DIM}")
        subtitle.append(now, style=f"bold {BRAND_GREEN}")
        subtitle.append("  │  ", style=f"dim {BRAND_DIM}")

        # Status dot animation
        dot_frames = ["◉ LIVE", "◎ LIVE", "◉ LIVE", "◈ LIVE"]
        status = dot_frames[self._frame % len(dot_frames)]
        subtitle.append(status, style=f"bold {BRAND_GREEN}")

        combined = Text()
        combined.append("\n")
        combined.append_text(title)
        combined.append("\n")
        combined.append_text(subtitle)
        combined.append("\n")

        return Panel(
            Align.center(combined),
            border_style=accent,
            box=box.DOUBLE_EDGE,
            padding=(0, 2),
        )

    # =========================================================================
    # STATS CARDS ROW
    # =========================================================================

    def _make_stats_cards(self, stats: dict) -> Columns:
        """Build the top row KPI cards."""
        total_t = stats["total_threats"]
        total_a = stats["total_alerts"]
        crit = stats["severity_counts"].get("CRITICAL", 0)
        high = stats["severity_counts"].get("HIGH", 0)

        cards = []

        # Threats card
        t_text = Text()
        t_text.append(f"  {total_t:,}", style=f"bold {BRAND_CYAN}")
        t_text.append("\n  THREATS DETECTED", style=f"dim {BRAND_DIM}")
        cards.append(Panel(t_text, border_style=BRAND_CYAN, box=box.ROUNDED,
                           title="[bold]🛡️  Threats[/bold]", title_align="left",
                           padding=(0, 1)))

        # Alerts card
        a_text = Text()
        a_text.append(f"  {total_a:,}", style=f"bold {BRAND_ORANGE}")
        a_text.append("\n  ALERTS RAISED", style=f"dim {BRAND_DIM}")
        cards.append(Panel(a_text, border_style=BRAND_ORANGE, box=box.ROUNDED,
                           title="[bold]🔔  Alerts[/bold]", title_align="left",
                           padding=(0, 1)))

        # Critical card
        c_text = Text()
        c_text.append(f"  {crit:,}", style=f"bold {BRAND_RED}")
        c_text.append("\n  CRITICAL", style=f"dim {BRAND_DIM}")
        cards.append(Panel(c_text, border_style=BRAND_RED, box=box.ROUNDED,
                           title="[bold]🔴  Critical[/bold]", title_align="left",
                           padding=(0, 1)))

        # High card
        h_text = Text()
        h_text.append(f"  {high:,}", style=f"bold {BRAND_YELLOW}")
        h_text.append("\n  HIGH SEVERITY", style=f"dim {BRAND_DIM}")
        cards.append(Panel(h_text, border_style=BRAND_YELLOW, box=box.ROUNDED,
                           title="[bold]🟠  High[/bold]", title_align="left",
                           padding=(0, 1)))

        return Columns(cards, expand=True, equal=True, padding=(0, 1))

    # =========================================================================
    # SEVERITY BREAKDOWN PANEL
    # =========================================================================

    def _make_severity_panel(self, stats: dict) -> Panel:
        """Build the severity gauge panel."""
        sev_table = Table(
            show_header=True, header_style=f"bold {BRAND_CYAN}",
            box=box.SIMPLE_HEAVY, expand=True, show_lines=False,
            padding=(0, 1),
        )
        sev_table.add_column("SEVERITY", style="bold", min_width=10)
        sev_table.add_column("COUNT", justify="right", min_width=6)
        sev_table.add_column("DISTRIBUTION", min_width=26)

        total_sev = sum(stats["severity_counts"].get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        max_sev = max(stats["severity_counts"].values()) if stats["severity_counts"] else 1

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = stats["severity_counts"].get(sev, 0)
            style, icon, _, color = SEVERITY_STYLES[sev]
            bar = self._gauge_bar(count, max_sev, width=22, color=color)

            label = Text()
            label.append(f"{icon} {sev}", style=style)

            count_text = Text(f"{count:,}", style=style)

            sev_table.add_row(label, count_text, bar)

        return Panel(
            sev_table,
            title="[bold]📊  Severity Breakdown[/bold]",
            title_align="left",
            border_style=BRAND_DIM,
            box=box.ROUNDED,
            padding=(0, 0),
        )

    # =========================================================================
    # THREAT TYPES PANEL
    # =========================================================================

    def _make_threat_types_panel(self, stats: dict) -> Panel:
        """Build the threat categories panel."""
        table = Table(
            show_header=True, header_style=f"bold {BRAND_MAGENTA}",
            box=box.SIMPLE_HEAVY, expand=True, show_lines=False,
            padding=(0, 1),
        )
        table.add_column("THREAT TYPE", style="bold", min_width=20)
        table.add_column("COUNT", justify="right", min_width=6)
        table.add_column("BAR", min_width=15)

        sorted_threats = sorted(stats["threat_types"].items(), key=lambda x: x[1], reverse=True)[:8]
        max_t = sorted_threats[0][1] if sorted_threats else 1

        for ttype, count in sorted_threats:
            icon = THREAT_ICONS.get(ttype, "❓")
            bar = self._gauge_bar(count, max_t, width=14, color=BRAND_MAGENTA)
            label = Text()
            label.append(f"{icon} ", style="")
            label.append(ttype, style=f"bold {BRAND_CYAN}")
            table.add_row(label, Text(f"{count:,}", style=f"{BRAND_MAGENTA}"), bar)

        if not sorted_threats:
            table.add_row(
                Text("No threats yet", style=f"dim {BRAND_DIM}"),
                Text("—", style=f"dim"),
                Text("", style=""),
            )

        return Panel(
            table,
            title="[bold]⚔️  Threat Categories[/bold]",
            title_align="left",
            border_style=BRAND_DIM,
            box=box.ROUNDED,
            padding=(0, 0),
        )

    # =========================================================================
    # TOP SOURCE IPs PANEL
    # =========================================================================

    def _make_sources_panel(self, stats: dict) -> Panel:
        """Build the top attackers panel."""
        table = Table(
            show_header=True, header_style=f"bold {BRAND_RED}",
            box=box.SIMPLE_HEAVY, expand=True, show_lines=False,
            padding=(0, 1),
        )
        table.add_column("#", style=f"dim {BRAND_DIM}", width=3)
        table.add_column("SOURCE IP", style=f"bold {BRAND_CYAN}", min_width=16)
        table.add_column("HITS", justify="right", min_width=6)
        table.add_column("SEVERITY", min_width=10)

        sources = list(stats["top_sources"].items())[:8]

        for idx, (ip, count) in enumerate(sources, 1):
            # Color-code by hit count
            if count > 100:
                sev_label = Text("● CRITICAL", style=f"bold {BRAND_RED}")
            elif count > 50:
                sev_label = Text("● HIGH", style=f"bold {BRAND_ORANGE}")
            elif count > 20:
                sev_label = Text("● MEDIUM", style=f"bold {BRAND_YELLOW}")
            else:
                sev_label = Text("● LOW", style=f"bold {BRAND_GREEN}")

            rank_style = f"bold {BRAND_RED}" if idx <= 3 else f"dim {BRAND_DIM}"
            table.add_row(
                Text(f"{idx}", style=rank_style),
                Text(ip, style=f"bold {BRAND_CYAN}"),
                Text(f"{count:,}", style=f"{BRAND_ORANGE}"),
                sev_label,
            )

        if not sources:
            table.add_row(
                Text("—"), Text("No sources yet", style=f"dim {BRAND_DIM}"),
                Text("—"), Text("—"),
            )

        return Panel(
            table,
            title="[bold]🎯  Top Attackers[/bold]",
            title_align="left",
            border_style=BRAND_DIM,
            box=box.ROUNDED,
            padding=(0, 0),
        )

    # =========================================================================
    # ACTIVITY SPARKLINE PANEL
    # =========================================================================

    def _make_activity_panel(self, stats: dict) -> Panel:
        """Build the activity sparkline panel."""
        self._history.append(stats["total_threats"])

        # Show delta from previous snapshot
        if len(self._history) >= 2:
            deltas = [
                max(self._history[i] - self._history[i - 1], 0)
                for i in range(1, len(self._history))
            ]
        else:
            deltas = [0]

        spark = self._sparkline(deltas, width=50)

        content = Text()
        content.append("  Activity  ", style=f"bold {BRAND_CYAN}")
        content.append(spark, style=f"{BRAND_GREEN}")
        content.append("  ", style="")

        # Current rate
        rate = deltas[-1] if deltas else 0
        content.append(f"  +{rate} new", style=f"bold {BRAND_GREEN}" if rate > 0 else f"dim {BRAND_DIM}")

        return Panel(
            content,
            border_style=BRAND_DIM,
            box=box.ROUNDED,
            padding=(0, 1),
        )

    # =========================================================================
    # RECENT THREATS LIVE FEED
    # =========================================================================

    def _make_threat_feed(self, stats: dict) -> Panel:
        """Build the live threat feed panel."""
        table = Table(
            show_header=True, header_style=f"bold {BRAND_CYAN}",
            box=box.SIMPLE, expand=True, show_lines=False,
            padding=(0, 1),
        )
        table.add_column("TIME", style=f"dim", width=10)
        table.add_column("TYPE", min_width=18)
        table.add_column("SOURCE", style=f"{BRAND_CYAN}", min_width=22)
        table.add_column("DEST", style=f"{BRAND_GREEN}", min_width=22)
        table.add_column("SCORE", justify="right", width=7)

        for t in stats["recent_threats"][-12:]:
            ts = t.get("timestamp", "?")
            if "T" in ts:
                ts = ts.split("T")[1][:8]

            threat_type = t.get("threat_type", "?")
            icon = THREAT_ICONS.get(threat_type, "❓")
            score = t.get("anomaly_score", 0)

            # Color score
            if score >= 0.8:
                score_style = f"bold {BRAND_RED}"
            elif score >= 0.5:
                score_style = f"bold {BRAND_ORANGE}"
            else:
                score_style = f"{BRAND_YELLOW}"

            type_text = Text()
            type_text.append(f"{icon} ", style="")
            type_text.append(threat_type, style=f"bold {BRAND_MAGENTA}")

            table.add_row(
                Text(ts, style=f"dim {BRAND_DIM}"),
                type_text,
                Text(f"{t.get('src_ip', '?')}:{t.get('src_port', '?')}"),
                Text(f"{t.get('dst_ip', '?')}:{t.get('dst_port', '?')}"),
                Text(f"{score:.2f}", style=score_style),
            )

        if not stats["recent_threats"]:
            table.add_row(
                Text("—"), Text("No threats detected yet", style=f"dim {BRAND_DIM}"),
                Text("—"), Text("—"), Text("—"),
            )

        return Panel(
            table,
            title="[bold]📡  Live Threat Feed[/bold]",
            title_align="left",
            border_style=BRAND_CYAN,
            box=box.ROUNDED,
            padding=(0, 0),
        )

    # =========================================================================
    # FOOTER
    # =========================================================================

    def _make_footer(self) -> Panel:
        """Build the status bar footer."""
        footer = Text()
        footer.append("  ◆ ", style=f"{BRAND_CYAN}")
        footer.append("Ctrl+C", style=f"bold {BRAND_MAGENTA}")
        footer.append(" to exit  ", style=f"dim {BRAND_DIM}")
        footer.append("◆ ", style=f"{BRAND_CYAN}")
        footer.append("Threat Log: ", style=f"dim {BRAND_DIM}")
        footer.append(self.threat_log, style=f"bold {BRAND_CYAN}")
        footer.append("  ◆ ", style=f"{BRAND_CYAN}")
        footer.append("Alert Log: ", style=f"dim {BRAND_DIM}")
        footer.append(self.alert_log, style=f"bold {BRAND_CYAN}")
        footer.append("  ", style="")

        return Panel(
            Align.center(footer),
            border_style=BRAND_DIM,
            box=box.ROUNDED,
            padding=(0, 0),
        )

    # =========================================================================
    # FULL LAYOUT ASSEMBLY (RICH)
    # =========================================================================

    def _build_layout(self, stats: dict) -> Layout:
        """Assemble the full dashboard layout."""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=6),
            Layout(name="stats_cards", size=5),
            Layout(name="activity", size=3),
            Layout(name="middle", size=14),
            Layout(name="feed", minimum_size=10),
            Layout(name="footer", size=3),
        )

        # Header
        layout["header"].update(self._make_header())

        # KPI cards
        layout["stats_cards"].update(self._make_stats_cards(stats))

        # Activity sparkline
        layout["activity"].update(self._make_activity_panel(stats))

        # Middle row: severity + threat types + top sources
        layout["middle"].split_row(
            Layout(name="severity", ratio=1),
            Layout(name="threats", ratio=1),
            Layout(name="sources", ratio=1),
        )
        layout["severity"].update(self._make_severity_panel(stats))
        layout["threats"].update(self._make_threat_types_panel(stats))
        layout["sources"].update(self._make_sources_panel(stats))

        # Live threat feed
        layout["feed"].update(self._make_threat_feed(stats))

        # Footer
        layout["footer"].update(self._make_footer())

        return layout

    # =========================================================================
    # PLAIN-TEXT DASHBOARD (fallback, no dependencies)
    # =========================================================================

    def _render_plain(self, stats: dict):
        """Render dashboard using plain print statements."""
        os.system("clear" if os.name == "posix" else "cls")

        print("=" * 70)
        print("   🛡️  AEGIS NIPS — REAL-TIME DASHBOARD")
        print("=" * 70)
        print(f"   Timestamp:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Total Threats: {stats['total_threats']}")
        print(f"   Total Alerts:  {stats['total_alerts']}")
        print()

        # Severity breakdown
        print("   ── SEVERITY BREAKDOWN ──")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = stats["severity_counts"].get(sev, 0)
            bar = "█" * min(count, 40)
            print(f"   {sev:<10} {count:>5}  {bar}")
        print()

        # Threat types
        print("   ── THREAT TYPES ──")
        for ttype, count in sorted(stats["threat_types"].items(), key=lambda x: x[1], reverse=True)[:8]:
            bar = "▓" * min(count, 30)
            print(f"   {ttype:<22} {count:>5}  {bar}")
        print()

        # Top source IPs
        print("   ── TOP SOURCE IPs ──")
        for ip, count in list(stats["top_sources"].items())[:8]:
            print(f"   {ip:<20} {count:>5} alerts")
        print()

        # Recent threats
        print("   ── RECENT THREATS ──")
        for t in stats["recent_threats"][-8:]:
            ts = t.get("timestamp", "?")
            if "T" in ts:
                ts = ts.split("T")[1][:8]
            print(
                f"   {ts}  {t.get('threat_type', '?'):<18} "
                f"{t.get('src_ip', '?')}:{t.get('src_port', '?')} → "
                f"{t.get('dst_ip', '?')}:{t.get('dst_port', '?')}  "
                f"Score:{t.get('anomaly_score', 0):.2f}"
            )
        print()
        print("   Press Ctrl+C to exit")
        print("=" * 70)

    # =========================================================================
    # MAIN LOOP
    # =========================================================================

    def run(self, refresh: float = 2.0):
        """Run the dashboard in a refresh loop."""
        if HAS_RICH:
            self._run_rich(refresh)
        else:
            self._run_plain(refresh)

    def _run_rich(self, refresh: float):
        """Full Rich live-updating dashboard."""
        console = Console()
        console.clear()

        try:
            with Live(console=console, refresh_per_second=2, screen=True) as live:
                while True:
                    threats = self._load_jsonl(self.threat_log)
                    alerts = self._load_jsonl(self.alert_log)
                    stats = self._compute_stats(threats, alerts)
                    layout = self._build_layout(stats)
                    live.update(layout)
                    time.sleep(refresh)

        except KeyboardInterrupt:
            console.clear()
            console.print(
                Panel(
                    Align.center(
                        Text("\n  🛡️  Aegis NIPS Dashboard — Session Ended  \n", style=f"bold {BRAND_CYAN}")
                    ),
                    border_style=BRAND_CYAN,
                    box=box.DOUBLE_EDGE,
                ),
            )

    def _run_plain(self, refresh: float):
        """Plain-text fallback loop."""
        print("🛡️  Aegis Dashboard starting (plain mode — install 'rich' for premium UI)...")
        print(f"   Threat log: {self.threat_log}")
        print(f"   Alert log:  {self.alert_log}")
        print()

        try:
            while True:
                threats = self._load_jsonl(self.threat_log)
                alerts = self._load_jsonl(self.alert_log)
                stats = self._compute_stats(threats, alerts)
                self._render_plain(stats)
                time.sleep(refresh)
        except KeyboardInterrupt:
            print("\nDashboard stopped.")


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis NIPS — Dashboard")
    parser.add_argument("--threat-log", type=str, default=DEFAULT_THREAT_LOG)
    parser.add_argument("--alert-log", type=str, default=DEFAULT_ALERT_LOG)
    parser.add_argument("--refresh", type=float, default=2.0,
                        help="Refresh interval in seconds")
    args = parser.parse_args()

    dash = Dashboard(threat_log=args.threat_log, alert_log=args.alert_log)
    dash.run(refresh=args.refresh)
