#!/usr/bin/env python3
"""
Aegis NIPS — Unified Entry Point

Usage:
    python main.py collect   --label 0 --output data/normal.csv --duration 120
    python main.py collect   --label 1 --output data/attack.csv --duration 120
    python main.py train     --synthetic
    python main.py train     --normal data/normal.csv --attack data/attack.csv
    python main.py protect   --model models/aegis_model.pkl --setup-iptables
    python main.py dashboard
"""

import sys
import os
import argparse

# Ensure src/ is on PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    DATA_DIR,
    DEFAULT_NORMAL_CSV,
    DEFAULT_ATTACK_CSV,
    DEFAULT_MODEL_PATH,
    DEFAULT_QUEUE_NUM,
    DEFAULT_THREAT_LOG,
    ensure_directories,
)


def cmd_collect(args):
    """Run the packet collector."""
    from collector import DataCollector

    output = args.output or os.path.join(
        DATA_DIR,
        "attack_log.csv" if args.label == 1 else "normal_log.csv",
    )

    collector = DataCollector(output_file=output, label=args.label)

    if args.validate:
        collector.validate_engine()
    else:
        collector.start(duration=args.duration, count=args.count)


def cmd_train(args):
    """Run the ML training pipeline."""
    from trainer import main as trainer_main

    # Build sys.argv for trainer
    sys.argv = ["trainer.py"]

    if args.synthetic:
        sys.argv.append("--synthetic")
    else:
        sys.argv.extend(["--normal", args.normal or DEFAULT_NORMAL_CSV])
        sys.argv.extend(["--attack", args.attack or DEFAULT_ATTACK_CSV])

    if args.model:
        sys.argv.extend(["--model", args.model])

    trainer_main()


def cmd_protect(args):
    """Run the packet interceptor (IPS mode)."""
    from interceptor import AegisInterceptor, setup_iptables

    if os.geteuid() != 0:
        print("❌ Protection mode requires root. Run with sudo.")
        sys.exit(1)

    if args.clean_iptables:
        setup_iptables(args.queue, enable=False)
        sys.exit(0)

    if args.setup_iptables:
        setup_iptables(args.queue, enable=True)

    interceptor = AegisInterceptor(
        queue_num=args.queue,
        model_path=args.model,
        log_file=args.log_file or DEFAULT_THREAT_LOG,
        dry_run=args.dry_run,
    )

    try:
        interceptor.start()
    except KeyboardInterrupt:
        pass
    finally:
        if args.setup_iptables:
            setup_iptables(args.queue, enable=False)


def cmd_dashboard(args):
    """Run the real-time monitoring dashboard."""
    from dashboard import Dashboard

    dash = Dashboard(
        threat_log=args.threat_log or DEFAULT_THREAT_LOG,
        alert_log=args.alert_log,
    )
    dash.run(refresh=args.refresh)


# =============================================================================
# ARGUMENT PARSER
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis NIPS — AI-Powered Network Intrusion Prevention System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s collect  --label 0 --duration 120
  %(prog)s collect  --label 1 --output data/attack.csv --count 5000
  %(prog)s train    --synthetic
  %(prog)s train    --normal data/normal.csv --attack data/attack.csv
  %(prog)s protect  --model models/aegis_model.pkl --setup-iptables
  %(prog)s dashboard
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # ---- collect ----
    p_collect = subparsers.add_parser("collect", help="Capture network traffic for training")
    p_collect.add_argument("--label", type=int, default=0, choices=[0, 1],
                           help="0=normal, 1=attack")
    p_collect.add_argument("--output", type=str, default=None,
                           help="Output CSV path")
    p_collect.add_argument("--duration", type=int, default=None,
                           help="Capture duration in seconds")
    p_collect.add_argument("--count", type=int, default=None,
                           help="Number of packets to capture")
    p_collect.add_argument("--validate", action="store_true",
                           help="Validate engine only")
    p_collect.set_defaults(func=cmd_collect)

    # ---- train ----
    p_train = subparsers.add_parser("train", help="Train the ML model")
    p_train.add_argument("--normal", type=str, default=None,
                         help="Normal traffic CSV")
    p_train.add_argument("--attack", type=str, default=None,
                         help="Attack traffic CSV")
    p_train.add_argument("--synthetic", action="store_true",
                         help="Use synthetic data for demo")
    p_train.add_argument("--model", type=str, default=None,
                         help="Output model path")
    p_train.set_defaults(func=cmd_train)

    # ---- protect ----
    p_protect = subparsers.add_parser("protect", help="Run IPS in protection mode")
    p_protect.add_argument("--model", type=str, default=None,
                           help="Path to trained model")
    p_protect.add_argument("--queue", type=int, default=DEFAULT_QUEUE_NUM,
                           help="NFQUEUE number")
    p_protect.add_argument("--log-file", type=str, default=None,
                           help="Threat log path")
    p_protect.add_argument("--setup-iptables", action="store_true",
                           help="Auto-setup iptables")
    p_protect.add_argument("--clean-iptables", action="store_true",
                           help="Remove iptables rules and exit")
    p_protect.add_argument("--dry-run", action="store_true",
                           help="Run without iptables")
    p_protect.set_defaults(func=cmd_protect)

    # ---- dashboard ----
    p_dash = subparsers.add_parser("dashboard", help="Real-time monitoring")
    p_dash.add_argument("--threat-log", type=str, default=None)
    p_dash.add_argument("--alert-log", type=str, default=None)
    p_dash.add_argument("--refresh", type=float, default=2.0,
                        help="Refresh interval in seconds")
    p_dash.set_defaults(func=cmd_dashboard)

    return parser


# =============================================================================
# MAIN
# =============================================================================

def main():
    ensure_directories()
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print("\n🛡️  Aegis NIPS — Choose a command to get started!")
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
