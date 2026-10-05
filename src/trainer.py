#!/usr/bin/env python3
"""
Aegis NIPS — ML Model Training Pipeline

Usage:
    # Train from collected CSVs
    python trainer.py --normal data/normal_log.csv --attack data/attack_log.csv

    # Generate synthetic data and train (for demo / testing)
    python trainer.py --synthetic

    # Evaluate an existing model
    python trainer.py --evaluate --model models/aegis_model.pkl
"""

import os
import sys
import json
import pickle
import logging
import argparse
import warnings
from datetime import datetime
from typing import Tuple, List, Dict, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    cross_val_score,
)
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve,
)

from config import (
    CANONICAL_FEATURES,
    NON_NUMERIC_FIELDS,
    RANDOM_FOREST_PARAMS,
    TEST_SPLIT_RATIO,
    CV_FOLDS,
    DEFAULT_NORMAL_CSV,
    DEFAULT_ATTACK_CSV,
    DEFAULT_MODEL_PATH,
    DEFAULT_SCALER_PATH,
    DEFAULT_FEATURE_LIST_PATH,
    MODEL_DIR,
    REPORT_DIR,
    DATA_DIR,
    SYNTHETIC_NORMAL_COUNT,
    SYNTHETIC_ATTACK_COUNT,
    ensure_directories,
)

warnings.filterwarnings("ignore", category=FutureWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA LOADING & PREPROCESSING
# =============================================================================

def load_and_merge(
    normal_path: str,
    attack_path: str,
) -> pd.DataFrame:
    """
    Load normal (label=0) and attack (label=1) CSVs, merge into one DataFrame.
    """
    dfs = []

    if os.path.exists(normal_path):
        df_normal = pd.read_csv(normal_path)
        df_normal["label"] = 0
        dfs.append(df_normal)
        logger.info("Loaded %d normal samples from %s", len(df_normal), normal_path)
    else:
        logger.warning("Normal data not found: %s", normal_path)

    if os.path.exists(attack_path):
        df_attack = pd.read_csv(attack_path)
        df_attack["label"] = 1
        dfs.append(df_attack)
        logger.info("Loaded %d attack samples from %s", len(df_attack), attack_path)
    else:
        logger.warning("Attack data not found: %s", attack_path)

    if not dfs:
        raise FileNotFoundError("No data files found. Provide CSVs or use --synthetic.")

    df = pd.concat(dfs, ignore_index=True)
    logger.info(
        "Merged dataset: %d samples (Normal: %d, Attack: %d)",
        len(df),
        (df["label"] == 0).sum(),
        (df["label"] == 1).sum(),
    )
    return df


def clean_features(df: pd.DataFrame, feature_list: List[str]) -> Tuple[np.ndarray, np.ndarray]:
    """
    Extract numeric feature matrix X and label vector y from the DataFrame.

    Only columns in *feature_list* are kept, in that exact order.
    Missing columns are filled with 0.
    """
    # Extract labels BEFORE dropping non-numeric columns (label is in NON_NUMERIC_FIELDS)
    y = df["label"].values.astype(np.int32)

    # Drop non-numeric columns
    for col in NON_NUMERIC_FIELDS:
        if col in df.columns:
            df = df.drop(columns=[col])

    # Ensure all canonical features exist
    for feat in feature_list:
        if feat not in df.columns:
            df[feat] = 0.0

    # Extract in canonical order
    X = df[feature_list].values.astype(np.float64)

    # Handle NaN / inf
    X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

    logger.info("Feature matrix: %s, Labels: %s", X.shape, y.shape)
    return X, y


# =============================================================================
# SYNTHETIC DATA GENERATOR (for demo / testing without live capture)
# =============================================================================

def generate_synthetic_data(
    n_normal: int = SYNTHETIC_NORMAL_COUNT,
    n_attack: int = SYNTHETIC_ATTACK_COUNT,
    save: bool = True,
) -> pd.DataFrame:
    """
    Generate realistic synthetic network traffic data.

    Normal traffic:
      - Common ports (80, 443, 22, 53)
      - Standard TTL values (64, 128)
      - Low entropy payloads
      - Normal packet rates

    Attack traffic:
      - SYN floods (high rate, SYN flag, no ACK)
      - Port scans (sequential ports, small packets)
      - High-entropy payloads (encrypted C2)
      - XMAS/NULL scans (suspicious flags)
      - DoS (extreme packet rates)
    """
    rng = np.random.default_rng(42)
    rows = []

    # --- Normal traffic ---
    logger.info("Generating %d synthetic normal samples...", n_normal)
    for _ in range(n_normal):
        proto_choice = rng.choice(["tcp_web", "tcp_ssh", "udp_dns", "tcp_https", "tcp_general"])
        row = _gen_normal_packet(rng, proto_choice)
        row["label"] = 0
        rows.append(row)

    # --- Attack traffic ---
    logger.info("Generating %d synthetic attack samples...", n_attack)
    attack_types = ["syn_flood", "port_scan", "xmas_scan", "null_scan",
                    "dos_flood", "encrypted_c2", "brute_force", "udp_flood"]

    per_type = n_attack // len(attack_types)
    remainder = n_attack % len(attack_types)

    for i, attack_type in enumerate(attack_types):
        count = per_type + (1 if i < remainder else 0)
        for _ in range(count):
            row = _gen_attack_packet(rng, attack_type)
            row["label"] = 1
            rows.append(row)

    df = pd.DataFrame(rows)

    if save:
        ensure_directories()
        normal_df = df[df["label"] == 0]
        attack_df = df[df["label"] == 1]
        normal_df.to_csv(os.path.join(DATA_DIR, "synthetic_normal.csv"), index=False)
        attack_df.to_csv(os.path.join(DATA_DIR, "synthetic_attack.csv"), index=False)
        logger.info("Synthetic data saved to data/synthetic_*.csv")

    return df


def _gen_normal_packet(rng, proto_type: str) -> Dict:
    """Generate a single normal packet's features."""
    row = {}

    if proto_type == "tcp_web":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = 80
        row["protocol"] = 6
        row["packet_size"] = rng.integers(60, 1500)
        row["ttl"] = rng.choice([64, 128]) + rng.integers(-3, 4)
        row["entropy"] = rng.uniform(2.0, 5.0)
        row["payload_size"] = rng.integers(0, 1400)
        row["tcp_window"] = rng.integers(8000, 65535)
        row["syn_flag"] = rng.choice([0, 1], p=[0.8, 0.2])
        row["ack_flag"] = 1 if not row["syn_flag"] else rng.choice([0, 1])
        row["psh_flag"] = rng.choice([0, 1], p=[0.6, 0.4])
        row["flags"] = (row["syn_flag"] << 1) | (row["ack_flag"] << 4) | (row["psh_flag"] << 3)
    elif proto_type == "tcp_https":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = 443
        row["protocol"] = 6
        row["packet_size"] = rng.integers(60, 1500)
        row["ttl"] = rng.choice([64, 128]) + rng.integers(-3, 4)
        row["entropy"] = rng.uniform(6.0, 8.0)  # encrypted
        row["payload_size"] = rng.integers(100, 1400)
        row["tcp_window"] = rng.integers(8000, 65535)
        row["syn_flag"] = rng.choice([0, 1], p=[0.85, 0.15])
        row["ack_flag"] = 1 if not row["syn_flag"] else 0
        row["psh_flag"] = rng.choice([0, 1], p=[0.5, 0.5])
        row["flags"] = (row["syn_flag"] << 1) | (row["ack_flag"] << 4) | (row["psh_flag"] << 3)
    elif proto_type == "tcp_ssh":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = 22
        row["protocol"] = 6
        row["packet_size"] = rng.integers(60, 600)
        row["ttl"] = rng.choice([64, 128]) + rng.integers(-2, 3)
        row["entropy"] = rng.uniform(5.5, 7.5)
        row["payload_size"] = rng.integers(20, 500)
        row["tcp_window"] = rng.integers(8000, 65535)
        row["syn_flag"] = rng.choice([0, 1], p=[0.9, 0.1])
        row["ack_flag"] = 1
        row["psh_flag"] = rng.choice([0, 1])
        row["flags"] = (row["syn_flag"] << 1) | (row["ack_flag"] << 4) | (row["psh_flag"] << 3)
    elif proto_type == "udp_dns":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = 53
        row["protocol"] = 17
        row["packet_size"] = rng.integers(40, 512)
        row["ttl"] = rng.choice([64, 128]) + rng.integers(-2, 3)
        row["entropy"] = rng.uniform(3.0, 5.5)
        row["payload_size"] = rng.integers(20, 300)
        row["tcp_window"] = 0
        row["syn_flag"] = 0
        row["ack_flag"] = 0
        row["psh_flag"] = 0
        row["flags"] = 0
    else:  # tcp_general
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = rng.choice([80, 443, 8080, 8443, 3306, 5432])
        row["protocol"] = 6
        row["packet_size"] = rng.integers(60, 1500)
        row["ttl"] = rng.choice([64, 128]) + rng.integers(-3, 4)
        row["entropy"] = rng.uniform(2.0, 6.0)
        row["payload_size"] = rng.integers(0, 1400)
        row["tcp_window"] = rng.integers(8000, 65535)
        row["syn_flag"] = rng.choice([0, 1], p=[0.85, 0.15])
        row["ack_flag"] = 1 if not row["syn_flag"] else 0
        row["psh_flag"] = rng.choice([0, 1], p=[0.6, 0.4])
        row["flags"] = (row["syn_flag"] << 1) | (row["ack_flag"] << 4) | (row["psh_flag"] << 3)

    # Common fields
    row.setdefault("rst_flag", 0)
    row.setdefault("fin_flag", 0)
    row.setdefault("urg_flag", 0)
    row["ip_id"] = rng.integers(0, 65535)
    row["ip_flags"] = rng.choice([0, 2])  # 0=none, 2=DF
    row["tcp_urgptr"] = 0
    row["tcp_options"] = rng.integers(0, 5)
    row["suspicious_flags"] = 0
    row["packet_rate"] = rng.uniform(0.1, 20.0)
    row["byte_rate"] = row["packet_rate"] * row["packet_size"]
    row["avg_entropy"] = row["entropy"] + rng.uniform(-0.5, 0.5)
    row["port_rate"] = rng.uniform(0.1, 30.0)
    row["anomaly_score"] = rng.uniform(0.0, 0.3)

    return row


def _gen_attack_packet(rng, attack_type: str) -> Dict:
    """Generate a single attack packet's features."""
    row = {}

    if attack_type == "syn_flood":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = rng.choice([80, 443, 22, 8080])
        row["protocol"] = 6
        row["packet_size"] = rng.integers(40, 80)  # small
        row["ttl"] = rng.integers(20, 255)  # spoofed, random TTL
        row["entropy"] = rng.uniform(0.0, 2.0)  # no payload
        row["payload_size"] = 0
        row["tcp_window"] = rng.integers(1024, 65535)
        row["syn_flag"] = 1
        row["ack_flag"] = 0
        row["rst_flag"] = 0
        row["fin_flag"] = 0
        row["psh_flag"] = 0
        row["urg_flag"] = 0
        row["flags"] = 0x02  # SYN only
        row["suspicious_flags"] = 0
        row["packet_rate"] = rng.uniform(200, 5000)  # very high
        row["port_rate"] = rng.uniform(150, 3000)
        row["anomaly_score"] = rng.uniform(0.6, 1.0)

    elif attack_type == "port_scan":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = rng.integers(1, 1024)  # scanning privileged ports
        row["protocol"] = 6
        row["packet_size"] = rng.integers(40, 70)
        row["ttl"] = rng.choice([64, 128]) + rng.integers(-5, 5)
        row["entropy"] = 0.0
        row["payload_size"] = 0
        row["tcp_window"] = rng.integers(1024, 4096)
        row["syn_flag"] = 1
        row["ack_flag"] = 0
        row["rst_flag"] = 0
        row["fin_flag"] = 0
        row["psh_flag"] = 0
        row["urg_flag"] = 0
        row["flags"] = 0x02
        row["suspicious_flags"] = 0
        row["packet_rate"] = rng.uniform(50, 500)
        row["port_rate"] = rng.uniform(0.5, 5.0)  # low per-port but many ports
        row["anomaly_score"] = rng.uniform(0.4, 0.8)

    elif attack_type == "xmas_scan":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = rng.integers(1, 1024)
        row["protocol"] = 6
        row["packet_size"] = rng.integers(40, 70)
        row["ttl"] = rng.choice([64, 128])
        row["entropy"] = 0.0
        row["payload_size"] = 0
        row["tcp_window"] = 0
        row["syn_flag"] = 0
        row["ack_flag"] = 0
        row["rst_flag"] = 0
        row["fin_flag"] = 1
        row["psh_flag"] = 1
        row["urg_flag"] = 1
        row["flags"] = 0x29  # FIN+PSH+URG
        row["suspicious_flags"] = 1
        row["packet_rate"] = rng.uniform(10, 200)
        row["port_rate"] = rng.uniform(0.5, 5.0)
        row["anomaly_score"] = rng.uniform(0.7, 1.0)

    elif attack_type == "null_scan":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = rng.integers(1, 1024)
        row["protocol"] = 6
        row["packet_size"] = rng.integers(40, 60)
        row["ttl"] = rng.choice([64, 128])
        row["entropy"] = 0.0
        row["payload_size"] = 0
        row["tcp_window"] = 0
        row["syn_flag"] = 0
        row["ack_flag"] = 0
        row["rst_flag"] = 0
        row["fin_flag"] = 0
        row["psh_flag"] = 0
        row["urg_flag"] = 0
        row["flags"] = 0
        row["suspicious_flags"] = 1
        row["packet_rate"] = rng.uniform(10, 200)
        row["port_rate"] = rng.uniform(0.5, 5.0)
        row["anomaly_score"] = rng.uniform(0.7, 1.0)

    elif attack_type == "dos_flood":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = rng.choice([80, 443])
        row["protocol"] = rng.choice([6, 17])
        row["packet_size"] = rng.integers(40, 1500)
        row["ttl"] = rng.integers(10, 255)
        row["entropy"] = rng.uniform(0.0, 4.0)
        row["payload_size"] = rng.integers(0, 1400)
        row["tcp_window"] = rng.integers(0, 65535)
        row["syn_flag"] = rng.choice([0, 1])
        row["ack_flag"] = rng.choice([0, 1])
        row["rst_flag"] = 0
        row["fin_flag"] = 0
        row["psh_flag"] = 0
        row["urg_flag"] = 0
        row["flags"] = (row["syn_flag"] << 1) | (row["ack_flag"] << 4)
        row["suspicious_flags"] = 0
        row["packet_rate"] = rng.uniform(500, 10000)
        row["port_rate"] = rng.uniform(300, 8000)
        row["anomaly_score"] = rng.uniform(0.7, 1.0)

    elif attack_type == "encrypted_c2":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = rng.choice([80, 8080, 8443, 4444, 5555])  # non-standard
        row["protocol"] = 6
        row["packet_size"] = rng.integers(200, 1400)
        row["ttl"] = rng.choice([64, 128])
        row["entropy"] = rng.uniform(7.2, 8.0)  # very high — encrypted C2
        row["payload_size"] = rng.integers(200, 1200)
        row["tcp_window"] = rng.integers(8000, 65535)
        row["syn_flag"] = 0
        row["ack_flag"] = 1
        row["rst_flag"] = 0
        row["fin_flag"] = 0
        row["psh_flag"] = 1
        row["urg_flag"] = 0
        row["flags"] = 0x18  # ACK+PSH
        row["suspicious_flags"] = 0
        row["packet_rate"] = rng.uniform(1, 30)
        row["port_rate"] = rng.uniform(1, 20)
        row["anomaly_score"] = rng.uniform(0.4, 0.8)

    elif attack_type == "brute_force":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = rng.choice([22, 3389, 21, 23])
        row["protocol"] = 6
        row["packet_size"] = rng.integers(60, 400)
        row["ttl"] = rng.choice([64, 128])
        row["entropy"] = rng.uniform(3.0, 6.0)
        row["payload_size"] = rng.integers(20, 300)
        row["tcp_window"] = rng.integers(8000, 65535)
        row["syn_flag"] = rng.choice([0, 1], p=[0.7, 0.3])
        row["ack_flag"] = 1
        row["rst_flag"] = 0
        row["fin_flag"] = rng.choice([0, 1], p=[0.8, 0.2])
        row["psh_flag"] = 1
        row["urg_flag"] = 0
        row["flags"] = (row["syn_flag"] << 1) | (row["ack_flag"] << 4) | (row["psh_flag"] << 3)
        row["suspicious_flags"] = 0
        row["packet_rate"] = rng.uniform(30, 200)
        row["port_rate"] = rng.uniform(30, 150)
        row["anomaly_score"] = rng.uniform(0.3, 0.7)

    elif attack_type == "udp_flood":
        row["sport"] = rng.integers(1024, 65535)
        row["dport"] = rng.integers(1, 65535)
        row["protocol"] = 17
        row["packet_size"] = rng.integers(40, 1500)
        row["ttl"] = rng.integers(10, 255)
        row["entropy"] = rng.uniform(0.0, 5.0)
        row["payload_size"] = rng.integers(0, 1400)
        row["tcp_window"] = 0
        row["syn_flag"] = 0
        row["ack_flag"] = 0
        row["rst_flag"] = 0
        row["fin_flag"] = 0
        row["psh_flag"] = 0
        row["urg_flag"] = 0
        row["flags"] = 0
        row["suspicious_flags"] = 0
        row["packet_rate"] = rng.uniform(300, 8000)
        row["port_rate"] = rng.uniform(200, 5000)
        row["anomaly_score"] = rng.uniform(0.6, 1.0)

    # Common computed fields
    row["ip_id"] = rng.integers(0, 65535)
    row["ip_flags"] = rng.choice([0, 2])
    row["tcp_urgptr"] = 0
    row["tcp_options"] = rng.integers(0, 3)
    row["byte_rate"] = row.get("packet_rate", 1) * row.get("packet_size", 100)
    row["avg_entropy"] = row.get("entropy", 0) + rng.uniform(-0.3, 0.3)

    return row


# =============================================================================
# MODEL TRAINING
# =============================================================================

def train_model(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: List[str],
) -> Tuple:
    """
    Train a Random Forest classifier.

    Returns:
        (model, scaler, X_test, y_test, y_pred, y_prob)
    """
    logger.info("=" * 60)
    logger.info("TRAINING PIPELINE")
    logger.info("=" * 60)

    # ---- Split ----
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SPLIT_RATIO,
        random_state=42,
        stratify=y,
    )
    logger.info("Train: %d samples | Test: %d samples", len(X_train), len(X_test))

    # ---- Scale ----
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # ---- Train ----
    logger.info("Training Random Forest with params: %s", RANDOM_FOREST_PARAMS)
    model = RandomForestClassifier(**RANDOM_FOREST_PARAMS)
    model.fit(X_train_scaled, y_train)

    # ---- Predict ----
    y_pred = model.predict(X_test_scaled)
    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    # ---- Cross-validation ----
    logger.info("Running %d-fold stratified cross-validation...", CV_FOLDS)
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=cv, scoring="f1")
    logger.info("CV F1 scores: %s", [f"{s:.4f}" for s in cv_scores])
    logger.info("CV F1 mean: %.4f (±%.4f)", cv_scores.mean(), cv_scores.std())

    return model, scaler, X_test, y_test, y_pred, y_prob


# =============================================================================
# EVALUATION
# =============================================================================

def evaluate_model(
    y_test: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    feature_names: List[str],
    model,
) -> Dict:
    """Compute and log all evaluation metrics."""
    logger.info("=" * 60)
    logger.info("EVALUATION RESULTS")
    logger.info("=" * 60)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    try:
        auc = roc_auc_score(y_test, y_prob)
    except ValueError:
        auc = 0.0

    logger.info("Accuracy:  %.4f", acc)
    logger.info("Precision: %.4f", prec)
    logger.info("Recall:    %.4f", rec)
    logger.info("F1 Score:  %.4f", f1)
    logger.info("ROC AUC:   %.4f", auc)
    logger.info("Confusion Matrix:\n%s", cm)

    report_str = classification_report(
        y_test, y_pred,
        target_names=["Normal (0)", "Attack (1)"],
        zero_division=0,
    )
    logger.info("\n%s", report_str)

    # Feature importances
    importances = model.feature_importances_
    feat_imp = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1],
        reverse=True,
    )
    logger.info("Top 10 Feature Importances:")
    for name, imp in feat_imp[:10]:
        logger.info("  %-20s %.4f", name, imp)

    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "roc_auc": float(auc),
        "confusion_matrix": cm.tolist(),
        "feature_importances": {n: float(i) for n, i in feat_imp},
        "classification_report": report_str,
    }


# =============================================================================
# SAVE / EXPORT
# =============================================================================

def save_model_bundle(
    model,
    scaler: StandardScaler,
    feature_names: List[str],
    metrics: Dict,
    model_path: str = DEFAULT_MODEL_PATH,
    scaler_path: str = DEFAULT_SCALER_PATH,
    features_path: str = DEFAULT_FEATURE_LIST_PATH,
) -> None:
    """Save model, scaler, feature list, and report as a bundle."""
    ensure_directories()

    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    logger.info("Model saved:   %s", model_path)

    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    logger.info("Scaler saved:  %s", scaler_path)

    with open(features_path, "w") as f:
        json.dump(feature_names, f, indent=2)
    logger.info("Features saved: %s", features_path)

    # Save report
    report_path = os.path.join(
        REPORT_DIR,
        f"training_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
    )
    report = {
        "timestamp": datetime.now().isoformat(),
        "model_path": model_path,
        "feature_count": len(feature_names),
        "metrics": metrics,
        "hyperparameters": RANDOM_FOREST_PARAMS,
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved:  %s", report_path)


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Aegis NIPS — ML Model Training Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python trainer.py --synthetic
  python trainer.py --normal data/normal_log.csv --attack data/attack_log.csv
  python trainer.py --evaluate --model models/aegis_model.pkl
        """,
    )
    parser.add_argument("--normal", type=str, default=DEFAULT_NORMAL_CSV,
                        help="Path to normal traffic CSV")
    parser.add_argument("--attack", type=str, default=DEFAULT_ATTACK_CSV,
                        help="Path to attack traffic CSV")
    parser.add_argument("--synthetic", action="store_true",
                        help="Generate synthetic data and train")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL_PATH,
                        help="Output model path")
    parser.add_argument("--evaluate", action="store_true",
                        help="Evaluate existing model (requires --model)")
    args = parser.parse_args()

    ensure_directories()
    feature_names = list(CANONICAL_FEATURES)

    if args.synthetic:
        logger.info("Generating synthetic training data...")
        df = generate_synthetic_data()
    else:
        df = load_and_merge(args.normal, args.attack)

    X, y = clean_features(df, feature_names)

    model, scaler, X_test, y_test, y_pred, y_prob = train_model(X, y, feature_names)

    metrics = evaluate_model(y_test, y_pred, y_prob, feature_names, model)

    save_model_bundle(model, scaler, feature_names, metrics, model_path=args.model)

    logger.info("=" * 60)
    logger.info("TRAINING COMPLETE")
    logger.info("=" * 60)
    logger.info("Model ready at: %s", args.model)
    logger.info("To use: python main.py protect --model %s", args.model)


if __name__ == "__main__":
    main()
