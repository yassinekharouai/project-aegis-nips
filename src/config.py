"""
Aegis NIPS — Central Configuration
All paths, thresholds, model hyperparameters, and constants live here.
"""

import os

# ==============================================================================
# PATHS
# ==============================================================================
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")

DEFAULT_NORMAL_CSV = os.path.join(DATA_DIR, "normal_log.csv")
DEFAULT_ATTACK_CSV = os.path.join(DATA_DIR, "attack_log.csv")
DEFAULT_MODEL_PATH = os.path.join(MODEL_DIR, "aegis_model.pkl")
DEFAULT_SCALER_PATH = os.path.join(MODEL_DIR, "aegis_scaler.pkl")
DEFAULT_FEATURE_LIST_PATH = os.path.join(MODEL_DIR, "aegis_features.json")
DEFAULT_THREAT_LOG = os.path.join(LOG_DIR, "aegis_threats.jsonl")
DEFAULT_ALERT_LOG = os.path.join(LOG_DIR, "aegis_alerts.jsonl")
DEFAULT_SYSTEM_LOG = os.path.join(LOG_DIR, "aegis.log")

# ==============================================================================
# CANONICAL FEATURE LIST — ORDER MATTERS FOR MODEL INFERENCE
# These are the numeric features used by the ML model, in exact order.
# ==============================================================================
CANONICAL_FEATURES = [
    "packet_size",
    "ttl",
    "protocol",
    "ip_id",
    "ip_flags",
    "payload_size",
    "entropy",
    "sport",
    "dport",
    "flags",
    "tcp_window",
    "tcp_urgptr",
    "tcp_options",
    "syn_flag",
    "ack_flag",
    "rst_flag",
    "fin_flag",
    "psh_flag",
    "urg_flag",
    "suspicious_flags",
    "packet_rate",
    "byte_rate",
    "avg_entropy",
    "port_rate",
    "anomaly_score",
]

# Fields to exclude from ML input (non-numeric / metadata)
NON_NUMERIC_FIELDS = {"src_ip", "dst_ip", "flow", "timestamp", "label", "protocol_name"}

# ==============================================================================
# SECURITY ENGINE THRESHOLDS
# ==============================================================================
LOW_ENTROPY_THRESHOLD = 4.5      # Normal text typically below this
HIGH_ENTROPY_THRESHOLD = 7.5     # Encrypted / random data above this
DOS_RATE_THRESHOLD = 100         # packets/sec to flag as potential DoS
FLOOD_RATE_THRESHOLD = 500       # packets/sec to flag as flood
ANOMALY_DROP_THRESHOLD = 0.7     # anomaly score above which to DROP in heuristic mode

COMMON_PORTS = {80, 443, 53, 22, 25, 3306, 5432, 8080, 8443}
ENCRYPTED_PORTS = {443, 993, 995, 465, 587}
COMMON_TCP_FLAGS = {0x02, 0x10, 0x18}  # SYN, ACK, PSH+ACK

# ==============================================================================
# ML MODEL HYPERPARAMETERS
# ==============================================================================
RANDOM_FOREST_PARAMS = {
    "n_estimators": 200,
    "max_depth": 20,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
    "random_state": 42,
    "n_jobs": -1,
    "class_weight": "balanced",
}

TEST_SPLIT_RATIO = 0.2
CV_FOLDS = 5

# ==============================================================================
# NFQUEUE CONFIGURATION
# ==============================================================================
DEFAULT_QUEUE_NUM = 1

# ==============================================================================
# ALERT MANAGER CONFIGURATION
# ==============================================================================
ALERT_RATE_LIMIT_SECONDS = 10    # Min seconds between alerts for same src IP
ALERT_MAX_BUFFER = 10000         # Max alerts to keep in log file

# ==============================================================================
# DASHBOARD CONFIGURATION
# ==============================================================================
DASHBOARD_REFRESH_SECONDS = 1.0

# ==============================================================================
# SYNTHETIC DATA GENERATION (for demo / testing)
# ==============================================================================
SYNTHETIC_NORMAL_COUNT = 3000
SYNTHETIC_ATTACK_COUNT = 2000

# ==============================================================================
# HELPER — ensure directories exist
# ==============================================================================
def ensure_directories():
    """Create all required directories if they don't exist."""
    for d in [DATA_DIR, MODEL_DIR, REPORT_DIR, LOG_DIR]:
        os.makedirs(d, exist_ok=True)
