# 🛡️ Project Aegis NIPS

**AI-Powered Network Intrusion Prevention System**

A real-time, inline Network Intrusion Prevention System (NIPS) that uses machine learning to detect and block malicious network traffic. Built with Python, Scapy, NFQUEUE, and scikit-learn.

> **Project Type:** Cybersecurity + Machine Learning  
> **Stack:** Python · Scapy · NFQUEUE · scikit-learn · iptables  
> **Platform:** Linux (requires root for live interception)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Documentation](#documentation)

---

## Overview

Aegis NIPS is a complete, end-to-end network intrusion prevention system that goes beyond simple signature-based detection. It combines:

1. **Real-time packet capture** — Sniff live network traffic and extract 25+ features per packet
2. **Machine learning classification** — Random Forest model trained on labelled normal/attack traffic
3. **Inline prevention** — Intercept packets via Linux NFQUEUE and DROP malicious ones in real time
4. **Heuristic fallback** — Shannon entropy analysis, TCP flag anomaly detection, and rate-based DoS detection when no ML model is loaded
5. **Operational tooling** — Alert management, threat logging, and a real-time CLI dashboard

---

## Features

| Category | Feature |
|---|---|
| **Packet Analysis** | 25-feature extraction (header, payload, flow, statistical) |
| **ML Detection** | Random Forest classifier with cross-validated training pipeline |
| **Entropy Analysis** | Shannon entropy to detect encrypted C2 channels on plaintext ports |
| **Flag Detection** | XMAS, NULL, SYN+FIN, SYN+RST scan detection |
| **DoS Detection** | Rate-based packet flood and port-targeted DoS detection |
| **Flow Tracking** | Stateful per-flow packet/byte rate and entropy tracking |
| **Inline Blocking** | NFQUEUE-based real-time packet DROP with iptables integration |
| **Alert System** | Severity-classified alerts (LOW→CRITICAL) with rate limiting |
| **Threat Logging** | JSON-Lines append-only logs for forensic analysis |
| **Dashboard** | Real-time CLI monitoring (plain text or rich terminal) |
| **Attack Simulator** | 9-category attack generator (SYN flood, XSS, SQLi, brute force, etc.) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    NETWORK TRAFFIC                          │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐     ┌────────────────────────────┐
│   iptables + NFQUEUE     │     │   Packet Collector         │
│   (Kernel-space hook)    │     │   (Training mode - Scapy)  │
└──────────┬───────────────┘     └──────────┬─────────────────┘
           │                                │
           ▼                                ▼
┌──────────────────────────────────────────────────────────────┐
│                    SECURITY ENGINE                           │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐   │
│  │  Feature     │  │  Anomaly     │  │  ML Classifier    │   │
│  │  Extraction  │──│  Scoring     │──│  (Random Forest)  │   │
│  │  (25 feats)  │  │  (Heuristic) │  │  predict(X) → 0/1│   │
│  └─────────────┘  └──────────────┘  └───────────────────┘   │
└──────────────────────┬───────────────────────────────────────┘
                       │
            ┌──────────┴──────────┐
            ▼                     ▼
    ┌──────────────┐      ┌──────────────┐
    │   ACCEPT     │      │    DROP      │
    │  (Benign)    │      │  (Malicious) │
    └──────────────┘      └──────┬───────┘
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
            ┌──────────────┐         ┌──────────────┐
            │ Alert Manager│         │ Threat Log   │
            │ (Severity +  │         │ (JSONL)      │
            │  Rate Limit) │         └──────────────┘
            └──────────────┘
```

---

## Installation

### Prerequisites

- **Linux** (Ubuntu/Debian/Kali recommended)
- **Python 3.8+**
- **Root access** (for packet capture and NFQUEUE)

### Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/project-aegis-nips.git
cd project-aegis-nips

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install system dependencies (for NFQUEUE)
sudo apt-get install -y libnetfilter-queue-dev python3-dev
```

---

## Quick Start

```bash
cd src

# Step 1: Generate synthetic data and train the model (no root needed)
python main.py train --synthetic

# Step 2: Run the dashboard to monitor (separate terminal)
python main.py dashboard

# Step 3: Start protection mode (requires root + trained model)
sudo python main.py protect --model ../models/aegis_model.pkl --setup-iptables
```

---

## Usage Guide

### 1. Collect Training Data

```bash
# Collect normal traffic (label=0)
sudo python main.py collect --label 0 --output ../data/normal_log.csv --duration 120

# In another terminal, generate attack traffic
sudo bash ../attack_generator.sh

# Collect attack traffic (label=1)
sudo python main.py collect --label 1 --output ../data/attack_log.csv --duration 120
```

### 2. Train the ML Model

```bash
# Train from collected CSVs
python main.py train --normal ../data/normal_log.csv --attack ../data/attack_log.csv

# Or use synthetic data for demo
python main.py train --synthetic
```

Training output includes:
- Accuracy, Precision, Recall, F1-Score, ROC-AUC
- 5-fold stratified cross-validation
- Feature importance ranking
- Confusion matrix
- Saved model bundle (`models/`)

### 3. Deploy Protection

```bash
# Start the IPS with trained model
sudo python main.py protect --model ../models/aegis_model.pkl --setup-iptables

# Or run in heuristic-only mode (no model)
sudo python main.py protect --setup-iptables

# Cleanup iptables rules when done
sudo python main.py protect --clean-iptables
```

### 4. Monitor

```bash
python main.py dashboard
```

---

## Project Structure

```
project-aegis-nips/
├── src/
│   ├── main.py              # Unified CLI entry point
│   ├── config.py             # Central configuration
│   ├── engine.py             # Security engine (feature extraction + ML + heuristics)
│   ├── trainer.py            # ML training pipeline + synthetic data generator
│   ├── collector.py          # Packet capture for training data
│   ├── interceptor.py        # NFQUEUE-based inline packet interception
│   ├── alert_manager.py      # Severity-classified alerting system
│   ├── dashboard.py          # Real-time CLI monitoring
│   └── __init__.py
├── tests/
│   ├── test_engine.py        # Engine unit tests
│   └── test_trainer.py       # Trainer unit tests
├── data/                     # Training data CSVs (generated)
├── models/                   # Trained model bundles (generated)
├── reports/                  # Training evaluation reports (generated)
├── logs/                     # Runtime logs (generated)
├── attack_generator.sh       # Comprehensive attack simulation script
├── requirements.txt          # Python dependencies
├── ARCHITECTURE.md           # Detailed architecture documentation
├── INTERVIEW_PREP.md         # Interview Q&A for this project
└── README.md
```

---

## How It Works

### Feature Extraction (25 Features)

| # | Feature | Description |
|---|---------|-------------|
| 1 | `packet_size` | Total packet length in bytes |
| 2 | `ttl` | Time-to-Live (low = scanning/traceroute) |
| 3 | `protocol` | IP protocol number (6=TCP, 17=UDP, 1=ICMP) |
| 4 | `ip_id` | IP identification field |
| 5 | `ip_flags` | IP flags (DF, MF) |
| 6 | `payload_size` | Application layer payload size |
| 7 | `entropy` | Shannon entropy of payload (0–8) |
| 8 | `sport` | Source port |
| 9 | `dport` | Destination port |
| 10 | `flags` | TCP flags (combined) |
| 11 | `tcp_window` | TCP window size |
| 12 | `tcp_urgptr` | TCP urgent pointer |
| 13 | `tcp_options` | Number of TCP options |
| 14–19 | `syn/ack/rst/fin/psh/urg_flag` | Individual TCP flag bits |
| 20 | `suspicious_flags` | Anomalous flag combination detected |
| 21 | `packet_rate` | Packets/sec for this flow |
| 22 | `byte_rate` | Bytes/sec for this flow |
| 23 | `avg_entropy` | Rolling average entropy per flow |
| 24 | `port_rate` | Packets/sec to destination port |
| 25 | `anomaly_score` | Composite heuristic score [0, 1] |

### Decision Pipeline

1. **Extract** 25 features from the raw packet
2. **Score** using heuristic rules (entropy, flags, rates)
3. **Classify** with Random Forest model (if loaded)
4. **Verdict**: `ACCEPT`, `DROP`, or `LOG`
5. **Alert** if dropped (severity-classified, rate-limited)

---

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Full technical deep-dive into system design
- **[INTERVIEW_PREP.md](INTERVIEW_PREP.md)** — 30+ interview questions with detailed answers

---

## Running Tests

```bash
cd project-aegis-nips
python -m pytest tests/ -v
```

---

## License

This project is for educational and portfolio purposes.

---

## Author

Cybersecurity student project — AI-Powered Network Intrusion Prevention System.
