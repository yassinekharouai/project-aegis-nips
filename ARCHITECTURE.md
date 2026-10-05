# 🏗️ Project Aegis NIPS — Architecture Document

A comprehensive technical deep-dive into the design, implementation, and rationale behind every component of the Aegis AI-Powered Network Intrusion Prevention System.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Data Flow Architecture](#2-data-flow-architecture)
3. [Component Deep-Dive](#3-component-deep-dive)
   - [3.1 Configuration Module](#31-configuration-module-configpy)
   - [3.2 Security Engine](#32-security-engine-enginepy)
   - [3.3 ML Training Pipeline](#33-ml-training-pipeline-trainerpy)
   - [3.4 Packet Collector](#34-packet-collector-collectorpy)
   - [3.5 Packet Interceptor](#35-packet-interceptor-interceptorpy)
   - [3.6 Alert Manager](#36-alert-manager-alert_managerpy)
   - [3.7 Dashboard](#37-dashboard-dashboardpy)
   - [3.8 Attack Generator](#38-attack-generator-attack_generatorsh)
4. [Feature Engineering](#4-feature-engineering)
5. [Machine Learning Pipeline](#5-machine-learning-pipeline)
6. [Security Architecture](#6-security-architecture)
7. [Performance Considerations](#7-performance-considerations)
8. [Deployment Model](#8-deployment-model)
9. [Design Decisions & Trade-offs](#9-design-decisions--trade-offs)
10. [Limitations & Future Work](#10-limitations--future-work)

---

## 1. System Overview

### 1.1 What Is Aegis?

Aegis is a **Network Intrusion Prevention System (NIPS)** — not merely a detection system (IDS). The critical distinction:

| Capability | IDS | IPS (Aegis) |
|---|---|---|
| Detect threats | ✅ | ✅ |
| Alert on threats | ✅ | ✅ |
| **Block threats in real-time** | ❌ | ✅ |
| Packet modification | ❌ | Possible |

Aegis sits **inline** in the network stack using Linux NFQUEUE. Every packet passes through Aegis before being allowed into or out of the system. This enables real-time DROP of malicious packets — the attacker's packets are silently discarded before they reach the application.

### 1.2 Dual-Mode Operation

Aegis operates in two modes:

**Collection Mode** (no model loaded):
- All packets are ACCEPTED
- Features are extracted and saved to CSV for training
- Heuristic anomaly scoring flags suspicious packets for labelling
- Used during Phase 1-2 of deployment

**Inference Mode** (model loaded):
- Packets are classified by the Random Forest model
- Malicious packets (prediction=1) are DROPPED
- Benign packets (prediction=0) are ACCEPTED
- Falls back to heuristic scoring if model inference fails
- Used during Phase 3+ (production)

### 1.3 Technology Stack

| Component | Technology | Why |
|---|---|---|
| Packet capture | Scapy | Deep packet inspection, protocol dissection, pure Python |
| Inline interception | NFQUEUE (netfilterqueue) | Kernel-space hook, userspace verdict, zero-copy |
| Firewall integration | iptables | Standard Linux firewall, NFQUEUE target |
| ML model | scikit-learn (Random Forest) | Interpretable, fast inference, handles tabular data well |
| Feature scaling | StandardScaler | Normalize feature distributions for ML |
| Data handling | pandas + numpy | Efficient tabular data and numerical operations |
| Logging | Python logging + JSON-Lines | Structured, append-only, parseable |
| Dashboard | rich (optional) | Beautiful terminal UI, graceful degradation |

---

## 2. Data Flow Architecture

### 2.1 Training Data Flow

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Normal      │     │  Packet          │     │  CSV File       │
│  Network     │────▶│  Collector       │────▶│  label=0        │
│  Traffic     │     │  (Scapy sniff)   │     │  normal_log.csv │
└──────────────┘     └──────────────────┘     └────────┬────────┘
                                                       │
┌──────────────┐     ┌──────────────────┐     ┌────────▼────────┐
│  Attack      │     │  Packet          │     │  CSV File       │
│  Traffic     │────▶│  Collector       │────▶│  label=1        │
│  (generator) │     │  (Scapy sniff)   │     │  attack_log.csv │
└──────────────┘     └──────────────────┘     └────────┬────────┘
                                                       │
                     ┌──────────────────┐     ┌────────▼────────┐
                     │  Trainer         │     │  Merged         │
                     │  (Pipeline)      │◀────│  Dataset        │
                     └────────┬─────────┘     └─────────────────┘
                              │
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
       ┌──────────┐   ┌──────────┐   ┌──────────┐
       │  Model   │   │  Scaler  │   │  Feature │
       │  .pkl    │   │  .pkl    │   │  List    │
       └──────────┘   └──────────┘   └──────────┘
```

### 2.2 Live Protection Data Flow

```
            NETWORK
               │
               ▼
┌──────────────────────────┐
│  iptables (kernel)       │
│  -j NFQUEUE --queue-num 1│
└──────────┬───────────────┘
           │ raw packet bytes
           ▼
┌──────────────────────────┐
│  NetfilterQueue          │
│  (userspace binding)     │
└──────────┬───────────────┘
           │ packet object
           ▼
┌──────────────────────────┐
│  AegisInterceptor        │
│  .packet_callback()      │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  SecurityEngine          │
│  1. extract_features()   │──▶ 25 numeric features
│  2. decide()             │──▶ (ACCEPT|DROP|LOG, confidence)
└──────────┬───────────────┘
           │
      ┌────┴────┐
      ▼         ▼
  ACCEPT      DROP
  packet      packet
  .accept()   .drop()
                │
                ▼
         ┌──────────────┐
         │ AlertManager │──▶ JSONL log
         │ (rate-limit) │──▶ Console output
         └──────────────┘
```

### 2.3 How NFQUEUE Works (Critical Concept)

NFQUEUE is the mechanism that makes this an **IPS** rather than a passive IDS.

1. **iptables rule** redirects packets to a queue: `iptables -I INPUT -j NFQUEUE --queue-num 1`
2. Packets arrive at the queue in **kernel space** and are held there
3. Our Python program (userspace) **binds** to the queue via `netfilterqueue`
4. For each packet, our callback receives the raw bytes
5. We parse with Scapy, extract features, run the model
6. We issue a **verdict**: `packet.accept()` or `packet.drop()`
7. The kernel executes the verdict — the packet is either forwarded or silently discarded

This is fundamentally different from Scapy's `sniff()`, which only **copies** packets — it cannot block them. NFQUEUE provides true inline interception.

---

## 3. Component Deep-Dive

### 3.1 Configuration Module (`config.py`)

**Purpose:** Single source of truth for all paths, thresholds, hyperparameters, and constants.

**Key Design:**
- `CANONICAL_FEATURES` — An ordered list of 25 feature names. This is the most critical configuration: the ML model's input vector must be in this exact order. Both `trainer.py` (training) and `engine.py` (inference) reference this list.
- `NON_NUMERIC_FIELDS` — Fields to exclude from ML input (IP addresses, timestamps, flow IDs)
- `RANDOM_FOREST_PARAMS` — Hyperparameters in one place for easy tuning
- `ensure_directories()` — Creates `data/`, `models/`, `reports/`, `logs/` on first run

**Why centralized config matters:** Without this, every module hardcodes its own paths and thresholds. When you change the model directory, you'd have to update 5 files. With `config.py`, you change it once.

---

### 3.2 Security Engine (`engine.py`)

**Purpose:** The core analytical brain — feature extraction, anomaly scoring, and ML-based decision making.

**Class: `SecurityEngine`**

#### Feature Extraction (`extract_features()`)

Takes a Scapy packet object and returns a dictionary of 25 numeric features:

**Basic IP Features:**
- `packet_size` — Total length (larger than typical → data exfiltration risk)
- `ttl` — Time-to-Live (very low TTL → traceroute/scanning; randomized TTL → spoofed)
- `protocol` — IP protocol number (6=TCP, 17=UDP, 1=ICMP)
- `ip_id`, `ip_flags` — Fragment identification and flags

**Payload Analysis:**
- `payload_size` — Application-layer data length
- `entropy` — Shannon entropy of payload bytes (0.0–8.0)
  - 0–4.5 = plaintext/structured data
  - 4.5–6.5 = compressed/encoded
  - 6.5–8.0 = encrypted/random (suspicious on plaintext ports)

**Transport Layer:**
- `sport`, `dport` — Source/destination ports
- `flags` — Combined TCP flags value
- `tcp_window` — Advertised window size
- `tcp_urgptr` — Urgent pointer (non-zero → unusual)
- `tcp_options` — Number of TCP options
- Individual flag bits: `syn_flag`, `ack_flag`, `rst_flag`, `fin_flag`, `psh_flag`, `urg_flag`

**Security Indicators:**
- `suspicious_flags` — Binary flag for impossible TCP combos (XMAS, NULL, SYN+FIN, SYN+RST)

**Flow-State Features (stateful):**
- `packet_rate` — Packets/sec for this source→destination flow
- `byte_rate` — Bytes/sec for this flow
- `avg_entropy` — Rolling average entropy across the flow
- `port_rate` — Packets/sec targeting this specific port (DoS detection)

**Composite Score:**
- `anomaly_score` — Weighted combination of 7 heuristic signals, capped at 1.0

#### Anomaly Scoring (`_calculate_anomaly_score()`)

A rule-based heuristic that produces a score from 0.0 (normal) to 1.0 (highly anomalous):

| Signal | Weight | Rationale |
|---|---|---|
| High entropy on plaintext port | +0.3 | Encrypted C2 over HTTP |
| Suspicious TCP flag combo | +0.5 | XMAS/NULL/SYN+FIN scans |
| Unusual privileged port | +0.2 | Service on non-standard port |
| High port_rate (>100 pps) | +0.4 | Port-targeted DoS |
| Low TTL (<32) | +0.2 | Traceroute/scanning |
| Empty payload on data port | +0.1 | Probe/scan behavior |
| Rapid connection setup | +0.1 | Automated scanning |

This score serves dual purpose:
1. **As a feature** — the ML model uses it as one of its 25 inputs
2. **As a fallback** — when no model is loaded, packets with score > 0.7 are flagged

#### Decision Engine (`decide()`)

Two-tier decision making:

```
if model is None:
    → Heuristic mode: ACCEPT everything, LOG if anomaly > 0.7
else:
    → ML mode: predict(features) → 0=ACCEPT, 1=DROP
    → If model fails: fallback to heuristic
```

#### Model Input Preparation (`_prepare_for_model()`)

Critical function that converts the feature dictionary into an ordered float list:
```python
vector = [float(features.get(f, 0.0)) for f in self.feature_names]
```

This guarantees the model always receives features in the same order it was trained on, regardless of dictionary insertion order. Missing features default to 0.0.

If a StandardScaler was saved during training, it's applied here to normalize values.

---

### 3.3 ML Training Pipeline (`trainer.py`)

**Purpose:** End-to-end pipeline from raw CSV data to saved model bundle.

#### Data Loading (`load_and_merge()`)

- Reads separate normal (label=0) and attack (label=1) CSV files
- Merges into a single DataFrame
- Handles missing files gracefully

#### Feature Cleaning (`clean_features()`)

- Drops non-numeric columns (IP addresses, timestamps, flow IDs)
- Ensures all 25 canonical features exist (fills missing with 0.0)
- Extracts feature matrix X and label vector y in canonical column order
- Replaces NaN/inf with safe values

#### Synthetic Data Generator

Generates realistic fake traffic for demo/testing without needing live capture:

**Normal Traffic Profiles:**
- `tcp_web` — HTTP on port 80, low entropy, mixed SYN/ACK
- `tcp_https` — HTTPS on port 443, high entropy (encrypted, expected)
- `tcp_ssh` — SSH on port 22, medium-high entropy
- `udp_dns` — DNS on port 53, small packets, medium entropy
- `tcp_general` — Various common ports

**Attack Traffic Profiles:**
- `syn_flood` — Small packets, SYN-only, extremely high packet rates
- `port_scan` — Sequential low ports, SYN-only, no payload
- `xmas_scan` — FIN+PSH+URG flags, suspicious_flags=1
- `null_scan` — No flags set, suspicious_flags=1
- `dos_flood` — Very high rates, mixed protocols
- `encrypted_c2` — High entropy on non-encrypted ports (C2 channel)
- `brute_force` — SSH/RDP repeated connections
- `udp_flood` — Random ports, extreme rates

#### Model Training (`train_model()`)

1. **Train/Test Split** — 80/20, stratified (preserves class balance)
2. **Feature Scaling** — `StandardScaler` (zero mean, unit variance)
3. **Random Forest Training** — 200 trees, max_depth=20, balanced class weights
4. **Cross-Validation** — 5-fold stratified CV with F1 scoring
5. **Prediction** — On held-out test set

**Why Random Forest?**
- Handles tabular data very well (our features are structured, not images/text)
- Robust to feature scale differences (though we still scale)
- Provides feature importance rankings (interpretability for interviews!)
- Fast inference (~0.1ms per prediction)
- Handles class imbalance with `class_weight='balanced'`
- No need for feature selection — inherent feature selection via information gain

#### Evaluation (`evaluate_model()`)

Computes all standard ML metrics:
- **Accuracy** — Overall correctness
- **Precision** — Of packets we dropped, how many were actually attacks? (avoid blocking legit traffic)
- **Recall** — Of all attacks, how many did we catch? (miss rate)
- **F1 Score** — Harmonic mean of precision/recall
- **ROC-AUC** — Area under the ROC curve (model quality independent of threshold)
- **Confusion Matrix** — True/false positives/negatives
- **Feature Importances** — Which features matter most for classification

#### Model Bundle Persistence

Saves three files as a "bundle":
- `aegis_model.pkl` — The trained Random Forest
- `aegis_scaler.pkl` — The fitted StandardScaler
- `aegis_features.json` — The feature name list (for correct column ordering)

Plus a timestamped JSON report in `reports/`.

---

### 3.4 Packet Collector (`collector.py`)

**Purpose:** Capture live network traffic and save labelled feature CSVs.

**Key Design Decisions:**
- `--label` flag (0 or 1) — Set the label at capture time instead of editing code
- **Append mode** — If the CSV already exists, new packets are appended (don't lose data)
- **Signal handler** — Ctrl+C saves data before exiting (no data loss)
- **Engine validation** — Before starting, creates a test packet and verifies feature extraction works
- **Progress reporting** — Every 100 packets, logs count, protocol breakdown, and capture rate

**Capture Methods:**
- Duration-based: `--duration 120` (capture for 2 minutes)
- Count-based: `--count 5000` (capture exactly 5000 packets)
- Indefinite: Run until Ctrl+C

---

### 3.5 Packet Interceptor (`interceptor.py`)

**Purpose:** Real-time inline packet interception and blocking via NFQUEUE.

**Critical Design: Fail-Safe**
```python
except Exception as e:
    packet.accept()  # NEVER block traffic due to our own bugs
```

If any error occurs during feature extraction or model inference, the packet is **accepted**. This prevents a bug in Aegis from causing a denial of service against the host system.

**iptables Integration:**
- `--setup-iptables` — Automatically adds NFQUEUE rules to INPUT, OUTPUT, and FORWARD chains
- `--clean-iptables` — Removes the rules on exit
- Rules are also cleaned up in the `finally` block (crash-safe)

**Performance Tracking:**
- Latency: measures time from packet arrival to verdict (target: <1ms)
- PPS: packets per second throughput
- Drop rate: percentage of packets dropped
- Rolling window of 1000 latency samples

**Threat Logging:**
- JSONL (JSON-Lines) format — one JSON object per line
- Append-only — O(1) per write (vs. the original code which read/wrote the entire JSON array on every packet — O(n))
- Records: timestamp, IPs, ports, threat type, confidence, anomaly score

---

### 3.6 Alert Manager (`alert_manager.py`)

**Purpose:** Structured alerting with severity classification and rate limiting.

**Severity Classification:**

| Level | Criteria | Examples |
|---|---|---|
| CRITICAL | Active exploitation, high confidence | XMAS scan, NULL scan, SYN+FIN |
| HIGH | DoS, floods, encrypted C2 | SYN flood, UDP flood |
| MEDIUM | Moderate confidence anomalies | Unusual port + protocol |
| LOW | Informational | Minor anomaly score |

**Rate Limiting:**
- Tracks `{src_ip: last_alert_timestamp}` in memory
- Suppresses alerts from the same source IP within `ALERT_RATE_LIMIT_SECONDS` (default: 10s)
- Prevents log flooding during active attacks (a SYN flood generates thousands of packets per second — you don't want thousands of alerts)

**Aggregation:**
- Tracks `{src_ip: {threat_type: count}}` for repeat offender analysis
- `get_top_offenders()` — Top N source IPs by total alert count
- `get_threat_summary()` — Aggregate threat type distribution

---

### 3.7 Dashboard (`dashboard.py`)

**Purpose:** Real-time terminal monitoring.

**Graceful Degradation:**
- If `rich` library is installed → beautiful colorized tables with severity-coded output
- If not → plain-text dashboard with ASCII bars

**Data Source:** Reads JSONL log files on each refresh cycle (default: 2 seconds). Does not require a running interceptor — can be used for post-incident analysis too.

**Displays:**
- Severity breakdown (CRITICAL/HIGH/MEDIUM/LOW with visual bars)
- Threat type distribution
- Top source IPs
- Recent threat timeline

---

### 3.8 Attack Generator (`attack_generator.sh`)

**Purpose:** Generate realistic attack traffic for model training.

**9 Attack Categories:**

1. **Network Layer** — SYN flood, UDP flood, ICMP flood, fragmentation, FIN/XMAS/ACK/NULL scans, IP spoofing
2. **Transport Layer** — SYN-ACK flood, RST flood, TCP connection flood, port scans
3. **Application Layer** — Slowloris, Slow POST, HTTP pipelining flood, HTTP request flood
4. **Web Application** — SQLi, XSS, command injection, path traversal, directory brute-force
5. **Authentication** — HTTP login brute force, Basic auth brute force, session hijacking, JWT attacks
6. **DDoS/Amplification** — DNS, NTP, Memcached, SSDP amplification
7. **Protocol-Specific** — SSL/TLS downgrade, DNS cache poisoning, ARP spoofing, DHCP starvation
8. **Malware/Payloads** — Metasploit payloads, file upload, web shell access
9. **Evasion** — IP fragmentation evasion, decoy scans, idle scan, MAC spoofing, stealth scan

**Auto-setup:** Checks for and installs required tools (hping3, nmap, slowhttptest, etc.)

---

## 4. Feature Engineering

### 4.1 Why These 25 Features?

Each feature captures a different dimension of network behavior:

**Packet-level features** (1–13) — What does this individual packet look like?
- Size, TTL, flags, window size — basic packet properties
- Entropy — is the payload encrypted/compressed?
- Ports — what service is targeted?

**Security features** (14–20) — Does this packet match known attack patterns?
- Individual flag bits — enables the model to learn flag-based attack signatures
- `suspicious_flags` — hardcoded rules for impossible combinations

**Flow-level features** (21–24) — What does the traffic pattern look like over time?
- Rate features — high rates indicate floods/DoS
- Average entropy — sustained high entropy indicates encrypted C2

**Composite feature** (25) — What do our heuristic rules think?
- `anomaly_score` — aggregates 7 rule-based signals into one score

### 4.2 Shannon Entropy — Deep Dive

Shannon entropy measures the randomness/information content of data:

```
H = -Σ p(x) · log₂(p(x))   for each byte value x ∈ [0, 255]
```

- **H = 0** → All bytes are the same (e.g., `\x00\x00\x00...`)
- **H ≈ 3.5–4.5** → English text
- **H ≈ 5.0–6.5** → Compressed data (zlib, gzip)
- **H ≈ 7.5–8.0** → Encrypted or truly random data

**Security application:** If a packet on port 80 (HTTP, plaintext) has entropy > 7.5, that's suspicious — it might be an encrypted C2 channel tunneled over HTTP.

### 4.3 Stateful Flow Tracking

The engine maintains per-flow state using `connection_tracker[flow_key]`:
```python
{
    "packet_count": 0,     # Total packets in this flow
    "byte_count": 0,       # Total bytes
    "first_seen": time(),  # When flow started
    "last_seen": time(),   # Most recent packet
    "payload_entropies": []  # Rolling entropy window
}
```

This enables rate calculations (`packet_count / time_diff`) that are critical for DoS detection — you can't detect a flood from a single packet.

---

## 5. Machine Learning Pipeline

### 5.1 Algorithm Choice: Random Forest

**Why Random Forest over other options:**

| Algorithm | Pros | Cons | Verdict |
|---|---|---|---|
| Random Forest | Fast inference, interpretable, handles tabular data, robust | Not the highest accuracy | ✅ **Selected** |
| Logistic Regression | Very fast, simple | Linear boundaries, lower accuracy on complex patterns | Considered as baseline |
| SVM | Good with high-dimensional data | Slow inference, hard to interpret | Rejected (latency) |
| Neural Network (MLP) | Can learn complex patterns | Needs more data, slower inference, black box | Rejected (interpretability, data requirements) |
| XGBoost | Highest accuracy on tabular | Slower inference than RF, more hyperparameters | Good alternative |

For an inline IPS, **inference speed** is critical (every packet waits for the verdict), and **interpretability** matters for security forensics. Random Forest gives us both.

### 5.2 Class Imbalance Handling

In production, normal traffic vastly outnumbers attack traffic. We handle this with:
- `class_weight='balanced'` — Automatically adjusts weights inversely proportional to class frequency
- `stratify=y` in train/test split — Preserves class ratios in both sets
- **Stratified K-Fold CV** — Each fold maintains class proportions

### 5.3 Feature Scaling

We use `StandardScaler` (zero mean, unit variance):
```
X_scaled = (X - mean) / std_dev
```

This is important because features have very different scales:
- `ttl` ∈ [1, 255]
- `packet_rate` ∈ [0, 10000+]
- `entropy` ∈ [0, 8]

Without scaling, high-magnitude features would dominate tree splits (less impactful for RF than other algorithms, but still good practice).

### 5.4 Evaluation Metrics — Why Each Matters

For a security system, **not all errors are equal**:

- **False Positive** (FP) — Blocking legitimate traffic. Impact: service disruption.
- **False Negative** (FN) — Allowing an attack. Impact: security breach.

| Metric | Formula | What It Tells You |
|---|---|---|
| Precision | TP / (TP + FP) | Of packets we dropped, how many were real attacks? High precision = few false alarms |
| Recall | TP / (TP + FN) | Of all attacks, how many did we catch? High recall = few missed attacks |
| F1 | 2 · (P · R) / (P + R) | Balance between precision and recall |
| ROC-AUC | Area under ROC curve | Model quality independent of decision threshold |

**In production, you'd tune the threshold based on risk tolerance:**
- High-security environment → Favor recall (catch all attacks, tolerate some false positives)
- High-availability environment → Favor precision (never block legit traffic, tolerate some misses)

---

## 6. Security Architecture

### 6.1 Fail-Safe Design

The #1 principle: **Aegis must never cause a denial of service against its own host.**

Every error path defaults to `packet.accept()`:
```python
try:
    features = engine.extract_features(packet)
    decision = engine.decide(features)
except Exception:
    packet.accept()  # fail-safe
```

### 6.2 Signal Handling

Both the collector and interceptor handle SIGINT and SIGTERM:
- Save any pending data before exit
- Remove iptables rules if we added them
- Log final statistics

### 6.3 iptables Rule Lifecycle

```
Start:  iptables -I INPUT  -j NFQUEUE --queue-num 1
        iptables -I OUTPUT -j NFQUEUE --queue-num 1
        iptables -I FORWARD -j NFQUEUE --queue-num 1

Stop:   iptables -D INPUT  -j NFQUEUE --queue-num 1
        iptables -D OUTPUT -j NFQUEUE --queue-num 1
        iptables -D FORWARD -j NFQUEUE --queue-num 1
```

Rules are added to the beginning of the chain (`-I` = insert first) to ensure all traffic is processed. They are cleaned up on exit, including in `finally` blocks to handle crashes.

### 6.4 Log Integrity

- JSONL format (append-only) — No risk of corrupting existing logs on write failure
- Each line is an independent JSON object — Partial writes don't corrupt the file
- Rate limiting prevents log exhaustion attacks (attacker can't fill disk by generating alerts)

---

## 7. Performance Considerations

### 7.1 Latency Budget

For inline packet interception, every millisecond counts:

| Operation | Typical Latency |
|---|---|
| NFQUEUE callback overhead | ~0.05ms |
| Scapy packet parsing | ~0.1ms |
| Feature extraction | ~0.05ms |
| StandardScaler transform | ~0.01ms |
| Random Forest predict | ~0.1ms |
| Total | **~0.3ms per packet** |

At 1000 packets/sec, this uses ~30% of a single CPU core.

### 7.2 Memory Efficiency

- `connection_tracker` — defaultdict with lazy initialization
- `rate_tracker` — deque(maxlen=100) per port (bounded memory)
- `payload_entropies` — List capped at 50 entries per flow
- `latency_samples` — List capped at 1000 entries

### 7.3 JSONL vs JSON for Logging

The original interceptor read and wrote the entire JSON array on every packet:
```python
# BAD: O(n) per packet
with open(log) as f:
    logs = json.load(f)       # Read ALL logs
logs.append(new_record)
with open(log, 'w') as f:
    json.dump(logs, f)        # Write ALL logs
```

After 10,000 packets, this is reading/writing 10,000 records per packet. We switched to JSONL:
```python
# GOOD: O(1) per packet
with open(log, 'a') as f:
    f.write(json.dumps(record) + '\n')
```

---

## 8. Deployment Model

### 8.1 Phase 1: Data Collection

```bash
# Terminal 1: Collect normal traffic
sudo python main.py collect --label 0 --duration 300

# Terminal 1 (later): Collect attack traffic
sudo python main.py collect --label 1 --duration 300

# Terminal 2: Generate attacks
sudo bash attack_generator.sh
```

### 8.2 Phase 2: Model Training

```bash
python main.py train --normal data/normal_log.csv --attack data/attack_log.csv
```

### 8.3 Phase 3: Deployment

```bash
sudo python main.py protect --model models/aegis_model.pkl --setup-iptables
```

### 8.4 Phase 4: Monitoring

```bash
python main.py dashboard
```

---

## 9. Design Decisions & Trade-offs

### 9.1 Why Scapy Instead of Raw Sockets?

Scapy provides protocol dissection out of the box. With raw sockets, we'd have to manually parse IP/TCP/UDP headers from bytes. Scapy adds ~0.1ms per packet parsing overhead, but eliminates hundreds of lines of manual parsing code and makes the feature extraction readable and maintainable.

### 9.2 Why Random Forest Instead of Deep Learning?

- Our features are tabular (25 numeric columns), not images or sequences
- Random Forest achieves >95% accuracy on tabular classification tasks
- Inference time ~0.1ms (vs. 1–10ms for even small neural networks)
- Interpretable — `feature_importances_` tells us exactly which features matter
- No GPU required for inference

### 9.3 Why NFQUEUE Instead of Scapy's Send/Receive?

NFQUEUE provides kernel-level packet interception with userspace verdicts. Scapy's `sniff()` only copies packets — it cannot block them. To build a prevention (not just detection) system, we need NFQUEUE.

### 9.4 Why JSONL Instead of a Database?

- Zero dependencies (no SQLite, PostgreSQL, etc.)
- Append-only writes are atomic at the OS level
- Each line is independently parseable (corruption-resistant)
- Easy to `grep`, `wc -l`, `tail -f`
- For a single-host IPS, this is sufficient. At scale, you'd switch to a SIEM (Splunk, ELK).

### 9.5 Why Heuristic Scoring AND ML?

Defense in depth:
1. Heuristic rules catch **known** attack patterns (XMAS scan, NULL scan) with zero false negatives
2. ML catches **unknown** patterns by learning from data
3. The heuristic score is itself a feature for the ML model — the ML can learn to trust or override it
4. If the model fails, heuristics provide a fallback

---

## 10. Limitations & Future Work

### 10.1 Current Limitations

- **Single-host** — Only protects the machine it runs on (no network-level deployment)
- **No encrypted payload inspection** — Cannot inspect TLS-encrypted traffic (would need SSL termination)
- **No state persistence across restarts** — Flow tracking resets on restart
- **Single-model** — One model for all traffic; could benefit from specialized models per protocol
- **No automatic retraining** — Model staleness over time as attack patterns evolve

### 10.2 Future Enhancements

- **Deep packet inspection** with protocol-aware parsers (HTTP, DNS, SMTP)
- **Ensemble models** — Combine RF + Isolation Forest + LSTM for temporal patterns
- **Automatic retraining** — Periodic retraining on new labelled data
- **Network-level deployment** — Run on a gateway/router to protect an entire subnet
- **SIEM integration** — Forward alerts to Splunk, ELK, or Wazuh
- **IP reputation feeds** — Integrate threat intelligence feeds (AbuseIPDB, OTX)
- **GeoIP enrichment** — Flag traffic from unusual geographic locations
- **Web UI** — Replace CLI dashboard with a web-based monitoring interface
