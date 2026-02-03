# KAVACH AI-Agentic SOC

## 🛡️ Project Overview

The SOC Operations Copilot is a production-grade Security Operations Center (SOC) platform designed for high-integrity threat detection, deterministic automated investigations, and safety-first incident promotion. It combines traditional SIEM capabilities (rules, IOCs, MITRE ATT&CK) with fail-closed AI assistance to reduce alert fatigue without compromising security posture.

Unlike black-box AI systems, this platform enforces strict deterministic evaluation pipelines, ensuring that every critical log is evaluated, every detection is traceable, and no incident is created without explicit evidence.

---

## 🏗️ High-Level Architecture

The system operates on a rigorous pipeline architecture:

```
[Log Ingestion] -> [Normalization] -> [Deterministic Rule Engine] -> [Detection] -> [AI Investigation] -> [Incident Promotion]
       ^                  ^                      ^                        |                 ^                    ^
       |                  |                      |                        |                 |                    |
   Raw Logs          ProcessedLog           Rule/MITRE/IOC          DetectionAlert    AI Context/JSON       Incident
```

---

## 🔄 End-to-End Pipeline Flow

### 1️⃣ Log Ingestion
- **Endpoint:** `/api/v1/logs/ingest`
- **Storage:** Persisted immediately as `ProcessedLog`.
- **Normalization:** All logs are normalized with standardized timestamps, severity scores, categories, and enriched fields (MITRE TTPs, IOC metadata).

### 2️⃣ Rule Engine (Deterministic)
The rule engine is the core of the detection pipeline, operating in two mutually exclusive modes to guarantee coverage:
1.  **ID-based Mode:** Triggered immediately upon ingestion. Evaluates *specific* log IDs to ensure zero-latency detection for critical events.
2.  **Time-window Mode:** Runs periodically to catch streaming or out-of-order logs within a safety window.

**Key Guarantee:** Every ingested log is evaluated exactly once per detection source.

### 3️⃣ Detection Creation
When the rule engine identifies a threat, it creates a `DetectionAlert`.
- **Sources:** Rules, MITRE High-Confidence matches, Critical IOCs.
- **Attributes:** Rule Name, Severity (Critical/High/Medium/Low), Confidence Score (0-100).
- **Deduplication:** Stable fingerprinting ensures that the same log event does not trigger duplicate alerts.

### 4️⃣ AI Investigation (Fail-Closed)
AI is strictly an *assistive* post-detection layer.
- **Trigger:** Only runs *after* a valid detection is created.
- **Model:** Uses a dedicated AI model for automated investigation.
- **Output:** Strict JSON-structured reasoning (no free-text hallucinations).
- **Fail-Closed:** If the AI fails, times out, or produces invalid JSON, the investigation is marked as `failed`, and **no incident is created**. The underlying detection remains for manual review.
- **Constraint:** The AI **never** creates detections on its own.

### 5️⃣ Incident Creation
Incidents are promoted alerts, not raw AI outputs.
- **Prerequisite:** A completed, successful AI investigation with sufficient confidence.
- **Promotion Logic:** Deterministic evaluation of the AI's findings against safety thresholds.
- **Safety Gates:** Promotion is blocked unless:
    -   Confidence Score is present and valid.
    -   Severity is defined.
    -   The decision is explicitly "true".

### 6️⃣ Safety & Integrity Guarantees
- **Confidence Clamping:** All confidence scores are strictly bounded between 0 and 100.
- **Consistency Enforcement:** Severity and confidence must align (e.g., CRITICAL severity cannot have low confidence).
- **Invariant:** One processed log ≤ one detection per source.
- **Observability:** Structured debug logs trace every decision, skip, and error.

---

## 🔍 Detection Sources

The platform utilizes a multi-layered detection strategy:

### 1. Rule-Based Detections
Python-based logic classes that enforce specific threat signatures (e.g., `BruteForceSSHRule`, `PowerShellEncodedRule`).

### 2. MITRE High-Risk Detections
Automatically flags logs matching high-fidelity MITRE ATT&CK techniques:
-   Execution
-   Credential Access
-   Persistence
-   Lateral Movement
-   Command and Control
-   Defense Evasion

### 3. IOC-Based Detections
Leverages threat intelligence to flag known bad indicators:
-   **Malicious** verdict → **CRITICAL** severity
-   **Suspicious** verdict → **HIGH** severity

### 4. Critical Severity Fallback
**Rule:** `RULE-CRITICAL-FALLBACK`
-   **Purpose:** A safety net to ensure that *any* log marked as CRITICAL by the ingestion normalization process generates a detection, even if it doesn't match a specific behavioral rule. This prevents critical signals from being silently dropped.

---

## 🤖 AI Investigation Behavior

The AI model acts as a tier-1 analyst, not a detection engine.

-   **Role:** Analyzes the context (log fields, correlation findings) of an existing alert.
-   **Capabilities:**
    -   Assesses if the alert is a true positive.
    -   Assigns a confidence score.
    -   Maps observed activity to MITRE techniques.
    -   Recommends response actions.
-   **Reliability:** Implements retry logic for transient model failures. If the model is unavailable or unresponsive, the system degrades safely to a "manual review needed" state.

---

## 🚨 Incident Lifecycle

1.  **Detection:** A `DetectionAlert` is created by the Rule Engine.
2.  **Investigation:** The system queues an AI investigation task.
3.  **Analysis:** The AI model reviews evidence and outputs a structured verdict.
4.  **Gating:** The pipeline validates the AI verdict against safety invariants (confidence thresholds, required fields).
5.  **Promotion:** If gates pass, an `Incident` is created and linked to the alert. If gates fail, the alert remains as "Open" for human operator review.

---

## 🛡️ Safety & Fail-Closed Design

This system is engineered to prevent "silent failures" and "hallucinated incidents."

### What This System Guarantees
-   **Deterministic Evaluation:** If a log is ingested, it *will* be checked against rules.
-   **Fail-Closed AI:** AI errors stop the automation, they do not create bad data.
-   **No Silent Drops:** The fallback mechanism catches unhandled critical logs.
-   **Auditability:** Every step from ingestion to incident is logged with trace IDs (processed_ids, fingerprints).

### What This System Intentionally Does NOT Do
-   **No Black-Box Detections:** Detections are code, not probabilistic guesses.
-   **No AI-Created Alerts:** AI only reviews what the Rule Engine finds.
-   **No Silent Promotions:** Incidents require explicit, validated evidence.

---

## 📊 Current Status

-   **Pipeline:** Production-Ready & Deterministic
-   **Ingestion:** Active (REST API)
-   **Detection:** Active (Rules + MITRE + IOC + Fallback)
-   **Investigation:** Active (AI-Assisted, Fail-Closed)
-   **Incidents:** Active (Automated Promotion with Safety Gates)
