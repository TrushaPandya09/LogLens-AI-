

# LogLens 🔎

### Local Cybersecurity Log Analysis & Security Insight Dashboard

LogLens is a lightweight Python and Flask-based web application designed to analyze system and application log files and identify potentially important security patterns.

The application parses uploaded `.log` or `.txt` files, extracts useful event information, identifies authentication failures and recurring IP activity, summarizes important observations, classifies findings by severity, and provides informational recommended actions for further investigation.

> LogLens is designed as a defensive cybersecurity and SOC-oriented learning project. It does not automatically block, modify, or respond to security events.

---

## 🚀 Features

### 📊 Log Analysis

LogLens analyzes uploaded log files and provides:

- Total number of events
- Successful login count
- Failed login count
- Error count
- Warning count
- Number of unique IP addresses
- Frequently occurring source IP addresses

### 🔍 Suspicious Pattern Detection

The application identifies basic patterns such as:

- Multiple failed login attempts
- Repeated activity from the same source IP
- Authentication failures
- Multiple application/system errors

### ⚠️ Severity Classification

Detected findings can be classified using simple rule-based severity levels such as:

- LOW
- MEDIUM
- HIGH

This helps prioritize which events may require further investigation.

### 📝 Security Summary

LogLens automatically generates a concise summary of important observations found in the analyzed log.

Example:

> Multiple failed login attempts detected.

> A frequently occurring source IP was observed.

### 🛡️ Recommended Actions

For detected security patterns, LogLens provides informational guidance to help an analyst determine what should be investigated next.

Example:

> Review the authentication events associated with this IP and verify whether the activity is legitimate.

The application does not automatically perform the recommended action.

### 📁 File Upload

Users can upload supported `.log` and `.txt` files through the web interface for analysis.

Unsupported file types are rejected.

### 💻 Local Web Dashboard

The project uses Flask to provide a local browser-based dashboard.

---

# 🏗️ How It Works

```text
             Log File
                │
                ▼
        ┌─────────────────┐
        │  File Upload    │
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │  Log Parser     │
        │    Python       │
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Pattern Detection│
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Event Analysis  │
        └────────┬────────┘
                 │
        ┌────────┴─────────┐
        ▼                  ▼
   Severity           Security Summary
        │                  │
        └────────┬─────────┘
                 ▼
        ┌─────────────────┐
        │ Recommended     │
        │ Action          │
        └────────┬────────┘
                 ▼
        ┌─────────────────┐
        │ Web Dashboard    │
        └─────────────────┘

## Technology stack

Python, Flask, HTML, CSS, JavaScript, and regular expressions. There is no database, external API, or cloud service.

## Project structure

```text
LogLens/
├── app.py
├── requirements.txt
├── README.md
├── sample.log
├── analyzer/
│   ├── __init__.py
│   └── log_analyzer.py
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── script.js
```

## Installation

From the LogLens folder, create and optionally activate a virtual environment, then install the only dependency:

```bash
pip install -r requirements.txt
```

## How to run

```bash
python app.py
```

Open `http://127.0.0.1:5000` in a browser.

## How to use `sample.log`

On the dashboard, choose the included `sample.log` file and click **Analyze log**. The app reads the selected file locally, calculates its statistics, and renders the results. It does not scan folders or read any other files.

## Example analysis

The fictional sample contains 12 events, 3 failed logins, 3 successful logins, 3 errors, 3 warnings, and 4 unique IP addresses. The addresses `192.168.10.21` and `192.168.10.44` appear frequently, with `192.168.10.44` appearing around the failed-login events.

## What I learned from this project

- How Flask routes connect an HTML form to Python code.
- How regular expressions can extract security-relevant patterns from plain text.
- How to count and summarize events with Python collections.
- How to build a clear dashboard that communicates defensive findings.
- Why file validation and limiting input size are useful safety controls.

## Future improvements

- Support configurable log formats and additional timestamp parsing.
- Add charts for event levels over time.
- Add optional filtering by IP, event level, or date.
- Add automated tests for more log formats and edge cases.
