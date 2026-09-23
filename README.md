# AI-Assisted User Behavior Analytics

> 🚧 Active Development

An experimental security engineering project focused on User Behavior Analytics (UBA),
AI-assisted security investigation, SIEM correlation, cross-source security event
correlation, and incident analysis.

**Status:** 🟡 In Development

---

## Overview

UserBehaviorAnalysis is a Python-based security engineering project designed to
analyze user and endpoint activity, normalize security telemetry, detect suspicious
behavior, and provide a foundation for AI-assisted security investigation.

The project is being developed as a modular pipeline that can connect UBA detections
with SIEM telemetry and, in later stages, correlate evidence from XDR/EDR/IPS
sources and trigger SOAR workflows.

> The project is experimental and actively evolving. Features, APIs, directory
> structures, and architecture may change during development.

---

## Security Investigation Architecture

```text
                    User / Endpoint Activity
                                  |
                                  v
                     +----------------+
                     | UBA Detection  |
                     +-------+--------+
                                  |
                                  v
                     +----------------+
                     |        SIEM           |
                     | Wazuh / Events |
                     +-------+--------+
                                  |
                                 v
                     +----------------+
                     |       AI Agent     |
                     |    Investigation  |
                     +-------+--------+
                                  |
                                  v
                      +----------------+
                      | XDR Correlation|
                      +-------+--------+ 
                                    |
                  +----------+----------+
                  |                                  |
                  v                                 v
             +---------+             +---------+
             |     EDR     |             |     IPS     |
             +----+----+           +----+----+
                   |                                  |
                  +----------+----------+
                                    |
                                   v
                    +------------------+
                    | Incident Analysis|
                    +--------+---------+
                                   |
                                   v
                    +------------------+
                    |           SOAR         |
                    | Response / Enrich|
                    +------------------+
```

The architecture represents the target development direction. Not every component
shown above is currently implemented.

---

## Current Development

Current development focuses on:

- User behavior analysis
- Windows Security and Sysmon event processing
- Behavioral anomaly detection foundations
- Security event normalization
- SIEM event analysis
- Wazuh integration
- AI-assisted alert investigation foundations
- Cross-source security event correlation
- XDR / EDR / IPS evidence correlation architecture
- Incident analysis and summarization foundations

---

## Implemented Components

### Windows Event Log Parser

The project contains a Windows Event Log parser supporting two processing modes:

**Offline mode**

- Reads `.evtx` files
- Uses `python-evtx`
- Can process EVTX data on Linux/macOS without requiring the Windows Event Log API
- Normalizes raw events into a common event schema

**Live Windows mode**

- Uses `pywin32`
- Reads Windows Event Log channels
- Designed for Security and Sysmon telemetry
- Windows-only functionality

The parser normalizes events into a `UserBehaviorEvent` model based on Pydantic.

Example normalized fields include:

- Event ID
- Event name
- Category
- Source
- Timestamp
- Computer
- User
- Domain
- Logon ID
- Source IP
- Logon type
- Process name
- Process ID
- Parent process
- Command line
- Destination IP
- Destination port
- DNS query
- Target object
- Target filename
- Raw event data

---

## Wazuh Integration

The project includes functionality for working with Wazuh-related security telemetry.

The intended data flow is:

```text
Windows / Linux Endpoint
          |
          v
        Wazuh
          |
          v
   Security Alert / Event
          |
          v
 UserBehaviorAnalysis
          |
          v
 Normalization / Analysis
```

Wazuh Indexer / OpenSearch REST APIs can be used as a source of security event
data for subsequent processing and correlation.

---

## Detection & Investigation Direction

The long-term detection workflow is designed around:

```text
Telemetry
   |
   v
Normalization
   |
   v
Behavioral Features
   |
   v
Detection / Risk Scoring
   |
   v
SIEM Context
   |
   v
AI-Assisted Investigation
   |
   v
Cross-Source Correlation
   |
   v
Incident Analysis
   |
   v
Response Automation
```

The goal is not simply to generate another alert. The project aims to provide
additional context around an alert and correlate evidence across multiple security
sources.

---

## Project Structure

The repository is organized around source code, documentation, configuration,
parsing, and security documentation.

```text
UserBehaviorAnalysis/
|
+-- docs/
|
+-- src/
|
+-- .gitignore
+-- LICENSE
+-- README.md
+-- ROADMAP.md
+-- SECURITY.md
+-- config.py
+-- config.yaml
+-- parser.py
+-- requirements.txt
+-- utils.py
```

Additional modules are being developed under `src/` as the architecture evolves.

---

## Requirements

Recommended environment:

- Python 3.10+
- Git
- Linux, macOS, or Windows for the applicable components
- Wazuh / OpenSearch for SIEM integration
- Windows endpoint with Security/Sysmon logs for live Windows collection

### Python Dependencies

The current runtime dependencies include:

- `pydantic`
- `PyYAML`
- `python-evtx`
- `pywin32` (Windows only)
- `requests`
- `urllib3`

Future modules may introduce:

- `scikit-learn`
- `FastAPI`
- `Uvicorn`
- `Streamlit`

These future dependencies are intentionally not required by the current baseline
installation unless the related modules are enabled.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/agunix/UserBehaviorAnalysis.git
cd UserBehaviorAnalysis
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## Configuration

Configuration is kept separately from application logic.

Before running the project, review:

```text
config.yaml
```

Do not commit:

- passwords
- API tokens
- authentication secrets
- private keys
- production credentials

Use environment variables or a local secrets mechanism for sensitive values.

---

## Windows EVTX Processing

The offline parser can process `.evtx` files.

Example:

```text
data/
└── evtx/
    ├── Security.evtx
    └── Sysmon.evtx
```

The parser converts raw Windows events into a normalized
`UserBehaviorEvent` representation for downstream processing.

---

## Security Event Normalization

A normalized event schema allows later modules to work independently from
the original event source.

For example:

```text
Windows Security Event
          |
          v
     Raw Event
          |
          v
  Event Normalization
          |
          v
 UserBehaviorEvent
          |
          +----> Feature Extraction
          |
          +----> Detection Engine
          |
          +----> Correlation
          |
          +----> Investigation
```

This design makes it possible to extend the project with additional telemetry
sources without coupling every downstream component to a specific log format.

---

## Planned Development

### Phase 1 — UBA Foundation

- [x] Windows EVTX parsing
- [x] Event normalization
- [x] Initial Wazuh integration
- [ ] Feature extraction expansion
- [ ] Behavioral baseline

### Phase 2 — Detection Engineering

- [ ] Behavioral detection rules
- [ ] Risk scoring
- [ ] Anomaly detection
- [ ] Detection tuning
- [ ] False-positive analysis

### Phase 3 — AI-Assisted Investigation

- [ ] AI investigation agent
- [ ] Alert context enrichment
- [ ] Investigation workflow
- [ ] Incident summarization
- [ ] Evidence-based reasoning

### Phase 4 — Cross-Source Correlation

- [ ] SIEM correlation
- [ ] EDR correlation
- [ ] XDR correlation
- [ ] IPS evidence correlation
- [ ] Timeline generation

### Phase 5 — SOAR & Response

- [ ] Automated enrichment
- [ ] Threat intelligence integration
- [ ] Response playbooks
- [ ] Automated response actions
- [ ] Detection feedback loop

---

## Security Engineering Goals

The project is intended to explore practical concepts in:

- User Behavior Analytics
- Detection Engineering
- SIEM Engineering
- Security Automation
- Security Event Correlation
- Threat Detection
- Incident Investigation
- XDR / EDR correlation
- SOAR
- AI-assisted SOC workflows

---

## Development Principles

The project follows these principles:

1. Normalize security telemetry before analysis.
2. Keep detection logic modular.
3. Separate data collection from investigation.
4. Preserve raw evidence for investigation and auditing.
5. Correlate multiple security signals before making conclusions.
6. Keep automated response actions explicit and controllable.
7. Avoid embedding credentials or secrets in source code.
8. Document experimental components and their limitations.

---

## Limitations

This project is currently under active development.

It should not be considered a production-ready autonomous SOC platform.

Detection accuracy, AI-assisted analysis, correlation quality, and automated response
capabilities require additional validation, testing, tuning, and operational safeguards.

---

## Roadmap

See:

```text
ROADMAP.md
```

for the current development roadmap.

---

## Security Policy

Security-related issues should be reported privately rather than disclosed through
public GitHub issues.

See:

```text
SECURITY.md
```

for the repository security policy.

---

## License

This project is licensed under the MIT License.

Copyright (c) 2026 Aghaverdi Kalantarli.

See the `LICENSE` file for the complete license text.

---

## Author

**Aghaverdi Kalantarli**

Cyber Security Engineer | Security Researcher

GitHub:

https://github.com/agunix

Project:

https://github.com/agunix/UserBehaviorAnalysis

---

## Disclaimer

This project is developed for security research, engineering, education, and
authorized testing.

Only use the project against systems, endpoints, logs, and infrastructure for
which you have appropriate authorization.
