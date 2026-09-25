# AI-Assisted User Behavior Analytics

> 🚧 Active Development

An experimental security engineering project focused on
User Behavior Analytics (UBA), AI-assisted investigation,
SIEM correlation and security incident analysis.

Status: 🟡 In Development

## Architecture

```
      ┌──────────────┐
      │ User Activity│
      └──────┬───────┘
             ↓
   ┌────────────────────┐
   │        UBA         │
   │ Behavioral Rules   │
   └─────────┬──────────┘
             ↓
   ┌────────────────────┐
   │        SIEM        │
   │   Wazuh / ELK      │
   └─────────┬──────────┘
             ↓
   ┌────────────────────┐
   │     AI AGENT       │
   │                    │
   │ Analyze            │
   │ Correlate          │
   │ Enrich             │
   │ Investigate        │
   └─────────┬──────────┘
             ↓
   ┌────────────────────┐
   │        XDR         │
   └─────────┬──────────┘
             ↓
   ┌─────────┴─────────┐
   ↓                   ↓
┌───────┐           ┌───────┐
│  EDR  │           │  IPS  │
└───┬───┘           └───┬───┘
    └─────────┬─────────┘
              ↓
   ┌────────────────────┐
   │ Incident Analysis  │
   └─────────┬──────────┘
             ↓
         🚧 SOAR
```

This project is currently under active development. Features and architecture may change.

## Current Development

The current development focuses on:

- User behavior analysis
- Behavioral anomaly detection
- SIEM event analysis (Windows Security/Sysmon via Wazuh, Linux SSHD/PAM/auditd/syscheck via Wazuh)
- AI-assisted alert investigation
- Cross-source security event correlation
- XDR/EDR/IPS evidence correlation
- Incident summarization

### Planned

- SOAR integration
- Automated enrichment
- Automated response
- Detection feedback loop
- False-positive reduction
- Risk scoring

## Project Structure

```
AI-UBA/
├── src/
│   ├── config/         # Centralized configuration (YAML + env overrides)
│   ├── parser/         # Windows EVTX offline/live parsing -> UserBehaviorEvent
│   ├── integrations/   # Wazuh Indexer clients (Windows + Linux sources)
│   ├── features/       # (planned) behavioral feature extraction
│   ├── model/          # (planned) scikit-learn anomaly detection
│   ├── risk/           # (planned) hybrid rule+ML risk scoring
│   ├── api/            # (planned) FastAPI service
│   └── dashboard/      # (planned) Streamlit dashboard
├── docs/                # Wazuh agent/manager config snippets
├── data/, logs/, tests/
└── requirements.txt
```

## Getting Started

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export AIUBA_WAZUH_INDEXER__PASSWORD=<your-wazuh-indexer-password>
PYTHONPATH=. python -m src.integrations.wazuh_client   # Windows/Sysmon events
PYTHONPATH=. python -m src.integrations.linux_client    # SSHD/PAM/auditd/syscheck events
```

See `docs/wazuh_agent_localfile.xml` and `docs/wazuh_custom_rule.xml` for wiring
AI-UBA's own anomaly alerts back into Wazuh.
