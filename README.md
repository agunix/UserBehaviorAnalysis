# AI-Assisted User Behavior Analytics

> 🚧 Active Development

An experimental security engineering project focused on
User Behavior Analytics (UBA), AI-assisted investigation,
SIEM correlation and security incident analysis.

Status: 🟡 In Development

## Architecture

                    ┌─────────────────────┐
                    │   User Activity     │
                    │ Windows / Linux     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │                 UBA Detection              │
                    │                Behavioral Rules            │
                    └──────────┬──────────┘
                                                 │
                                                ▼
                    ┌─────────────────────┐
                    │                      Wazuh                      │
                    │                       SIEM                        │
                    └──────────┬──────────┘
                                                 │
                                                ▼
                    ┌─────────────────────┐
                    │                    AI Agent                     │
                    │                 Investigation                 │
                    └──────────┬──────────┘
                                                │
                    ┌──────────┴──────────┐
                    ▼                                                      ▼
             ┌─────────────┐       ┌─────────────┐
             │              XDR             │       │             SIEM             │
             │         Correlation       │       │           Context           │
             └──────┬──────┘       └──────┬──────┘
                    │                                                       │
                    └──────────┬──────────┘
                                                ▼
                    ┌─────────────────────┐
                    │                 Incident Analysis           │
                    └──────────┬──────────┘
                                                ▼
                    ┌─────────────────────┐
                    │                         SOAR                     │
                    │                Response / Enrich           │
                    └─────────────────────┘

This project is currently under active development. Features and architecture may change.

## Implemented

- Wazuh UBA alert ingestion
- UBA alert parsing
- SIEM event normalization
- Security event correlation
- Initial investigation workflow

## In progress

- AI investigation agent
- XDR correlation
- Incident analysis

## Planned

- SOAR integration
- Automated enrichment
- Automated response
- Detection feedback loop
- False-positive reduction

## Project structure

UserBehaviorAnalysis/
│
├── src/
│   ├── api/
│   ├── ai-agent/
│   ├── correlation/
│   ├── detection-engine/
│   ├── incident-analysis/
│   ├── integrations/
│   └── features/
│
├── docs/
│   ├── architecture/
│   ├── detection/
│   ├── integration/
│   └── investigation/
│
├── config.py
├── config.yaml
├── parser.py
├── utils.py
├── requirements.txt
├── ROADMAP.md
├── SECURITY.md
├── LICENSE
└── README.md