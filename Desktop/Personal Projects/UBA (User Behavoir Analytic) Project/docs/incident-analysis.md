# Incident Analysis

## Objective

The incident analysis layer transforms individual security alerts into a broader investigation context.

## Investigation Flow

Initial Alert
    ↓
Event Collection
    ↓
Entity Identification
    ↓
Cross-Source Correlation
    ↓
Evidence Aggregation
    ↓
Incident Timeline
    ↓
AI Assessment
    ↓
Human Validation

## Evidence Types

### Behavioral Evidence

UBA-related activity.

### Endpoint Evidence

EDR process and endpoint telemetry.

### Network Evidence

IPS and network security events.

### Authentication Evidence

Login and authentication activity.

## Incident Context

An investigation may contain:

- User
- Endpoint
- Source IP
- Destination IP
- Process
- Timestamp
- Detection
- Related events
- EDR evidence
- IPS evidence

## AI Assessment

The AI Agent may provide:

- Summary
- Potential explanation
- Related evidence
- Investigation recommendations

AI output must remain distinguishable from observed evidence.

## Human Validation

Final incident classification should be validated by an analyst.

## Current Status

🚧 Active Development