# Detection Engineering

## Objective

The detection layer identifies security-relevant user and endpoint behavior and generates events for further UBA analysis.

## Detection Pipeline

Windows Event
    ↓
Wazuh Agent
    ↓
Localfile Collection
    ↓
Wazuh Decoder
    ↓
Custom Detection Rule
    ↓
Alert
    ↓
UBA Parser

## Current Detection Sources

- Windows security events
- PowerShell activity
- Authentication events
- Process execution
- File activity

## Wazuh Custom Rules

The repository contains custom Wazuh rules used during laboratory testing.

See:

- `wazuh_custom_rule.xml`
- `wazuh_agent_localfile.xml`

## Example Detection

Describe one of your actual detection cases here.

### Detection

PowerShell-related suspicious behavior.

### Input

Windows security telemetry.

### Processing

Wazuh agent → Wazuh manager → custom rule.

### Output

UBA-relevant security alert.

## False Positive Reduction

Future work includes:

- Threshold tuning
- Context-aware detection
- User baselines
- Risk scoring
- Correlation with endpoint telemetry

## MITRE ATT&CK Mapping

Where applicable, detections will be mapped to relevant ATT&CK techniques.