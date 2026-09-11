# UBA Model

## Objective

The objective of the UBA component is to identify potentially anomalous user behavior from security telemetry.

## Data Sources

Current data sources include:

- Authentication events
- Windows security events
- Process activity
- File activity
- Network-related events

## Behavioral Features

Potential features include:

- Login frequency
- Login time
- Source IP
- Destination host
- Process execution
- File access
- Authentication failures
- Privilege changes

## Detection Approach

The project currently combines rule-based security detection with behavioral analysis.

## Baseline

A user baseline can be represented as:

User
→ Normal login times
→ Normal source IPs
→ Normal endpoints
→ Normal activity frequency
→ Normal access patterns

## Anomaly Detection

An event may become suspicious when multiple behavioral deviations occur simultaneously.

## Risk Scoring

Future development will introduce a behavioral risk score.

Example:

Risk =
Behavioral Anomaly
+
Authentication Anomaly
+
Endpoint Evidence
+
Network Evidence

## Current Status

🚧 Active Development