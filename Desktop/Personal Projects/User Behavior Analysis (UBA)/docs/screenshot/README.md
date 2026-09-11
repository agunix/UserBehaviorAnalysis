Wazuh → Python UBA Parser


The current pipeline extracts relevant security events from Wazuh alert telemetry and transforms them into a structured dataset for further UBA analysis.

Current Lab Evidence
1. UBA Detection in Wazuh

Example of a behavioral security event detected and collected through Wazuh from a Windows lab endpoint.

Screenshot: 01-wazuh-uba-detection.png

2. Security Telemetry Processing

Python-based parser currently processes Wazuh alert telemetry and extracts relevant fields for the UBA dataset.

Screenshot: 02-uba-log-parser.png

3. Continuous Processing

The parser is currently being tested as a continuously running Linux service to process incoming security telemetry.

Screenshot: 03-uba-parser-service.png