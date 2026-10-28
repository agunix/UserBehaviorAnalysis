"""
UBA :: Wazuh Integration
------------------------------
Consists of two components:

1. WazuhIndexerClient
   From Wazuh Indexer (OpenSearch, port 9200, Basic Auth) from `wazuh-alerts-*` index
   recieved Sysmon/Security alerts and existing `UserBehaviorEvent` mapped to UBA's internal model. 
   The mapping is based on the same logic as in the parser module (see: src/parser/parser.py).

   NOTE: DO NOT USE THERE Wazuh Manager API (port 55000, JWT), 
   because alerts are stored in the indexer.

2. WazuhAlertWriter
   To "inject" the anomalies detected by UBA back into Wazuh.
   Wazuh's official `POST /events` endpoint is currently unstable 
   (it is in the process of being removed from Wazuh's own repository), 
   so we are using a documented and reliable method: the JSON string 
   is written to a local file, the Wazuh agent monitors this file using 
   `<localfile><log_format>json</log_format></localfile>`, 
   and a custom decoder and rule on the manager convert it into an alert.
   See: docs/wazuh_agent_localfile.xml və docs/wazuh_custom_rule.xml

Example usage:
    from src.integrations.wazuh_client import WazuhIndexerClient, WazuhAlertWriter

    client = WazuhIndexerClient()
    for event in client.fetch_recent_events(minutes=60):
        print(event.model_dump())

    writer = WazuhAlertWriter()
    writer.write_alert(
        user="CORP\\uba_user",
        rule_name="UBA_AnomalousLoginTime",
        severity="high",
        risk_score=87.5,
        description="User logged in at an unusual time",
        details={"logon_hour": 3, "baseline_hours": [8, 18]},
    )
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from src.config.config import get_settings
from src.parser.parser import UserBehaviorEvent, normalize_event
from src.parser.utils import get_event_metadata, normalize_timestamp, safe_get

logger = logging.getLogger("uba.wazuh_client")

# Suppress urllib3 self-signed certificate warnings (for test environments only;
# use verify_ssl=True in production and remove this line).
try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


# --------------------------------------------------------------------------- #
# Wazuh alert JSON -> UserBehaviorEvent mapping
# --------------------------------------------------------------------------- #
# Wazuh’s Windows/Sysmon decoder stores raw EVTX fields under 
# `data.win.eventdata.*`, primarily in camelCase format (starting with 
# a lowercase letter). System fields, meanwhile, are located under 
# `data.win.system.*`. We perform case-insensitive searches to 
# align with the names found in the EVTX XML, ensuring 
# resilience against minor variations between different Wazuh versions.

def _ci_get(d: Dict[str, Any], *keys: str) -> Optional[str]:
    """Case-insensitive key search. Returns the first non-empty value found."""
    if not d:
        return None
    lowered = {k.lower(): v for k, v in d.items()}
    for key in keys:
        val = lowered.get(key.lower())
        if val not in (None, ""):
            return val
    return None


def wazuh_alert_to_user_behavior_event(alert: Dict[str, Any]) -> Optional[UserBehaviorEvent]:
    """
    Converts a single Wazuh alert document (from the indexer _search result `_source`)
    to a `UserBehaviorEvent`. Returns None for non-Sysmon/Security alerts
    (if data.win is not present).
    """
    data = alert.get("data", {}) or {}
    win = data.get("win", {}) or {}
    system = win.get("system", {}) or {}
    eventdata = win.get("eventdata", {}) or {}

    raw_event_id = _ci_get(system, "eventID")
    if raw_event_id is None:
        return None  # Not a Sysmon/Security alert (e.g., Linux auth, firewall, etc.)

    try:
        event_id = int(raw_event_id)
    except (TypeError, ValueError):
        return None

    meta = get_event_metadata(event_id)

    raw_ts = _ci_get(system, "systemTime") or alert.get("timestamp")
    computer = _ci_get(system, "computer") or (alert.get("agent") or {}).get("name")
    record_id_raw = _ci_get(system, "eventRecordID")

    # _FIELD_ALIASES with the same logic, but source is the `eventdata` dict
    field_map = {
        "user": ("TargetUserName", "SubjectUserName", "User"),
        "domain": ("TargetDomainName", "SubjectDomainName"),
        "logon_id": ("TargetLogonId", "SubjectLogonId"),
        "source_ip": ("IpAddress", "SourceIp"),
        "logon_type": ("LogonType",),
        "process_name": ("Image", "NewProcessName"),
        "process_id": ("ProcessId", "NewProcessId"),
        "parent_process_name": ("ParentImage",),
        "command_line": ("CommandLine",),
        "destination_ip": ("DestinationIp",),
        "destination_port": ("DestinationPort",),
        "dns_query": ("QueryName",),
        "target_object": ("TargetObject",),
        "target_filename": ("TargetFilename",),
    }
    normalized_fields = {}
    for target_field, aliases in field_map.items():
        val = _ci_get(eventdata, *aliases)
        if val is not None:
            normalized_fields[target_field] = val

    return UserBehaviorEvent(
        event_id=event_id,
        event_name=meta["name"],
        category=meta["category"],
        source=meta["source"],
        timestamp=normalize_timestamp(raw_ts) if raw_ts else None,
        computer=computer,
        record_id=int(record_id_raw) if record_id_raw and str(record_id_raw).isdigit() else None,
        raw={**eventdata, "_wazuh_rule_id": (alert.get("rule") or {}).get("id")},
        **normalized_fields,
    )


# --------------------------------------------------------------------------- #
# WazuhIndexerClient
# --------------------------------------------------------------------------- #

class WazuhIndexerClient:
    """A client that queries alerts from the Wazuh Indexer (OpenSearch)."""

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.cfg = self.settings.wazuh_indexer
        self._auth = HTTPBasicAuth(self.cfg.username, self.cfg.password)

    def _search(self, query: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.cfg.base_url}/{self.cfg.index_pattern}/_search"
        resp = requests.post(
            url,
            json=query,
            auth=self._auth,
            verify=self.cfg.verify_ssl,
            timeout=self.cfg.request_timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_recent_events(
        self,
        minutes: int = 60,
        event_ids: Optional[List[int]] = None,
        agent_name: Optional[str] = None,
        size: int = 1000,
    ) -> Iterator[UserBehaviorEvent]:
        """
        Fetches recent Windows/Sysmon alerts from the Wazuh Indexer and normalizes them into UserBehaviorEvent objects.

        NOT: Wazuh indexer queries are limited by default to a maximum of 10,000 results
        (index.max_result_window). For larger time ranges, use `fetch_events_paginated`.
        """
        event_ids = event_ids or self.settings.parser.included_event_ids
        now = datetime.now(timezone.utc)
        since = now - timedelta(minutes=minutes)

        must_clauses: List[Dict[str, Any]] = [
            {"range": {"timestamp": {"gte": since.isoformat(), "lte": now.isoformat()}}},
            {"terms": {"data.win.system.eventID": [str(eid) for eid in event_ids]}},
        ]
        if agent_name:
            must_clauses.append({"match": {"agent.name": agent_name}})

        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {"bool": {"must": must_clauses}},
        }

        result = self._search(query)
        hits = result.get("hits", {}).get("hits", [])
        logger.info("Received Wazuh indexer %d alerts (last %d mins)", len(hits), minutes)

        for hit in hits:
            source = hit.get("_source", {})
            event = wazuh_alert_to_user_behavior_event(source)
            if event is not None:
                yield event

    def fetch_events_paginated(
        self,
        start: datetime,
        end: datetime,
        event_ids: Optional[List[int]] = None,
        page_size: int = 1000,
    ) -> Iterator[UserBehaviorEvent]:
        """
        `search_after` based pagination query — for exceeding the 10,000 result limit.
        Use for fetching large time ranges (e.g., 30 days for model training).
        """
        event_ids = event_ids or self.settings.parser.included_event_ids
        search_after = None

        while True:
            must_clauses = [
                {"range": {"timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}},
                {"terms": {"data.win.system.eventID": [str(eid) for eid in event_ids]}},
            ]
            query: Dict[str, Any] = {
                "size": page_size,
                "sort": [{"timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
                "query": {"bool": {"must": must_clauses}},
            }
            if search_after:
                query["search_after"] = search_after

            result = self._search(query)
            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                break

            for hit in hits:
                event = wazuh_alert_to_user_behavior_event(hit.get("_source", {}))
                if event is not None:
                    yield event

            search_after = hits[-1]["sort"]
            if len(hits) < page_size:
                break


# --------------------------------------------------------------------------- #
# WazuhAlertWriter - Injecting UBA anomalies back into Wazuh
# --------------------------------------------------------------------------- #

class WazuhAlertWriter:
    """
   The UBA risk_engine writes anomalies it detects to a local file as a JSON string. 
   This file must be monitored by the Wazuh agent using `localfile` (with `log_format=json`) 
   so that a custom rule on the manager can convert it into an alert.

    Setup steps (one-time):
      1. Specify the `output_file` path on the machine where this script runs 
      (typically on the Wazuh agent itself or a shared location the agent can read from).
      2. Check the agent's ossec.conf: docs/wazuh_agent_localfile.xml
      3. Manager-in local_rules.xml-inə bax: docs/wazuh_custom_rule.xml
      4. Manager-i restart edin, `wazuh-logtest` ilə test edin.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.output_file: Path = self.settings.wazuh_alert_output.output_file
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

    def write_alert(
        self,
        user: str,
        rule_name: str,
        severity: str,
        risk_score: float,
        description: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Appends an anomaly alert to a file as a JSON string. 
        `severity`: "low" | "medium" | "high" | "critical" 
        (according to risk_engine thresholds)
        """
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "AI-UBA",
            "alert_type": "user_behavior_anomaly",
            "rule_name": rule_name,
            "user": user,
            "severity": severity,
            "risk_score": round(risk_score, 2),
            "description": description,
            "details": details or {},
        }

        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

        logger.info(
            "UBA alert written: user=%s rule=%s severity=%s score=%.2f",
            user, rule_name, severity, risk_score,
        )
        return payload


# --------------------------------------------------------------------------- #
# CLI test entrypoint (for debugging)
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    client = WazuhIndexerClient()
    count = 0
    for evt in client.fetch_recent_events(minutes=120):
        count += 1
        if count <= 5:
            print(evt.model_dump_json(indent=2))
    print(f"\nTotal normalized events: {count}")
