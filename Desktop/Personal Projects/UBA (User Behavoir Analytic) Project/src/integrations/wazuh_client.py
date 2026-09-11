"""
AI-UBA :: Wazuh Integration
------------------------------
İki əsas komponentdən ibarətdir:

1. WazuhIndexerClient
   Wazuh Indexer-dən (OpenSearch, port 9200, Basic Auth) `wazuh-alerts-*` index-i
   üzərindən Sysmon/Security alert-lərini çəkir və mövcud `UserBehaviorEvent`
   sxeminə (bax: src/parser/parser.py) map edir.

   QEYD: Wazuh Manager API-si (port 55000, JWT) burada İSTİFADƏ OLUNMUR, çünki
   alert-lər manager-də deyil, indexer-də saxlanılır.

2. WazuhAlertWriter
   AI-UBA-nın öz aşkarladığı anomaliyaları geri Wazuh-a "inject" etmək üçün.
   Wazuh-un rəsmi `POST /events` endpoint-i hazırda qeyri-stabildir (Wazuh-un
   öz repo-sunda silinmə mərhələsindədir), ona görə sənədləşdirilmiş və etibarlı
   üsuldan istifadə edirik: JSON sətri lokal fayla yazılır, Wazuh agent bu faylı
   `<localfile><log_format>json</log_format></localfile>` ilə izləyir, manager-də
   isə custom decoder+rule bunu alert-ə çevirir.
   Bax: docs/wazuh_agent_localfile.xml və docs/wazuh_custom_rule.xml

İstifadə nümunəsi:
    from src.integrations.wazuh_client import WazuhIndexerClient, WazuhAlertWriter

    client = WazuhIndexerClient()
    for event in client.fetch_recent_events(minutes=60):
        print(event.model_dump())

    writer = WazuhAlertWriter()
    writer.write_alert(
        user="CORP\\agaverdi.k",
        rule_name="AIUBA_AnomalousLoginTime",
        severity="high",
        risk_score=87.5,
        description="İstifadəçi adi iş saatlarından kənar giriş etdi",
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

from src.config import get_settings
from src.parser.parser import UserBehaviorEvent, normalize_event
from src.parser.utils import get_event_metadata, normalize_timestamp, safe_get

logger = logging.getLogger("aiuba.wazuh_client")

# urllib3-ün self-signed sertifikat xəbərdarlıqlarını sussuzlaşdır (yalnız test mühiti üçün;
# production-da verify_ssl=True istifadə edin və bu sətri silin).
try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


# --------------------------------------------------------------------------- #
# Wazuh alert JSON -> UserBehaviorEvent map edilməsi
# --------------------------------------------------------------------------- #
# Wazuh-un Windows/Sysmon decoder-i xam EVTX sahələrini `data.win.eventdata.*`
# altında, əsasən camelCase (ilk hərf kiçik) formatda saxlayır. Sistem sahələri
# isə `data.win.system.*` altındadır. EVTX XML-dəki adlarla uyğunluq üçün
# case-insensitive axtarış aparırıq ki, Wazuh versiyaları arasındakı kiçik
# fərqlərə qarşı dayanıqlı olsun.

def _ci_get(d: Dict[str, Any], *keys: str) -> Optional[str]:
    """Case-insensitive açar axtarışı. Birinci tapılan qeyri-boş dəyəri qaytarır."""
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
    Tək bir Wazuh alert sənədini (indexer _search nəticəsindəki `_source`)
    `UserBehaviorEvent`-ə çevirir. Sysmon/Security mənşəli olmayan alert-lər
    üçün None qaytarır (data.win yoxdursa).
    """
    data = alert.get("data", {}) or {}
    win = data.get("win", {}) or {}
    system = win.get("system", {}) or {}
    eventdata = win.get("eventdata", {}) or {}

    raw_event_id = _ci_get(system, "eventID")
    if raw_event_id is None:
        return None  # Sysmon/Security mənşəli deyil (məs. Linux auth, firewall və s.)

    try:
        event_id = int(raw_event_id)
    except (TypeError, ValueError):
        return None

    meta = get_event_metadata(event_id)

    raw_ts = _ci_get(system, "systemTime") or alert.get("timestamp")
    computer = _ci_get(system, "computer") or (alert.get("agent") or {}).get("name")
    record_id_raw = _ci_get(system, "eventRecordID")

    # _FIELD_ALIASES ilə eyni məntiq, sadəcə mənbə `eventdata` dict-idir
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
    """Wazuh Indexer-dən (OpenSearch) alert sorğulayan client."""

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
        Son `minutes` dəqiqə ərzindəki Windows/Sysmon alert-lərini çəkir və
        UserBehaviorEvent-ə normallaşdırır.

        NOT: Wazuh indexer sorğuları defolt olaraq maksimum 10.000 nəticə ilə
        məhdudlaşır (index.max_result_window). Böyük vaxt aralıqları üçün
        `fetch_events_paginated`-dan istifadə edin.
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
        logger.info("Wazuh indexer-dən %d alert alındı (son %d dəq)", len(hits), minutes)

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
        `search_after` ilə səhifələnən sorğu — 10.000 limitini keçmək üçün.
        Böyük tarixi aralıqları (məs. modelin train edilməsi üçün 30 gün) çəkərkən istifadə edin.
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
# WazuhAlertWriter - AI-UBA anomaliyalarını geri Wazuh-a inject etmək
# --------------------------------------------------------------------------- #

class WazuhAlertWriter:
    """
    AI-UBA risk_engine tərəfindən aşkarlanan anomaliyaları JSON sətri kimi
    lokal fayla yazır. Bu fayl Wazuh agent-in `localfile` (log_format=json)
    ilə izlədiyi fayl olmalıdır ki, manager-də custom rule bunu alert-ə çevirsin.

    Qurulum addımları (bir dəfəlik):
      1. Bu skriptin işlədiyi maşında (adətən Wazuh agent-in özündə və ya
         agent-in oxuya biləcəyi paylaşılan yerdə) `output_file` yolunu təyin edin.
      2. Agent-in ossec.conf-una bax: docs/wazuh_agent_localfile.xml
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
        Bir anomaliya alert-ini JSON sətri kimi fayla append edir.
        `severity`: "low" | "medium" | "high" | "critical" (risk_engine threshold-larına uyğun)
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
            "AI-UBA alert yazıldı: user=%s rule=%s severity=%s score=%.2f",
            user, rule_name, severity, risk_score,
        )
        return payload


# --------------------------------------------------------------------------- #
# CLI test giriş nöqtəsi
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    client = WazuhIndexerClient()
    count = 0
    for evt in client.fetch_recent_events(minutes=120):
        count += 1
        if count <= 5:
            print(evt.model_dump_json(indent=2))
    print(f"\nCəmi normallaşdırılan event: {count}")
