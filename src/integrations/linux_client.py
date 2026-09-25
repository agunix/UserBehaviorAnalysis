"""
AI-UBA :: Linux Integration (Wazuh)
--------------------------------------
`wazuh_client.py` ilə eyni məqsədə xidmət edir (Wazuh Indexer-dən alert çəkib
UserBehaviorEvent-ə normallaşdırmaq), lakin Linux mənbələri Windows-dan
STRUKTURCA fərqlidir, ona görə ayrı fayldır:

  - Windows/Sysmon: hər event-in ədədi bir `EventID`-si var (1, 4624, 4688...),
    filtrasiya bunun üzərindən aparılır.
  - Linux mənbələri (sshd/PAM, auditd, syscheck) belə vahid ID sxeminə malik
    deyil. Bunun əvəzinə Wazuh-un öz `rule.groups` təsnifatı istifadə olunur
    (məs: "sshd", "audit_command", "syscheck").

Əhatə olunan 3 mənbə və Wazuh-dakı xam sahə yerləri:

  1. SSH/PAM autentifikasiya  -> data.srcip, data.srcuser, data.dstuser
  2. Auditd (proses/syscall)  -> data.audit.* (exe, command, uid, euid,
                                  syscall, key, execve.a0..aN)
  3. Syscheck (FIM)           -> syscheck.* (DİQQƏT: `data` altında DEYİL,
                                  sənəddə top-level sahədir)

QEYD (dəqiqlik üçün şəffaflıq): auditd sahələrinin `data.audit.*` altında
olması Windows-dakı `data.win.*` konvensiyasına əsaslanan MƏNTİQİ fərziyyədir
və Wazuh-un rəsmi sənədləşməsindəki nümunələrlə üst-üstə düşür, lakin sizin
konkret Wazuh versiyanızda kiçik fərqlər ola bilər. Ona görə aşağıdakı
`_extract_audit_fields` funksiyası HƏM `data.audit`, HƏM DƏ (ehtiyat üçün)
sənədin kökündəki `audit` açarını yoxlayır. İlk real testdən sonra
`python -m src.integrations.linux_client --debug` ilə xam JSON-u çap edib
təsdiqləyin; uyğunsuzluq olarsa mənə göndərin, mapping-i dəqiqləşdirərik.

İstifadə:
    from src.integrations.linux_client import LinuxWazuhClient
    from src.integrations.wazuh_client import WazuhAlertWriter  # eyni loopback

    client = LinuxWazuhClient()
    for event in client.fetch_recent_events(minutes=60):
        print(event.model_dump())
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from src.config.config import get_settings
from src.parser.parser import UserBehaviorEvent
from src.parser.utils import normalize_timestamp

logger = logging.getLogger("aiuba.linux_client")

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


# --------------------------------------------------------------------------- #
# Köməkçi: case-insensitive dict axtarışı (wazuh_client.py-dəki ilə eynidir)
# --------------------------------------------------------------------------- #

def _ci_get(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    if not d:
        return None
    lowered = {k.lower(): v for k, v in d.items()}
    for key in keys:
        val = lowered.get(key.lower())
        if val not in (None, ""):
            return val
    return None


# --------------------------------------------------------------------------- #
# rule.groups -> (event_name, category) təsnifatı
# --------------------------------------------------------------------------- #

_GROUP_METADATA: List[tuple] = [
    # (qrup adı, event_name, category) - sıra vacibdir, ilk uyğunluq qalib gəlir
    ("authentication_failed", "LinuxLoginFailure", "auth"),
    ("authentication_success", "LinuxLoginSuccess", "auth"),
    ("sshd", "SshdEvent", "auth"),
    ("pam", "PamEvent", "auth"),
    ("audit_command", "AuditdCommandExec", "process"),
    ("audit", "AuditdEvent", "process"),
    ("syscheck", "FileIntegrityChange", "filesystem"),
]


def _classify_by_groups(groups: List[str]) -> tuple:
    groups_lower = {g.lower() for g in (groups or [])}
    for group_key, name, category in _GROUP_METADATA:
        if group_key in groups_lower:
            return name, category
    return "LinuxUnclassified", "uncategorized"


# --------------------------------------------------------------------------- #
# Sahə çıxarıcıları (mənbəyə görə)
# --------------------------------------------------------------------------- #

def _extract_auth_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """SSH/PAM auth alert-lərindən: data.srcip, data.srcuser, data.dstuser."""
    fields = {}
    src_ip = _ci_get(data, "srcip")
    src_user = _ci_get(data, "srcuser")
    dst_user = _ci_get(data, "dstuser")
    if src_ip:
        fields["source_ip"] = src_ip
    # dstuser adətən hədəf hesabdır (kimə giriş edilib) - user sahəsi kimi saxlayırıq
    if dst_user:
        fields["user"] = dst_user
    elif src_user:
        fields["user"] = src_user
    return fields


def _extract_audit_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Auditd alert-lərindən process/command məlumatı.
    Həm `data.audit.*`, həm ehtiyat olaraq kökdəki `audit.*` yoxlanılır.
    """
    audit = data.get("audit") if isinstance(data.get("audit"), dict) else {}
    fields = {}

    exe = _ci_get(audit, "exe")
    command = _ci_get(audit, "command")
    uid = _ci_get(audit, "uid")
    euid = _ci_get(audit, "euid")
    syscall_key = _ci_get(audit, "key")

    if exe:
        fields["process_name"] = exe
    if command:
        fields["command_line"] = command
    elif exe:
        # command sahəsi yoxdursa, execve.a0..aN-dən CLI-ni yenidən qurmağa çalış
        argv = []
        i = 0
        while True:
            arg = _ci_get(audit, f"execve.a{i}")
            if arg is None:
                break
            argv.append(str(arg))
            i += 1
        if argv:
            fields["command_line"] = " ".join(argv)

    user_id = uid or euid
    if user_id:
        fields["user"] = str(user_id)  # ehtiyat: UID rəqəmi, username-ə çevirmək lazım gələ bilər
    if syscall_key:
        fields["target_object"] = syscall_key  # audit "key" - hansı qaydaya uyğun gəldiyi

    return fields


def _extract_syscheck_fields(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    FIM alert-lərindən: `alert["syscheck"]` (top-level, `data` altında DEYİL).
    """
    syscheck = alert.get("syscheck", {}) or {}
    fields = {}

    path = _ci_get(syscheck, "path")
    if path:
        fields["target_filename"] = path

    event_type = _ci_get(syscheck, "event")  # added | modified | deleted
    uid_after = _ci_get(syscheck, "uid_after")
    uname_after = _ci_get(syscheck, "uname_after")

    if uname_after:
        fields["user"] = uname_after
    elif uid_after:
        fields["user"] = str(uid_after)

    if event_type:
        # raw-a əlavə ediləcək, sxemdə xüsusi sahə yoxdur
        fields.setdefault("_syscheck_event_type", event_type)

    return fields


# --------------------------------------------------------------------------- #
# Əsas mapper: Wazuh alert -> UserBehaviorEvent
# --------------------------------------------------------------------------- #

def linux_alert_to_user_behavior_event(alert: Dict[str, Any]) -> Optional[UserBehaviorEvent]:
    """
    Linux mənşəli (sshd/PAM/auditd/syscheck) bir Wazuh alert sənədini
    `UserBehaviorEvent`-ə çevirir. Tanınmayan mənbə üçün None qaytarır.
    """
    rule = alert.get("rule", {}) or {}
    groups = rule.get("groups", []) or []
    event_name, category = _classify_by_groups(groups)

    if category == "uncategorized":
        return None  # bizim izlədiyimiz Linux mənbələrindən deyil

    data = alert.get("data", {}) or {}

    normalized: Dict[str, Any] = {}
    if category == "auth":
        normalized.update(_extract_auth_fields(data))
    elif category == "process":
        normalized.update(_extract_audit_fields(data))
    elif category == "filesystem":
        normalized.update(_extract_syscheck_fields(alert))

    raw_ts = alert.get("timestamp")
    computer = (alert.get("agent") or {}).get("name")

    raw_payload = {**data}
    if category == "filesystem":
        raw_payload["syscheck"] = alert.get("syscheck", {})
    raw_payload["_wazuh_rule_id"] = rule.get("id")
    raw_payload["_wazuh_rule_groups"] = groups
    raw_payload["_wazuh_rule_level"] = rule.get("level")

    return UserBehaviorEvent(
        event_id=int(rule.get("id", -1)) if str(rule.get("id", "")).isdigit() else -1,
        event_name=event_name,
        category=category,
        source="linux",
        timestamp=normalize_timestamp(raw_ts) if raw_ts else None,
        computer=computer,
        raw=raw_payload,
        **{k: v for k, v in normalized.items() if not k.startswith("_")},
    )


# --------------------------------------------------------------------------- #
# LinuxWazuhClient - Indexer sorğusu (rule.groups filteri ilə)
# --------------------------------------------------------------------------- #

class LinuxWazuhClient:
    """
    `WazuhIndexerClient`-dən (wazuh_client.py) fərqli olaraq, filtri
    `data.win.system.eventID` yox, `rule.groups` üzərindən aparır.
    Auth (basic), host/port/index_pattern konfiqurasiyası eynidir
    (`config.yaml`-dakı `wazuh_indexer` bölməsi paylaşılır).
    """

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
        rule_groups: Optional[List[str]] = None,
        agent_name: Optional[str] = None,
        size: int = 1000,
    ) -> Iterator[UserBehaviorEvent]:
        rule_groups = rule_groups or self.settings.parser.linux_rule_groups
        now = datetime.now(timezone.utc)
        since = now - timedelta(minutes=minutes)

        must_clauses: List[Dict[str, Any]] = [
            {"range": {"timestamp": {"gte": since.isoformat(), "lte": now.isoformat()}}},
            {"terms": {"rule.groups": rule_groups}},
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
        logger.info("Wazuh indexer-dən %d Linux alert alındı (son %d dəq)", len(hits), minutes)

        for hit in hits:
            event = linux_alert_to_user_behavior_event(hit.get("_source", {}))
            if event is not None:
                yield event

    def fetch_events_paginated(
        self,
        start: datetime,
        end: datetime,
        rule_groups: Optional[List[str]] = None,
        page_size: int = 1000,
    ) -> Iterator[UserBehaviorEvent]:
        rule_groups = rule_groups or self.settings.parser.linux_rule_groups
        search_after = None

        while True:
            must_clauses = [
                {"range": {"timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}},
                {"terms": {"rule.groups": rule_groups}},
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
                event = linux_alert_to_user_behavior_event(hit.get("_source", {}))
                if event is not None:
                    yield event

            search_after = hits[-1]["sort"]
            if len(hits) < page_size:
                break


# --------------------------------------------------------------------------- #
# CLI test giriş nöqtəsi
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    debug = "--debug" in sys.argv

    client = LinuxWazuhClient()
    count = 0
    for evt in client.fetch_recent_events(minutes=120):
        count += 1
        if count <= 5:
            print(evt.model_dump_json(indent=2))
    print(f"\nCəmi normallaşdırılan Linux event: {count}")

    if debug and count == 0:
        print(
            "\nHeç bir event tapılmadı. --debug: raw alert strukturunu yoxlamaq üçün "
            "birbaşa curl ilə sorğu göndərib nəticəni mənə göndərin:\n"
            "  curl -k -u <user>:<pass> "
            "'https://127.0.0.1:9200/wazuh-alerts-*/_search?size=1' "
            "-H 'Content-Type: application/json' "
            "-d '{\"query\":{\"terms\":{\"rule.groups\":[\"sshd\",\"audit\",\"syscheck\"]}}}'"
        )
