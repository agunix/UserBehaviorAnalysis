"""
UBA :: API Service Layer
-----------------------------
Dashboard/API for bussiness users and analysts. It provides:

  - From Wazuh Indexer (by means of Windows + Linux clients) fetches events in the last N minutes (configurable, default 60)
  - Caches frequently accessed queries (to avoid loading the Indexer)
  - Aggregates events into a single list and calculates summaries (KPIs, timelines, top-N)

Design notes:
  * Queries are ordered by `timestamp desc` so that when the window is large, the most recent events are retained rather than the oldest. 
    This is why clients use the `_search` method with `sort` and `track_total_hits` instead of `_search_by_id` (which is faster but returns only the most recent events).
  * In a single query, a maximum of `api.max_events_per_source` (<= 10,000, the OpenSearch `max_result_window` limit) events are retrieved per source; 
    the total count (`track_total_hits`) and the `truncated` flag are calculated accurately.
  * This module does not render HTML; From UI field (username, command line, 
    etc. - which could be under the attacker's control) it only displays via `textContent`.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from src.config.config import get_settings
from src.integrations.linux_client import LinuxWazuhClient, linux_alert_to_user_behavior_event
from src.integrations.wazuh_client import WazuhIndexerClient, wazuh_alert_to_user_behavior_event
from src.parser.parser import UserBehaviorEvent

logger = logging.getLogger("aiuba.api.service")

VALID_SOURCES = ("all", "windows", "linux")
OPENSEARCH_MAX_WINDOW = 10_000
MAX_CACHE_ENTRIES = 8
FAILURE_EVENT_NAMES = {"LogonFailure", "LinuxLoginFailure"}
_IGNORED_IPS = {"", "-", "::1", "127.0.0.1", "::"}


class IndexerUnavailable(Exception):
    """Do not expose internal details to the user (no sensitive information)."""


def friendly_error(exc: Exception) -> str:
    """Convert requests errors to user-friendly messages without exposing sensitive information."""
    if isinstance(exc, requests.exceptions.SSLError):
        return "SSL error: certificate and wazuh_indexer.verify_ssl settings"
    if isinstance(exc, requests.exceptions.Timeout):
        return "Indexer timeout: no response within the expected time"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Indexer connection error: check host/port and Docker port mapping"
    if isinstance(exc, requests.exceptions.HTTPError):
        status = exc.response.status_code if exc.response is not None else None
        if status in (401, 403):
            return "Indexer authentication error: check username/password"
        return f"Indexer HTTP {status} returned"
    return "Indexer returned an unexpected response"


# --------------------------------------------------------------------------- #
# Timestamp parse (Python 3.9+ for tolerance: +0000, Z, 7 digit fraction)
# --------------------------------------------------------------------------- #

_OFFSET_RE = re.compile(r"([+-]\d{2})(\d{2})$")
_FRAC_RE = re.compile(r"\.(\d+)")
_EPOCH_MIN = datetime.min.replace(tzinfo=timezone.utc)


def parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        s = value.strip().replace("Z", "+00:00")
        s = _OFFSET_RE.sub(r"\1:\2", s)
        s = _FRAC_RE.sub(lambda m: "." + m.group(1).ljust(6, "0")[:6], s, count=1)
        dt = datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Summary calculation (clean function - easy to test)
# --------------------------------------------------------------------------- #

def _bucket_seconds(minutes: int) -> int:
    if minutes <= 60:
        return 300
    if minutes <= 360:
        return 900
    if minutes <= 1440:
        return 3600
    return 6 * 3600


def _top(counter: Counter, n: int = 10) -> List[Dict[str, Any]]:
    return [{"name": k, "count": v} for k, v in counter.most_common(n)]


def build_summary(
    events: List[UserBehaviorEvent],
    start: datetime,
    end: datetime,
    minutes: int,
) -> Dict[str, Any]:
    users: Counter = Counter()
    ips: Counter = Counter()
    hosts: Counter = Counter()
    categories: Counter = Counter()
    by_source = {"windows": 0, "linux": 0}
    failures = 0

    bucket = _bucket_seconds(minutes)
    first = int(start.timestamp()) // bucket * bucket
    last = int(end.timestamp()) // bucket * bucket
    n_buckets = (last - first) // bucket + 1
    totals = [0] * n_buckets
    fails = [0] * n_buckets

    for ev in events:
        is_fail = ev.event_name in FAILURE_EVENT_NAMES
        failures += 1 if is_fail else 0
        categories[ev.category or "uncategorized"] += 1
        by_source["linux" if ev.source == "linux" else "windows"] += 1
        if ev.user:
            users[ev.user] += 1
        if ev.source_ip and ev.source_ip not in _IGNORED_IPS:
            ips[ev.source_ip] += 1
        if ev.computer:
            hosts[ev.computer] += 1

        ts = parse_ts(ev.timestamp)
        if ts is None:
            continue
        idx = (int(ts.timestamp()) // bucket * bucket - first) // bucket
        if 0 <= idx < n_buckets:
            totals[idx] += 1
            fails[idx] += 1 if is_fail else 0

    return {
        "total": len(events),
        "kpis": {
            "auth_failures": failures,
            "unique_users": len(users),
            "unique_source_ips": len(ips),
            "unique_hosts": len(hosts),
        },
        "by_source": by_source,
        "by_category": _top(categories, 20),
        "top_users": _top(users),
        "top_source_ips": _top(ips),
        "top_hosts": _top(hosts),
        "timeline": {
            "bucket_seconds": bucket,
            "buckets": [
                {
                    "t": datetime.fromtimestamp(first + i * bucket, tz=timezone.utc).isoformat(),
                    "total": totals[i],
                    "auth_failures": fails[i],
                }
                for i in range(n_buckets)
            ],
        },
    }


def _event_to_dict(ev: UserBehaviorEvent) -> Dict[str, Any]:
    """Convert event to JSON; format timestamp for browser compatibility (including Safari)."""
    d = ev.model_dump()
    ts = parse_ts(d.get("timestamp"))
    if ts is not None:
        d["timestamp"] = ts.isoformat()
    return d


# --------------------------------------------------------------------------- #
# EventService
# --------------------------------------------------------------------------- #

class EventService:
    def __init__(self, settings=None, windows_client=None, linux_client=None):
        self.settings = settings or get_settings()
        self.windows_client = windows_client or WazuhIndexerClient(self.settings)
        self.linux_client = linux_client or LinuxWazuhClient(self.settings)
        self._cache: "OrderedDict[Tuple[int, str], Tuple[float, Dict[str, Any]]]" = OrderedDict()
        self._lock = threading.Lock()

    # ----- Direct request to Indexer ----- #

    def _query_newest(
        self,
        client,
        mapper: Callable[[Dict[str, Any]], Optional[UserBehaviorEvent]],
        filter_clause: Dict[str, Any],
        start: datetime,
        end: datetime,
        cap: int,
    ) -> Tuple[List[UserBehaviorEvent], int]:
        query = {
            "size": cap,
            "track_total_hits": True,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}},
                        filter_clause,
                    ]
                }
            },
        }
        try:
            result = client._search(query)
        except requests.exceptions.RequestException as exc:
            logger.warning("Indexer request failed: %s", type(exc).__name__)
            raise IndexerUnavailable(friendly_error(exc)) from exc

        hits_obj = result.get("hits", {}) or {}
        hits = hits_obj.get("hits", []) or []
        total = hits_obj.get("total", len(hits))
        total_value = total.get("value", len(hits)) if isinstance(total, dict) else int(total)

        events: List[UserBehaviorEvent] = []
        skipped = 0
        for hit in hits:
            try:
                ev = mapper(hit.get("_source", {}) or {})
            except Exception:  # noqa: BLE001 - no need to expose internal details to the user; just skip the event
                logger.warning("Failed to map event: %s", hit.get("_id"))
                skipped += 1
                continue
            if ev is not None:
                events.append(ev)
        if skipped:
            logger.warning("%d events could not be mapped and were skipped", skipped)
        return events, total_value

    def _fetch(self, minutes: int, source: str) -> Dict[str, Any]:
        cap = max(1, min(self.settings.api.max_events_per_source, OPENSEARCH_MAX_WINDOW))
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes)

        events: List[UserBehaviorEvent] = []
        total_in_window = 0

        if source in ("all", "windows"):
            filt = {"terms": {"data.win.system.eventID": [str(i) for i in self.settings.parser.included_event_ids]}}
            evs, total = self._query_newest(
                self.windows_client, wazuh_alert_to_user_behavior_event, filt, start, end, cap
            )
            events += evs
            total_in_window += total

        if source in ("all", "linux"):
            filt = {"terms": {"rule.groups": self.settings.parser.linux_rule_groups}}
            evs, total = self._query_newest(
                self.linux_client, linux_alert_to_user_behavior_event, filt, start, end, cap
            )
            events += evs
            total_in_window += total

        events.sort(key=lambda e: parse_ts(e.timestamp) or _EPOCH_MIN, reverse=True)
        return {
            "events": events,
            "start": start,
            "end": end,
            "total_in_window": total_in_window,
            "truncated": total_in_window > len(events),
            "generated_at": end,
        }

    # ----- General API ----- #

    def overview(self, minutes: int, source: str, limit: int) -> Dict[str, Any]:
        if source not in VALID_SOURCES:
            raise ValueError(f"source {source} must be one of {VALID_SOURCES}")

        ttl = max(0, self.settings.api.cache_ttl_seconds)
        key = (minutes, source)
        cached = False

        with self._lock:
            entry = self._cache.get(key)
            if entry and entry[0] > time.monotonic():
                data = entry[1]
                cached = True
                self._cache.move_to_end(key)
            else:
                data = self._fetch(minutes, source)
                if ttl:
                    self._cache[key] = (time.monotonic() + ttl, data)
                    self._cache.move_to_end(key)
                    while len(self._cache) > MAX_CACHE_ENTRIES:
                        self._cache.popitem(last=False)

        events: List[UserBehaviorEvent] = data["events"]
        return {
            "meta": {
                "generated_at": data["generated_at"].isoformat(),
                "window": {
                    "minutes": minutes,
                    "start": data["start"].isoformat(),
                    "end": data["end"].isoformat(),
                },
                "source": source,
                "total_in_window": data["total_in_window"],
                "analyzed_events": len(events),
                "returned_events": min(limit, len(events)),
                "truncated": data["truncated"],
                "cached": cached,
            },
            "summary": build_summary(events, data["start"], data["end"], minutes),
            "events": [_event_to_dict(e) for e in events[:limit]],
        }

    def check_indexer(self) -> Dict[str, Any]:
        cfg = self.settings.wazuh_indexer
        try:
            resp = requests.get(
                f"{cfg.base_url}/",
                auth=(cfg.username, cfg.password),
                verify=cfg.verify_ssl,
                timeout=5,
            )
            resp.raise_for_status()
            info = resp.json()
            return {
                "ok": True,
                "cluster_name": info.get("cluster_name"),
                "version": (info.get("version") or {}).get("number"),
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("Indexer health check failed: %s", type(exc).__name__)
            return {"ok": False, "detail": friendly_error(exc)}
