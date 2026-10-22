"""EventService + build_summary testləri (Wazuh Indexer saxta klientlərlə əvəz olunur)."""

from datetime import datetime, timedelta, timezone

import pytest
import requests

from src.api.service import EventService, IndexerUnavailable, build_summary, parse_ts
from src.config.config import ApiSettings, Settings


def _ts(minutes_ago: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")  # Wazuh formatı


def linux_alert(minutes_ago, groups, user="ubuntu", ip=None, rule_id="5710"):
    data = {"dstuser": user}
    if ip:
        data["srcip"] = ip
    return {
        "timestamp": _ts(minutes_ago),
        "agent": {"name": "ubuntu_host"},
        "rule": {"id": rule_id, "level": 5, "groups": groups},
        "data": data,
    }


def windows_alert(minutes_ago, event_id="4625", user="alice", ip="10.0.0.9"):
    return {
        "timestamp": _ts(minutes_ago),
        "agent": {"name": "WIN01"},
        "rule": {"id": "60122", "level": 5, "groups": ["windows"]},
        "data": {"win": {
            "system": {"eventID": event_id, "systemTime": _ts(minutes_ago).replace("+0000", "Z"), "computer": "WIN01.corp"},
            "eventdata": {"targetUserName": user, "ipAddress": ip},
        }},
    }


class FakeClient:
    def __init__(self, docs=None, total=None, error=None):
        self.docs = docs or []
        self.total = len(self.docs) if total is None else total
        self.error = error
        self.calls = 0
        self.last_query = None

    def _search(self, query):
        self.calls += 1
        self.last_query = query
        if self.error:
            raise self.error
        return {"hits": {"total": {"value": self.total}, "hits": [{"_source": d} for d in self.docs]}}


def make_service(win=None, lin=None, ttl=15, cap=5000):
    settings = Settings(api=ApiSettings(cache_ttl_seconds=ttl, max_events_per_source=cap))
    return EventService(settings, windows_client=win or FakeClient(), linux_client=lin or FakeClient())


def test_parse_ts_handles_wazuh_formats():
    assert parse_ts("2026-10-13T14:07:53.132+0000").isoformat() == "2026-10-13T14:07:53.132000+00:00"
    assert parse_ts("2026-08-03T10:15:32.1234567Z").isoformat() == "2026-08-03T10:15:32.123456+00:00"
    assert parse_ts("2026-10-02T16:01:30.723+0400").isoformat() == "2026-10-02T12:01:30.723000+00:00"
    assert parse_ts("garbage") is None
    assert parse_ts(None) is None


def test_overview_merges_sources_and_computes_summary():
    win = FakeClient([windows_alert(10), windows_alert(20, event_id="4624", user="bob")])
    lin = FakeClient([
        linux_alert(5, ["authentication_failed", "sshd"], user="root", ip="185.220.101.4"),
        linux_alert(30, ["pam", "syslog"], rule_id="5502"),
    ])
    out = make_service(win, lin).overview(minutes=60, source="all", limit=100)

    s = out["summary"]
    assert s["total"] == 4
    assert s["by_source"] == {"windows": 2, "linux": 2}
    assert s["kpis"]["auth_failures"] == 2          # 4625 + linux authentication_failed
    assert s["kpis"]["unique_source_ips"] == 2      # 10.0.0.9 və 185.220.101.4
    assert {u["name"] for u in s["top_users"]} == {"alice", "bob", "root", "ubuntu"}
    assert sum(b["total"] for b in s["timeline"]["buckets"]) == 4
    assert sum(b["auth_failures"] for b in s["timeline"]["buckets"]) == 2
    # ən yeni event birinci
    stamps = [parse_ts(e["timestamp"]) for e in out["events"]]
    assert stamps == sorted(stamps, reverse=True)
    assert out["meta"]["truncated"] is False


def test_source_filter_only_queries_requested_client():
    win, lin = FakeClient([windows_alert(5)]), FakeClient([linux_alert(5, ["sshd"])])
    svc = make_service(win, lin)
    out = svc.overview(minutes=60, source="linux", limit=10)
    assert win.calls == 0 and lin.calls == 1
    assert out["summary"]["by_source"]["windows"] == 0


def test_query_requests_newest_first_with_total_hits():
    lin = FakeClient([linux_alert(1, ["sshd"])])
    make_service(lin=lin).overview(minutes=15, source="linux", limit=5)
    q = lin.last_query
    assert q["sort"] == [{"timestamp": {"order": "desc"}}]
    assert q["track_total_hits"] is True
    assert {"terms": {"rule.groups": ["sshd", "pam", "authentication_success", "authentication_failed",
                                       "audit_command", "audit", "syscheck"]}} in q["query"]["bool"]["must"]


def test_truncated_flag_uses_total_not_page_size():
    lin = FakeClient([linux_alert(i, ["sshd"]) for i in range(3)], total=250)
    out = make_service(lin=lin, cap=3).overview(minutes=60, source="linux", limit=10)
    assert out["meta"]["truncated"] is True
    assert out["meta"]["total_in_window"] == 250
    assert out["meta"]["analyzed_events"] == 3
    assert lin.last_query["size"] == 3


def test_cache_avoids_second_indexer_call_and_ttl_zero_disables_it():
    lin = FakeClient([linux_alert(1, ["sshd"])])
    svc = make_service(lin=lin, ttl=60)
    first = svc.overview(60, "linux", 10)
    second = svc.overview(60, "linux", 10)
    assert lin.calls == 1 and first["meta"]["cached"] is False and second["meta"]["cached"] is True

    lin2 = FakeClient([linux_alert(1, ["sshd"])])
    svc2 = make_service(lin=lin2, ttl=0)
    svc2.overview(60, "linux", 10)
    svc2.overview(60, "linux", 10)
    assert lin2.calls == 2


def test_limit_only_slices_table_not_summary():
    lin = FakeClient([linux_alert(i, ["sshd"]) for i in range(1, 8)])
    out = make_service(lin=lin).overview(60, "linux", limit=3)
    assert len(out["events"]) == 3 and out["summary"]["total"] == 7 and out["meta"]["returned_events"] == 3


@pytest.mark.parametrize("exc, fragment", [
    (requests.exceptions.ConnectionError("boom 10.1.2.3"), "qoşulmaq olmadı"),
    (requests.exceptions.ConnectTimeout("t"), "timeout"),
    (requests.exceptions.SSLError("s"), "SSL"),
])
def test_indexer_errors_become_safe_messages(exc, fragment):
    svc = make_service(lin=FakeClient(error=exc))
    with pytest.raises(IndexerUnavailable) as info:
        svc.overview(60, "linux", 10)
    assert fragment in str(info.value)
    assert "10.1.2.3" not in str(info.value)   # host/detal sızmasın


def test_http_401_message():
    resp = requests.Response()
    resp.status_code = 401
    err = requests.exceptions.HTTPError(response=resp)
    with pytest.raises(IndexerUnavailable) as info:
        make_service(lin=FakeClient(error=err)).overview(60, "linux", 10)
    assert "autentifikasiya" in str(info.value)


def test_bad_document_is_skipped_not_fatal():
    good = linux_alert(1, ["sshd"])
    bad = {"rule": {"groups": ["sshd"], "id": "x"}, "data": None, "timestamp": 12345}
    out = make_service(lin=FakeClient([bad, good])).overview(60, "linux", 10)
    assert out["summary"]["total"] >= 1


def test_build_summary_empty():
    now = datetime.now(timezone.utc)
    s = build_summary([], now - timedelta(minutes=60), now, 60)
    assert s["total"] == 0 and s["kpis"]["auth_failures"] == 0
    assert all(b["total"] == 0 for b in s["timeline"]["buckets"])


def test_event_timestamps_are_normalized_for_browsers():
    lin = FakeClient([linux_alert(3, ["sshd"])])
    out = make_service(lin=lin).overview(60, "linux", 10)
    stamp = out["events"][0]["timestamp"]
    assert stamp.endswith("+00:00") and "+0000" not in stamp
    assert parse_ts(stamp) is not None
