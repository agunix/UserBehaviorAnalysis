# tests/test_parser_utils.py
import pytest
from src.parser.utils import get_event_metadata, normalize_timestamp, safe_get, xml_event_to_dict


def test_get_event_metadata_known_id():
    meta = get_event_metadata(4624)
    assert meta["name"] == "LogonSuccess"
    assert meta["category"] == "auth"


def test_get_event_metadata_unknown_id():
    meta = get_event_metadata(99999)
    assert meta["category"] == "uncategorized"


def test_normalize_timestamp_truncates_extra_precision():
    raw = "2026-08-03T10:15:32.1234567Z"
    result = normalize_timestamp(raw)
    assert result is not None
    assert result.startswith("2026-08-03T10:15:32.123456")


def test_normalize_timestamp_invalid_input_returns_raw():
    raw = "not-a-timestamp"
    assert normalize_timestamp(raw) == raw


def test_safe_get_returns_default_for_empty_string():
    d = {"user": ""}
    assert safe_get(d, "user", default="unknown") == "unknown"


def test_safe_get_returns_value_when_present():
    d = {"user": "aghaverdi"}
    assert safe_get(d, "user", default="unknown") == "aghaverdi"


def test_xml_event_to_dict_parses_basic_event():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4624</EventID>
        <TimeCreated SystemTime="2026-08-03T10:15:32.123456Z"/>
        <EventRecordID>101</EventRecordID>
        <Channel>Security</Channel>
        <Computer>HOST01</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">test.user</Data>
      </EventData>
    </Event>"""
    result = xml_event_to_dict(xml)
    assert result["event_id"] == 4624
    assert result["computer"] == "HOST01"
    assert result["event_data"]["TargetUserName"] == "test.user"