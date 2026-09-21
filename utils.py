"""
AI-UBA :: Parser Utils
------------------------
Helper functions for processing Windows Event Log (EVTX) XMLs:
  - XML -> Python dict turning
  - Event ID -> human-readable screen and category dictionary
  - Timestamp normalization (UTC, ISO-8601)
  - Safe field extraction
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from xml.etree import ElementTree as ET

# EVTX namespace for XML  
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


# --------------------------------------------------------------------------- #
# Event ID -> Metadata mapping
# --------------------------------------------------------------------------- #
# category: group behavior analysis for (auth, process, network, persistence, account_mgmt)
EVENT_ID_METADATA: Dict[int, Dict[str, str]] = {
    4624: {"name": "LogonSuccess", "category": "auth", "source": "security"},
    4625: {"name": "LogonFailure", "category": "auth", "source": "security"},
    4634: {"name": "Logoff", "category": "auth", "source": "security"},
    4648: {"name": "ExplicitCredLogon", "category": "auth", "source": "security"},
    4672: {"name": "SpecialPrivilegesAssigned", "category": "privilege", "source": "security"},
    4688: {"name": "ProcessCreation", "category": "process", "source": "security"},
    4720: {"name": "UserCreated", "category": "account_mgmt", "source": "security"},
    4722: {"name": "UserEnabled", "category": "account_mgmt", "source": "security"},
    4724: {"name": "PasswordResetAttempt", "category": "account_mgmt", "source": "security"},
    4732: {"name": "GroupMembershipAdded", "category": "privilege", "source": "security"},
    4768: {"name": "KerberosTGTRequested", "category": "auth", "source": "security"},
    4769: {"name": "KerberosServiceTicketRequested", "category": "auth", "source": "security"},
    1: {"name": "SysmonProcessCreate", "category": "process", "source": "sysmon"},
    3: {"name": "SysmonNetworkConnect", "category": "network", "source": "sysmon"},
    7: {"name": "SysmonImageLoad", "category": "process", "source": "sysmon"},
    8: {"name": "SysmonCreateRemoteThread", "category": "process_injection", "source": "sysmon"},
    10: {"name": "SysmonProcessAccess", "category": "process_injection", "source": "sysmon"},
    11: {"name": "SysmonFileCreate", "category": "filesystem", "source": "sysmon"},
    13: {"name": "SysmonRegistrySetValue", "category": "persistence", "source": "sysmon"},
    22: {"name": "SysmonDnsQuery", "category": "network", "source": "sysmon"},
}


def get_event_metadata(event_id: int) -> Dict[str, str]:
    "Returns metadata for the given event ID; returns default if ID is unknown."
    return EVENT_ID_METADATA.get(
        event_id,
        {"name": "Unknown", "category": "uncategorized", "source": "unknown"},
    )


# --------------------------------------------------------------------------- #
# Timestamp normalization
# --------------------------------------------------------------------------- #

def normalize_timestamp(raw_ts: str) -> Optional[str]:
    """
    In the Windows Event Log SystemTime value (for example: '2026-08-03T10:15:32.1234567Z')
    converts to the ISO-8601  format (microsecond precision) .
    """
    if not raw_ts:
        return None
    try:
        # Windows FILETIME-based timestamps many times 7 digit fractional seconds,
        # Python only supports maximum 6 digits -> truncated.
        cleaned = re.sub(r"(\.\d{6})\d*Z$", r"\1Z", raw_ts)
        cleaned = cleaned.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return raw_ts  # fallback: keep the original value, continue processing


# --------------------------------------------------------------------------- #
# XML -> dict
# --------------------------------------------------------------------------- #

def xml_event_to_dict(xml_string: str) -> Dict[str, Any]:
    """
    Converts a single Windows Event XML (from python-evtx) to a structured dict.

    Returned structure:
    {
        "event_id": int,
        "timestamp": str (ISO-8601 UTC),
        "channel": str,
        "computer": str,
        "provider": str,
        "record_id": int,
        "event_data": {field_name: field_value, ...}
    }
    """
    root = ET.fromstring(xml_string)

    system = root.find("e:System", _NS)
    if system is None:
        raise ValueError("In the Event XML <System> elements not found")

    event_id_el = system.find("e:EventID", _NS)
    event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else -1

    time_created = system.find("e:TimeCreated", _NS)
    raw_ts = time_created.get("SystemTime") if time_created is not None else None

    provider_el = system.find("e:Provider", _NS)
    provider = provider_el.get("Name") if provider_el is not None else None

    channel_el = system.find("e:Channel", _NS)
    channel = channel_el.text if channel_el is not None else None

    computer_el = system.find("e:Computer", _NS)
    computer = computer_el.text if computer_el is not None else None

    record_id_el = system.find("e:EventRecordID", _NS)
    record_id = int(record_id_el.text) if record_id_el is not None and record_id_el.text else None

    # EventData / UserData belong fields (Name attribute)
    event_data: Dict[str, Any] = {}
    event_data_el = root.find("e:EventData", _NS)
    if event_data_el is not None:
        for data_el in event_data_el.findall("e:Data", _NS):
            key = data_el.get("Name") or f"Data{len(event_data)}"
            event_data[key] = data_el.text

    return {
        "event_id": event_id,
        "timestamp": normalize_timestamp(raw_ts) if raw_ts else None,
        "channel": channel,
        "computer": computer,
        "provider": provider,
        "record_id": record_id,
        "event_data": event_data,
    }


def safe_get(d: Dict[str, Any], key: str, default: Any = None) -> Any:
    "Turns a dictionary into a None-safe way to extract values (replaces empty strings with the default)."
    val = d.get(key, default)
    if val is None or val == "":
        return default
    return val
