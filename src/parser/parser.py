"""
UBA :: Windows Event Log Parser
-------------------------------------
This module works in two modes:

  1. OFFLINE  - .evtx files are reading (with python-evtx) from `data/evtx/` folder
                Also works on not Server/analytic environment (Linux/macOS daxil),
                because python-evtx files parses on the bytecode level , do not required Windows API.

  2. LIVE     - Follows Security and Sysmon channels in real-time on Windows system via `pywin32` (win32evtlog).
                    Works only on Windows environment.

Every raw event from both modes is normalized to the same `UserBehaviorEvent` schema, 
so that the next `features/feature_extractor.py` module can work independently of the source.

Example usage:
    from src.parser.parser import WindowsEventLogParser

    parser = WindowsEventLogParser()
    for event in parser.parse_all():
        print(event.model_dump())
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from pydantic import BaseModel, Field

from src.config.config import get_settings
from src.parser.utils import (
    get_event_metadata,
    safe_get,
    xml_event_to_dict,
)

logger = logging.getLogger("uba.parser")


# --------------------------------------------------------------------------- #
# Normalized UserBehaviorEvent schema
# --------------------------------------------------------------------------- #

class UserBehaviorEvent(BaseModel):
    """
    Source (Security / Sysmon, offline / live) unit event schema.
    feature_extractor.py and risk_engine.py works only on this schema.
    """

    event_id: int
    event_name: str
    category: str          # auth | process | network | privilege | persistence | account_mgmt | ...
    source: str             # security | sysmon
    timestamp: Optional[str] = None
    computer: Optional[str] = None
    record_id: Optional[int] = None

    # Normalized fields (different event IDs may have same meaning but different names)
    user: Optional[str] = None
    domain: Optional[str] = None
    logon_id: Optional[str] = None
    source_ip: Optional[str] = None
    logon_type: Optional[str] = None

    process_name: Optional[str] = None
    process_id: Optional[str] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None

    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None
    dns_query: Optional[str] = None

    target_object: Optional[str] = None   # registry/persistence for events
    target_filename: Optional[str] = None  # for filesystem events

    # Unstructured raw event data (event_data dictionary from xml_event_to_dict)
    raw: Dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Functions for normalizing raw events to UserBehaviorEvent
# --------------------------------------------------------------------------- #

# Fields that carry the same meaning appear under different names across different event IDs.
# This dictionary stores a list of possible source keys for each normalized field.
_FIELD_ALIASES: Dict[str, List[str]] = {
    "user": ["TargetUserName", "SubjectUserName", "User"],
    "domain": ["TargetDomainName", "SubjectDomainName"],
    "logon_id": ["TargetLogonId", "SubjectLogonId"],
    "source_ip": ["IpAddress", "SourceIp"],
    "logon_type": ["LogonType"],
    "process_name": ["Image", "NewProcessName"],
    "process_id": ["ProcessId", "NewProcessId"],
    "parent_process_name": ["ParentImage"],
    "command_line": ["CommandLine"],
    "destination_ip": ["DestinationIp"],
    "destination_port": ["DestinationPort"],
    "dns_query": ["QueryName"],
    "target_object": ["TargetObject"],
    "target_filename": ["TargetFilename"],
}


def normalize_event(raw_event: Dict[str, Any]) -> UserBehaviorEvent:
    """Normalizes a raw event dictionary to a UserBehaviorEvent."""
    event_id = raw_event["event_id"]
    meta = get_event_metadata(event_id)
    event_data = raw_event.get("event_data", {})

    normalized_fields: Dict[str, Any] = {}
    for target_field, aliases in _FIELD_ALIASES.items():
        for alias in aliases:
            value = safe_get(event_data, alias)
            if value is not None:
                normalized_fields[target_field] = value
                break

    return UserBehaviorEvent(
        event_id=event_id,
        event_name=meta["name"],
        category=meta["category"],
        source=meta["source"],
        timestamp=raw_event.get("timestamp"),
        computer=raw_event.get("computer"),
        record_id=raw_event.get("record_id"),
        raw=event_data,
        **normalized_fields,
    )


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #

@dataclass
class ParseStats:
    files_processed: int = 0
    events_read: int = 0
    events_kept: int = 0
    events_skipped_filtered: int = 0
    events_failed: int = 0
    errors: List[str] = field(default_factory=list)


class WindowsEventLogParser:
    """
    Reads EVTX files (offline) or the live Windows Event Log (live, Windows only)
    and generates a normalized stream of `UserBehaviorEvent`s.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.stats = ParseStats()

    # ------------------------------------------------------------------ #
    # OFFLINE condition (.evtx files)
    # ------------------------------------------------------------------ #

    def parse_evtx_file(self, file_path: Path) -> Iterator[UserBehaviorEvent]:
        """
        Reads a single .evtx file line by line (lazily). 
        The `python-evtx` library is required: pip install python-evtx
        """
        try:
            from Evtx.Evtx import Evtx  # python-evtx packets
        except ImportError as exc:
            raise ImportError(
                "There are no python-evtx packets installed. Install it: pip install python-evtx"
            ) from exc

        included_ids = set(self.settings.parser.included_event_ids)

        try:
            with Evtx(str(file_path)) as log:
                for record in log.records():
                    self.stats.events_read += 1
                    try:
                        xml_string = record.xml()
                        raw = xml_event_to_dict(xml_string)

                        if included_ids and raw["event_id"] not in included_ids:
                            self.stats.events_skipped_filtered += 1
                            continue

                        event = normalize_event(raw)
                        self.stats.events_kept += 1
                        yield event

                    except Exception as exc:  # noqa: BLE001 - tək record xətası bütün faylı dayandırmasın
                        self.stats.events_failed += 1
                        self.stats.errors.append(f"{file_path.name}#{record.offset()}: {exc}")
                        logger.warning("Event parse error (%s): %s", file_path.name, exc)
                        continue

        except Exception as exc:
            logger.error("Failed to open EVTX file: %s -> %s", file_path, exc)
            self.stats.errors.append(f"{file_path.name}: {exc}")
            return

        self.stats.files_processed += 1

    def parse_directory(self, directory: Optional[Path] = None) -> Iterator[UserBehaviorEvent]:
        """ Parse all .evtx files in the `evtx_input_dir` directory."""
        directory = directory or self.settings.parser.evtx_input_dir
        directory = Path(directory)

        if not directory.exists():
            logger.warning("EVTX input directory does not exist: %s", directory)
            return

        evtx_files = sorted(directory.glob("*.evtx"))
        if not evtx_files:
            logger.info("No .evtx files found in directory: %s", directory)
            return

        for file_path in evtx_files:
            logger.info("Parsing: %s", file_path.name)
            yield from self.parse_evtx_file(file_path)

    # ------------------------------------------------------------------ #
    # LIVE condition (only Windows, pywin32)
    # ------------------------------------------------------------------ #

    def stream_live(self, channel: Optional[str] = None) -> Iterator[UserBehaviorEvent]:
        """
        Following Windows Event Logs with real-time mode.
        Works only on Windows systems with `pywin32` installed.
        """
        try:
            import win32evtlog  # pywin32 paketi
        except ImportError as exc:
            raise ImportError(
                "There are no any pywin32 packages installed (only available on Windows). "
                "Install it: pip install pywin32"
            ) from exc

        channels = [channel] if channel else self.settings.parser.channels
        included_ids = set(self.settings.parser.included_event_ids)

        handles = []
        for ch in channels:
            try:
                h = win32evtlog.EvtSubscribe(
                    ch,
                    win32evtlog.EvtSubscribeToFutureEvents,
                    SignalEvent=None,
                )
                handles.append((ch, h))
                logger.info("Live monitoring started: %s", ch)
            except Exception as exc:
                logger.error("Failed to subscribe to channel (%s): %s", ch, exc)

        while True:
            for ch, handle in handles:
                events = win32evtlog.EvtNext(handle, 10, timeout=1000)
                for evt in events:
                    self.stats.events_read += 1
                    try:
                        xml_string = win32evtlog.EvtRender(
                            evt, win32evtlog.EvtRenderEventXml
                        )
                        raw = xml_event_to_dict(xml_string)

                        if included_ids and raw["event_id"] not in included_ids:
                            self.stats.events_skipped_filtered += 1
                            continue

                        event = normalize_event(raw)
                        self.stats.events_kept += 1
                        yield event

                    except Exception as exc:  # noqa: BLE001
                        self.stats.events_failed += 1
                        logger.warning("Live event parse error (%s): %s", ch, exc)
                        continue

    # ------------------------------------------------------------------ #
    # Single entry point for both offline and live modes
    # ------------------------------------------------------------------ #

    def parse_all(self) -> Iterator[UserBehaviorEvent]:
        """Uses the `parser.mode` value in `config.yaml` to select offline/live mode."""
        if self.settings.parser.mode == "live":
            yield from self.stream_live()
        else:
            yield from self.parse_directory()

    # ------------------------------------------------------------------ #
    # Persisting results to disk (JSONL, partitioned by day)
    # ------------------------------------------------------------------ #

    def persist(self, events: Iterator[UserBehaviorEvent]) -> Path:
        """
        Writes normalized events to `parsed_output_dir/YYYY-MM-DD.jsonl` format.
        The next feature extraction step will read these files.
        """
        output_dir = self.settings.parser.parsed_output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / f"{datetime.now(timezone.utc):%Y-%m-%d}.jsonl"

        count = 0
        with open(out_path, "a", encoding="utf-8") as f:
            for event in events:
                f.write(event.model_dump_json() + "\n")
                count += 1

        logger.info("Written: %d events -> %s", count, out_path)
        return out_path


# --------------------------------------------------------------------------- #
# CLI test entry point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    parser = WindowsEventLogParser()
    output_file = parser.persist(parser.parse_directory())

    print(f"Files: {parser.stats.files_processed}")
    print(f"Events read: {parser.stats.events_read}")
    print(f"Events kept: {parser.stats.events_kept}")
    print(f"Events skipped: {parser.stats.events_skipped_filtered}")
    print(f"Events failed: {parser.stats.events_failed}")
    print(f"Output file: {output_file}")
