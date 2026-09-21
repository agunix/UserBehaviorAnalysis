"""
AI-UBA :: Windows Event Log Parser
-------------------------------------

This module provides a unified interface to parse Windows Event Logs from two sources:

  1. 1. OFFLINE – Reads .evtx files from the `data/evtx/` folder (using python-evtx). 
                           It works in non-server/non-analytical environments (including Linux/macOS)
                           because python-evtx parses the file at the bytecode level and does not require 
                           the Windows API.

  2. LIVE            - Monitors Security and Sysmon channels in real-time on Windows systems
                           using `pywin32` (win32evtlog). Works only on Windows.

Raw events from both modes are normalized to the same `UserBehaviorEvent` schema so that 
the subsequent `features/feature_extractor.py` module can operate independently of the source.

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

from src.config import get_settings
from src.parser.utils import (
    get_event_metadata,
    safe_get,
    xml_event_to_dict,
)

logger = logging.getLogger("aiuba.parser")


# --------------------------------------------------------------------------- #

# Normalized Event Schema

# --------------------------------------------------------------------------- #

class UserBehaviorEvent(BaseModel):
    """

    Unified event schema independent of the source (Security / Sysmon, offline / live).

    """

    event_id: int
    event_name: str
    category: str          # auth | process | network | privilege | persistence | account_mgmt | ...
    source: str             # security | sysmon
    timestamp: Optional[str] = None
    computer: Optional[str] = None
    record_id: Optional[int] = None


    # Normalized fields for behavioral analysis

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


    target_object: Optional[str] = None   # for registry/persistence events
    target_filename: Optional[str] = None  # for filesystem events

    # Unnormalized remaining fields (kept for audit/debug purposes)

    raw: Dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #

# Function to map raw event_data to UserBehaviorEvent
# --------------------------------------------------------------------------- #

# Different event IDs may have the same meaning for certain fields, but with different names.
# This dictionary maps each normalized field to a list of possible source keys.

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

    """Converts the output of `xml_event_to_dict` to a `UserBehaviorEvent`."""

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

    Parses EVTX files (offline) or live Windows Event Log (live, Windows only)
    and creates a stream of normalized `UserBehaviorEvent` objects.

    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.stats = ParseStats()

    # ------------------------------------------------------------------ #

    # OFFLINE mode (.evtx files)

    # ------------------------------------------------------------------ #

    def parse_evtx_file(self, file_path: Path) -> Iterator[UserBehaviorEvent]:
        """

        Parses a single .evtx file line by line (lazy).
        `python-evtx` library is required: pip install python-evtx
        """
        try:
            from evtx.Evtx import Evtx  # python-evtx package
        except ImportError as exc:
            raise ImportError(
                "python-evtx package not found. Please install it: pip install python-evtx"

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


                    except Exception as exc:  # noqa: BLE001 - do not let a single record error halt the entire file
                        self.stats.events_failed += 1
                        self.stats.errors.append(f"{file_path.name}#{record.offset()}: {exc}")
                        logger.warning("Event parse error (%s): %s", file_path.name, exc)
                        continue

        except Exception as exc:
            logger.error("EVTX cannot open: %s -> %s", file_path, exc)
            self.stats.errors.append(f"{file_path.name}: {exc}")
            return

        self.stats.files_processed += 1

    def parse_directory(self, directory: Optional[Path] = None) -> Iterator[UserBehaviorEvent]:

        """It sequentially parses all .evtx files in the `evtx_input_dir` folder."""

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
    # LIVE mode (Windows only, pywin32)

    # ------------------------------------------------------------------ #

    def stream_live(self, channel: Optional[str] = None) -> Iterator[UserBehaviorEvent]:
        """

        Streams Windows Event Log entries in real-time.
        Only works on Windows systems with `pywin32` installed.
        """
        try:
            import win32evtlog  # pywin32 package
        except ImportError as exc:
            raise ImportError(
                "pywin32 package not found (only available on Windows). "
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

                logger.info("Live streaming started: %s", ch)
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
    # Single entry point
    # ------------------------------------------------------------------ #

    def parse_all(self) -> Iterator[UserBehaviorEvent]:
        """Selects offline/live mode based on the `parser.mode` value in `config.yaml`."""

        if self.settings.parser.mode == "live":
            yield from self.stream_live()
        else:
            yield from self.parse_directory()

    # ------------------------------------------------------------------ #
    # Nəticələrin diskə yazılması (JSONL, gün üzrə partisiyalanmış)
    # ------------------------------------------------------------------ #

    def persist(self, events: Iterator[UserBehaviorEvent]) -> Path:
        """

        Writes normalized events in `parsed_output_dir/YYYY-MM-DD.jsonl` format.
        The subsequent feature extraction step will read these files.

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
# CLI test entry point (for debugging)
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    parser = WindowsEventLogParser()
    output_file = parser.persist(parser.parse_directory())

    print(f"Files: {parser.stats.files_processed}")
    print(f"Events read: {parser.stats.events_read}")
    print(f"Events kept (filtered): {parser.stats.events_kept}")
    print(f"Events skipped (filtered): {parser.stats.events_skipped_filtered}")
    print(f"Failed events: {parser.stats.events_failed}")
    print(f"Output file: {output_file}")