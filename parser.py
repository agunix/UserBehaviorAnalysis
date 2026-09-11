"""
AI-UBA :: Windows Event Log Parser
-------------------------------------
Bu modul iki rejimdə işləyir:

  1. OFFLINE  - `data/evtx/` qovluğundakı .evtx fayllarını (python-evtx ilə) oxuyur.
                Server/analitik olmayan mühitlərdə də (Linux/macOS daxil) işləyir,
                çünki python-evtx faylı bytecode səviyyəsində parse edir, Windows API tələb etmir.

  2. LIVE     - Windows sistemində real-vaxt rejimində `pywin32` (win32evtlog) vasitəsilə
                Security və Sysmon kanallarını izləyir. Yalnız Windows-da işləyir.

Hər iki rejimdən çıxan xam event-lər eyni `UserBehaviorEvent` sxeminə normallaşdırılır ki,
sonrakı `features/feature_extractor.py` modulu mənbədən asılı olmadan işləyə bilsin.

İstifadə nümunəsi:
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

logger = logging.getLogger("aiuba.parser")


# --------------------------------------------------------------------------- #
# Normallaşdırılmış Event Sxemi
# --------------------------------------------------------------------------- #

class UserBehaviorEvent(BaseModel):
    """
    Mənbədən (Security / Sysmon, offline / live) asılı olmayan vahid event sxemi.
    feature_extractor.py və risk_engine.py yalnız bu sxem üzərində işləyir.
    """

    event_id: int
    event_name: str
    category: str          # auth | process | network | privilege | persistence | account_mgmt | ...
    source: str             # security | sysmon
    timestamp: Optional[str] = None
    computer: Optional[str] = None
    record_id: Optional[int] = None

    # Davranış analitikası üçün ən çox istifadə olunan normallaşdırılmış sahələr
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

    target_object: Optional[str] = None   # registry/persistence event-lər üçün
    target_filename: Optional[str] = None  # filesystem event-lər üçün

    # Normallaşdırılmamış qalan bütün sahələr (audit/debug üçün saxlanılır)
    raw: Dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Xam event_data-nı UserBehaviorEvent-ə map edən funksiya
# --------------------------------------------------------------------------- #

# Fərqli event ID-lərdə eyni məna daşıyan sahələr fərqli adlar altında gəlir.
# Bu lüğət hər normallaşdırılmış sahə üçün mümkün mənbə açarlarının siyahısını saxlayır.
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
    """Bir `xml_event_to_dict` çıxışını `UserBehaviorEvent`-ə çevirir."""
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
    EVTX fayllarını (offline) və ya canlı Windows Event Log-u (live, yalnız Windows)
    oxuyub normallaşdırılmış `UserBehaviorEvent` axını yaradır.
    """

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.stats = ParseStats()

    # ------------------------------------------------------------------ #
    # OFFLINE rejim (.evtx faylları)
    # ------------------------------------------------------------------ #

    def parse_evtx_file(self, file_path: Path) -> Iterator[UserBehaviorEvent]:
        """
        Tək bir .evtx faylını sətir-sətir (lazy) oxuyur.
        `python-evtx` kitabxanası tələb olunur: pip install python-evtx
        """
        try:
            from Evtx.Evtx import Evtx  # python-evtx paketi
        except ImportError as exc:
            raise ImportError(
                "python-evtx paketi tapılmadı. Quraşdırın: pip install python-evtx"
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
                        logger.warning("Event parse xətası (%s): %s", file_path.name, exc)
                        continue

        except Exception as exc:
            logger.error("EVTX fayl açıla bilmədi: %s -> %s", file_path, exc)
            self.stats.errors.append(f"{file_path.name}: {exc}")
            return

        self.stats.files_processed += 1

    def parse_directory(self, directory: Optional[Path] = None) -> Iterator[UserBehaviorEvent]:
        """`evtx_input_dir` qovluğundakı bütün .evtx fayllarını ardıcıl parse edir."""
        directory = directory or self.settings.parser.evtx_input_dir
        directory = Path(directory)

        if not directory.exists():
            logger.warning("EVTX input qovluğu mövcud deyil: %s", directory)
            return

        evtx_files = sorted(directory.glob("*.evtx"))
        if not evtx_files:
            logger.info("Qovluqda .evtx fayl tapılmadı: %s", directory)
            return

        for file_path in evtx_files:
            logger.info("Parse edilir: %s", file_path.name)
            yield from self.parse_evtx_file(file_path)

    # ------------------------------------------------------------------ #
    # LIVE rejim (yalnız Windows, pywin32)
    # ------------------------------------------------------------------ #

    def stream_live(self, channel: Optional[str] = None) -> Iterator[UserBehaviorEvent]:
        """
        Windows Event Log-u real-vaxt rejimində izləyir.
        Yalnız Windows sistemində, `pywin32` quraşdırılmış olduqda işləyir.
        """
        try:
            import win32evtlog  # pywin32 paketi
        except ImportError as exc:
            raise ImportError(
                "pywin32 paketi tapılmadı (yalnız Windows-da mövcuddur). "
                "Quraşdırın: pip install pywin32"
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
                logger.info("Canlı izləmə başladıldı: %s", ch)
            except Exception as exc:
                logger.error("Kanala abunə olunmadı (%s): %s", ch, exc)

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
                        logger.warning("Canlı event parse xətası (%s): %s", ch, exc)
                        continue

    # ------------------------------------------------------------------ #
    # Vahid giriş nöqtəsi
    # ------------------------------------------------------------------ #

    def parse_all(self) -> Iterator[UserBehaviorEvent]:
        """`config.yaml`-dakı `parser.mode` dəyərinə görə offline/live rejimi seçir."""
        if self.settings.parser.mode == "live":
            yield from self.stream_live()
        else:
            yield from self.parse_directory()

    # ------------------------------------------------------------------ #
    # Nəticələrin diskə yazılması (JSONL, gün üzrə partisiyalanmış)
    # ------------------------------------------------------------------ #

    def persist(self, events: Iterator[UserBehaviorEvent]) -> Path:
        """
        Normallaşdırılmış event-ləri `parsed_output_dir/YYYY-MM-DD.jsonl` formatında yazır.
        Sonrakı feature extraction mərhələsi bu faylları oxuyacaq.
        """
        output_dir = self.settings.parser.parsed_output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / f"{datetime.now(timezone.utc):%Y-%m-%d}.jsonl"

        count = 0
        with open(out_path, "a", encoding="utf-8") as f:
            for event in events:
                f.write(event.model_dump_json() + "\n")
                count += 1

        logger.info("Yazıldı: %d event -> %s", count, out_path)
        return out_path


# --------------------------------------------------------------------------- #
# CLI test giriş nöqtəsi
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    parser = WindowsEventLogParser()
    output_file = parser.persist(parser.parse_directory())

    print(f"Fayllar: {parser.stats.files_processed}")
    print(f"Oxunan event-lər: {parser.stats.events_read}")
    print(f"Saxlanılan (filter keçən) event-lər: {parser.stats.events_kept}")
    print(f"Filtrlənib atılan: {parser.stats.events_skipped_filtered}")
    print(f"Uğursuz: {parser.stats.events_failed}")
    print(f"Çıxış faylı: {output_file}")
