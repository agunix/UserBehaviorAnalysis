"""
AI-UBA :: Configuration Module
--------------------------------
Centralized configuration management for the AI-UBA application.

Configuration sources (in priority order, highest to lowest):
    1. Environment variables (with AIUBA_ prefix)
    2. config.yaml file (in data/ or config/ directory)
    3. Default values in code

Other modules access configuration in this way:
    from src.config.config import get_settings
    settings = get_settings()
    print(settings.parser.channels)
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


# Path constants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "src" / "config" / "config.yaml"
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"



# Sub-config objects

class ParserSettings(BaseModel):
    "Configuration for the Windows Event Log parser"

    # Channels to monitor. Sysmon defaults to this name when installed.
    channels: List[str] = Field(
        default_factory=lambda: [
            "Security",
            "Microsoft-Windows-Sysmon/Operational",
        ]
    )

    # Event IDs to pay attention to (Security + Sysmon combination).
    # If empty, -> all events.
    included_event_ids: List[int] = Field(
        default_factory=lambda: [
            4624,  # Successful logon
            4625,  # Failed logon
            4634,  # Logoff
            4648,  # Logon with explicit credentials
            4672,  # Special privileges assigned
            4688,  # Process creation (Security)
            4720,  # User account created
            4722,  # User account enabled
            4724,  # Password reset attempt
            4732,  # Member added to security-enabled local group
            4768,  # Kerberos TGT requested
            4769,  # Kerberos service ticket requested
            1,     # Sysmon: Process creation
            3,     # Sysmon: Network connection
            7,     # Sysmon: Image loaded
            8,     # Sysmon: CreateRemoteThread
            10,    # Sysmon: ProcessAccess
            11,    # Sysmon: File created
            13,    # Sysmon: Registry value set
            22,    # Sysmon: DNS query
        ]
    )

    # In the live mode, how often to poll the Windows Event Log for new events (in seconds).
    poll_interval_seconds: int = 5

    # EVTX file directory (offline/batch mode)
    evtx_input_dir: Path = DATA_DIR / "evtx"

    # Parsed output directory (offline/batch mode)
    parsed_output_dir: Path = DATA_DIR / "parsed"

    mode: Literal["live", "offline"] = "offline"

    @field_validator("evtx_input_dir", "parsed_output_dir", mode="before")
    @classmethod
    def _to_path(cls, v):
        return Path(v)


class LoggingSettings(BaseModel):
    "Configuration for the application's internal logging (not to be mixed with analyzed Windows logs)."

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_file: Path = LOGS_DIR / "aiuba.log"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5

    @field_validator("log_file", mode="before")
    @classmethod
    def _to_path(cls, v):
        return Path(v)


class WazuhIndexerSettings(BaseModel):
    """
    Configuration for the Wazuh Indexer (OpenSearch, port 9200).
    Note: alerts are stored here, not in the Wazuh Manager API (55000).
    Authentication is done via Basic Auth (not JWT).
    """

    host: str = "127.0.0.1"
    port: int = 9200
    # Environment variable overrides:
    #   AIUBA_WAZUH_INDEXER__USERNAME=admin
    #   AIUBA_WAZUH_INDEXER__PASSWORD=...
    username: str = "admin"
    password: str = ""
    verify_ssl: bool = False  # for self-signed certificates; default is False; should be True in production
    index_pattern: str = "wazuh-alerts-*"
    request_timeout_seconds: int = 30

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"


class WazuhAlertOutputSettings(BaseModel):
    """
    Configuration for injecting AI-UBA's detected anomalies back into Wazuh.
    Method: JSON log line -> agent's localfile monitor -> custom rule in manager.
    (See: src/integrations/wazuh_client.py and docs/wazuh_custom_rule.xml)
    """

    output_file: Path = DATA_DIR / "aiuba_alerts" / "aiuba_events.json"

    @field_validator("output_file", mode="before")
    @classmethod
    def _to_path(cls, v):
        return Path(v)


class RiskSettings(BaseModel):
    "Risk engine for initial (hybrid rule+ML) settings."

    # Rule-based scoring and ml-based scoring weights (sum must be 1.0)
    rule_weight: float = 0.6
    ml_weight: float = 0.4

    # Risk level thresholds (on a 0-100 scale)
    low_threshold: int = 30
    medium_threshold: int = 60
    high_threshold: int = 85

    @field_validator("ml_weight")
    @classmethod
    def _weights_sum_check(cls, v, info):
        rule_weight = info.data.get("rule_weight")
        if rule_weight is not None and not (0.99 <= rule_weight + v <= 1.01):
            raise ValueError("rule_weight + ml_weight must sum to 1.0")
        return v


class Settings(BaseModel):
    "All configuration settings for the AI-UBA application."

    environment: Literal["development", "staging", "production"] = "development"
    project_root: Path = PROJECT_ROOT

    parser: ParserSettings = Field(default_factory=ParserSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    risk: RiskSettings = Field(default_factory=RiskSettings)
    wazuh_indexer: WazuhIndexerSettings = Field(default_factory=WazuhIndexerSettings)
    wazuh_alert_output: WazuhAlertOutputSettings = Field(default_factory=WazuhAlertOutputSettings)

    model_config = ConfigDict(arbitrary_types_allowed=True)



# Configuration Loading Logic

def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _apply_env_overrides(raw: dict) -> dict:
    """
    Applies environment variable overrides to the configuration.
    Nested keys are represented using the '__' separator.
    For example: AIUBA_PARSER__MODE=live -> raw["parser"]["mode"] = "live"
    """
    prefix = "AIUBA_"
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        path_parts = env_key[len(prefix):].lower().split("__")
        cursor = raw
        for part in path_parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[path_parts[-1]] = env_val
    return raw


@lru_cache(maxsize=1)
def get_settings(config_path: Optional[str] = None) -> Settings:
    """
    Returns a single instance of the configuration (singleton) using lru_cache.
    If different configuration is needed during testing, call get_settings.cache_clear().
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    raw = _load_yaml(path)
    raw = _apply_env_overrides(raw)
    settings = Settings(**raw)

    # Ensure required directories exist
    settings.parser.evtx_input_dir.mkdir(parents=True, exist_ok=True)
    settings.parser.parsed_output_dir.mkdir(parents=True, exist_ok=True)
    settings.logging.log_file.parent.mkdir(parents=True, exist_ok=True)
    settings.wazuh_alert_output.output_file.parent.mkdir(parents=True, exist_ok=True)

    return settings


if __name__ == "__main__":
    # Manual test: `python -m src.config.config`
    s = get_settings()
    print(s.model_dump_json(indent=2, exclude={"project_root"}))
