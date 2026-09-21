"""
AI-UBA :: Configuration Module

All configuration settings for the application.

Configuration sources (in order of precedence, highest to lowest):
    1. Environment variables (with AIUBA_ prefix)
    2. config.yaml file (in data/ or config/ directory)
    3. Default values in code

Other modules access the configuration as follows:
    from src.config import get_settings
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

# --------------------------------------------------------------------------- #
# Path variables
# --------------------------------------------------------------------------- #

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "src" / "config.yaml"
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"


# --------------------------------------------------------------------------- #
# Alternative configuration models
# --------------------------------------------------------------------------- #

class ParserSettings(BaseModel):
    "Configuration for Windows Event Log parser."

    # Channels to monitor. Sysmon is installed by default, so it has this name.
    channels: List[str] = Field(
        default_factory=lambda: [
            "Security",
            "Microsoft-Windows-Sysmon/Operational",
        ]
    )

# --------------------------------------------------------------------------- #
# Sub-config objects
# --------------------------------------------------------------------------- #
class ParserSettings(BaseModel):
    "Windows Event Log parser configuration."

    # EVTX channels to be monitored. Sysmon uses this name when installed with default settings.
 
    channels: List[str] = Field(
        default_factory=lambda: [
            "Security",
            "Microsoft-Windows-Sysmon/Operational",
        ]
    )



    # Event IDs to include (Security + Sysmon combined).
    # If left empty -> all events are processed.
 
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

    # How many seconds to wait between polling for new events (live mode).
    poll_interval_seconds: int = 5

    # EVTX files to read in offline mode (if empty, all .evtx files in evtx_input_dir are processed).
    evtx_input_dir: Path = DATA_DIR / "evtx"

    # Directory where parsed and normalized events will be written

    # Live mode (only Windows, pywin32) and offline mode (batch processing of EVTX files) are supported.
    poll_interval_seconds: int = 5

    # This can read EVTX files (offline/batch mode)
    evtx_input_dir: Path = DATA_DIR / "evtx"

    # Directory where parsed and normalized events will be written
    parsed_output_dir: Path = DATA_DIR / "parsed"

    mode: Literal["live", "offline"] = "offline"

    @field_validator("evtx_input_dir", "parsed_output_dir", mode="before")
    @classmethod
    def _to_path(cls, v):
        return Path(v)


class LoggingSettings(BaseModel):
    "Internal logging configuration (to avoid mixing with analyzed Windows logs)."

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
    Configuration for Wazuh Indexer (OpenSearch, port 9200).
    Attention: alerts are stored here, not in Wazuh Manager API (55000).
    Authentication is done via Basic Auth (not JWT).
    """

    host: str = "127.0.0.1"
    port: int = 9200
    # Passwords should be loaded from .env / environment variables, not YAML:
    #   UBA_WAZUH_INDEXER__USERNAME=admin
    #   UBA_WAZUH_INDEXER__PASSWORD=...
    username: str = "admin"
    password: str = "" #
    verify_ssl: bool = False  # self-signed certificate false, for production is true
    index_pattern: str = "wazuh-alerts-*"
    request_timeout_seconds: int = 30

    """
    Wazuh Indexer (OpenSearch, port 9200) üçün ayarlar.
    Warning: Alerts are stored here, not in Wazuh Manager API (55000).
    Authentication is done via Basic Auth (not JWT).
    """

    host: str = "127.0.0.1"
    port: int = 9200
    # Passwords should be loaded from .env / environment variables, not YAML:
    #   AIUBA_WAZUH_INDEXER__USERNAME=admin
    #   AIUBA_WAZUH_INDEXER__PASSWORD=...
    username: str = "admin"
    password: str = "SecretPassword"
    verify_ssl: bool = False  # self-signed certificate false, for production is true
 
    index_pattern: str = "wazuh-alerts-*"
    request_timeout_seconds: int = 30

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"


class WazuhAlertOutputSettings(BaseModel):

    """
    Configuration for Wazuh alert output.
    Method: JSON log line -> agent's localfile monitor -> manager's custom rule.
    (See: src/integrations/wazuh_client.py and docs/wazuh_custom_rule.xml)

    Settings for 'injecting' anomalies detected by AI-UBA back into Wazuh. 
    Method: JSON log string -> file monitored by the agent's localfile -> custom rule on the manager. 
    (See: src/integrations/wazuh_client.py and docs/wazuh_custom_rule.xml)

    """

    output_file: Path = DATA_DIR / "aiuba_alerts" / "aiuba_events.json"

    @field_validator("output_file", mode="before")
    @classmethod
    def _to_path(cls, v):
        return Path(v)


class RiskSettings(BaseModel):

    """Configuration for the risk engine."""

    # Rule-based scoring with ML-based anomaly score (overall 1.0 weight)
    rule_weight: float = 0.6
    ml_weight: float = 0.4

    # Risk level thresholds (on a 0-100 scale)

    "Initial hybrid (rule+ML) settings."

    # Rule-based scoring ilə ML-based anomaly score-un çəkiləri (cəmi 1.0 olmalıdır)
    rule_weight: float = 0.6
    ml_weight: float = 0.4

    # Risk level thresholds (0-100 scale)

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

    "Root object for the application's configuration."
    environment: Literal["development", "staging", "production"] = "development"
    project_root: Path = PROJECT_ROOT

    parser: ParserSettings = Field(default_factory=ParserSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    risk: RiskSettings = Field(default_factory=RiskSettings)
    wazuh_indexer: WazuhIndexerSettings = Field(default_factory=WazuhIndexerSettings)
    wazuh_alert_output: WazuhAlertOutputSettings = Field(default_factory=WazuhAlertOutputSettings)

    model_config = ConfigDict(arbitrary_types_allowed=True)


# --------------------------------------------------------------------------- #

# Installation helper functions

# --------------------------------------------------------------------------- #

def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _apply_env_overrides(raw: dict) -> dict:

    """
    Applies environment variables with the 'AIUBA_' prefix to the configuration.
    Nested keys are represented using the '__' separator.
    For example: AIUBA_PARSER__MODE=live -> raw["parser"]["mode"] = "live"

    Applies environment variables prefixed with `AIUBA_` to the configuration. 
    The `__` separator is used for nested keys. 
    Example: `AIUBA_PARSER__MODE=live` -> `raw["parser"]["mode"] = "live"`
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
    Returns a single instance (singleton) of the application's configuration (lru_cache).
    If different config is needed during testing, call get_settings.cache_clear().
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    raw = _load_yaml(path)
    raw = _apply_env_overrides(raw)
    settings = Settings(**raw)


    # Ensure that required directories exist

    settings.parser.evtx_input_dir.mkdir(parents=True, exist_ok=True)
    settings.parser.parsed_output_dir.mkdir(parents=True, exist_ok=True)
    settings.logging.log_file.parent.mkdir(parents=True, exist_ok=True)
    settings.wazuh_alert_output.output_file.parent.mkdir(parents=True, exist_ok=True)

    return settings


if __name__ == "__main__":

    # Fast manual test: `python -m src.config.config`

    s = get_settings()
    print(s.model_dump_json(indent=2, exclude={"project_root"}))
