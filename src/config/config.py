from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "src" / "config" / "config.yaml"
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"


class ParserSettings(BaseModel):
    channels: List[str] = Field(
        default_factory=lambda: ["Security", "Microsoft-Windows-Sysmon/Operational"]
    )
    included_event_ids: List[int] = Field(
        default_factory=lambda: [
            4624, 4625, 4634, 4648, 4672, 4688, 4720, 4722, 4724, 4732, 4768, 4769,
            1, 3, 7, 8, 10, 11, 13, 22,
        ]
    )
    poll_interval_seconds: int = 5
    evtx_input_dir: Path = DATA_DIR / "evtx"
    parsed_output_dir: Path = DATA_DIR / "parsed"
    mode: Literal["live", "offline"] = "offline"

    # Linux mənbələr (auditd, sshd/PAM, syscheck) Wazuh-da Event ID ilə deyil,
    # rule.groups ilə identifikasiya olunur - bax: src/integrations/linux_client.py
    linux_rule_groups: List[str] = Field(
        default_factory=lambda: [
            "sshd",
            "pam",
            "authentication_success",
            "authentication_failed",
            "audit_command",
            "audit",
            "syscheck",
        ]
    )

    @field_validator("evtx_input_dir", "parsed_output_dir", mode="before")
    @classmethod
    def _to_path(cls, v):
        return Path(v)


class LoggingSettings(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_file: Path = LOGS_DIR / "aiuba.log"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5

    @field_validator("log_file", mode="before")
    @classmethod
    def _to_path(cls, v):
        return Path(v)


class WazuhIndexerSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 9200
    username: str = "admin"
    password: str = ""
    verify_ssl: bool = False
    index_pattern: str = "wazuh-alerts-*"
    request_timeout_seconds: int = 30

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"


class WazuhAlertOutputSettings(BaseModel):
    output_file: Path = DATA_DIR / "aiuba_alerts" / "aiuba_events.json"

    @field_validator("output_file", mode="before")
    @classmethod
    def _to_path(cls, v):
        return Path(v)


class RiskSettings(BaseModel):
    rule_weight: float = 0.6
    ml_weight: float = 0.4
    low_threshold: int = 30
    medium_threshold: int = 60
    high_threshold: int = 85

    @field_validator("ml_weight")
    @classmethod
    def _weights_sum_check(cls, v, info):
        rule_weight = info.data.get("rule_weight")
        if rule_weight is not None and not (0.99 <= rule_weight + v <= 1.01):
            raise ValueError("rule_weight + ml_weight cəmi 1.0 olmalıdır")
        return v


class Settings(BaseModel):
    environment: Literal["development", "staging", "production"] = "development"
    project_root: Path = PROJECT_ROOT

    parser: ParserSettings = Field(default_factory=ParserSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    risk: RiskSettings = Field(default_factory=RiskSettings)
    wazuh_indexer: WazuhIndexerSettings = Field(default_factory=WazuhIndexerSettings)
    wazuh_alert_output: WazuhAlertOutputSettings = Field(default_factory=WazuhAlertOutputSettings)

    model_config = ConfigDict(arbitrary_types_allowed=True)


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _apply_env_overrides(raw: dict) -> dict:
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
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    raw = _load_yaml(path)
    raw = _apply_env_overrides(raw)
    settings = Settings(**raw)

    settings.parser.evtx_input_dir.mkdir(parents=True, exist_ok=True)
    settings.parser.parsed_output_dir.mkdir(parents=True, exist_ok=True)
    settings.logging.log_file.parent.mkdir(parents=True, exist_ok=True)
    settings.wazuh_alert_output.output_file.parent.mkdir(parents=True, exist_ok=True)

    return settings


if __name__ == "__main__":
    s = get_settings()
    print(s.model_dump_json(indent=2, exclude={"project_root"}))
