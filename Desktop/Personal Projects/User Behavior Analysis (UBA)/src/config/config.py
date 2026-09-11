"""
AI-UBA :: Configuration Module
--------------------------------
Bütün layihə üçün mərkəzləşdirilmiş konfiqurasiya idarəetməsi.

Konfiqurasiya mənbələri (prioritet sırası ilə, ən yüksəkdən ən aşağıya):
    1. Environment variables (AIUBA_ prefiksi ilə)
    2. config.yaml faylı (data/ və ya config/ qovluğunda)
    3. Kod daxilindəki default dəyərlər

Digər modullar konfiqurasiyaya bu şəkildə müraciət edir:
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
# Path sabitləri
# --------------------------------------------------------------------------- #

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "src" / "config.yaml"
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"


# --------------------------------------------------------------------------- #
# Alt-konfiqurasiya modelləri
# --------------------------------------------------------------------------- #

class ParserSettings(BaseModel):
    """Windows Event Log parser üçün ayarlar."""

    # İzlənəcək EVTX kanalları. Sysmon defolt olaraq quraşdırıldıqda bu ada sahib olur.
    channels: List[str] = Field(
        default_factory=lambda: [
            "Security",
            "Microsoft-Windows-Sysmon/Operational",
        ]
    )

    # Diqqətə alınacaq event ID-lər (Security + Sysmon qarışıq).
    # Boş saxlanılsa -> bütün event-lər emal olunur.
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

    # Canlı (live) rejimdə neçə saniyədən bir yeni event-lər üçün sorğu edilsin
    poll_interval_seconds: int = 5

    # EVTX fayllarının oxunacağı qovluq (offline/batch rejim üçün)
    evtx_input_dir: Path = DATA_DIR / "evtx"

    # Parse olunmuş normallaşdırılmış event-lərin yazılacağı yer
    parsed_output_dir: Path = DATA_DIR / "parsed"

    mode: Literal["live", "offline"] = "offline"

    @field_validator("evtx_input_dir", "parsed_output_dir", mode="before")
    @classmethod
    def _to_path(cls, v):
        return Path(v)


class LoggingSettings(BaseModel):
    """Tətbiqin öz iç loglaması üçün ayarlar (analiz olunan Windows logları ilə qarışdırılmasın)."""

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
    Wazuh Indexer (OpenSearch, port 9200) üçün ayarlar.
    Diqqət: alert-lər BURADA saxlanılır, Wazuh Manager API-də (55000) YOX.
    Autentifikasiya Basic Auth ilədir (JWT deyil).
    """

    host: str = "192.168.100.100"
    port: int = 9200
    # Şifrələr .env / environment variable-lardan gəlməlidir, YAML-a yazılmamalıdır:
    #   AIUBA_WAZUH_INDEXER__USERNAME=admin
    #   AIUBA_WAZUH_INDEXER__PASSWORD=...
    username: str = "admin"
    password: str = "SecretPassword"
    verify_ssl: bool = False  # self-signed sertifikat üçün defolt False; prod-da True olmalıdır
    index_pattern: str = "wazuh-alerts-*"
    request_timeout_seconds: int = 30

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"


class WazuhAlertOutputSettings(BaseModel):
    """
    AI-UBA-nın öz aşkarladığı anomaliyaları geri Wazuh-a 'inject' etmək üçün ayarlar.
    Metod: JSON log sətri -> agent-in localfile monitor etdiyi fayl -> manager-də custom rule.
    (Bax: src/integrations/wazuh_client.py və docs/wazuh_custom_rule.xml)
    """

    output_file: Path = DATA_DIR / "aiuba_alerts" / "aiuba_events.json"

    @field_validator("output_file", mode="before")
    @classmethod
    def _to_path(cls, v):
        return Path(v)


class RiskSettings(BaseModel):
    """Risk engine üçün ilkin (hibrid rule+ML) ayarlar."""

    # Rule-based scoring ilə ML-based anomaly score-un çəkiləri (cəmi 1.0 olmalıdır)
    rule_weight: float = 0.6
    ml_weight: float = 0.4

    # Risk səviyyəsi threshold-ları (0-100 şkalası üzrə)
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
    """Bütün konfiqurasiyanın kök obyekti."""

    environment: Literal["development", "staging", "production"] = "development"
    project_root: Path = PROJECT_ROOT

    parser: ParserSettings = Field(default_factory=ParserSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    risk: RiskSettings = Field(default_factory=RiskSettings)
    wazuh_indexer: WazuhIndexerSettings = Field(default_factory=WazuhIndexerSettings)
    wazuh_alert_output: WazuhAlertOutputSettings = Field(default_factory=WazuhAlertOutputSettings)

    model_config = ConfigDict(arbitrary_types_allowed=True)


# --------------------------------------------------------------------------- #
# Yükləmə məntiqi
# --------------------------------------------------------------------------- #

def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _apply_env_overrides(raw: dict) -> dict:
    """
    AIUBA_ prefiksli environment variable-ları config-ə tətbiq edir.
    Nested key-lər üçün '__' ayırıcısı istifadə olunur.
    Məsələn: AIUBA_PARSER__MODE=live -> raw["parser"]["mode"] = "live"
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
    Tətbiq boyu tək instance (singleton) qaytarır (lru_cache ilə).
    Test zamanı fərqli config istifadə etmək lazımdırsa get_settings.cache_clear() çağırılmalıdır.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    raw = _load_yaml(path)
    raw = _apply_env_overrides(raw)
    settings = Settings(**raw)

    # İşlək qovluqların mövcudluğunu təmin et
    settings.parser.evtx_input_dir.mkdir(parents=True, exist_ok=True)
    settings.parser.parsed_output_dir.mkdir(parents=True, exist_ok=True)
    settings.logging.log_file.parent.mkdir(parents=True, exist_ok=True)
    settings.wazuh_alert_output.output_file.parent.mkdir(parents=True, exist_ok=True)

    return settings


if __name__ == "__main__":
    # Sürətli mənual test: `python -m src.config.config`
    s = get_settings()
    print(s.model_dump_json(indent=2, exclude={"project_root"}))
