"""Pydantic v2 config base + YAML loader/validator for all forge frameworks."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class RateLimitConfig(BaseModel):
    """Rate limiting settings shared across all frameworks."""
    requests_per_second: float = Field(default=10.0, gt=0, le=1000)
    burst:               int   = Field(default=20, gt=0)
    backoff_factor:      float = Field(default=2.0, gt=0)
    max_backoff_seconds: float = Field(default=60.0, gt=0)


class BruteForceConfig(BaseModel):
    """Brute force safety settings — lockout prevention."""
    timeout_seconds:     int   = Field(default=30, gt=0)
    delay_seconds:       float = Field(default=3.0, ge=0)
    max_attempts:        int   = Field(default=3, gt=0)
    lockout_threshold:   int   = Field(default=5, gt=0)
    spray_delay_seconds: float = Field(default=60.0, ge=30)
    spray_max_rounds:    int   = Field(default=1, gt=0)


class ReportConfig(BaseModel):
    """Report output configuration."""
    formats:   list[str] = Field(default=["html", "pdf"])
    output_dir: str      = Field(default="results")

    @field_validator("formats")
    @classmethod
    def validate_formats(cls, v: list[str]) -> list[str]:
        valid = {"html", "pdf", "json", "csv"}
        for f in v:
            if f not in valid:
                raise ValueError(f"Invalid report format: {f}. Valid: {valid}")
        return v


class BaseForgeConfig(BaseModel):
    """Base configuration shared across all three frameworks."""
    target:        str            = ""
    engagement:    str            = "default"
    tester:        str            = "anonymous"
    mode:          str            = "blackbox"
    rate:          RateLimitConfig = Field(default_factory=RateLimitConfig)
    brute_force:   BruteForceConfig = Field(default_factory=BruteForceConfig)
    report:        ReportConfig    = Field(default_factory=ReportConfig)
    scope:         list[str]       = Field(default_factory=list)
    excluded:      list[str]       = Field(default_factory=list)
    workers:       int             = Field(default=10, gt=0, le=100)
    verbose:       bool            = False
    quiet:         bool            = False
    dry_run:       bool            = False
    auto_confirm:  bool            = False
    proxy:         str | None      = None
    extra:         dict[str, Any]  = Field(default_factory=dict)


def load_config(config_path: Path, model_class: type[BaseForgeConfig] = BaseForgeConfig) -> BaseForgeConfig:
    """Load and validate a YAML config file.

    Args:
        config_path:  Path to the YAML config file.
        model_class:  Pydantic model class to validate against.

    Returns:
        Validated config instance.

    Raises:
        SystemExit: If config file is invalid.
    """
    if not config_path.exists():
        return model_class()
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        return model_class(**raw)
    except Exception as exc:
        print(f"[!] Config validation error in {config_path}: {exc}", file=sys.stderr)
        sys.exit(1)


def generate_default_config(model_class: type[BaseForgeConfig], output_path: Path) -> None:
    """Write a default config YAML to disk.

    Args:
        model_class:  Pydantic model to generate defaults from.
        output_path:  Path to write the YAML file.
    """
    defaults = model_class().model_dump()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(yaml.dump(defaults, default_flow_style=False), encoding="utf-8")
    print(f"[+] Default config written to: {output_path}")


class TestConfig:
    """Unit tests for config module."""

    def test_default_config(self) -> None:
        cfg = BaseForgeConfig()
        assert cfg.workers == 10
        assert cfg.rate.requests_per_second == 10.0
        assert cfg.brute_force.delay_seconds == 3.0

    def test_load_config_missing_file(self, tmp_path: Path) -> None:
        cfg = load_config(tmp_path / "nonexistent.yaml")
        assert isinstance(cfg, BaseForgeConfig)

    def test_load_config_valid_yaml(self, tmp_path: Path) -> None:
        p = tmp_path / "config.yaml"
        p.write_text("workers: 5\nengagement: test_eng\n")
        cfg = load_config(p)
        assert cfg.workers == 5
        assert cfg.engagement == "test_eng"

    def test_generate_default_config(self, tmp_path: Path) -> None:
        p = tmp_path / "default.yaml"
        generate_default_config(BaseForgeConfig, p)
        assert p.exists()
        content = p.read_text()
        assert "workers" in content

    def test_invalid_report_format(self) -> None:
        try:
            ReportConfig(formats=["docx"])
            assert False, "Should have raised"
        except Exception:
            pass
