"""Configuration management.

Configuration is loaded from (in order of precedence):
  1. Environment variables  (prefixed BGPLS_)
  2. YAML config file       (default: config.yaml, overridden by --config CLI arg)
  3. Built-in defaults

Usage::

    from bgp_ls_collector.config import load_config
    cfg = load_config("config.yaml")
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class PeerCfg:
    """Configuration for a single BGP peer (Nokia SROS router)."""
    neighbor_ip: str
    remote_as: int
    description: str = ""
    # Overrides global defaults
    hold_time: int | None = None
    connect_retry: int | None = None
    passive: bool = True


@dataclass
class AppConfig:
    # ---- BGP ----
    local_as: int = 65000
    router_id: str = "127.0.0.1"
    bgp_bind: str = "0.0.0.0"
    bgp_port: int = 179
    hold_time: int = 90
    connect_retry: int = 30
    allow_dynamic_peers: bool = False
    peers: list[PeerCfg] = field(default_factory=list)

    # ---- API ----
    api_host: str = "0.0.0.0"
    api_port: int = 8090
    api_workers: int = 1

    # ---- Logging ----
    log_level: str = "INFO"
    log_format: str = "text"    # "text" or "json"


def load_config(path: str | Path | None = None) -> AppConfig:
    """Load configuration from YAML file and environment variables."""
    raw: dict[str, Any] = {}

    if path:
        config_path = Path(path)
        if config_path.exists():
            with config_path.open() as fh:
                raw = yaml.safe_load(fh) or {}
        else:
            raise FileNotFoundError(f"Config file not found: {path}")

    # BGP section
    bgp = raw.get("bgp", {})
    api = raw.get("api", {})
    logging_cfg = raw.get("logging", {})

    peers = []
    for p in bgp.get("peers", []):
        peers.append(
            PeerCfg(
                neighbor_ip=p["neighbor_ip"],
                remote_as=int(p["remote_as"]),
                description=p.get("description", ""),
                hold_time=p.get("hold_time"),
                connect_retry=p.get("connect_retry"),
                passive=bool(p.get("passive", True)),
            )
        )

    cfg = AppConfig(
        local_as=int(bgp.get("local_as", 65000)),
        router_id=bgp.get("router_id", "127.0.0.1"),
        bgp_bind=bgp.get("bind", "0.0.0.0"),
        bgp_port=int(bgp.get("port", 179)),
        hold_time=int(bgp.get("hold_time", 90)),
        connect_retry=int(bgp.get("connect_retry", 30)),
        allow_dynamic_peers=bool(bgp.get("allow_dynamic_peers", False)),
        peers=peers,
        api_host=api.get("host", "0.0.0.0"),
        api_port=int(api.get("port", 8090)),
        log_level=logging_cfg.get("level", "INFO").upper(),
        log_format=logging_cfg.get("format", "text"),
    )

    # Environment variable overrides (BGPLS_*)
    _apply_env(cfg)
    return cfg


def _apply_env(cfg: AppConfig) -> None:
    """Apply BGPLS_* environment variables over config."""
    overrides = {
        "BGPLS_LOCAL_AS": ("local_as", int),
        "BGPLS_ROUTER_ID": ("router_id", str),
        "BGPLS_BGP_BIND": ("bgp_bind", str),
        "BGPLS_BGP_PORT": ("bgp_port", int),
        "BGPLS_HOLD_TIME": ("hold_time", int),
        "BGPLS_API_HOST": ("api_host", str),
        "BGPLS_API_PORT": ("api_port", int),
        "BGPLS_LOG_LEVEL": ("log_level", str),
        "BGPLS_LOG_FORMAT": ("log_format", str),
        "BGPLS_ALLOW_DYNAMIC": ("allow_dynamic_peers", lambda v: v.lower() == "true"),
    }
    for env_var, (attr, cast) in overrides.items():
        val = os.environ.get(env_var)
        if val is not None:
            setattr(cfg, attr, cast(val))
