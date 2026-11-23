"""Configuration file (``/etc/bw-meter/config.toml``) for bw-meter."""

from __future__ import annotations

import ipaddress
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

DEFAULT_CONFIG_PATH = Path("/etc/bw-meter/config.toml")


class ConfigError(ValueError):
    """The configuration file is unreadable or holds an invalid value."""


@dataclass
class Config:
    #: Interfaces counting against the data cap; None means "not configured".
    metered: list[str] | None = None
    #: Tunnel endpoints per VPN interface, as (ip, port), on top of the ones
    #: the distiller detects with ``wg``.
    vpn_endpoints: dict[str, list[tuple[str, int]]] = field(default_factory=dict)


def resolve_config_path(path: Path | str | None = None) -> Path:
    """Return the config path: *path*, else ``BW_METER_CONFIG``, else the default."""
    if path:
        return Path(path)
    env = os.environ.get("BW_METER_CONFIG")
    if env:
        return Path(env)
    return DEFAULT_CONFIG_PATH


def parse_endpoint(text: str) -> tuple[str, int]:
    """Parse ``ip:port`` or ``[ipv6]:port`` into a normalised (ip, port) pair."""
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ConfigError(f"bad endpoint {text!r}: expected ip:port or [ipv6]:port")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    elif ":" in host:
        raise ConfigError(f"bad endpoint {text!r}: put an IPv6 address in brackets")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ConfigError(f"bad endpoint {text!r}: {exc}") from None
    return str(ip), int(port)


def load_config(path: Path | str | None = None) -> Config:
    """Read the configuration; a missing file gives the defaults."""
    config_path = resolve_config_path(path)
    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return Config()
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {config_path}: {exc}") from None

    config = Config()
    interfaces = data.get("interfaces", {})
    if not isinstance(interfaces, dict):
        raise ConfigError(f"{config_path}: interfaces must be a table")
    metered = interfaces.get("metered")
    if metered is not None:
        if not isinstance(metered, list) or not metered or not all(isinstance(i, str) for i in metered):
            raise ConfigError(f"{config_path}: interfaces.metered must be a non-empty list of interface names")
        config.metered = metered

    vpn = data.get("vpn", {})
    if not isinstance(vpn, dict):
        raise ConfigError(f"{config_path}: vpn must be a table of [vpn.<interface>] sections")
    for iface, section in vpn.items():
        endpoints = section.get("endpoints", []) if isinstance(section, dict) else None
        if not isinstance(endpoints, list):
            raise ConfigError(f"{config_path}: vpn.{iface}.endpoints must be a list")
        try:
            config.vpn_endpoints[iface] = [parse_endpoint(str(e)) for e in endpoints]
        except ConfigError as exc:
            raise ConfigError(f"{config_path}: vpn.{iface}: {exc}") from None
    return config
