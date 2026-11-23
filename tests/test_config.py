"""Tests for bw_meter.config."""

from __future__ import annotations

import pytest

from bw_meter.config import Config, ConfigError, load_config, parse_endpoint


class TestParseEndpoint:
    def test_ipv4(self):
        assert parse_endpoint("203.0.113.7:51820") == ("203.0.113.7", 51820)

    def test_ipv6_in_brackets(self):
        assert parse_endpoint("[2001:db8::1]:51820") == ("2001:db8::1", 51820)

    def test_ipv6_is_normalised(self):
        assert parse_endpoint("[2001:0db8:0:0::1]:51820") == ("2001:db8::1", 51820)

    @pytest.mark.parametrize(
        "bad",
        ["203.0.113.7", "203.0.113.7:x", "nohost:51820", "2001:db8::1:51820", "", "203.0.113.7:0", "203.0.113.7:65536"],
    )
    def test_bad(self, bad):
        with pytest.raises(ConfigError):
            parse_endpoint(bad)


class TestLoadConfig:
    def test_missing_file_gives_defaults(self, tmp_path):
        assert load_config(tmp_path / "absent.toml") == Config()

    def test_empty_file_gives_defaults(self, tmp_path):
        path = tmp_path / "config.toml"
        path.write_text("")
        assert load_config(path) == Config()

    def test_metered_and_vpn(self, tmp_path):
        path = tmp_path / "config.toml"
        path.write_text(
            '[interfaces]\nmetered = ["wlan1"]\n\n[vpn.wg0]\nendpoints = ["203.0.113.7:51820", "[2001:db8::1]:51820"]\n'
        )
        config = load_config(path)
        assert config.metered == ["wlan1"]
        assert config.vpn_endpoints == {"wg0": [("203.0.113.7", 51820), ("2001:db8::1", 51820)]}

    def test_env_var_names_the_file(self, tmp_path, monkeypatch):
        path = tmp_path / "config.toml"
        path.write_text('[interfaces]\nmetered = ["eth0"]\n')
        monkeypatch.setenv("BW_METER_CONFIG", str(path))
        assert load_config().metered == ["eth0"]

    def test_invalid_toml(self, tmp_path):
        path = tmp_path / "config.toml"
        path.write_text("[interfaces\n")
        with pytest.raises(ConfigError, match="config.toml"):
            load_config(path)

    def test_metered_must_be_list_of_strings(self, tmp_path):
        path = tmp_path / "config.toml"
        path.write_text('[interfaces]\nmetered = "wlan1"\n')
        with pytest.raises(ConfigError, match="metered"):
            load_config(path)

    def test_bad_endpoint_names_interface(self, tmp_path):
        path = tmp_path / "config.toml"
        path.write_text('[vpn.wg0]\nendpoints = ["nope"]\n')
        with pytest.raises(ConfigError, match="wg0"):
            load_config(path)

    @pytest.mark.parametrize(
        "text",
        ['interfaces = "x"\n', "vpn = 1\n", 'vpn = ["a"]\n', "[vpn]\nwg0 = 1\n"],
    )
    def test_wrong_table_types(self, tmp_path, text):
        path = tmp_path / "config.toml"
        path.write_text(text)
        with pytest.raises(ConfigError):
            load_config(path)

    def test_empty_metered_is_an_error(self, tmp_path):
        path = tmp_path / "config.toml"
        path.write_text("[interfaces]\nmetered = []\n")
        with pytest.raises(ConfigError, match="metered"):
            load_config(path)
