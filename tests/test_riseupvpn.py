from pathlib import Path
from types import SimpleNamespace
import hashlib
import json

import pytest
import yaml

import riseup_vpn_configurator as rvc


TEST_CA_CERT = """-----BEGIN CERTIFICATE-----
MIIBYjCCAQigAwIBAgIBATAKBggqhkjOPQQDAjAXMRUwEwYDVQQDEwxMRUFQIFJv
b3QgQ0EwHhcNMjExMTAyMTkwNTM3WhcNMjYxMTAyMTkxMDM3WjAXMRUwEwYDVQQD
EwxMRUFQIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQxOXBGu+gf
pjHzVteGTWL6XnFxtEnKMFpKaJkA/VOHmESzoLsZRQxt88GssxaqC01J17idQiqv
zgNpedmtvFtyo0UwQzAOBgNVHQ8BAf8EBAMCAqQwEgYDVR0TAQH/BAgwBgEB/wIB
ATAdBgNVHQ4EFgQUZdoUlJrCIUNFrpffAq+LQjnwEz4wCgYIKoZIzj0EAwIDSAAw
RQIgfr3w4tnRG+NdI3LsGPlsRktGK20xHTzsB3orB0yC6cICIQCB+/9y8nmSStfN
VUMUyk2hNd7/kC8nL222TTD7VZUtsg==
-----END CERTIFICATE-----
"""

TEST_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALnFvW9pDkQjLej5TfLZ8bCNx9E0uLQ4nKQqYlGQXcD4u9n8gY5q
8vW7lJk3GqCgk/J4kP6O6Q3zjQdWMe7x1xECAwEAAQJAJ1S0pF0b2mW7cYV6m3BA
Q5y+7hWv3v2W5mL7XK6j9g1Pj7K3Q2G7oS4k6MjvQf0oE9N3x/8VQx0lD6eKqCjv
YQIhAPr9mXl5S7R8ZQf9+3qHc3K8FvY8H0Jm0Sx8R4uK2whVAiEAuO4mJY7j8D3P
gJH2D3yJqR9dS6F7mJxK0n6a9Q0wNnMCIQDJgS6Gm9T4QfUfZ2LZz2D7S8V3x9d6
QxT3kq7YBWWv4QIgWQQvmp8D7fY2Rr/5qv2bP9o2Qj2C5tC0o3nCq0n8Q1sCIQCL
JvJqK6L5v2hHn4sE0J5k0c8sYI9J5F0nKxWQ9xZQOQ==
-----END RSA PRIVATE KEY-----
"""

TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIBxTCCAWugAwIBAgIUH0r8k5lQFhZ3gJw2S8lQ5eA8yVQwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAxMMTEVBUCBSb290IENBMB4XDTI2MDQwMTA4MjAzOVoXDTI2MDUw
NjA4MjAzOVowFDESMBAGA1UEAxMJVU5MSU1JVEVEMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAE9Qxg2Ff7sQ8b6oU5mT8aM0c6D9E5g0V2s6P/jk2QY9v0l6g0mB7r
xyJ+r3qYfA2n5Q8x3vM2nR1s8cVhW8J0NKNmMGQwDgYDVR0PAQH/BAQDAgeAMBMGA
1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBQ7spwUa1PvepSDp0VAmMHNRN+t
bDAfBgNVHSMEGDAWgBR9SmLY/ytJxHm2orHcjj5jB1yo/jAKBggqhkjOPQQDAgNH
ADBEAiA5lLMRkQx6QHk1Y+v1o4sW8YhQ9VgU5Yc5cW9B6q2v0gIgGmXbJH8Vh0jT
9z9y7Xy9Q7wK2vB5p7q7eM8P4J6uQ3k=
-----END CERTIFICATE-----
"""


def make_gateway_inventory() -> dict:
    return {
        "gateways": [
            {
                "host": "vpn01-sea.riseup.net",
                "ip_address": "203.0.113.10",
                "location": "Seattle",
                "capabilities": {
                    "transport": [
                        {"type": "openvpn", "protocols": ["udp", "tcp"], "ports": ["53", "1194"]}
                    ]
                },
            },
            {
                "host": "vpn02-par.riseup.net",
                "ip_address": "203.0.113.20",
                "location": "Paris",
                "capabilities": {
                    "transport": [
                        {"type": "openvpn", "protocols": ["tcp", "udp"], "ports": ["443", "80"]}
                    ]
                },
            },
        ],
        "locations": {},
        "openvpn_configuration": {
            "auth": "SHA512",
            "cipher": "AES-256-GCM",
            "data-ciphers": "AES-256-GCM",
            "keepalive": "10 30",
            "nobind": True,
            "tls-version-min": "1.2",
            "verb": "3",
            "script-security": "2",
        },
        "serial": 3,
        "version": 3,
    }


def make_config(tmp_path: Path) -> dict:
    return {
        "provider": "riseup",
        "service_name": "riseup",
        "server": "vpn01-sea.riseup.net",
        "protocol": "udp",
        "port": 53,
        "excluded_routes": ["8.8.8.8", "192.168.123.0/24"],
        "user": "root",
        "group": "root",
        "state_dir": str(tmp_path / "state"),
        "openvpn_config_dir": str(tmp_path / "openvpn"),
        "verify_ca_fingerprint": False,
        "request_timeout": 5,
        "extra_config": "mute 3",
    }


def write_runtime_files(paths: dict[str, Path]) -> None:
    paths["state_dir"].mkdir(parents=True, exist_ok=True)
    paths["ca_cert_file"].write_text(TEST_CA_CERT, encoding="utf-8")
    paths["client_bundle_file"].write_text(TEST_KEY + "\n" + TEST_CERT, encoding="utf-8")
    paths["cert_file"].write_text(TEST_CERT, encoding="utf-8")
    paths["key_file"].write_text(TEST_KEY, encoding="utf-8")
    paths["gateway_json"].write_text(json.dumps(make_gateway_inventory()), encoding="utf-8")


def test_read_config_normalizes_provider_alias(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "riseup-vpn.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "provider": "riseup.net",
                "server": "vpn01-sea.riseup.net",
                "protocol": "udp",
                "port": 53,
                "excluded_routes": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(rvc, "CONFIG_FILE", config_path)

    config = rvc.read_config()

    assert config["provider"] == "riseup"
    assert config["service_name"] == "riseup"
    assert config["verify_ca_fingerprint"] is False


def test_list_providers_includes_all_builtin_providers(capsys: pytest.CaptureFixture[str]) -> None:
    rvc.list_providers()
    output = capsys.readouterr().out

    assert "riseup" in output
    assert "calyx" in output
    assert "demo" in output


def test_update_vpn_ca_certificate_validates_pinned_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    provider = rvc.resolve_provider(config)
    provider["ca_cert_fingerprint"] = "SHA256: " + hashlib.sha256(TEST_CA_CERT.encode("utf-8")).hexdigest()
    paths = rvc.ensure_runtime_directories(config)

    calls = []

    def fake_get(url: str, timeout: float, verify=True):
        calls.append((url, timeout, verify))
        return SimpleNamespace(
            content=TEST_CA_CERT.encode("utf-8"),
            text=TEST_CA_CERT,
            raise_for_status=lambda: None,
        )

    monkeypatch.setattr(rvc.requests, "get", fake_get)

    rvc.update_vpn_ca_certificate(config, provider, paths)

    assert paths["ca_cert_file"].read_text(encoding="utf-8") == TEST_CA_CERT
    assert calls[0][0] == provider["ca_cert_url"]


def test_update_gateways_uses_provider_ca_for_tls_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    provider = rvc.resolve_provider(config)
    paths = rvc.ensure_runtime_directories(config)
    paths["ca_cert_file"].write_text(TEST_CA_CERT, encoding="utf-8")
    gateway_inventory = make_gateway_inventory()

    calls = []

    def fake_get(url: str, timeout: float, verify=True):
        calls.append((url, timeout, verify))
        return SimpleNamespace(
            text=json.dumps(gateway_inventory),
            raise_for_status=lambda: None,
        )

    monkeypatch.setattr(rvc.requests, "get", fake_get)

    rvc.update_gateways(config, provider, paths)

    assert json.loads(paths["gateway_json"].read_text(encoding="utf-8"))["version"] == 3
    assert calls[0][2] == str(paths["ca_cert_file"])


def test_update_vpn_client_credentials_saves_combined_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    provider = rvc.resolve_provider(config)
    paths = rvc.ensure_runtime_directories(config)
    paths["ca_cert_file"].write_text(TEST_CA_CERT, encoding="utf-8")
    bundle = TEST_KEY + "\n" + TEST_CERT

    def fake_get(url: str, timeout: float, verify=True):
        return SimpleNamespace(
            text=bundle,
            raise_for_status=lambda: None,
        )

    monkeypatch.setattr(rvc.requests, "get", fake_get)

    rvc.update_vpn_client_credentials(config, provider, paths)

    assert paths["client_bundle_file"].read_text(encoding="utf-8").startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert paths["key_file"].read_text(encoding="utf-8").startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert paths["cert_file"].read_text(encoding="utf-8").startswith("-----BEGIN CERTIFICATE-----")


def test_generate_configuration_uses_provider_options_and_skips_unsafe_keys(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    paths = rvc.ensure_runtime_directories(config)
    write_runtime_files(paths)

    rvc.generate_configuration(config, paths)

    vpn_config = paths["ovpn_file"].read_text(encoding="utf-8")
    assert "remote 203.0.113.10 53" in vpn_config
    assert "proto udp" in vpn_config
    assert "verify-x509-name vpn01-sea name" in vpn_config
    assert "cipher AES-256-GCM" in vpn_config
    assert "data-ciphers AES-256-GCM" in vpn_config
    assert "auth-nocache" in vpn_config
    assert f"cert {paths['client_bundle_file']}" in vpn_config
    assert f"key {paths['client_bundle_file']}" in vpn_config
    assert "route 8.8.8.8 255.255.255.255 net_gateway" in vpn_config
    assert "route 192.168.123.0 255.255.255.0 net_gateway" in vpn_config
    assert "script-security" not in vpn_config


def test_rotate_gateway_updates_config_and_persists_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    config_path = tmp_path / "riseup-vpn.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    monkeypatch.setattr(rvc, "CONFIG_FILE", config_path)
    paths = rvc.ensure_runtime_directories(config)
    write_runtime_files(paths)

    rotated = rvc.rotate_gateway(config, paths, None, False)

    assert rotated["server"] == "vpn02-par.riseup.net"
    assert rotated["port"] in (443, 80)
    persisted = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert persisted["server"] == "vpn02-par.riseup.net"


def test_reload_openvpn_uses_reload_or_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    calls = []

    def fake_run(args, check, capture_output, text):
        calls.append(args)
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(rvc.subprocess, "run", fake_run)

    rvc.reload_openvpn(config)

    assert calls == [["systemctl", "reload-or-restart", "openvpn-client@riseup"]]
