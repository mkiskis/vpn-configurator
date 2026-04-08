#!/usr/bin/env python3
import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib3
import yaml

from ipaddress import ip_network
from pathlib import Path
from typing import Any, NoReturn, Optional

import psutil
import requests
from urllib3.exceptions import InsecureRequestWarning

try:
    from icmplib import ICMPLibError, ping
except ImportError:  # pragma: no cover - optional at runtime outside packaged installs
    class ICMPLibError(Exception):
        pass

    def ping(*args, **kwargs):
        raise ICMPLibError("icmplib is not installed")

try:
    from pyasn1.codec.der import decoder
    from pyasn1_modules import pem, rfc2459
except ImportError:  # pragma: no cover - optional at runtime outside packaged installs
    decoder = None
    pem = None
    rfc2459 = None

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - this package targets Linux
    grp = None
    pwd = None


FORMAT = "%(levelname)s: %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)

APP_NAME = "riseup-vpn-configurator"
DEFAULT_STATE_DIR = Path("/var/lib/riseup-vpn-configurator")
DEFAULT_OPENVPN_CONFIG_DIR = Path("/etc/openvpn/client")
DEFAULT_CONFIG_TIMEOUT = 10
CONFIG_FILE = Path("/etc/riseup-vpn.yaml")
DEFAULT_CONFIG_TEMPLATE = Path(__file__).parent / "riseup-vpn.yaml"
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----",
    re.S,
)
CERTIFICATE_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.S,
)
SAFE_OPENVPN_KEYS = {
    "auth",
    "cipher",
    "connect-retry",
    "connect-timeout",
    "data-ciphers",
    "dev",
    "explicit-exit-notify",
    "float",
    "keepalive",
    "key-direction",
    "mssfix",
    "mute-replay-warnings",
    "nobind",
    "persist-key",
    "persist-tun",
    "ping",
    "ping-restart",
    "rcvbuf",
    "remote-cert-eku",
    "remote-cert-tls",
    "resolv-retry",
    "sndbuf",
    "tls-cipher",
    "tls-version-min",
    "tun-mtu",
    "verb",
}
PROVIDER_ALIASES = {
    "riseup": "riseup",
    "riseup.net": "riseup",
    "calyx": "calyx",
    "calyx.net": "calyx",
    "demo": "demo",
    "demo.bitmask.net": "demo",
}
BUILTIN_PROVIDERS = {
    "riseup": {
        "name": "Riseup Networks",
        "api_uri": "https://api.black.riseup.net:443",
        "vpn_api_version": 3,
        "provider_json_url": "https://riseup.net/provider.json",
        "ca_cert_url": "https://black.riseup.net/ca.crt",
        "ca_cert_fingerprint": "SHA256: fa4ce88e1c0c6c5c1c7fd5ba0b35dc09a2f306d81e3a05e9d7d5cfacfdd98453",
    },
    "calyx": {
        "name": "Calyx Institute",
        "api_uri": "https://api.calyx.net:4430",
        "vpn_api_version": 3,
        "provider_json_url": "https://calyx.net/provider.json",
        "ca_cert_url": "https://calyx.net/ca.crt",
        "ca_cert_fingerprint": "SHA256: 43683c9ba3862c5384a8c1885072fcac40b5d2d4dd67331443f13a3077fa2e69",
    },
    "demo": {
        "name": "Bitmask Demo",
        "api_uri": "https://api.demo.bitmask.net:4430",
        "vpn_api_version": 3,
        "provider_json_url": "https://demo.bitmask.net/provider.json",
        "ca_cert_url": "https://demo.bitmask.net/ca.crt",
        "ca_cert_fingerprint": "SHA256: 0f17c033115f6b76ff67871872303ff65034efe7dd1b910062ca323eb4da5c7e",
    },
}
ENDPOINT_OVERRIDE_KEYS = {
    "api_uri",
    "vpn_api_version",
    "provider_json_url",
    "gateway_api_url",
    "client_credentials_url",
    "ca_cert_url",
    "ca_cert_fingerprint",
}


def get_rtt(ip: str) -> float:
    try:
        response = ping(ip, timeout=2, count=5, interval=0.5)
        logging.debug(f"RTT probe result for {ip}: {response}")
        if response.avg_rtt == 0.0:
            return 9000.0
        return response.avg_rtt
    except ICMPLibError as exc:
        logging.warning(f"Error getting rtt for {ip}: {exc}")
        return 9000.0


def get_no_group_name() -> str:
    if grp is None:
        return "nogroup"
    for candidate in ("nogroup", "nobody"):
        try:
            grp.getgrnam(candidate)
            return candidate
        except KeyError:
            continue
    return "nogroup"


def get_default_openvpn_user() -> str:
    if pwd is None:
        return "nobody"
    for candidate in ("nobody", "openvpn", "root"):
        try:
            pwd.getpwnam(candidate)
            return candidate
        except KeyError:
            continue
    return "nobody"


def normalize_provider_name(provider_name: str) -> str:
    normalized = provider_name.strip().lower()
    return PROVIDER_ALIASES.get(normalized, normalized)


def sanitize_service_name(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_.@-]+", "-", value).strip("-")
    if not normalized:
        raise ValueError("service_name must contain at least one safe character")
    return normalized


def normalize_fingerprint(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return value.strip().lower().replace("sha256:", "").replace(":", "").replace(" ", "")


def atomic_write_text(path: Path, data: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def read_config() -> dict[str, Any]:
    if not CONFIG_FILE.exists():
        logging.error(f"Could not find config file {CONFIG_FILE}. Use --default-config for the default config file")
        sys.exit(1)
    with CONFIG_FILE.open(encoding="utf-8") as handle:
        try:
            config = yaml.safe_load(handle)
        except yaml.scanner.ScannerError as exc:
            logging.error(f"Could not parse yaml file: {exc}")
            sys.exit(1)
    if not config or not isinstance(config, dict):
        logging.error(f"Could not parse config file {CONFIG_FILE}")
        print_default_config(1)
    config.setdefault("provider", "riseup")
    config["provider"] = normalize_provider_name(str(config["provider"]))
    config.setdefault("excluded_routes", [])
    config.setdefault("request_timeout", DEFAULT_CONFIG_TIMEOUT)
    config.setdefault("state_dir", str(DEFAULT_STATE_DIR))
    config.setdefault("openvpn_config_dir", str(DEFAULT_OPENVPN_CONFIG_DIR))
    config.setdefault("verify_ca_fingerprint", False)
    config.setdefault("user", get_default_openvpn_user())
    config.setdefault("group", get_no_group_name())
    config.setdefault("service_name", config["provider"])
    config["service_name"] = sanitize_service_name(str(config["service_name"]))
    return config


def resolve_provider(config: dict[str, Any]) -> dict[str, Any]:
    provider_name = config["provider"]
    provider = dict(BUILTIN_PROVIDERS.get(provider_name, {}))

    for key in ENDPOINT_OVERRIDE_KEYS:
        if config.get(key) not in (None, ""):
            provider[key] = config[key]

    if not provider:
        logging.error(
            "Provider '%s' is unknown. Use --list-providers or configure explicit endpoint overrides.",
            provider_name,
        )
        sys.exit(1)

    provider["id"] = provider_name
    provider.setdefault("name", provider_name)
    provider.setdefault("vpn_api_version", 3)

    api_uri = provider.get("api_uri", "").rstrip("/")
    api_version = provider["vpn_api_version"]
    if api_uri:
        provider.setdefault("gateway_api_url", f"{api_uri}/{api_version}/config/eip-service.json")
        provider.setdefault("client_credentials_url", f"{api_uri}/{api_version}/cert")

    for required in ("gateway_api_url", "client_credentials_url", "ca_cert_url"):
        if not provider.get(required):
            logging.error(f"Provider '{provider_name}' is missing the '{required}' endpoint")
            sys.exit(1)
    return provider


def get_runtime_paths(config: dict[str, Any]) -> dict[str, Path]:
    state_dir = Path(str(config["state_dir"]))
    openvpn_dir = Path(str(config["openvpn_config_dir"]))
    service_name = config["service_name"]
    return {
        "state_dir": state_dir,
        "provider_json": state_dir / "provider.json",
        "gateway_json": state_dir / "gateways.json",
        "ca_cert_file": state_dir / "vpn-ca.pem",
        "client_bundle_file": state_dir / "client.pem",
        "cert_file": state_dir / "cert.pem",
        "key_file": state_dir / "key.pem",
        "ovpn_file": openvpn_dir / f"{service_name}.conf",
    }


def get_service_unit(config: dict[str, Any]) -> str:
    return f"openvpn-client@{config['service_name']}"


def check_root_permissions() -> None:
    if os.getuid() != 0:
        logging.error("This script needs to be executed with root permission.")
        sys.exit(1)


def ensure_runtime_directories(config: dict[str, Any]) -> dict[str, Path]:
    paths = get_runtime_paths(config)
    paths["state_dir"].mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(paths["state_dir"], 0o700)
    paths["ovpn_file"].parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    return paths


def validate_user_group(user: str, group_name: str) -> None:
    if pwd is not None:
        try:
            pwd.getpwnam(user)
        except KeyError:
            logging.error(f"Could not find user '{user}'. Adjust 'user' in {CONFIG_FILE}")
            sys.exit(1)
    if grp is not None:
        try:
            grp.getgrnam(group_name)
        except KeyError:
            logging.error(f"Could not find group '{group_name}'. Adjust 'group' in {CONFIG_FILE}")
            sys.exit(1)


def check_config_file() -> dict[str, Any]:
    config = read_config()
    resolve_provider(config)

    for required_key in ("server", "protocol", "port", "excluded_routes"):
        if required_key not in config:
            logging.error(f"Error checking configuration file ({CONFIG_FILE}): '{required_key}' not specified")
            sys.exit(1)

    if config["protocol"] not in ("tcp", "udp"):
        logging.error(
            "Error checking configuration file (%s): 'protocol' must be one of tcp|udp (specified was '%s')",
            CONFIG_FILE,
            config["protocol"],
        )
        sys.exit(1)

    if not str(config["port"]).isnumeric():
        logging.error(
            "Error checking configuration file (%s): 'port' must be numeric (specified was '%s')",
            CONFIG_FILE,
            config["port"],
        )
        sys.exit(1)

    if not isinstance(config["excluded_routes"], list):
        logging.error(f"Error checking configuration file ({CONFIG_FILE}): 'excluded_routes' must be a list")
        sys.exit(1)

    validate_user_group(str(config["user"]), str(config["group"]))

    for host in config["excluded_routes"]:
        try:
            _ = ip_network(host, strict=False)
        except ValueError:
            try:
                socket.gethostbyname(host)
            except socket.gaierror as exc:
                logging.error(
                    "Error checking configuration file (%s): exclude route '%s' is not an ip address/network or a valid hostname: %s",
                    CONFIG_FILE,
                    host,
                    exc,
                )
                sys.exit(1)
    logging.info("Configuration file: OK")
    return config


def print_default_config(return_code: int) -> NoReturn:
    print(DEFAULT_CONFIG_TEMPLATE.read_text(encoding="utf-8"))
    sys.exit(return_code)


def list_providers() -> None:
    for provider_id in sorted(BUILTIN_PROVIDERS):
        provider = BUILTIN_PROVIDERS[provider_id]
        gateway_api_url = f"{provider['api_uri']}/{provider['vpn_api_version']}/config/eip-service.json"
        print(
            f"{provider_id:<10} name={provider['name']:<18} "
            f"api={provider['api_uri']} gateway_api={gateway_api_url}"
        )


def hash_bytes_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_text(url: str, *, timeout: float, verify: Any = True, allow_insecure: bool = False) -> str:
    try:
        response = requests.get(url, timeout=timeout, verify=verify)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        if not allow_insecure:
            raise
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, timeout=timeout, verify=False)
        response.raise_for_status()
        return response.text


def fetch_bytes(url: str, *, timeout: float, verify: Any = True, allow_insecure: bool = False) -> bytes:
    try:
        response = requests.get(url, timeout=timeout, verify=verify)
        response.raise_for_status()
        return response.content
    except requests.RequestException:
        if not allow_insecure:
            raise
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, timeout=timeout, verify=False)
        response.raise_for_status()
        return response.content


def update_provider_metadata(config: dict[str, Any], provider: dict[str, Any], paths: dict[str, Path]) -> None:
    provider_json_url = provider.get("provider_json_url")
    if not provider_json_url:
        return
    logging.info("Updating provider metadata")
    logging.debug(f"Fetching provider metadata from {provider_json_url}")
    try:
        metadata_text = fetch_text(
            provider_json_url,
            timeout=float(config["request_timeout"]),
            allow_insecure=False,
        )
        metadata = json.loads(metadata_text)
    except (requests.RequestException, ValueError) as exc:
        logging.warning(f"Could not refresh provider metadata from {provider_json_url}: {exc}")
        return

    for key, value in provider.items():
        metadata[key] = value
    atomic_write_text(paths["provider_json"], json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    logging.info(f"Successfully cached provider metadata to {paths['provider_json']}")


def update_gateways(config: dict[str, Any], provider: dict[str, Any], paths: dict[str, Path]) -> None:
    logging.info("Updating VPN gateway list")
    logging.debug(f"Fetching gateways from {provider['gateway_api_url']}")
    try:
        gateway_text = fetch_text(
            provider["gateway_api_url"],
            timeout=float(config["request_timeout"]),
            verify=str(paths["ca_cert_file"]),
        )
        gateway_json = json.loads(gateway_text)
    except (requests.RequestException, ValueError) as exc:
        logging.error(exc)
        sys.exit(1)

    atomic_write_text(paths["gateway_json"], json.dumps(gateway_json, indent=2, sort_keys=True) + "\n")
    logging.info(f"Successfully saved VPN gateway list to {paths['gateway_json']}")


def update_vpn_ca_certificate(config: dict[str, Any], provider: dict[str, Any], paths: dict[str, Path]) -> None:
    logging.info("Updating VPN CA certificate")
    expected_fingerprint = normalize_fingerprint(provider.get("ca_cert_fingerprint"))
    allow_insecure = bool(expected_fingerprint)
    try:
        payload = fetch_bytes(
            provider["ca_cert_url"],
            timeout=float(config["request_timeout"]),
            allow_insecure=allow_insecure,
        )
    except requests.RequestException as exc:
        logging.error(exc)
        sys.exit(1)

    ca_cert_text = payload.decode("utf-8")
    if "-----BEGIN CERTIFICATE-----" not in ca_cert_text or "-----END CERTIFICATE-----" not in ca_cert_text:
        logging.error(f"Response is invalid\nURL: {provider['ca_cert_url']}\nResponse:\n{ca_cert_text}")
        sys.exit(1)

    if config.get("verify_ca_fingerprint", True) and expected_fingerprint:
        actual_fingerprint = hash_bytes_sha256(payload)
        if actual_fingerprint != expected_fingerprint:
            logging.error(
                "CA certificate fingerprint mismatch: expected %s, got %s",
                expected_fingerprint,
                actual_fingerprint,
            )
            sys.exit(1)

    atomic_write_bytes(paths["ca_cert_file"], payload)
    logging.info(f"Successfully saved VPN CA certificate to {paths['ca_cert_file']}")


def split_credentials_bundle(bundle_text: str) -> tuple[str, str]:
    key_match = PRIVATE_KEY_PATTERN.search(bundle_text)
    certificate_matches = CERTIFICATE_PATTERN.findall(bundle_text)

    if key_match is None:
        raise ValueError(f"Private key could not be found:\n{bundle_text}")
    if not certificate_matches:
        raise ValueError(f"Certificate could not be found:\n{bundle_text}")

    key = key_match.group(0).strip()
    cert = "\n".join(certificate.strip() for certificate in certificate_matches)
    return key, cert


def update_vpn_client_credentials(config: dict[str, Any], provider: dict[str, Any], paths: dict[str, Path]) -> None:
    logging.info("Updating client certificate/key")
    try:
        payload = fetch_text(
            provider["client_credentials_url"],
            timeout=float(config["request_timeout"]),
            verify=str(paths["ca_cert_file"]),
        )
        key, cert = split_credentials_bundle(payload)
    except (requests.RequestException, ValueError) as exc:
        logging.error(exc)
        sys.exit(1)

    atomic_write_text(paths["client_bundle_file"], payload.strip() + "\n")
    logging.info(f"Successfully saved combined VPN client bundle to {paths['client_bundle_file']}")

    atomic_write_text(paths["key_file"], key + "\n")
    logging.info(f"Successfully saved VPN client key to {paths['key_file']}")

    atomic_write_text(paths["cert_file"], cert + "\n")
    logging.info(f"Successfully saved VPN client certificate to {paths['cert_file']}")


def load_gateways(paths: dict[str, Path]) -> dict[str, Any]:
    if not paths["gateway_json"].exists():
        logging.error(f"Could not find gateway list ({paths['gateway_json']}). You can get it with --update")
        sys.exit(1)
    with paths["gateway_json"].open(encoding="utf-8") as handle:
        return json.load(handle)


def get_openvpn_transports(gateway: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        transport for transport in gateway.get("capabilities", {}).get("transport", [])
        if transport.get("type") == "openvpn"
    ]


def get_excluded_routes(config: dict[str, Any]) -> str:
    output = []
    for host in config["excluded_routes"]:
        try:
            network = ip_network(host, strict=False)
            logging.debug(f"Added '{network.network_address}' as an exception")
            output.append(f"route {network.network_address} {network.netmask} net_gateway")
        except ValueError:
            try:
                _, _, ip_addresses = socket.gethostbyname_ex(host)
                for ip_address in ip_addresses:
                    logging.debug(f"Resolved '{host}' to '{ip_address}'. Added as an exception")
                    output.append(f"route {ip_address} 255.255.255.255 net_gateway")
            except socket.gaierror as exc:
                logging.error(f"Error parsing {host} in excluded_routes (not an ipaddress/network or hostname): {exc}")
                sys.exit(1)
    return "\n".join(output)


def list_gateways(config: dict[str, Any], paths: dict[str, Path], bench: bool) -> None:
    gateways = load_gateways(paths)["gateways"]

    if bench:
        logging.info("Listing VPN gateways with rtt (round-trip-time). Turn off the VPN first for proper results.")
        for gateway in gateways:
            gateway["rtt"] = get_rtt(gateway["ip_address"])
        sorted_gateways = sorted(gateways, key=lambda gateway: gateway["rtt"])
    else:
        sorted_gateways = sorted(gateways, key=lambda gateway: (gateway["location"], gateway["host"]))

    output = []
    for gateway in sorted_gateways:
        parts = [
            f"{gateway['host']}",
            f"provider={config['provider']}",
            f"location={gateway['location']:<13}",
            f"ip={gateway['ip_address']:<15}",
        ]
        if bench:
            rtt_label = f"{gateway['rtt']} ms"
            parts.append(f"rtt={rtt_label:<11}")
        for transport in get_openvpn_transports(gateway):
            protocols = ",".join(transport["protocols"])
            ports = ",".join(transport["ports"])
            parts.append(f"protocols={protocols:<7}")
            parts.append(f"ports={ports}")
        output.append(" ".join(parts))
    print("\n".join(output).strip())


def render_provider_openvpn_options(openvpn_configuration: dict[str, Any]) -> list[str]:
    options = []
    for key in sorted(openvpn_configuration):
        if key in {"remote", "proto", "ca", "cert", "key", "verify-x509-name"}:
            continue
        if key not in SAFE_OPENVPN_KEYS:
            logging.warning(f"Ignoring unsupported provider OpenVPN option: {key}")
            continue
        value = openvpn_configuration[key]
        if isinstance(value, bool):
            if value:
                options.append(key)
            continue
        if value == "":
            options.append(key)
            continue
        options.append(f"{key} {value}")
    return options


def choose_transport(
    gateway: dict[str, Any],
    preferred_protocol: str,
    preferred_port: int,
) -> tuple[str, int]:
    transports = get_openvpn_transports(gateway)
    if not transports:
        raise ValueError(f"Gateway '{gateway['host']}' does not expose an OpenVPN transport")

    protocol_preferences = []
    for protocol in (preferred_protocol, "udp", "tcp"):
        if protocol not in protocol_preferences:
            protocol_preferences.append(protocol)

    port_preferences = []
    for port in (preferred_port, 53, 80, 1194, 443):
        if port not in port_preferences:
            port_preferences.append(port)

    for transport in transports:
        protocols = [protocol.lower() for protocol in transport.get("protocols", [])]
        ports = [int(port) for port in transport.get("ports", [])]

        for protocol in protocol_preferences:
            if protocol not in protocols:
                continue
            for port in port_preferences:
                if port in ports:
                    return protocol, port
            return protocol, ports[0]

    fallback_transport = transports[0]
    return fallback_transport["protocols"][0].lower(), int(fallback_transport["ports"][0])


def get_gateway_by_name(gateways: list[dict[str, Any]], server_name: str) -> Optional[dict[str, Any]]:
    for gateway in gateways:
        if gateway["host"] == server_name or gateway["ip_address"] == server_name:
            return gateway
    return None


def get_server_info(config: dict[str, Any], paths: dict[str, Path]) -> dict[str, Any]:
    gateway_inventory = load_gateways(paths)
    gateways = gateway_inventory["gateways"]
    gateway = get_gateway_by_name(gateways, str(config["server"]))
    if gateway is None:
        logging.error(f"Gateway '{config['server']}' not found in gateway list. Please check with --list-gateways")
        sys.exit(1)

    try:
        protocol, port = choose_transport(gateway, str(config["protocol"]), int(config["port"]))
    except ValueError as exc:
        logging.error(exc)
        sys.exit(1)

    return {
        "hostname": gateway["host"],
        "ip_address": gateway["ip_address"],
        "proto": protocol,
        "port": port,
        "location": gateway["location"],
        "extra_config": config.get("extra_config", ""),
        "openvpn_configuration": gateway_inventory.get("openvpn_configuration", {}),
    }


def build_openvpn_config(config: dict[str, Any], paths: dict[str, Path], server_info: dict[str, Any]) -> str:
    openvpn_configuration = server_info.get("openvpn_configuration", {})
    provider_option_lines = render_provider_openvpn_options(openvpn_configuration)
    provider_option_keys = set(openvpn_configuration.keys())
    excluded_routes = get_excluded_routes(config)

    lines = [
        "# reference manual: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/",
        "client",
    ]

    if "dev" not in provider_option_keys:
        lines.append("dev tun")

    lines.extend(
        [
            "",
            f"remote {server_info['ip_address']} {server_info['port']} # {server_info['hostname']} in {server_info['location']}",
            f"proto {server_info['proto']}",
            f"verify-x509-name {server_info['hostname'].split('.')[0]} name",
        ]
    )

    if "resolv-retry" not in provider_option_keys:
        lines.append("resolv-retry infinite")
    if "remote-cert-tls" not in provider_option_keys:
        lines.append("remote-cert-tls server")
    if "auth-nocache" not in provider_option_keys:
        lines.append("auth-nocache")

    if provider_option_lines:
        lines.append("")
        lines.append("# BEGIN PROVIDER OPTIONS")
        lines.extend(provider_option_lines)
        lines.append("# END PROVIDER OPTIONS")

    if excluded_routes:
        lines.append("")
        lines.append("# BEGIN EXCLUDE ROUTES")
        lines.extend(excluded_routes.splitlines())
        lines.append("# END EXCLUDE ROUTES")

    lines.extend(
        [
            "",
            f"ca {paths['ca_cert_file']}",
            f"cert {paths['client_bundle_file']}",
            f"key {paths['client_bundle_file']}",
        ]
    )

    if config.get("user"):
        lines.append(f"user {config['user']}")
    if config.get("group"):
        lines.append(f"group {config['group']}")

    extra_config = str(server_info["extra_config"]).strip()
    if extra_config:
        lines.append("")
        lines.append(extra_config)

    return "\n".join(lines).strip() + "\n"


def generate_configuration(config: dict[str, Any], paths: dict[str, Path]) -> None:
    for path in (paths["ca_cert_file"], paths["client_bundle_file"]):
        if not path.exists():
            logging.error(f"File ({path}) not found. You can get it by using --update")
            sys.exit(1)

    server_info = get_server_info(config, paths)
    config_text = build_openvpn_config(config, paths, server_info)
    atomic_write_text(paths["ovpn_file"], config_text)
    logging.info(f"Successfully saved Bitmask/OpenVPN configuration file to {paths['ovpn_file']}")


def get_systemctl_state(service_unit: str) -> str:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_unit],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout.strip() or "unknown"
    except OSError as exc:
        return f"unavailable ({exc})"


def show_status(config: dict[str, Any], provider: dict[str, Any], paths: dict[str, Path]) -> None:
    logging.info(f"Provider: {provider['id']} ({provider['name']})")
    logging.info(f"Service unit: {get_service_unit(config)}")
    logging.info(f"Service state: {get_systemctl_state(get_service_unit(config))}")
    logging.info(f"Configured server: {config['server']} {config['protocol']}/{config['port']}")

    if paths["ca_cert_file"].exists():
        logging.info("CA certificate: OK")
    else:
        logging.warning("CA certificate not found. You can get it with --update")

    if paths["key_file"].exists():
        logging.info("Client key: OK")
    else:
        logging.warning("Client key not found. You can get it with --update")

    if paths["client_bundle_file"].exists():
        logging.info("Combined client PEM bundle: OK")
    else:
        logging.warning("Combined client PEM bundle not found. You can get it with --update")

    if not paths["cert_file"].exists():
        logging.warning("Client certificate not found. You can get it with --update")
    elif decoder is None or pem is None or rfc2459 is None:
        logging.warning("pyasn1 is not installed, so certificate validity details are unavailable")
    else:
        with paths["cert_file"].open() as handle:
            substrate = pem.readPemFromFile(handle)
            cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
        not_before = next(cert["tbsCertificate"]["validity"]["notBefore"].values()).asDateTime
        not_after = next(cert["tbsCertificate"]["validity"]["notAfter"].values()).asDateTime
        logging.info(
            "Client certificate is valid from %s to %s",
            not_before.strftime("%d.%m.%Y"),
            not_after.strftime("%d.%m.%Y"),
        )

    if paths["gateway_json"].exists():
        logging.info("VPN gateway list: OK")
    else:
        logging.warning("VPN gateway list not found. You can get it with --update")

    if paths["ovpn_file"].exists():
        logging.info(f"VPN configuration ({paths['ovpn_file']}): OK")
    else:
        logging.warning(f"VPN configuration ({paths['ovpn_file']}) not found. You can get it with --generate-config")

    openvpn_found = False
    for process in psutil.process_iter():
        if "openvpn" in process.name():
            openvpn_found = True
            logging.info(f"Found a running openvpn process: '{' '.join(process.cmdline())}' with pid {process.pid}")
    if not openvpn_found:
        logging.warning("No running openvpn process found")

    try:
        response = requests.get("https://api4.ipify.org?format=json", timeout=5)
        response.raise_for_status()
        logging.info(f"Your IPv4 address: {response.json()['ip']}")
    except requests.RequestException as exc:
        logging.warning(f"Error finding your public IPv4 address: {exc}")


def save_config(config: dict[str, Any]) -> None:
    atomic_write_text(CONFIG_FILE, yaml.safe_dump(config, sort_keys=False))


def rotate_gateway(
    config: dict[str, Any],
    paths: dict[str, Path],
    target_server: Optional[str],
    benchmark: bool,
) -> dict[str, Any]:
    gateway_inventory = load_gateways(paths)
    gateways = [gateway for gateway in gateway_inventory["gateways"] if get_openvpn_transports(gateway)]
    current_server = str(config["server"])

    if target_server:
        gateway = get_gateway_by_name(gateways, target_server)
        if gateway is None:
            logging.error(f"Gateway '{target_server}' not found in gateway list.")
            sys.exit(1)
        selected = gateway
    else:
        candidates = [gateway for gateway in gateways if gateway["host"] != current_server]
        if not candidates:
            logging.error("No alternative gateways are available for rotation.")
            sys.exit(1)
        if benchmark:
            for gateway in candidates:
                gateway["rtt"] = get_rtt(gateway["ip_address"])
            selected = sorted(candidates, key=lambda gateway: (gateway["rtt"], gateway["host"]))[0]
        else:
            ordered = sorted(gateways, key=lambda gateway: gateway["host"])
            current_index = next(
                (index for index, gateway in enumerate(ordered) if gateway["host"] == current_server),
                -1,
            )
            selected = ordered[(current_index + 1) % len(ordered)]
            if selected["host"] == current_server:
                logging.error("No alternative gateways are available for rotation.")
                sys.exit(1)

    protocol, port = choose_transport(selected, str(config["protocol"]), int(config["port"]))
    config["server"] = selected["host"]
    config["protocol"] = protocol
    config["port"] = port
    save_config(config)
    logging.info(
        "Rotated gateway to %s (%s %s/%s)",
        selected["host"],
        selected["location"],
        protocol,
        port,
    )
    return config


def uninstall(config: dict[str, Any], paths: dict[str, Path]) -> NoReturn:
    for path in (paths["state_dir"], CONFIG_FILE, paths["ovpn_file"]):
        try:
            if path.is_file():
                path.unlink()
                logging.info(f"Deleted file {path}")
            else:
                shutil.rmtree(path)
                logging.info(f"Deleted directory {path}")
        except FileNotFoundError:
            continue
    sys.exit(0)


def print_error_log(config: dict[str, Any]) -> None:
    service_unit = get_service_unit(config)
    logging.info("Printing debug log")
    try:
        process = subprocess.run(
            ["journalctl", "-u", service_unit, "-n", "50"],
            capture_output=True,
            text=True,
            check=False,
        )
        logging.info(process.stdout)
    except OSError as exc:
        logging.error(f"Could not get logs for {service_unit}: {exc}")


def run_systemctl(config: dict[str, Any], *args: str) -> None:
    service_unit = get_service_unit(config)
    try:
        subprocess.run(
            ["systemctl", *args, service_unit],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        logging.error(f"Could not run systemctl {' '.join(args)} for {service_unit}: {exc}")
        print_error_log(config)
        sys.exit(1)


def start_openvpn(config: dict[str, Any]) -> None:
    run_systemctl(config, "start")
    logging.info("VPN successfully started")


def stop_openvpn(config: dict[str, Any]) -> None:
    run_systemctl(config, "stop")
    logging.info("VPN successfully stopped")


def reload_openvpn(config: dict[str, Any]) -> None:
    run_systemctl(config, "reload-or-restart")
    logging.info("VPN successfully reloaded")


def show_version() -> NoReturn:
    from importlib.metadata import version

    logging.info(f"Running {APP_NAME} v{version(APP_NAME)}")
    sys.exit(0)


def update_all_material(config: dict[str, Any], provider: dict[str, Any], paths: dict[str, Path]) -> None:
    update_provider_metadata(config, provider, paths)
    update_vpn_ca_certificate(config, provider, paths)
    update_gateways(config, provider, paths)
    update_vpn_client_credentials(config, provider, paths)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true", help="show verbose output")
    parser.add_argument("--no-check-certificate", action="store_true", help="deprecated and ignored")
    parser.add_argument("-d", "--default-config", action="store_true", help="print default config file riseup-vpn.yaml")
    parser.add_argument("-u", "--update", action="store_true", help="update provider metadata, gateway list, and client certificate/key")
    parser.add_argument("--uninstall", action="store_true", help="remove generated state, config, and OpenVPN files")
    parser.add_argument("-l", "--list-gateways", action="store_true", help="show available VPN servers for the configured provider")
    parser.add_argument("-p", "--list-providers", action="store_true", help="show built-in Bitmask providers")
    parser.add_argument("-b", "--benchmark", action="store_true", help="use with --list-gateways or --rotate to measure latency")
    parser.add_argument("-c", "--check-config", action="store_true", help=f"check syntax of {CONFIG_FILE}")
    parser.add_argument("-g", "--generate-config", action="store_true", help="generate the OpenVPN client configuration")
    parser.add_argument("-s", "--status", action="store_true", help="show the current state of the configured VPN")
    parser.add_argument("--start", action="store_true", help="start the OpenVPN systemd unit")
    parser.add_argument("--stop", action="store_true", help="stop the OpenVPN systemd unit")
    parser.add_argument("--restart", action="store_true", help="restart the OpenVPN systemd unit")
    parser.add_argument("--reload", action="store_true", help="regenerate the OpenVPN configuration and reload or restart the unit")
    parser.add_argument("--rotate", action="store_true", help="switch to another gateway and reload or restart the unit")
    parser.add_argument("--target-server", help="gateway hostname to use with --rotate")
    parser.add_argument("--log", action="store_true", help="show systemd log")
    parser.add_argument("--version", action="store_true", help="show version")

    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.no_check_certificate:
        logging.warning("--no-check-certificate is deprecated and ignored")

    if args.version:
        show_version()
    if args.default_config:
        print_default_config(0)
    if args.list_providers:
        list_providers()
        return

    check_root_permissions()
    config = read_config()
    provider = resolve_provider(config)
    paths = ensure_runtime_directories(config)

    if args.uninstall:
        uninstall(config, paths)

    if args.update:
        update_all_material(config, provider, paths)
    elif args.check_config:
        check_config_file()
    elif args.list_gateways:
        check_config_file()
        list_gateways(config, paths, args.benchmark)
    elif args.generate_config:
        check_config_file()
        generate_configuration(config, paths)
    elif args.status:
        check_config_file()
        show_status(config, provider, paths)
    elif args.start:
        start_openvpn(config)
    elif args.stop:
        stop_openvpn(config)
    elif args.restart:
        stop_openvpn(config)
        start_openvpn(config)
    elif args.reload:
        check_config_file()
        generate_configuration(config, paths)
        reload_openvpn(config)
    elif args.rotate:
        check_config_file()
        config = rotate_gateway(config, paths, args.target_server, args.benchmark)
        generate_configuration(config, paths)
        reload_openvpn(config)
    elif args.log:
        print_error_log(config)


if __name__ == "__main__":
    main()
