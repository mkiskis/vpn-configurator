[![tests](https://github.com/mkiskis/vpn-configurator/actions/workflows/tests.yaml/badge.svg?branch=main)](https://github.com/mkiskis/vpn-configurator/actions/workflows/tests.yaml)
![license](https://img.shields.io/github/license/mkiskis/vpn-configurator?color=green)
![latest tag](https://img.shields.io/github/v/tag/mkiskis/vpn-configurator?sort=semver)

# riseup-vpn-configurator

`riseup-vpn-configurator` is now a small Bitmask-compatible OpenVPN configurator for servers and headless Linux systems.

It keeps the original CLI-driven workflow, but adds:

- built-in support for the known Bitmask providers: `riseup`, `calyx`, and `demo`
- manual gateway selection across provider inventories
- live `reload` and `rotate` commands for running `openvpn-client@<service>`
- optional CA pinning and provider-specific API verification
- safer defaults for runtime state and generated file permissions

## What it manages

- `/etc/riseup-vpn.yaml`
- `/var/lib/riseup-vpn-configurator`
- `/etc/openvpn/client/<service_name>.conf`
- `openvpn-client@<service_name>.service`

## Installation

Install as root so the package writes its config, cert, key, and OpenVPN client files with the intended permissions:

```bash
sudo pip install riseup-vpn-configurator
```

Or for development:

```bash
git clone https://github.com/mkiskis/vpn-configurator.git
cd riseup-vpn-configurator
sudo poetry install
sudo poetry run riseup-vpn-configurator --help
```

## Commands

```bash
usage: riseup-vpn-configurator [-h] [-v] [--no-check-certificate] [-d] [-u] [--uninstall] [-l] [-p] [-b] [-c] [-g] [-s] [--start] [--stop] [--restart] [--reload] [--rotate] [--target-server TARGET_SERVER] [--log] [--version]
```

Useful flows:

```bash
# show built-in providers
sudo riseup-vpn-configurator --list-providers

# fetch CA, gateway inventory, and short-lived client credentials
sudo riseup-vpn-configurator --update

# inspect gateways for the configured provider
sudo riseup-vpn-configurator --list-gateways
sudo riseup-vpn-configurator --list-gateways --benchmark

# generate or refresh the OpenVPN client config
sudo riseup-vpn-configurator --generate-config
sudo riseup-vpn-configurator --reload

# rotate to another gateway and reload the running unit
sudo riseup-vpn-configurator --rotate
sudo riseup-vpn-configurator --rotate --benchmark
sudo riseup-vpn-configurator --rotate --target-server vpn02-par.riseup.net

# start on boot
sudo systemctl enable openvpn-client@riseup
sudo systemctl start openvpn-client@riseup
```

## Default config

Default config file: `/etc/riseup-vpn.yaml`

```yaml
---
provider: riseup
service_name: riseup
server: vpn07-par.riseup.net
protocol: udp
port: 53
state_dir: /var/lib/riseup-vpn-configurator
excluded_routes:
  - 8.8.8.8
  - 192.168.123.0/24
user: nobody
group: nogroup
verify_ca_fingerprint: false
extra_config: |
  # empty extra_config
```

### Provider overrides

If you want to use a custom Bitmask-compatible provider, keep `provider` set to any label you want and add explicit overrides:

```yaml
provider: custom
service_name: custom
api_uri: https://api.example.net:4430
vpn_api_version: 3
gateway_api_url: https://api.example.net:4430/3/config/eip-service.json
client_credentials_url: https://api.example.net:4430/3/cert
ca_cert_url: https://example.net/ca.crt
ca_cert_fingerprint: SHA256: ...
```

## Security and ops notes

- CA fingerprint verification is disabled by default, but can be re-enabled per config.
- Gateway and client credential API calls are verified against the fetched provider CA, which helps with private provider PKI setups.
- The `/3/cert` response is preserved as a combined PEM bundle and used directly for OpenVPN `cert` and `key`.
- Generated certs, keys, and OpenVPN config files are written atomically with restrictive permissions.
- `--reload` uses `systemctl reload-or-restart`, so config changes can be applied to a running VPN unit without a separate manual restart step.
- Client certificates are short-lived by design; this tool does not try to keep long-lived persistent sessions alive forever.

## Known limitations

- This tool still targets Linux and `systemd`.
- Gateway rotation is manual or operator-triggered; it does not continuously rebalance in the background.
- Firewall or kill-switch management is intentionally out of scope here. Pair it with host firewall policy if you need that control plane.
