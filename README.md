# NetworkManager OpenVPN 3 SSO Plugin

A NetworkManager VPN plugin that drives the **OpenVPN 3 Linux client** and adds browser-based Single Sign-On (SSO) support for server-driven web authentication.

This is a hard fork of [`quinnjr/network-manager-openvpn-sso`](https://github.com/quinnjr/network-manager-openvpn-sso), reworked to talk to the OpenVPN 3 Linux D-Bus services instead of spawning an `openvpn` 2.x process. Many thanks to [Joseph R. Quinn](https://github.com/quinnjr) for the original NetworkManager integration and the Plasma UI plugin.

[![CI](https://github.com/code-acrobat/network-manager-openvpn3-sso/actions/workflows/ci.yml/badge.svg)](https://github.com/code-acrobat/network-manager-openvpn3-sso/actions/workflows/ci.yml)
[![Release](https://github.com/code-acrobat/network-manager-openvpn3-sso/actions/workflows/release.yml/badge.svg)](https://github.com/code-acrobat/network-manager-openvpn3-sso/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/LICENSE-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **OpenVPN 3 backend** - Sessions run through the openvpn3-linux services (configuration manager, session manager, netcfg) instead of spawning an `openvpn` 2.x process
- **Browser-based SSO authentication** - On the server's auth-URL attention the plugin opens your default browser; you complete the login (including any second factor at the identity provider) and the backend finishes the handshake by itself
- **Profile synthesis** - Works both with an intact `config`-style profile and with the fragment form `nmcli connection import type openvpn` produces (NM splits inline certs into files; the plugin reassembles an equivalent profile for the OpenVPN 3 configuration manager)
- **NetworkManager-aware IP config** - Relays the tunnel device, address, prefix, and internal gateway to NM; marks the tunnel `never-default` so NM does not hijack the system default route or DNS
- **Full NetworkManager integration** - Works with NetworkManager and network applets

## Installation

### Debian / Ubuntu

```bash
sudo dpkg -i networkmanager-openvpn3-sso_${VERSION}_amd64.deb
sudo apt-get install -f  # Install any missing dependencies
```

Depends on the `openvpn3` package (openvpn3-linux ≥ 20).

### Fedora / RHEL / CentOS

```bash
sudo dnf install networkmanager-openvpn3-sso-${VERSION}.x86_64.rpm
```

### Arch Linux

```bash
sudo pacman -U networkmanager-openvpn3-sso-${VERSION}-x86_64.pkg.tar.zst
```

## Usage

### Importing an OpenVPN Configuration

1. Import your `.ovpn` file using NetworkManager:

```bash
nmcli connection import type openvpn file your-vpn-config.ovpn
```

2. Modify the connection to use the SSO plugin:

```bash
# Get the connection name
nmcli connection show | grep vpn

# Update to use SSO plugin
nmcli connection modify "your-vpn-name" vpn.service-type org.freedesktop.NetworkManager.openvpn3-sso
```

3. Connect to the VPN:

```bash
nmcli connection up "your-vpn-name"
```

Your default browser opens for the SSO login. Complete the authentication in the browser (including any second factor at the identity provider) and the VPN connection is established automatically.

### Using with Network Manager GUI

#### GNOME

The VPN connection will appear in your system's network settings and can be activated from there. When connecting, your browser will open for authentication.

#### KDE Plasma

This project includes a native **plasma-nm UI plugin** that integrates directly with KDE Plasma's network applet. When installed, you can:

- Create, configure, and manage OpenVPN SSO connections from Plasma's network settings
- Import `.ovpn` files directly through the Plasma UI
- Connect and disconnect from the system tray network applet

The plugin is built automatically during installation if KDE dependencies are available.

**If the plugin is not installed**, you can still use:

1. **Command line**: `nmcli connection up "your-vpn-name"`
2. **nm-connection-editor**: GTK-based GUI that works on KDE
3. **vpn-sso-connect**: Helper script with KDialog integration (installed with this package)

## Requirements

- NetworkManager
- **openvpn3** (openvpn3-linux; the plugin talks to its D-Bus services)
- D-Bus
- A graphical session (for browser-based authentication)

## Building from Source

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install build-essential pkg-config

# Fedora
sudo dnf install gcc pkgconf
```

The build is pure Rust (no system D-Bus/OpenSSL dev packages needed).

### Build

```bash
git clone https://github.com/code-acrobat/network-manager-openvpn3-sso.git
cd network-manager-openvpn3-sso
cargo build --release
```

### Install

```bash
sudo ./install.sh
```

### Uninstall

```bash
sudo ./uninstall.sh
```

## Configuration

The plugin synthesizes its profile into `/var/lib/nm-openvpn3-sso/<uuid>.ovpn` (file mode `0600`, it contains the client's private key) when the NM connection arrives as fragments. OpenVPN 3's netcfg owns the tun device, addresses, routes and kernel-level DNS: the plugin does not take that over — it only reports the resulting configuration to NetworkManager and asks NM not to treat the tunnel as the system default route (`never-default`), so DNS and default routing stay with your underlying network unless the VPN server pushes specific routes.

Credentials for the SSO flow are handled by the OpenVPN 3 backend and the browser; this plugin stores nothing.

## Troubleshooting

### Browser doesn't open

The plugin (spawned by NetworkManager as root) has no desktop session environment. It derives the graphical session from the filesystem and opens the URL in the user's browser, preferring `xdg-desktop-portal` (invoked as the desktop user, via the session bus — it works even when the plugin's own environment can't reach the desktop session) and falling back to `xdg-open` run as the desktop user. Every attempt — success or failure — is logged, so check:

```bash
journalctl -t nm-openvpn3-sso-service -f
```

### Connection times out

Check the NetworkManager logs for details:

```bash
journalctl -u NetworkManager -f
```

The OpenVPN 3 side has its own log:

```bash
openvpn3 log --config <name>.ovpn
```

### VPN connects but no network access

Verify that the VPN routes were applied:

```bash
ip route | grep tun
```

Note: the plugin intentionally does **not** make the tunnel the system default route. If you need everything routed into the VPN, that must come from the server's pushed route list.

## How It Works

1. NetworkManager activates the VPN connection and spawns `nm-openvpn3-sso-service`
2. The plugin rebuilds (or reads) the OpenVPN profile and imports it into the OpenVPN 3 configuration manager (`net.openvpn.v3.configuration`)
3. It creates a session (`net.openvpn.v3.sessions`) and drives it: `Ready()` → `Connect()` → status/signal watching (with a property-poll fallback — openvpn3 v20 does not reliably re-emit connected/disconnected signals)
4. On the server's auth-URL attention the plugin opens your browser; after you authenticate, the backend completes the handshake on its own
5. Once connected, the plugin collects the tunnel configuration from the session and netcfg device and sends `Config` / `Ip4Config` signals to NetworkManager

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

- [GitHub Issues](https://github.com/code-acrobat/network-manager-openvpn3-sso/issues)

---

Hard fork of [quinnjr/network-manager-openvpn-sso](https://github.com/quinnjr/network-manager-openvpn-sso), ported to the OpenVPN 3 Linux client. Many thanks to [Joseph R. Quinn](https://github.com/quinnjr) for the original plugin and the Plasma UI. MIT License — see [LICENSE](LICENSE).
