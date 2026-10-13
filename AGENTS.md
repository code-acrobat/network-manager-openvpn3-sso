# AGENTS.md

NetworkManager VPN plugin (Rust binary `nm-openvpn3-sso-service`) driving the **OpenVPN 3 Linux** daemons over the system D-Bus (no openvpn2 process). Spawned by NM as root on VPN activation; speaks the NM VPN plugin D-Bus protocol back to NM.

Hard fork of `quinnjr/network-manager-openvpn-sso`. Shared surface with upstream: `dbus.rs`, `config.rs`, packaging — everything else diverged.

## Layout

```
Cargo.toml            bin nm-openvpn3-sso-service; cargo-deb metadata (Depends openvpn3)
data/                 NM plugin discovery (*.name), dbus-bus policy, nmcli helper script
plasma-nm-plugin/     KDE Plasma VPN config UI (unchanged from upstream)
docs/                 landing page (GitHub Pages via pages.yml)
.github/workflows/    ci.yml (Test, Check, Rustfmt, Clippy -D warnings, Build, Plasma) · release.yml (tag v* → deb release) · pages.yml
install.sh / uninstall.sh / PKGBUILD
```

## Source map (src/)

| File | Role |
|---|---|
| `main.rs` | tokio main: tracing → journald (tag `nm-openvpn3-sso-service`), then `dbus::run_service()` |
| `dbus.rs` | NM plugin D-Bus service (`org.freedesktop.NetworkManager.openvpn3-sso`, interface `…VPN.Plugin`): `connect`/`disconnect`/`need_secrets` (zero-touch), consumes `VpnEvent`s, emits NM signals — `Config` must contain `gateway` (external VPN gateway; NM hard-fails without it), `Ip4Config` with `never-default` so the tunnel is not the system default |
| `config.rs` | `ConnectionConfig::from_nm_settings`: reads NM `connection`/`vpn` settings; `raw_data` keeps all `vpn.data` pairs. Fragment parsing feeds profile synthesis. Unit tests |
| `openvpn3.rs` | OpenVPN 3 backend (`OpenVpn3Manager`) + shared types (`VpnEvent`, `VpnState`, `VpnConfig`). Owns profile synthesis from fragments (0600 under `/var/lib/nm-openvpn3-sso`), configmgr Import + stale-session cleanup, NewTunnel → Ready → Connect, status watch with 5 s poll fallback, SSO auth-URL → browser open (capability-free graphical-session discovery; NM drops CAP_SYS_PTRACE), config collection after connect |

## openvpn3 D-Bus cheat sheet

- Services `net.openvpn.v3.{sessions,configuration,netcfg,log,backends}`; sessions at `/net/openvpn/v3/sessions/<uuid-dashes-to-s>`
- Status `(major, minor, txt)`: major 2 CONNECTION (7 = connected), major 3 SESSION (22 = SSO auth URL)
- v20 quirks: no `connected_to` prop; `device_path` is a string, not an object path; `set_property("log_verbosity")` pre-ready crashes sessionmgr; `Disconnect()` removes the session; one session per config path
- openvpn3 netcfg always owns device/IP/routes/DNS — no handoff to NM (hence `dns-setup-disabled` override + `never-default`)

## Conventions

- Commit identity: run `~/bin/tnggitauthor` before committing; no personal endpoints anywhere.
- Test cycle: bump `version` in `Cargo.toml` before each `cargo deb` (apt skips same versions), and always pkill the stale plugin daemon after installing — NM (KillMode=process) lets it linger, and it keeps the D-Bus name.
- NM may call `connect` twice; browser open is deduped (5 s window in `open_in_browser`).
- openvpn3 D-Bus API source: Codeberg OpenVPN/openvpn3-linux; live introspection: `busctl --system tree net.openvpn.v3.sessions`, `openvpn3 sessions-list`.
