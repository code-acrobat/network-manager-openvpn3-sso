# AGENTS.md

NetworkManager VPN plugin (Rust binary `nm-openvpn3-sso-service`) that drives the
**OpenVPN 3 Linux** daemons over the system D-Bus instead of spawning an
openvpn2 process. Spawned by NetworkManager as root on VPN activation; talks the
NM VPN plugin D-Bus protocol back to NM.

This is a hard fork of `quinnjr/network-manager-openvpn-sso` (openvpn2
management-interface backend). The shared surface with upstream is `dbus.rs`,
`config.rs` and packaging; everything else diverged. Save divergence notes here
as you work.

## Layout

```
Cargo.toml            bin nm-openvpn3-sso-service; deb metadata (cargo-deb; Depends openvpn3)
data/
  *.name              NM plugin discovery file (/usr/lib/NetworkManager/VPN/) —
                      name=openvpn3-sso, service=…openvpn3-sso, program=/usr/lib/nm-openvpn3-sso-service
  *.conf              dbus-broker config allowing root to own the bus name
  vpn-sso-connect.sh  user-side helper: nmcli import + set vpn.service-type
plasma-nm-plugin/     KDE Plasma VPN config UI (unchanged from upstream, untouched)
docs/                 marketing/landing pages (GitHub Pages via .github/workflows/pages.yml)
.github/workflows/
  ci.yml              Test, Check, Rustfmt, Clippy (-D warnings), Build, Plasma build
  release.yml         on tag v*: builds + publishes the deb as a release artifact
  pages.yml           docs/ to GitHub Pages
install.sh / uninstall.sh / PKGBUILD
```

## Source map (src/)

| File | Role |
|---|---|
| `main.rs` | tokio main: tracing to journald (tag `nm-openvpn3-sso-service`) or stderr, then `dbus::run_service()` |
| `dbus.rs` | NM VPN plugin D-Bus service: system bus, `org.freedesktop.NetworkManager.openvpn3-sso`, object `/org/freedesktop/NetworkManager/VPN/Plugin`, interface `…VPN.Plugin`. Parses NM settings via `config.rs`, responds to `connect`/`connect_interactive`/`disconnect`/`need_secrets` (zero-touch), consumes `VpnEvent`s from the backend manager and **emits the NM signals**: `Config` (must contain `gateway` = external VPN gateway — NM's `_config_process_generic` hard-fails without it), `Ip4Config` (`address`, `prefix` from netmask, `int-gw`, `dns`, `never-default` so the tunnel is not made the system default), `StateChanged`, `Failure` |
| `config.rs` | `ConnectionConfig::from_nm_settings` — reads NM's `connection`/`vpn` settings; `raw_data` keeps all `vpn.data` key/value pairs. Fragments (ca/cert/key/tls-crypt paths + remote list + directives) feed profile synthesis in `openvpn3.rs`. Unit tests live here |
| `openvpn3.rs` | The OpenVPN 3 backend (`OpenVpn3Manager`) + all shared types (`VpnEvent`, `VpnState`, `VpnConfig`). Flow: read/synthesize profile → configmgr `Import` (single_use) + `SetOverride dns-setup-disabled` → disconnect stale sessions → sessionmgr `NewTunnel` → `Ready()` loop (45×1 s) → `Connect` → watch `StatusChange` (5 s poll fallback: v20 may not re-emit signals) → auth-URL attention opens the user's browser → on `(2,7)` collect device/IP/netmask/gateway/DNS → `VpnEvent::Connected`. Also: status-code constants (from openvpn3 `constants.py`), `find_graphical_session`/`open_in_browser` (capability-free runtime-dir env discovery; NM drops CAP_SYS_PTRACE so /proc scanning is impossible), `NetCfgParser` for the netcfg `network_config` prop, `scrape_tun_address` fallback, status-watchdog (90 s normal / 600 s auth phase) |

## openvpn3 D-Bus cheat sheet

- Services: `net.openvpn.v3.{sessions,configuration,netcfg,log,backends}` — session objects at `/net/openvpn/v3/sessions/<uuid-dashes-to-s>`
- Status = `(major, minor, txt)`: CONNECTION majors 2 (7=connected), SESSION major 3 (22 = SSO auth URL attention)
- v20 quirks: session has **no** `connected_to`/`connected` props; `device_path` is a plain string, not an object path; `set_property("log_verbosity")` pre-ready hard-crashes sessionmgr; `Disconnect()` removes the session object; ONE session per config path
- openvpn3 netcfg **always owns** device/IP/routes/DNS on the kernel side — no handoff to NM (that's why `dns-setup-disabled` override stays on and `never-default` is set)

## Conventions / tribal knowledge

- Author identities: run `~/bin/tnggitauthor` in the repo before committing; keep commit history clean of personal endpoints — the fork publishes to @code-acrobat for anyone.
- openvpn3 Linux D-Bus API docs: Codeberg OpenVPN/openvpn3-linux; runtime introspection on the live system: `busctl --system tree net.openvpn.v3.sessions`, `openvpn3 sessions-list`
- Test/verification on this system: bump `version` in `Cargo.toml` before each `cargo deb` build, run `sudo -n apt install ~/Schreibtisch/workspace/network-manager-openvpn-sso/target/debian/<deb>` and always `sudo -n /usr/bin/pkill -f nm-openvpn3-sso-"service"` after install to prevent an old plugin daemon from holding the D-Bus name. This reference is here as a private note; it does not ship in any packaged artifact.
- `vpn.data 'config'` (direct profile path) vs fragments (post `nmcli connection import`): synthesis covers fragments; changing one side usually means changing the other
- NM may call `connect` twice; dedupe the browser open (5 s window in `open_in_browser`)

## Housekeeping

- Don't retain personal micro-details in external trackers; write durable decisions into your local memory store.
- Physical cleanup on wrap-up of a test session (contains private key material): `sudo rm /etc/sudoers.d/nm-openvpn3-sso-test` and `rm /tmp/opencode/profile-synth.ovpn`.
