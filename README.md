# dmemcg-booster

Fork of Valve's [dmemcg-booster daemon](https://gitlab.steamos.cloud/holo/dmemcg-booster), adapted to target OpenRC environments.

## OpenRC Split Architecture

This fork supports split roles to work on OpenRC systems:

- `daemon` mode: privileged process that manages cgroups and limits.
- `agent` mode: user-session process that tracks focused windows (Hyprland) and reports focus to the daemon.

### Daemon mode (root)

Run as root (typically via OpenRC):

```bash
dmemcg-booster --mode daemon --poll-only \
  --socket-path /run/dmemcg-booster/focus.sock \
  --socket-owner-uid 1001 \
  --socket-mode-octal 0600
```

### Agent mode (user session)

Run as the desktop user inside your graphical session:

```bash
dmemcg-booster --mode agent --focus-provider=hyprland --socket-path /run/dmemcg-booster/focus.sock
```

The agent resends the current focus sample on a heartbeat, even if focus metadata did not change, so late-spawned child processes can still be migrated.

## Filter Layer (game targeting)

The daemon will not boost every focused app by default unless you explicitly allow that.

- Safe default: if no allow rules are configured, nothing is boosted.
- Matching is case-insensitive substring-based.

### CLI filter rules

- `--allow-class <text>`
- `--allow-exe <text>`
- `--allow-title <text>`
- `--allow-app <text>`
- `--deny-class <text>`
- `--deny-exe <text>`
- `--deny-title <text>`
- `--deny-app <text>`
- `--allow-all-focused` (opt-in fallback behavior)

Example:

```bash
dmemcg-booster --mode daemon --poll-only \
  --allow-exe steam \
  --allow-exe gamescope \
  --allow-class steam_app
```

### Config path

Use `--filter-config` with either:
- a single file path (for example `/etc/dmemcg-booster/nx-default-boost.conf`), or
- a directory path (for example `/etc/dmemcg-booster`).

When a directory is used, all regular files in that directory are loaded in lexicographic order.
If overlapping/conflicting values are found, the daemon logs an error with file and line, and keeps the first definition.

Example config:

```ini
# allow rules
allow_exe=steam,gamescope,wine,umu
allow_class=steam_app
allow_title=elden ring

# deny rules
deny_class=firefox
```

## OpenRC Service

An example OpenRC service script is included as `openrc/dmemcg-booster`.

Typical installation:

```bash
install -D -m 0755 openrc/dmemcg-booster /etc/init.d/dmemcg-booster
install -m 0644 openrc/conf.d/dmemcg-booster.conf /etc/conf.d/dmemcg-booster
mkdir -p /etc/dmemcg-booster
# place your filter files in /etc/dmemcg-booster/
# set DMEMCG_AGENT_UID to your desktop user's uid in /etc/conf.d/dmemcg-booster
rc-update add dmemcg-booster default
rc-service dmemcg-booster start
```

## Notes

- On OpenRC, start `agent` from the user session (autostart, WM startup, etc.).
- `standalone` mode also exists for single-process usage/testing.
- Socket hardening controls:
`--socket-mode-octal` sets socket permissions (octal). Modes with any "other" permissions are rejected.
- Daemon IPC accepts focus updates only from connections whose peer uid matches `--socket-owner-uid` (Linux), and focused target pids must also match that uid when --socket-owner-uid is set.”
- Agent heartbeat control:
`--agent-heartbeat-ms` sets the resend interval for unchanged focus samples.

# Issues

If you find problems with the contents of this repository, please create an issue and use the **🐞 Bug report** template.

## Submitting a bug report

Before submitting a bug, you should look at the [existing bug reports](https://github.com/Nitrux/dmemcg-booster/issues) to verify that no one has reported the bug already.

©2026 Valve Corporation<br>
©2026 Nitrux Latinoamericana S.C.
