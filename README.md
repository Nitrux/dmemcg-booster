# dmemcg-booster

Fork of Valve's [dmemcg-booster daemon](https://gitlab.steamos.cloud/holo/dmemcg-booster), adapted to target OpenRC environments.

For more in-depth information about dmemcg-booster, please see the [Wiki](https://github.com/Nitrux/dmemcg-booster/wiki).

## OpenRC Split Architecture

This fork supports split roles to work on OpenRC systems:

- `daemon` mode: privileged process that manages cgroups and limits.
- `agent` mode: user-session process that tracks focused windows (Hyprland) and reports focus to the daemon.

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
