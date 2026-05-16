use crate::cgroup::{CGroup, DMemLimit};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::{chown, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dbus::blocking::Connection;

mod cgroup;

const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const DEFAULT_FOCUS_REFRESH_MS: u64 = 2000;
const DEFAULT_FOCUS_STALE_TIMEOUT_MS: u64 = 5000;
const DEFAULT_AGENT_HEARTBEAT_MS: u64 = 1500;
const DEFAULT_DEDICATED_CGROUP_NAME: &str = "dmemcg-booster.focused";
const DEFAULT_SOCKET_PATH: &str = "/run/dmemcg-booster/focus.sock";
const DEFAULT_SOCKET_MODE: u32 = 0o660;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModeSelection {
    Daemon,
    Agent,
    Standalone,
}

#[derive(Clone, Copy)]
enum FocusProviderSelection {
    Auto,
    Hyprland,
    None,
}

#[derive(Clone, Debug)]
struct FocusSample {
    pid: Option<u32>,
    class: Option<String>,
    title: Option<String>,
    app: Option<String>,
}

#[derive(Default)]
struct GameFilter {
    allow_all_focused: bool,
    allow_classes: Vec<String>,
    allow_execs: Vec<String>,
    allow_titles: Vec<String>,
    allow_apps: Vec<String>,
    deny_classes: Vec<String>,
    deny_execs: Vec<String>,
    deny_titles: Vec<String>,
    deny_apps: Vec<String>,
}

impl GameFilter {
    fn from_args(args: &Args) -> Self {
        let mut filter = Self {
            allow_all_focused: args.allow_all_focused,
            allow_classes: normalize_rules(&args.allow_classes),
            allow_execs: normalize_rules(&args.allow_execs),
            allow_titles: normalize_rules(&args.allow_titles),
            allow_apps: normalize_rules(&args.allow_apps),
            deny_classes: normalize_rules(&args.deny_classes),
            deny_execs: normalize_rules(&args.deny_execs),
            deny_titles: normalize_rules(&args.deny_titles),
            deny_apps: normalize_rules(&args.deny_apps),
        };

        if let Some(path) = &args.filter_config {
            apply_filter_file(path, &mut filter);
        }

        filter
    }

    fn matches(&self, sample: &FocusSample, process: &ProcessInfo) -> bool {
        let class = sample.class.as_deref().map(normalize_value).unwrap_or_default();
        let title = sample.title.as_deref().map(normalize_value).unwrap_or_default();
        let app = sample.app.as_deref().map(normalize_value).unwrap_or_default();
        let exe = normalize_value(process.exe.as_str());

        if matches_any(&self.deny_classes, class.as_str())
            || matches_any(&self.deny_titles, title.as_str())
            || matches_any(&self.deny_apps, app.as_str())
            || matches_any(&self.deny_execs, exe.as_str())
        {
            return false;
        }

        if self.allow_all_focused {
            return true;
        }

        let has_allow_rules = !(self.allow_classes.is_empty()
            && self.allow_titles.is_empty()
            && self.allow_apps.is_empty()
            && self.allow_execs.is_empty());

        if !has_allow_rules {
            return false;
        }

        matches_any(&self.allow_classes, class.as_str())
            || matches_any(&self.allow_titles, title.as_str())
            || matches_any(&self.allow_apps, app.as_str())
            || matches_any(&self.allow_execs, exe.as_str())
    }
}

struct ProcessInfo {
    exe: String,
}

struct Args {
    mode: ModeSelection,
    use_system_bus: bool,
    poll_only: bool,
    poll_interval: Duration,
    focus_provider: FocusProviderSelection,
    focus_refresh_interval: Duration,
    focus_stale_timeout: Duration,
    agent_heartbeat_interval: Duration,
    dedicated_cgroup_name: String,
    socket_path: String,
    socket_mode: u32,
    socket_owner_uid: Option<u32>,
    filter_config: Option<String>,
    allow_all_focused: bool,
    allow_classes: Vec<String>,
    allow_execs: Vec<String>,
    allow_titles: Vec<String>,
    allow_apps: Vec<String>,
    deny_classes: Vec<String>,
    deny_execs: Vec<String>,
    deny_titles: Vec<String>,
    deny_apps: Vec<String>,
}

impl Args {
    fn parse() -> Self {
        let mut mode = ModeSelection::Daemon;
        let mut use_system_bus = false;
        let mut poll_only = false;
        let mut poll_interval_ms = DEFAULT_POLL_INTERVAL_MS;
        let mut focus_provider = FocusProviderSelection::Auto;
        let mut focus_refresh_ms = DEFAULT_FOCUS_REFRESH_MS;
        let mut focus_stale_timeout_ms = DEFAULT_FOCUS_STALE_TIMEOUT_MS;
        let mut agent_heartbeat_ms = DEFAULT_AGENT_HEARTBEAT_MS;
        let mut dedicated_cgroup_name = String::from(DEFAULT_DEDICATED_CGROUP_NAME);
        let mut socket_path = String::from(DEFAULT_SOCKET_PATH);
        let mut socket_mode = DEFAULT_SOCKET_MODE;
        let mut socket_owner_uid = None;
        let mut filter_config = None;
        let mut allow_all_focused = false;

        let mut allow_classes = Vec::new();
        let mut allow_execs = Vec::new();
        let mut allow_titles = Vec::new();
        let mut allow_apps = Vec::new();
        let mut deny_classes = Vec::new();
        let mut deny_execs = Vec::new();
        let mut deny_titles = Vec::new();
        let mut deny_apps = Vec::new();

        let mut iter = std::env::args().skip(1);
        while let Some(arg) = iter.next() {
            if let Some(mode_val) = arg.strip_prefix("--mode=") {
                mode = parse_mode(mode_val, mode);
            } else if arg == "--mode" {
                if let Some(mode_val) = iter.next() {
                    mode = parse_mode(mode_val.as_str(), mode);
                } else {
                    eprintln!("WARNING: Missing value for --mode, using default");
                }
            } else if arg == "--use-system-bus" {
                use_system_bus = true;
            } else if arg == "--poll-only" {
                poll_only = true;
            } else if let Some(ms) = arg.strip_prefix("--poll-interval-ms=") {
                if let Ok(value) = ms.parse::<u64>() {
                    poll_interval_ms = value.max(100);
                } else {
                    eprintln!("WARNING: Could not parse poll interval from '{arg}', using default");
                }
            } else if arg == "--poll-interval-ms" {
                if let Some(ms) = iter.next() {
                    if let Ok(value) = ms.parse::<u64>() {
                        poll_interval_ms = value.max(100);
                    } else {
                        eprintln!(
                            "WARNING: Could not parse poll interval value '{ms}', using default"
                        );
                    }
                } else {
                    eprintln!("WARNING: Missing value for --poll-interval-ms, using default");
                }
            } else if let Some(provider) = arg.strip_prefix("--focus-provider=") {
                focus_provider = parse_focus_provider(provider, focus_provider);
            } else if arg == "--focus-provider" {
                if let Some(provider) = iter.next() {
                    focus_provider = parse_focus_provider(provider.as_str(), focus_provider);
                } else {
                    eprintln!("WARNING: Missing value for --focus-provider, using default");
                }
            } else if let Some(ms) = arg.strip_prefix("--focus-refresh-ms=") {
                if let Ok(value) = ms.parse::<u64>() {
                    focus_refresh_ms = value.max(100);
                } else {
                    eprintln!(
                        "WARNING: Could not parse focus refresh interval from '{arg}', using default"
                    );
                }
            } else if arg == "--focus-refresh-ms" {
                if let Some(ms) = iter.next() {
                    if let Ok(value) = ms.parse::<u64>() {
                        focus_refresh_ms = value.max(100);
                    } else {
                        eprintln!(
                            "WARNING: Could not parse focus refresh interval value '{ms}', using default"
                        );
                    }
                } else {
                    eprintln!("WARNING: Missing value for --focus-refresh-ms, using default");
                }
            } else if let Some(ms) = arg.strip_prefix("--focus-stale-timeout-ms=") {
                if let Ok(value) = ms.parse::<u64>() {
                    focus_stale_timeout_ms = value.max(100);
                } else {
                    eprintln!(
                        "WARNING: Could not parse focus stale timeout from '{arg}', using default"
                    );
                }
            } else if arg == "--focus-stale-timeout-ms" {
                if let Some(ms) = iter.next() {
                    if let Ok(value) = ms.parse::<u64>() {
                        focus_stale_timeout_ms = value.max(100);
                    } else {
                        eprintln!(
                            "WARNING: Could not parse focus stale timeout value '{ms}', using default"
                        );
                    }
                } else {
                    eprintln!("WARNING: Missing value for --focus-stale-timeout-ms, using default");
                }
            } else if let Some(ms) = arg.strip_prefix("--agent-heartbeat-ms=") {
                if let Ok(value) = ms.parse::<u64>() {
                    agent_heartbeat_ms = value.max(100);
                } else {
                    eprintln!(
                        "WARNING: Could not parse agent heartbeat from '{arg}', using default"
                    );
                }
            } else if arg == "--agent-heartbeat-ms" {
                if let Some(ms) = iter.next() {
                    if let Ok(value) = ms.parse::<u64>() {
                        agent_heartbeat_ms = value.max(100);
                    } else {
                        eprintln!(
                            "WARNING: Could not parse agent heartbeat value '{ms}', using default"
                        );
                    }
                } else {
                    eprintln!("WARNING: Missing value for --agent-heartbeat-ms, using default");
                }
            } else if let Some(name) = arg.strip_prefix("--dedicated-cgroup=") {
                if name.trim().is_empty() || name.contains('/') {
                    eprintln!("WARNING: Invalid dedicated cgroup name '{name}', keeping previous value");
                } else {
                    dedicated_cgroup_name = String::from(name);
                }
            } else if arg == "--dedicated-cgroup" {
                if let Some(name) = iter.next() {
                    if name.trim().is_empty() || name.contains('/') {
                        eprintln!("WARNING: Invalid dedicated cgroup name '{name}', keeping previous value");
                    } else {
                        dedicated_cgroup_name = name;
                    }
                } else {
                    eprintln!("WARNING: Missing value for --dedicated-cgroup, using default");
                }
            } else if let Some(path) = arg.strip_prefix("--socket-path=") {
                if path.trim().is_empty() {
                    eprintln!("WARNING: Invalid socket path '{path}', keeping previous value");
                } else {
                    socket_path = String::from(path);
                }
            } else if arg == "--socket-path" {
                if let Some(path) = iter.next() {
                    if path.trim().is_empty() {
                        eprintln!("WARNING: Invalid socket path '{path}', keeping previous value");
                    } else {
                        socket_path = path;
                    }
                } else {
                    eprintln!("WARNING: Missing value for --socket-path, using default");
                }
            } else if let Some(mode) = arg.strip_prefix("--socket-mode-octal=") {
                if let Some(parsed) = parse_socket_mode(mode) {
                    socket_mode = parsed;
                } else {
                    eprintln!("WARNING: Invalid socket mode '{mode}', keeping previous value");
                }
            } else if arg == "--socket-mode-octal" {
                if let Some(mode) = iter.next() {
                    if let Some(parsed) = parse_socket_mode(mode.as_str()) {
                        socket_mode = parsed;
                    } else {
                        eprintln!("WARNING: Invalid socket mode '{mode}', keeping previous value");
                    }
                } else {
                    eprintln!("WARNING: Missing value for --socket-mode-octal, using default");
                }
            } else if let Some(uid) = arg.strip_prefix("--socket-owner-uid=") {
                if let Ok(parsed) = uid.parse::<u32>() {
                    socket_owner_uid = Some(parsed);
                } else {
                    eprintln!("WARNING: Invalid socket owner uid '{uid}', keeping previous value");
                }
            } else if arg == "--socket-owner-uid" {
                if let Some(uid) = iter.next() {
                    if let Ok(parsed) = uid.parse::<u32>() {
                        socket_owner_uid = Some(parsed);
                    } else {
                        eprintln!("WARNING: Invalid socket owner uid '{uid}', keeping previous value");
                    }
                } else {
                    eprintln!("WARNING: Missing value for --socket-owner-uid");
                }
            } else if let Some(path) = arg.strip_prefix("--filter-config=") {
                if !path.trim().is_empty() {
                    filter_config = Some(String::from(path));
                }
            } else if arg == "--filter-config" {
                if let Some(path) = iter.next() {
                    if !path.trim().is_empty() {
                        filter_config = Some(path);
                    }
                } else {
                    eprintln!("WARNING: Missing value for --filter-config");
                }
            } else if arg == "--allow-all-focused" {
                allow_all_focused = true;
            } else if let Some(rule) = arg.strip_prefix("--allow-class=") {
                allow_classes.push(String::from(rule));
            } else if arg == "--allow-class" {
                if let Some(rule) = iter.next() {
                    allow_classes.push(rule);
                }
            } else if let Some(rule) = arg.strip_prefix("--allow-exe=") {
                allow_execs.push(String::from(rule));
            } else if arg == "--allow-exe" {
                if let Some(rule) = iter.next() {
                    allow_execs.push(rule);
                }
            } else if let Some(rule) = arg.strip_prefix("--allow-title=") {
                allow_titles.push(String::from(rule));
            } else if arg == "--allow-title" {
                if let Some(rule) = iter.next() {
                    allow_titles.push(rule);
                }
            } else if let Some(rule) = arg.strip_prefix("--allow-app=") {
                allow_apps.push(String::from(rule));
            } else if arg == "--allow-app" {
                if let Some(rule) = iter.next() {
                    allow_apps.push(rule);
                }
            } else if let Some(rule) = arg.strip_prefix("--deny-class=") {
                deny_classes.push(String::from(rule));
            } else if arg == "--deny-class" {
                if let Some(rule) = iter.next() {
                    deny_classes.push(rule);
                }
            } else if let Some(rule) = arg.strip_prefix("--deny-exe=") {
                deny_execs.push(String::from(rule));
            } else if arg == "--deny-exe" {
                if let Some(rule) = iter.next() {
                    deny_execs.push(rule);
                }
            } else if let Some(rule) = arg.strip_prefix("--deny-title=") {
                deny_titles.push(String::from(rule));
            } else if arg == "--deny-title" {
                if let Some(rule) = iter.next() {
                    deny_titles.push(rule);
                }
            } else if let Some(rule) = arg.strip_prefix("--deny-app=") {
                deny_apps.push(String::from(rule));
            } else if arg == "--deny-app" {
                if let Some(rule) = iter.next() {
                    deny_apps.push(rule);
                }
            } else {
                eprintln!("WARNING: Unknown argument '{arg}', ignoring");
            }
        }

        Self {
            mode,
            use_system_bus,
            poll_only,
            poll_interval: Duration::from_millis(poll_interval_ms),
            focus_provider,
            focus_refresh_interval: Duration::from_millis(focus_refresh_ms),
            focus_stale_timeout: Duration::from_millis(focus_stale_timeout_ms),
            agent_heartbeat_interval: Duration::from_millis(agent_heartbeat_ms),
            dedicated_cgroup_name,
            socket_path,
            socket_mode,
            socket_owner_uid,
            filter_config,
            allow_all_focused,
            allow_classes,
            allow_execs,
            allow_titles,
            allow_apps,
            deny_classes,
            deny_execs,
            deny_titles,
            deny_apps,
        }
    }
}

fn parse_mode(value: &str, default: ModeSelection) -> ModeSelection {
    match value {
        "daemon" => ModeSelection::Daemon,
        "agent" => ModeSelection::Agent,
        "standalone" => ModeSelection::Standalone,
        _ => {
            eprintln!("WARNING: Unknown mode '{value}', keeping previous value");
            default
        }
    }
}

fn parse_focus_provider(value: &str, default: FocusProviderSelection) -> FocusProviderSelection {
    match value {
        "auto" => FocusProviderSelection::Auto,
        "hyprland" => FocusProviderSelection::Hyprland,
        "none" => FocusProviderSelection::None,
        _ => {
            eprintln!("WARNING: Unknown focus provider '{value}', keeping previous value");
            default
        }
    }
}

fn parse_socket_mode(value: &str) -> Option<u32> {
    let mode = value.trim_start_matches("0o").trim_start_matches('0');
    let mode = if mode.is_empty() { "0" } else { mode };
    let parsed = u32::from_str_radix(mode, 8).ok()?;
    if parsed <= 0o777 && (parsed & 0o007) == 0 {
        Some(parsed)
    } else {
        None
    }
}

fn normalize_value(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_rules(rules: &[String]) -> Vec<String> {
    rules
        .iter()
        .map(|r| normalize_value(r))
        .filter(|r| !r.is_empty())
        .collect()
}

fn matches_any(rules: &[String], value: &str) -> bool {
    rules.iter().any(|rule| value.contains(rule))
}

fn apply_filter_file(path: &str, filter: &mut GameFilter) {
    let contents = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("WARNING: Could not read filter config '{path}': {e}");
            return;
        }
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, raw_val)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        let val = raw_val.trim();
        if val.is_empty() {
            continue;
        }

        let values: Vec<String> = val
            .split(',')
            .map(|v| normalize_value(v))
            .filter(|v| !v.is_empty())
            .collect();

        if values.is_empty() {
            continue;
        }

        match key {
            "allow_all_focused" => {
                filter.allow_all_focused = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "allow_class" => filter.allow_classes.extend(values),
            "allow_exe" => filter.allow_execs.extend(values),
            "allow_title" => filter.allow_titles.extend(values),
            "allow_app" => filter.allow_apps.extend(values),
            "deny_class" => filter.deny_classes.extend(values),
            "deny_exe" => filter.deny_execs.extend(values),
            "deny_title" => filter.deny_titles.extend(values),
            "deny_app" => filter.deny_apps.extend(values),
            _ => {}
        }
    }
}

fn serialize_focus_sample(sample: &FocusSample) -> String {
    let pid = sample.pid.unwrap_or(0);
    format!(
        "FOCUS\t{}\t{}\t{}\t{}",
        pid,
        escape_field(sample.class.as_deref().unwrap_or("")),
        escape_field(sample.title.as_deref().unwrap_or("")),
        escape_field(sample.app.as_deref().unwrap_or(""))
    )
}

fn deserialize_focus_sample(payload: &str) -> Option<FocusSample> {
    let mut parts = payload.trim().split('\t');
    if parts.next()? != "FOCUS" {
        return None;
    }

    let pid_raw = parts.next().unwrap_or("0").trim();
    let pid = match pid_raw.parse::<u32>() {
        Ok(0) => None,
        Ok(v) => Some(v),
        Err(_) => None,
    };

    let class = unescape_field(parts.next().unwrap_or(""));
    let title = unescape_field(parts.next().unwrap_or(""));
    let app = unescape_field(parts.next().unwrap_or(""));

    Some(FocusSample {
        pid,
        class: if class.is_empty() { None } else { Some(class) },
        title: if title.is_empty() { None } else { Some(title) },
        app: if app.is_empty() { None } else { Some(app) },
    })
}

fn escape_field(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

fn unescape_field(raw: &str) -> String {
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }

        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

struct DbusState {
    connection: Connection,
    unit_queue: Arc<Mutex<HashSet<String>>>,
}

struct FocusPolicyState {
    dedicated_cgroup: Option<CGroup>,
    dedicated_cgroup_path: Option<PathBuf>,
    focused_limits: Option<DMemLimit>,
    unfocused_limits: Option<DMemLimit>,
    focused_root_pid: Option<u32>,
    moved_pids_original: HashMap<u32, PathBuf>,
    self_pid: u32,
}

impl FocusPolicyState {
    fn new(dedicated_cgroup_name: &str) -> Self {
        let focused_limits = CGroup::root().device_memory_capacity();
        if focused_limits.is_none() {
            eprintln!("INFO: dmem.capacity unavailable; focus policy is disabled");
        }

        let unfocused_limits = focused_limits.as_ref().map(|limits| {
            let mut zeroed = DMemLimit::new();
            for device in limits.keys() {
                zeroed.insert(device.clone(), 0);
            }
            zeroed
        });

        let dedicated_cgroup = match CGroup::ensure_child(dedicated_cgroup_name) {
            Ok(cgroup) => Some(cgroup),
            Err(e) => {
                eprintln!(
                    "INFO: Could not initialize dedicated cgroup '{dedicated_cgroup_name}': {e}"
                );
                None
            }
        };

        let dedicated_cgroup_path = dedicated_cgroup
            .as_ref()
            .map(|cgroup| cgroup.path().to_path_buf());

        Self {
            dedicated_cgroup,
            dedicated_cgroup_path,
            focused_limits,
            unfocused_limits,
            focused_root_pid: None,
            moved_pids_original: HashMap::new(),
            self_pid: std::process::id(),
        }
    }

    fn is_enabled(&self) -> bool {
        self.dedicated_cgroup.is_some()
            && self.focused_limits.is_some()
            && self.unfocused_limits.is_some()
    }

    fn update_focused_pid(&mut self, focused_pid: Option<u32>) {
        if !self.is_enabled() {
            return;
        }

        self.moved_pids_original.retain(|pid, _| process_exists(*pid));

        let normalized_focused_pid = focused_pid.filter(|pid| *pid != self.self_pid);
        if self.focused_root_pid != normalized_focused_pid {
            self.restore_previous_assignments();
            self.focused_root_pid = normalized_focused_pid;
        }

        if let Some(pid) = self.focused_root_pid {
            self.migrate_focused_tree(pid);
            self.write_focused_limits();
        } else {
            self.write_unfocused_limits();
        }
    }

    fn restore_previous_assignments(&mut self) {
        let Some(dedicated_cgroup_path) = self.dedicated_cgroup_path.clone() else {
            return;
        };

        let moved_entries: Vec<(u32, PathBuf)> = self.moved_pids_original.drain().collect();
        for (pid, original_cgroup_path) in moved_entries {
            if !process_exists(pid) || pid == self.self_pid {
                continue;
            }
            if original_cgroup_path == dedicated_cgroup_path {
                continue;
            }

            let target = if original_cgroup_path == PathBuf::from("/sys/fs/cgroup") {
                CGroup::root()
            } else if original_cgroup_path.starts_with("/sys/fs/cgroup") {
                CGroup::from_path(original_cgroup_path)
            } else {
                continue;
            };

            if let Err(e) = target.move_pid_into(pid) {
                eprintln!("WARNING: Could not restore pid {pid} to original cgroup: {e}");
            }
        }
    }

    fn migrate_focused_tree(&mut self, root_pid: u32) {
        let Some(dedicated_cgroup) = self.dedicated_cgroup.as_ref() else {
            return;
        };
        let Some(dedicated_cgroup_path) = self.dedicated_cgroup_path.clone() else {
            return;
        };

        for pid in collect_process_tree(root_pid) {
            if pid == self.self_pid || self.moved_pids_original.contains_key(&pid) {
                continue;
            }

            let Some(origin_cgroup) = CGroup::from_pid(pid) else {
                continue;
            };
            let origin_path = origin_cgroup.path().to_path_buf();
            if origin_path == dedicated_cgroup_path {
                continue;
            }

            if let Err(e) = dedicated_cgroup.move_pid_into(pid) {
                eprintln!("WARNING: Could not move pid {pid} into dedicated cgroup: {e}");
                continue;
            }
            self.moved_pids_original.insert(pid, origin_path);
        }
    }

    fn write_unfocused_limits(&self) {
        let Some(unfocused_limits) = &self.unfocused_limits else {
            return;
        };
        let Some(dedicated_cgroup_path) = self.dedicated_cgroup_path.clone() else {
            return;
        };

        let dedicated = CGroup::from_path(dedicated_cgroup_path);
        dedicated.write_device_memory_low(unfocused_limits);
    }

    fn write_focused_limits(&self) {
        let Some(focused_limits) = &self.focused_limits else {
            return;
        };
        let Some(dedicated_cgroup_path) = self.dedicated_cgroup_path.clone() else {
            return;
        };

        let dedicated = CGroup::from_path(dedicated_cgroup_path);
        dedicated.write_device_memory_low(focused_limits);
    }
}

enum FocusProvider {
    None,
    Hyprland(HyprlandFocusProvider),
}

impl FocusProvider {
    fn from_args(args: &Args) -> Self {
        match args.focus_provider {
            FocusProviderSelection::None => FocusProvider::None,
            FocusProviderSelection::Hyprland => {
                let provider = HyprlandFocusProvider::new(args.focus_refresh_interval);
                if let Some(provider) = provider {
                    FocusProvider::Hyprland(provider)
                } else {
                    eprintln!(
                        "WARNING: Focus provider 'hyprland' requested, but Hyprland IPC is unavailable"
                    );
                    FocusProvider::None
                }
            }
            FocusProviderSelection::Auto => {
                if let Some(provider) = HyprlandFocusProvider::new(args.focus_refresh_interval) {
                    FocusProvider::Hyprland(provider)
                } else {
                    FocusProvider::None
                }
            }
        }
    }

    fn poll_focus(&mut self) -> Option<FocusSample> {
        match self {
            FocusProvider::None => None,
            FocusProvider::Hyprland(provider) => provider.poll(),
        }
    }
}

struct HyprlandFocusProvider {
    control_socket_path: PathBuf,
    event_socket_path: PathBuf,
    event_socket: Option<UnixStream>,
    event_buffer: String,
    refresh_interval: Duration,
    last_refresh_at: Instant,
    force_refresh: bool,
}

impl HyprlandFocusProvider {
    fn new(refresh_interval: Duration) -> Option<Self> {
        let instance_sig = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok()?;
        let xdg_runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| String::from("/tmp"));

        let socket_root = PathBuf::from(xdg_runtime_dir)
            .join("hypr")
            .join(instance_sig);
        let control_socket_path = socket_root.join(".socket.sock");
        let event_socket_path = socket_root.join(".socket2.sock");

        let event_socket = Self::connect_event_socket(&event_socket_path);

        Some(Self {
            control_socket_path,
            event_socket_path,
            event_socket,
            event_buffer: String::new(),
            refresh_interval,
            last_refresh_at: Instant::now(),
            force_refresh: true,
        })
    }

    fn connect_event_socket(path: &PathBuf) -> Option<UnixStream> {
        let stream = UnixStream::connect(path).ok()?;
        stream.set_nonblocking(true).ok()?;
        Some(stream)
    }

    fn poll(&mut self) -> Option<FocusSample> {
        let mut should_refresh = self.force_refresh;

        if self.event_socket.is_none() {
            self.event_socket = Self::connect_event_socket(&self.event_socket_path);
            if self.event_socket.is_some() {
                self.force_refresh = true;
                should_refresh = true;
            }
        }

        if self.consume_events() {
            should_refresh = true;
        }

        if self.last_refresh_at.elapsed() >= self.refresh_interval {
            should_refresh = true;
        }

        if !should_refresh {
            return None;
        }

        self.force_refresh = false;
        self.last_refresh_at = Instant::now();
        self.query_active_window()
    }

    fn consume_events(&mut self) -> bool {
        let mut focus_changed = false;
        let mut buf = [0u8; 4096];

        loop {
            let read_result = {
                let Some(stream) = self.event_socket.as_mut() else {
                    break;
                };
                stream.read(&mut buf)
            };

            match read_result {
                Ok(0) => {
                    self.event_socket = None;
                    break;
                }
                Ok(size) => {
                    self.event_buffer
                        .push_str(String::from_utf8_lossy(&buf[..size]).as_ref());
                    while let Some(pos) = self.event_buffer.find('\n') {
                        let line = self.event_buffer[..pos].trim();
                        if line.starts_with("activewindow>>")
                            || line.starts_with("activewindowv2>>")
                            || line.starts_with("closewindow>>")
                        {
                            focus_changed = true;
                        }
                        self.event_buffer.drain(..=pos);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(_) => {
                    self.event_socket = None;
                    break;
                }
            }
        }

        focus_changed
    }

    fn query_active_window(&self) -> Option<FocusSample> {
        let mut socket = UnixStream::connect(&self.control_socket_path).ok()?;
        socket.write_all(b"j/activewindow").ok()?;
        let _ = socket.shutdown(Shutdown::Write);

        let mut response = String::new();
        socket.read_to_string(&mut response).ok()?;

        let pid = parse_json_u32_field(&response, "pid");
        let class = parse_json_string_field(&response, "class");
        let title = parse_json_string_field(&response, "title");
        let app = parse_json_string_field(&response, "initialClass");

        Some(FocusSample {
            pid,
            class,
            title,
            app,
        })
    }
}

fn parse_json_u32_field(json: &str, field_name: &str) -> Option<u32> {
    let needle = format!("\"{field_name}\":");
    let offset = json.find(needle.as_str())? + needle.len();

    let mut digits = String::new();
    let mut saw_number = false;

    for ch in json[offset..].chars() {
        if ch.is_ascii_whitespace() && !saw_number {
            continue;
        }
        if ch.is_ascii_digit() {
            digits.push(ch);
            saw_number = true;
            continue;
        }
        break;
    }

    if digits.is_empty() {
        None
    } else {
        digits.parse::<u32>().ok()
    }
}

fn parse_json_string_field(json: &str, field_name: &str) -> Option<String> {
    let needle = format!("\"{field_name}\":");
    let offset = json.find(needle.as_str())? + needle.len();
    let rest = &json[offset..];

    let start = rest.find('"')? + 1;
    let mut escaped = false;
    let mut out = String::new();

    for ch in rest[start..].chars() {
        if escaped {
            out.push(match ch {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '"' => '"',
                '\\' => '\\',
                other => other,
            });
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if ch == '"' {
            break;
        }

        out.push(ch);
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn process_exists(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).exists()
}

fn process_info(pid: u32) -> Option<ProcessInfo> {
    let exe_path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(ProcessInfo {
        exe: exe_path.to_string_lossy().to_string(),
    })
}

fn process_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if !line.starts_with("Uid:") {
            continue;
        }

        let mut parts = line.split_whitespace();
        let _label = parts.next();
        let real_uid = parts.next()?;
        return real_uid.parse::<u32>().ok();
    }
    None
}

fn collect_process_tree(root_pid: u32) -> Vec<u32> {
    if !process_exists(root_pid) {
        return Vec::new();
    }

    let mut by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
    let Ok(proc_entries) = fs::read_dir("/proc") else {
        return vec![root_pid];
    };

    for entry in proc_entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };

        let stat_path = format!("/proc/{pid}/stat");
        let Ok(stat) = fs::read_to_string(stat_path) else {
            continue;
        };
        let Some(ppid) = parse_ppid_from_stat(&stat) else {
            continue;
        };

        by_parent.entry(ppid).or_default().push(pid);
    }

    let mut result = Vec::new();
    let mut queue = VecDeque::new();
    let mut seen = HashSet::new();

    queue.push_back(root_pid);
    seen.insert(root_pid);

    while let Some(pid) = queue.pop_front() {
        result.push(pid);
        if let Some(children) = by_parent.get(&pid) {
            for child in children {
                if seen.insert(*child) {
                    queue.push_back(*child);
                }
            }
        }
    }

    result
}

fn parse_ppid_from_stat(stat: &str) -> Option<u32> {
    let end_of_comm = stat.rfind(") ")?;
    let rest = &stat[end_of_comm + 2..];
    let mut parts = rest.split_whitespace();
    let _state = parts.next()?;
    let ppid = parts.next()?;
    ppid.parse::<u32>().ok()
}

fn user_slice_id(cgroup: &CGroup) -> Option<String> {
    let parent = cgroup.parent();
    if let None = parent {
        return None;
    }

    let mut parent = parent.unwrap();
    loop {
        let name = parent.name();
        if name.starts_with("user-") && name.ends_with(".slice") {
            let user_id = &name[5..name.len() - 6];
            if u32::from_str(user_id).is_ok() {
                return Some(String::from(user_id));
            }
        }

        if let Some(grandparent) = parent.parent() {
            parent = grandparent;
        } else {
            break;
        }
    }

    None
}

fn try_activate_dmem_controller(
    cgroup: &mut CGroup,
    system: bool,
    write_limits: bool,
) -> Result<(), std::io::Error> {
    if let Some(mut parent) = cgroup.parent() {
        propagate_dmem_activation(&mut parent, system, write_limits);
    }

    if user_slice_id(&cgroup).is_some() && system {
        return Ok(());
    }

    let can_activate_controller = !cgroup.descendants().is_empty() || {
        if let Some(controllers) = cgroup.active_controllers() {
            !controllers.is_empty()
        } else {
            false
        }
    };
    if !can_activate_controller {
        return Ok(());
    }

    let mut retry = false;
    loop {
        if let Err(e) = cgroup.add_controller("dmem") {
            if e.kind() == std::io::ErrorKind::NotFound && !retry {
                if let Some(mut parent) = cgroup.parent() {
                    propagate_dmem_activation(&mut parent, system, write_limits);
                    retry = true;
                    continue;
                }
            }
            return Err(e);
        } else {
            return Ok(());
        }
    }
}

fn propagate_dmem_activation(cgroup: &mut CGroup, system: bool, write_limits: bool) {
    let has_active_dmem = {
        if let Some(controllers) = cgroup.active_controllers() {
            controllers.contains(&String::from("dmem"))
        } else {
            return;
        }
    };

    if !has_active_dmem {
        if let Err(_) = try_activate_dmem_controller(cgroup, system, write_limits) {
            return;
        }
    }

    if !write_limits {
        return;
    }

    let should_set_limit = {
        if let Some(parent) = cgroup.parent() {
            if let Some(user_id) = user_slice_id(&parent) {
                if system {
                    return;
                }
                let name = cgroup.name();
                let mut user_service_name = String::from("user@");
                user_service_name.push_str(user_id.as_str());
                user_service_name.push_str(".service");
                name == "app.slice" || name == user_service_name
            } else {
                true
            }
        } else {
            true
        }
    };

    if !should_set_limit {
        return;
    }

    let limits = CGroup::root().device_memory_capacity();
    if let None = limits {
        return;
    }
    cgroup.write_device_memory_low(&limits.unwrap());
}

fn activate_dmem_in_descendants(cgroup: &mut CGroup, system: bool, write_limits: bool) {
    let descendants = cgroup.descendants();
    if descendants.is_empty() {
        propagate_dmem_activation(cgroup, system, write_limits);
        return;
    }
    for mut desc in descendants {
        activate_dmem_in_descendants(&mut desc, system, write_limits);
    }
}

fn handle_new_unit(connection: &Connection, unit_path: String, system: bool, write_limits: bool) {
    let mut cgroup: Option<String> = None;

    let iface_names = [
        "org.freedesktop.systemd1.Service",
        "org.freedesktop.systemd1.Scope",
        "org.freedesktop.systemd1.Slice",
        "org.freedesktop.systemd1.Socket",
    ];
    for iface_name in iface_names.iter() {
        let get_cgroup_proxy = connection.with_proxy(
            "org.freedesktop.systemd1",
            unit_path.as_str(),
            Duration::from_secs(1),
        );
        let res: Result<(dbus::arg::Variant<String>,), dbus::Error> =
            get_cgroup_proxy.method_call("org.freedesktop.DBus.Properties", "Get", (iface_name, "ControlGroup"));

        if let Ok((candidate_cgroup,)) = res {
            cgroup = Some(candidate_cgroup.0);
            break;
        }
    }

    if let Some(cgroup_path) = cgroup {
        let mut cgroup = String::from("/sys/fs/cgroup");
        cgroup.push_str(cgroup_path.as_str());
        let mut cgroup = CGroup::from_path(PathBuf::from(cgroup));
        propagate_dmem_activation(&mut cgroup, system, write_limits);
    }
}

fn try_setup_dbus(use_system_bus: bool) -> Option<DbusState> {
    let connection = if use_system_bus {
        Connection::new_system()
    } else {
        Connection::new_session()
    };

    let connection = match connection {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("INFO: DBus unavailable ({err}). Falling back to polling mode.");
            return None;
        }
    };

    let new_unit_signal =
        dbus::message::MatchRule::new_signal("org.freedesktop.systemd1.Manager", "UnitNew");
    let unit_removed_signal =
        dbus::message::MatchRule::new_signal("org.freedesktop.systemd1.Manager", "UnitRemoved");

    let unit_queue: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    let new_unit_queue = unit_queue.clone();
    if let Err(err) = connection.add_match(new_unit_signal, move |_: (), _, msg| {
        if let Ok((_, unit)) = msg.read_all::<(String, dbus::Path)>() {
            if let Ok(mut queue) = new_unit_queue.lock() {
                queue.insert(unit.to_string());
            }
        }
        true
    }) {
        eprintln!("INFO: Could not subscribe to UnitNew ({err}). Falling back to polling mode.");
        return None;
    }

    let removed_unit_queue = unit_queue.clone();
    if let Err(err) = connection.add_match(unit_removed_signal, move |_: (), _, msg| {
        if let Ok((_, unit)) = msg.read_all::<(String, dbus::Path)>() {
            if let Ok(mut queue) = removed_unit_queue.lock() {
                queue.remove(&unit.to_string());
            }
        }
        true
    }) {
        eprintln!(
            "INFO: Could not subscribe to UnitRemoved ({err}). Falling back to polling mode."
        );
        return None;
    }

    Some(DbusState {
        connection,
        unit_queue,
    })
}

fn process_dbus_events(state: &DbusState, system: bool, write_limits: bool) {
    while state
        .connection
        .process(Duration::from_millis(100))
        .unwrap_or(false)
    {}

    if let Ok(mut queue) = state.unit_queue.lock() {
        for unit in queue.iter() {
            handle_new_unit(&state.connection, unit.to_string(), system, write_limits);
        }
        queue.clear();
    }
}

fn remove_stale_socket(path: &PathBuf) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(e) => {
            eprintln!(
                "WARNING: Could not inspect daemon socket path '{}': {e}",
                path.display()
            );
            return false;
        }
    };

    if !metadata.file_type().is_socket() {
        eprintln!(
            "WARNING: Refusing to remove non-socket path '{}'",
            path.display()
        );
        return false;
    }

    match fs::remove_file(path) {
        Ok(_) => true,
        Err(e) => {
            eprintln!(
                "WARNING: Could not remove stale daemon socket '{}': {e}",
                path.display()
            );
            false
        }
    }
}

fn setup_daemon_socket(path: &str, socket_mode: u32, socket_owner_uid: Option<u32>) -> Option<UnixListener> {
    let socket_path = PathBuf::from(path);
    if let Some(parent) = socket_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("WARNING: Could not create socket directory '{}': {e}", parent.display());
            return None;
        }
    }

    if !remove_stale_socket(&socket_path) {
        return None;
    }

    let socket = match UnixListener::bind(&socket_path) {
        Ok(sock) => sock,
        Err(e) => {
            eprintln!("WARNING: Could not bind daemon socket '{}': {e}", socket_path.display());
            return None;
        }
    };

    if let Err(e) = socket.set_nonblocking(true) {
        eprintln!("WARNING: Could not set daemon socket nonblocking mode: {e}");
        return None;
    }

    if let Some(uid) = socket_owner_uid {
        if let Err(e) = chown(&socket_path, Some(uid), None) {
            eprintln!("WARNING: Could not set daemon socket owner uid to {uid}: {e}");
        }
    }

    if let Err(e) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(socket_mode)) {
        eprintln!("WARNING: Could not set daemon socket permissions: {e}");
    }

    Some(socket)
}

fn peer_uid_from_stream(stream: &UnixStream) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let fd = stream.as_raw_fd();
        let mut peer = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut len as *mut libc::socklen_t,
            )
        };

        if rc == 0 && len as usize == std::mem::size_of::<libc::ucred>() {
            Some(peer.uid)
        } else {
            None
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        None
    }
}

fn receive_focus_samples(socket: &UnixListener, expected_uid: Option<u32>) -> Vec<FocusSample> {
    let mut samples = Vec::new();

    loop {
        match socket.accept() {
            Ok((mut stream, _)) => {
                if let Some(uid) = expected_uid {
                    match peer_uid_from_stream(&stream) {
                        Some(peer_uid) if peer_uid == uid => {}
                        Some(peer_uid) => {
                            eprintln!(
                                "WARNING: Ignoring focus sample from uid {peer_uid}, expected uid {uid}"
                            );
                            continue;
                        }
                        None => {
                            eprintln!(
                                "WARNING: Could not verify peer uid for focus sample; ignoring connection"
                            );
                            continue;
                        }
                    }
                }

                let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                let mut payload = String::new();
                if stream.read_to_string(&mut payload).is_err() {
                    continue;
                }

                for line in payload.lines() {
                    if let Some(sample) = deserialize_focus_sample(line) {
                        samples.push(sample);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => {
                eprintln!("WARNING: Focus socket receive failed: {e}");
                break;
            }
        }
    }

    samples
}

fn send_focus_sample(socket_path: &str, sample: &FocusSample) {
    let mut socket = match UnixStream::connect(socket_path) {
        Ok(sock) => sock,
        Err(e) => {
            eprintln!("WARNING: Could not create agent socket: {e}");
            return;
        }
    };

    let message = format!("{}\n", serialize_focus_sample(sample));
    if let Err(e) = socket.write_all(message.as_bytes()) {
        eprintln!("WARNING: Could not send focus sample to daemon socket '{socket_path}': {e}");
    }
    let _ = socket.shutdown(Shutdown::Write);
}

fn select_pid_for_policy(sample: &FocusSample, filter: &GameFilter, expected_uid: Option<u32>) -> Option<u32> {
    let pid = sample.pid?;

    if let Some(uid) = expected_uid {
        if process_uid(pid)? != uid {
            return None;
        }
    }

    let process = process_info(pid)?;
    if filter.matches(sample, &process) {
        Some(pid)
    } else {
        None
    }
}

fn run_daemon(args: &Args) {
    let dbus_state = if args.poll_only {
        None
    } else {
        try_setup_dbus(args.use_system_bus)
    };

    let mut focus_state = FocusPolicyState::new(args.dedicated_cgroup_name.as_str());
    let filter = GameFilter::from_args(args);
    let write_default_limits = !focus_state.is_enabled();

    let socket = setup_daemon_socket(
        args.socket_path.as_str(),
        args.socket_mode,
        args.socket_owner_uid,
    );
    let mut last_focus_update = Instant::now();

    loop {
        if let Some(state) = &dbus_state {
            process_dbus_events(state, args.use_system_bus, write_default_limits);
        }

        activate_dmem_in_descendants(&mut CGroup::root(), args.use_system_bus, write_default_limits);

        if let Some(socket) = &socket {
            let samples = receive_focus_samples(socket, args.socket_owner_uid);
            if !samples.is_empty() {
                last_focus_update = Instant::now();
                for sample in samples {
                    let pid = select_pid_for_policy(&sample, &filter, args.socket_owner_uid);
                    focus_state.update_focused_pid(pid);
                }
            }

            if last_focus_update.elapsed() >= args.focus_stale_timeout {
                focus_state.update_focused_pid(None);
            }
        }

        thread::sleep(args.poll_interval);
    }
}

fn run_agent(args: &Args) {
    let mut focus_provider = FocusProvider::from_args(args);
    if matches!(focus_provider, FocusProvider::None) {
        eprintln!("WARNING: Agent mode requires a focus provider (e.g. --focus-provider=hyprland)");
    }

    let mut last_sample: Option<FocusSample> = None;
    let mut last_sent = String::new();
    let mut last_sent_at = Instant::now();

    loop {
        if let Some(sample) = focus_provider.poll_focus() {
            last_sample = Some(sample);
        }

        if let Some(sample) = last_sample.as_ref() {
            let serialized = serialize_focus_sample(sample);
            if serialized != last_sent || last_sent_at.elapsed() >= args.agent_heartbeat_interval {
                send_focus_sample(args.socket_path.as_str(), &sample);
                last_sent = serialized;
                last_sent_at = Instant::now();
            }
        }

        thread::sleep(args.poll_interval);
    }
}

fn run_standalone(args: &Args) {
    let dbus_state = if args.poll_only {
        None
    } else {
        try_setup_dbus(args.use_system_bus)
    };

    let mut focus_provider = FocusProvider::from_args(args);
    let mut focus_state = FocusPolicyState::new(args.dedicated_cgroup_name.as_str());
    let filter = GameFilter::from_args(args);
    let write_default_limits = !focus_state.is_enabled();

    loop {
        if let Some(state) = &dbus_state {
            process_dbus_events(state, args.use_system_bus, write_default_limits);
        }

        activate_dmem_in_descendants(&mut CGroup::root(), args.use_system_bus, write_default_limits);

        if let Some(sample) = focus_provider.poll_focus() {
            let pid = select_pid_for_policy(&sample, &filter, args.socket_owner_uid);
            focus_state.update_focused_pid(pid);
        }

        thread::sleep(args.poll_interval);
    }
}

fn main() {
    let args = Args::parse();

    match args.mode {
        ModeSelection::Daemon => run_daemon(&args),
        ModeSelection::Agent => run_agent(&args),
        ModeSelection::Standalone => run_standalone(&args),
    }
}
