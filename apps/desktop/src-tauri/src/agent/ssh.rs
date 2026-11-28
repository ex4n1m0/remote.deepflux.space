//! SSH from the assistant (ADR-016): one tool, `ssh_run`, that runs a
//! command on ANOTHER machine over OpenSSH and brings back its exact
//! output — no remote-desktop session, no assistant and no model key
//! needed there.
//!
//! Everything here rides the OpenSSH client that ships with Windows
//! (`System32\OpenSSH\ssh.exe`, `ssh-keygen.exe`); this binary holds no SSH
//! implementation and no unsafe. The app keeps its own key pair under
//! `<app data>\ssh\` (ed25519, no passphrase, made on the first launch) and
//! its own `known_hosts`. Nothing can make it prompt: no password
//! authentication, no interactive host-key question — a first connection
//! records the host key (trust on first use, see the ADR) and says so in
//! its report; a changed one is refused by ssh itself. The client is
//! started with `-F none` and every option pinned on the command line, so
//! no ssh config file on this machine can add a proxy, another key, a
//! tunnel or a local command, and exactly one host-key type exists — one
//! entry in `known_hosts` is then the whole identity of the far machine.
//!
//! The model supplies the target and the command, so both are checked
//! before any process exists: the host and the login may not start with
//! `-` (ssh would read them as options) nor contain `@` in the host (ssh
//! would split a `user@host` destination), `--` ends the options before
//! the host, and the command is ONE argv element that goes to the far
//! machine — never through a local shell.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tauri::{AppHandle, Manager};

use super::tools;

/// Where the OpenSSH client lives on every Windows 10/11 with the
/// `OpenSSH.Client` capability. Resolved from `SystemRoot`, never from
/// `PATH`: a shell command the assistant ran must not be able to swap the
/// binary this module executes.
fn open_ssh_dir() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    Path::new(&root).join("System32").join("OpenSSH")
}

/// One remote target, already checked by [`validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub user: String,
    pub port: u16,
}

/// Which shell runs the command on the far machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// The SSH server's default shell (cmd.exe on Windows).
    Cmd,
    /// PowerShell, no profile, the command passed encoded — no quoting
    /// has to survive two shells.
    PowerShell,
}

/// The shell the model named: `cmd` or `powershell`, in any case. Anything
/// else is `None`, so a typo is refused instead of quietly meaning `cmd`.
pub fn shell_from_name(name: &str) -> Option<Shell> {
    match name.trim() {
        name if name.eq_ignore_ascii_case("cmd") => Some(Shell::Cmd),
        name if name.eq_ignore_ascii_case("powershell") => Some(Shell::PowerShell),
        _ => None,
    }
}

const HOST_MAX: usize = 253;
const USER_MAX: usize = 64;
/// Windows caps a command line at 32 767 characters, so one command stays
/// well below that.
pub const COMMAND_MAX: usize = 8_000;
/// The far Windows SSH server hands the command to cmd.exe, whose line is
/// capped at 8 191 characters, and the PowerShell form of a command is
/// about 2.7 times longer than the command itself — so that form has a
/// bound of its own.
const REMOTE_LINE_MAX: usize = 7_800;
/// How long ssh may take to reach the other machine, apart from the
/// command's own run time.
const CONNECT_TIMEOUT_SECS: u64 = 10;
/// A connection that stays silent this many 15-second intervals is
/// treated as dead, so a dropped link ends the call instead of sitting
/// out the whole timeout.
const SERVER_ALIVE_SECS: u64 = 15;
const SERVER_ALIVE_COUNT: u64 = 3;

/// Hostnames, IPv4 and bare IPv6: letters, digits, dots, colons, hyphens.
fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-')
}

/// A Windows login name, also `DOMAIN\name` or `name@domain`.
fn is_user_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '\\' | '@')
}

/// The login used when the caller names none: this Windows account's name.
pub fn default_user() -> String {
    std::env::var("USERNAME").unwrap_or_default()
}

/// Check what the model supplied. `port` is the raw number so an
/// out-of-range one is refused here instead of wrapping. A refusal never
/// quotes the refused input: tool text reaches the audit rail's outcome.
pub fn validate(host: &str, user: &str, port: u64, command: &str) -> Result<Target, String> {
    let host = host.trim();
    let user = user.trim();
    if host.is_empty() {
        return Err("no host — give the other machine's hostname or IP address".to_owned());
    }
    if host.len() > HOST_MAX {
        return Err(format!("the host is longer than {HOST_MAX} characters"));
    }
    if host.starts_with('-') || host.chars().any(|c| !is_host_char(c)) {
        return Err(
            "the host is not a hostname or an IP address (letters, digits, dots, colons, \
             hyphens — and no leading dash)"
                .to_owned(),
        );
    }
    let port = u16::try_from(port)
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| "the port must be 1-65535".to_owned())?;
    let user = if user.is_empty() {
        default_user()
    } else {
        user.to_owned()
    };
    if user.is_empty() {
        return Err(
            "no login name — this Windows account's name could not be read; give user".to_owned(),
        );
    }
    if user.len() > USER_MAX {
        return Err(format!("the user is longer than {USER_MAX} characters"));
    }
    if user.starts_with('-') || user.chars().any(|c| !is_user_char(c)) {
        return Err(
            "the user is not a login name (letters, digits, dot, dash, underscore, backslash, \
             at-sign — and no leading dash)"
                .to_owned(),
        );
    }
    if command.trim().is_empty() {
        return Err("no command".to_owned());
    }
    if command.chars().count() > COMMAND_MAX {
        return Err(format!(
            "the command is longer than {COMMAND_MAX} characters — put a longer one in a file \
             and run that"
        ));
    }
    Ok(Target {
        host: host.to_owned(),
        user,
        port,
    })
}

/// What is sent to the far machine as the one trailing argv element.
fn remote_command(command: &str, shell: Shell) -> Result<String, String> {
    match shell {
        Shell::Cmd => Ok(command.to_owned()),
        Shell::PowerShell => {
            // UTF-8 back to this machine: PowerShell writes in the console
            // code page unless told otherwise, which mangles accents.
            let wrapped = format!(
                "try {{ [Console]::OutputEncoding = [Text.Encoding]::UTF8 }} catch {{ }}; {command}"
            );
            let utf16: Vec<u8> = wrapped.encode_utf16().flat_map(u16::to_le_bytes).collect();
            use base64::Engine as _;
            let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
            // Text output: with anything else PowerShell may wrap the error
            // stream in XML when its streams are redirected.
            let built = format!(
                "powershell.exe -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand \
                 {encoded}"
            );
            if built.len() > REMOTE_LINE_MAX {
                return Err(format!(
                    "too long for the powershell shell: its encoded form has {} characters and \
                     at most {REMOTE_LINE_MAX} fit — put the command in a file and run that, or \
                     use shell cmd",
                    built.len()
                ));
            }
            Ok(built)
        }
    }
}

/// The whole ssh command line: fixed options first, then the login, `--`,
/// the host, and the remote command as the last element.
fn ssh_argv(key: &Path, known_hosts: &Path, target: &Target, remote_command: &str) -> Vec<String> {
    vec![
        // No config file of this machine: everything below is the whole
        // configuration.
        "-F".to_owned(),
        "none".to_owned(),
        "-T".to_owned(),
        "-i".to_owned(),
        key.to_string_lossy().into_owned(),
        "-p".to_owned(),
        target.port.to_string(),
        // Never a password prompt, never a host-key question.
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=accept-new".to_owned(),
        // `keyword=value` keeps the rest of the element verbatim, so a
        // path with spaces needs no quoting (checked on the shipped client).
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        // One identity, and no agent behind it: allowing this machine's
        // key is the whole grant.
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        "-o".to_owned(),
        "IdentityAgent=none".to_owned(),
        "-o".to_owned(),
        "GSSAPIAuthentication=no".to_owned(),
        // One host-key type: a second type would be a "new" key to
        // accept-new, not a changed one to refuse.
        "-o".to_owned(),
        "HostKeyAlgorithms=ssh-ed25519".to_owned(),
        "-o".to_owned(),
        "UpdateHostKeys=no".to_owned(),
        // Nothing that runs or reaches out from this machine on its own.
        "-o".to_owned(),
        "ForwardAgent=no".to_owned(),
        "-o".to_owned(),
        "PermitLocalCommand=no".to_owned(),
        "-o".to_owned(),
        "ClearAllForwardings=yes".to_owned(),
        "-o".to_owned(),
        "ProxyCommand=none".to_owned(),
        "-o".to_owned(),
        "ProxyJump=none".to_owned(),
        "-o".to_owned(),
        format!("ConnectTimeout={CONNECT_TIMEOUT_SECS}"),
        "-o".to_owned(),
        format!("ServerAliveInterval={SERVER_ALIVE_SECS}"),
        "-o".to_owned(),
        format!("ServerAliveCountMax={SERVER_ALIVE_COUNT}"),
        // ssh's own first-contact notice would otherwise land on stderr;
        // the report announces a first contact itself.
        "-o".to_owned(),
        "LogLevel=ERROR".to_owned(),
        "-l".to_owned(),
        target.user.clone(),
        "--".to_owned(),
        target.host.clone(),
        remote_command.to_owned(),
    ]
}

/// Whether `known_hosts` already holds an entry for the target. ssh writes
/// the machine's name (in lower case) and `[name]:port` for another port.
fn is_known(known_hosts: &Path, target: &Target) -> bool {
    let Ok(text) = std::fs::read_to_string(known_hosts) else {
        return false;
    };
    let by_name = format!("{} ", target.host).to_ascii_lowercase();
    let by_port = format!("[{}]:{} ", target.host, target.port).to_ascii_lowercase();
    text.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        line.starts_with(&by_name) || line.starts_with(&by_port)
    })
}

/// Put the run in words the model and the audit rail can read. The rail
/// judges a tool by its FIRST line: a failed connection and a timeout START
/// with "ssh_run failed"; a successful run keeps the runner's "exit code"
/// line first, and a first contact is noted AFTER the output — in words
/// that are none of the rail's refusal markers, and as a warning when its
/// entry could not be recorded.
fn frame_report(
    report: &str,
    target: &Target,
    known_hosts: &Path,
    was_known: bool,
    public_key: &Path,
) -> String {
    let host = &target.host;
    let public_key = public_key.display();
    if report.starts_with("exit code 255") {
        return format!(
            "ssh_run failed: the command could not run on {host} — ssh itself failed. The \
             stderr below says which: the machine may be off or unreachable, this machine's key \
             may not be accepted there (its public key is {public_key}), or its host key may \
             have changed.\n{report}"
        );
    }
    if report.starts_with("timed out") {
        return format!(
            "ssh_run failed: the command did not finish in time. The connection was closed \
             here; the command on {host} may still be running there — check before you \
             retry.\n{report}"
        );
    }
    let mut framed = report.to_owned();
    if !was_known {
        framed.push_str(if is_known(known_hosts, target) {
            "\nFIRST CONTACT: this machine's host key was not known before; it is now recorded, and a different key will be rejected from here on.\n"
        } else {
            "\nWARNING — FIRST CONTACT: this machine's host key was not known before and could NOT be recorded (the host-keys file could not be written), so every connection to it is a first contact. Tell the user.\n"
        });
    }
    framed
}

/// `<app data>\ssh`. Unlike the chat and audit folders this one does not
/// fall back to the temp folder: it holds a private key, and no key is
/// better than a key in a temp folder.
pub fn ssh_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|dir| dir.join("ssh"))
        .map_err(|_| "this machine's app data folder could not be found".to_owned())
}

/// One key generation at a time per process, so the first launch (the
/// worker makes the key) and a first `ssh_run` cannot both generate.
static KEY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The assistant's private key: `<dir>\id_ed25519` (+ `.pub`), made with
/// `ssh-keygen` when missing. An existing key is never replaced — other
/// machines may already allow it.
pub fn ensure_key(dir: &Path) -> Result<PathBuf, String> {
    let key = dir.join("id_ed25519");
    let public = key.with_extension("pub");
    if key.is_file() {
        return existing_key(&key, &public);
    }
    let _one_at_a_time = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if key.is_file() {
        return existing_key(&key, &public);
    }
    let keygen = open_ssh_dir().join("ssh-keygen.exe");
    if !keygen.is_file() {
        return Err(format!(
            "OpenSSH Client is not installed on this machine (no {})",
            keygen.display()
        ));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    remove_stale_temporaries(dir);
    // Made under a temporary name and renamed into place, so a key is
    // never seen half-written. (`with_extension` would not do for the
    // public half: it cuts at the LAST dot of a name that has several.)
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stem = format!("id_ed25519.{}.{}", std::process::id(), stamp);
    let tmp = dir.join(&stem);
    let tmp_pub = dir.join(format!("{stem}.pub"));
    let comment = format!(
        "deepflux@{}",
        std::env::var("COMPUTERNAME").unwrap_or_default()
    );
    let mut cmd = std::process::Command::new(&keygen);
    cmd.args(["-q", "-t", "ed25519", "-N", "", "-C"])
        .arg(comment)
        .arg("-f")
        .arg(&tmp);
    let made = tools::run_command(&mut cmd, Duration::from_secs(30))
        .unwrap_or_else(|e| format!("ssh-run failed: {e}"));
    if !made.starts_with("exit code 0") {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&tmp_pub);
        return Err(format!("ssh-keygen failed: {made}"));
    }
    // An existing private key is never replaced — other machines may
    // already allow it — so it is published only if nobody produced one
    // meanwhile.
    if key.is_file() {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&tmp_pub);
        return existing_key(&key, &public);
    }
    std::fs::rename(&tmp, &key).map_err(|e| format!("{}: {e}", key.display()))?;
    // Without its public half the key cannot be allowed anywhere, so a
    // key whose public half could not be published is withdrawn again.
    if let Err(e) = publish(&tmp_pub, &public) {
        let _ = std::fs::remove_file(&key);
        return Err(format!("{}: {e}", public.display()));
    }
    let _ = std::fs::remove_file(&tmp_pub);
    Ok(key)
}

/// A key that exists already. Its public half is what other machines
/// allow, so a lost one is remade from the private key.
fn existing_key(key: &Path, public: &Path) -> Result<PathBuf, String> {
    if !public.is_file() {
        let keygen = open_ssh_dir().join("ssh-keygen.exe");
        let mut cmd = std::process::Command::new(&keygen);
        cmd.arg("-y").arg("-f").arg(key);
        let printed = tools::run_command(&mut cmd, Duration::from_secs(30))
            .unwrap_or_else(|e| format!("ssh-run failed: {e}"));
        let Some(line) = printed
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("ssh-ed25519 "))
        else {
            return Err(format!(
                "the public half of this machine's SSH key is missing and could not be remade: \
                 {printed}"
            ));
        };
        std::fs::write(public, format!("{line}\n"))
            .map_err(|e| format!("{}: {e}", public.display()))?;
    }
    Ok(key.to_path_buf())
}

/// Temporary files of an interrupted key generation. Only ever called
/// while `KEY_LOCK` is held and no key exists yet, so anything that begins
/// with the key's name and has a suffix is left over.
fn remove_stale_temporaries(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("id_ed25519.") && name != "id_ed25519.pub" {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Move a finished file into place; a rename that cannot (another handle
/// on the file) is still a copy.
fn publish(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to).or_else(|_| std::fs::copy(from, to).map(|_| ()))
}

/// Run one command on another machine. Returns the same report shape as
/// `run_shell`: exit code, capped stdout, capped stderr — or a refusal
/// before anything ran.
pub fn run(
    app: &AppHandle,
    target: &Target,
    command: &str,
    shell: Shell,
    timeout: Duration,
) -> Result<String, String> {
    let dir = ssh_dir(app)?;
    let key = ensure_key(&dir)?;
    let known_hosts = dir.join("known_hosts");
    let ssh = open_ssh_dir().join("ssh.exe");
    if !ssh.is_file() {
        return Err(format!(
            "OpenSSH Client is not installed on this machine (no {})",
            ssh.display()
        ));
    }
    let remote_command = remote_command(command, shell)?;
    let was_known = is_known(&known_hosts, target);
    let mut cmd = std::process::Command::new(&ssh);
    cmd.args(ssh_argv(&key, &known_hosts, target, &remote_command));
    tools::run_command(&mut cmd, timeout).map(|report| {
        frame_report(
            &report,
            target,
            &known_hosts,
            was_known,
            &key.with_extension("pub"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: &str, user: &str, port: u64, command: &str) -> Result<Target, String> {
        validate(host, user, port, command)
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("df-ssh-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    #[test]
    fn targets_that_could_be_read_as_ssh_options_are_refused() {
        // Plain names, addresses and a non-default port pass.
        for host in ["DESKTOP-QVF400B", "192.168.100.40", "fe80::1", "pc.local."] {
            let ok = target(host, "igorc", 2222, "echo hi").expect("a plain host passes");
            assert_eq!((ok.host.as_str(), ok.port), (host, 2222));
        }
        // No login given: this Windows account's name.
        let own = target("host-a", "  ", 22, "echo hi").expect("passes");
        assert_eq!(own.user, default_user());

        for host in [
            "-oProxyCommand=x",
            "user@host",
            "two hosts",
            "",
            "h$ost",
            "a;b",
        ] {
            let refusal = target(host, "", 22, "echo hi").expect_err("must be refused");
            // A refusal never quotes what was refused (the empty host has
            // nothing to quote: every text "contains" it).
            if !host.is_empty() {
                assert!(!refusal.contains(host.trim()), "{host:?}: {refusal}");
            }
        }
        for user in ["-v", "a b", "u;ser"] {
            assert!(
                target("host", user, 22, "echo hi").is_err(),
                "{user:?} must be refused"
            );
        }
        assert!(target("host", "DOMAIN\\igor", 22, "echo hi").is_ok());
        assert!(target("host", "igor@example.com", 22, "echo hi").is_ok());
        for port in [0, 65536, u64::MAX] {
            assert!(
                target("host", "", port, "echo hi").is_err(),
                "port {port} must be refused"
            );
        }
        assert!(target("host", "", 22, "   ").is_err());
        assert!(target("host", "", 22, &"x".repeat(COMMAND_MAX + 1)).is_err());
        assert!(target(&"h".repeat(HOST_MAX + 1), "", 22, "echo hi").is_err());
    }

    #[test]
    fn a_shell_name_is_cmd_powershell_or_nothing() {
        assert_eq!(shell_from_name("cmd"), Some(Shell::Cmd));
        assert_eq!(shell_from_name("PowerShell"), Some(Shell::PowerShell));
        assert_eq!(shell_from_name(" powershell "), Some(Shell::PowerShell));
        assert_eq!(shell_from_name("sh"), None);
        assert_eq!(shell_from_name(""), None);
    }

    #[test]
    fn the_cmd_shell_command_travels_verbatim() {
        let tricky = "echo a & rem \"quoted\" | more >nul 2>&1";
        assert_eq!(
            remote_command(tricky, Shell::Cmd).expect("cmd keeps the command"),
            tricky
        );
    }

    #[test]
    fn the_powershell_command_is_encoded_so_no_quoting_survives_two_shells() {
        let command = "Write-Output \"héllo (x & y)\"";
        let built = remote_command(command, Shell::PowerShell).expect("short enough");
        let (head, encoded) = built
            .split_once("-EncodedCommand ")
            .expect("the options, then the encoded command");
        assert_eq!(
            head,
            "powershell.exe -NoProfile -NonInteractive -OutputFormat Text "
        );
        // The encoded form is one bare word: nothing in it for the far
        // cmd.exe to re-parse.
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')),
            "{encoded:?}"
        );
        assert!(!built.contains(command));

        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64");
        let (pairs, _odd_bytes) = bytes.as_chunks::<2>();
        let wide: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
        let decoded = String::from_utf16(&wide).expect("UTF-16");
        assert!(decoded.ends_with(command), "{decoded}");
        assert!(decoded.contains("OutputEncoding"));
    }

    #[test]
    fn the_powershell_form_has_its_own_length_bound() {
        assert!(remote_command(&"x".repeat(2_500), Shell::PowerShell).is_ok());
        let too_long = "x".repeat(4_000);
        let refusal =
            remote_command(&too_long, Shell::PowerShell).expect_err("too long for that shell");
        assert!(refusal.contains("too long"), "{refusal}");
        // The cmd form only obeys the general bound of a command.
        assert!(validate("host", "", 22, &too_long).is_ok());
    }

    #[test]
    fn ssh_reads_no_config_and_every_option_is_pinned() {
        let target = validate("host-a", "alice", 2222, "echo hi").expect("passes");
        let argv = ssh_argv(
            Path::new("C:\\Keys With Space\\id_ed25519"),
            Path::new("C:\\App Data\\known hosts"),
            &target,
            "echo hi",
        );
        assert_eq!(argv.last().map(String::as_str), Some("echo hi"));
        // `--`, then exactly one positional, then the command.
        let (host_index, _) = argv
            .iter()
            .enumerate()
            .find(|(_, arg)| arg.as_str() == "host-a")
            .expect("the host is on the line");
        assert_eq!(host_index, argv.len() - 2);
        // `… -l <login> -- <host> <command>`
        assert_eq!(argv[host_index - 1], "--");
        assert_eq!(argv[host_index - 2], "alice");
        assert_eq!(argv[host_index - 3], "-l");
        let after = |flag: &str| {
            argv.windows(2)
                .find(|pair| pair[0] == flag)
                .map(|pair| pair[1].clone())
                .expect("flag present")
        };
        assert_eq!(after("-F"), "none");
        assert_eq!(after("-i"), "C:\\Keys With Space\\id_ed25519");
        assert_eq!(after("-p"), "2222");
        let joined = argv.join("\n");
        for option in [
            "BatchMode=yes",
            "StrictHostKeyChecking=accept-new",
            "UserKnownHostsFile=C:\\App Data\\known hosts",
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "GSSAPIAuthentication=no",
            "HostKeyAlgorithms=ssh-ed25519",
            "UpdateHostKeys=no",
            "ForwardAgent=no",
            "PermitLocalCommand=no",
            "ClearAllForwardings=yes",
            "ProxyCommand=none",
            "ProxyJump=none",
            "LogLevel=ERROR",
        ] {
            let needle = format!("\n{option}\n");
            assert!(joined.contains(needle.as_str()), "{option}");
        }
        // Nothing interactive, nothing forwarded.
        for forbidden in [
            "StrictHostKeyChecking=no",
            "PasswordAuthentication=yes",
            "ForwardAgent=yes",
        ] {
            assert!(!joined.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn a_first_contact_is_announced_and_an_unrecorded_one_is_warned_about() {
        let dir = scratch_dir("known-hosts");
        let known_hosts = dir.join("known_hosts");
        std::fs::write(
            &known_hosts,
            "host-a ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHh4eA first\n\
             [host-b]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHh4eA other\n",
        )
        .expect("write a known_hosts");
        // ssh writes names in lower case: the check must not care.
        let upper = target("HOST-A", "", 22, "echo hi").expect("passes");
        assert!(is_known(&known_hosts, &upper));
        assert!(!is_known(
            &known_hosts,
            &target("host-b", "", 22, "echo").expect("passes")
        ));
        assert!(is_known(
            &known_hosts,
            &target("host-b", "", 2222, "echo").expect("passes")
        ));
        assert!(!is_known(
            &known_hosts,
            &target("host-c", "", 22, "echo").expect("passes")
        ));
        assert!(!is_known(&dir.join("missing"), &upper));

        let public = Path::new("C:\\keys\\id_ed25519.pub");
        let ok = "exit code 0\n--- stdout ---\nhi\n--- stderr ---\n";
        // A known host: the report is not touched.
        assert_eq!(frame_report(ok, &upper, &known_hosts, true, public), ok);
        // A first contact whose entry was recorded: the note follows the
        // output, and the audit rail (it judges the first line) still sees a
        // success. The first live run on 2026-11-28 was recorded as "denied"
        // because the note came first and used the word "refused".
        let fresh = target("host-c", "", 22, "echo hi").expect("passes");
        std::fs::write(
            &known_hosts,
            "host-c ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHh4eA recorded\n",
        )
        .expect("overwrite known_hosts");
        let recorded = frame_report(ok, &fresh, &known_hosts, false, public);
        assert!(recorded.starts_with(ok), "{recorded}");
        assert!(
            recorded.contains("\nFIRST CONTACT: this machine's host key was not known"),
            "{recorded}"
        );
        assert_eq!(crate::agent::audit::outcome_from_tool_text(&recorded), "ok");
        // A first contact whose entry could not be written.
        let lost = target("host-d", "", 22, "echo hi").expect("passes");
        let warned = frame_report(ok, &lost, &known_hosts, false, public);
        assert!(warned.starts_with(ok), "{warned}");
        assert!(warned.contains("\nWARNING — FIRST CONTACT:"), "{warned}");
        assert!(warned.contains("could NOT be recorded"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_connection_and_a_timeout_are_failures_with_their_cause() {
        let dir = scratch_dir("framing");
        let known_hosts = dir.join("known_hosts");
        let target = target("host-a", "", 22, "echo hi").expect("passes");
        let public = Path::new("C:\\keys\\id_ed25519.pub");
        let failed = frame_report(
            "exit code 255\n--- stdout ---\n\n--- stderr ---\nPermission denied (publickey).",
            &target,
            &known_hosts,
            false,
            public,
        );
        // The audit rail judges the first line: this must read as an error
        // (and not, through some word in it, as a refusal).
        assert!(failed.starts_with("ssh_run failed:"), "{failed}");
        assert!(failed.contains("ssh itself failed"));
        assert!(failed.contains(&public.display().to_string()));
        assert!(failed.contains("Permission denied"));
        let outcome = crate::agent::audit::outcome_from_tool_text(&failed);
        assert!(outcome.starts_with("error:ssh_run failed"), "{outcome}");
        let timed_out = frame_report(
            "timed out after 30s (process tree killed)\n--- partial stdout ---\n",
            &target,
            &known_hosts,
            true,
            public,
        );
        assert!(timed_out.starts_with("ssh_run failed:"), "{timed_out}");
        assert!(timed_out.contains("may still be running"));
        let outcome = crate::agent::audit::outcome_from_tool_text(&timed_out);
        assert!(outcome.starts_with("error:ssh_run failed"), "{outcome}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_app_key_is_made_once_never_replaced_and_its_public_half_kept() {
        assert!(
            open_ssh_dir().join("ssh-keygen.exe").is_file(),
            "this test needs the OpenSSH Client that ships with Windows"
        );
        let dir = scratch_dir("key");
        let key = ensure_key(&dir).expect("the first call makes the key");
        assert_eq!(key, dir.join("id_ed25519"));
        let public_path = key.with_extension("pub");
        let public = std::fs::read_to_string(&public_path).expect("public key");
        assert!(public.starts_with("ssh-ed25519 "), "{public}");
        let private = std::fs::read(&key).expect("private key");
        assert!(
            private.windows(11).any(|w| w == b"PRIVATE KEY"),
            "not a private key file"
        );

        assert_eq!(ensure_key(&dir).expect("the second call reuses it"), key);
        assert_eq!(
            std::fs::read(&key).expect("private key"),
            private,
            "an existing key is never replaced"
        );
        // A lost public half is remade from the same private key (the
        // comment does not survive that; the key itself does).
        std::fs::remove_file(&public_path).expect("remove the public half");
        let remade = ensure_key(&dir).expect("the public half is remade");
        assert_eq!(remade, key);
        let key_part = |text: &str| {
            text.split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
        };
        let remade_text = std::fs::read_to_string(&public_path).expect("public key again");
        assert_eq!(key_part(&remade_text), key_part(&public));
        assert_eq!(
            std::fs::read(&key).expect("private key"),
            private,
            "remaking the public half leaves the private key alone"
        );
        let left: Vec<_> = std::fs::read_dir(&dir)
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(left.len(), 2, "no temporary files left behind: {left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
