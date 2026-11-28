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
//! records the host key (trust on first use, see the ADR), a changed one is
//! refused by ssh itself.
//!
//! The model supplies the target and the command, so both are checked
//! before any process exists: the host and the login may not start with
//! `-` (ssh would read them as options) nor contain `@` in the host (ssh
//! would split a `user@host` destination), and the command is ONE argv
//! element that goes to the far machine — never through a local shell.

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

const HOST_MAX: usize = 253;
const USER_MAX: usize = 64;
/// Windows caps a command line at 32 767 characters, and the PowerShell
/// form grows the command by about 2.7× (UTF-16, then base64) — so one
/// command stays well below that.
pub const COMMAND_MAX: usize = 8_000;
/// How long ssh may take to reach the other machine, apart from the
/// command's own run time.
const CONNECT_TIMEOUT_SECS: u64 = 10;

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
/// out-of-range one is refused here instead of wrapping.
pub fn validate(host: &str, user: &str, port: u64, command: &str) -> Result<Target, String> {
    let host = host.trim();
    let user = user.trim();
    if host.is_empty() {
        return Err("no host — give the other machine's hostname or IP address".to_owned());
    }
    if host.len() > HOST_MAX {
        return Err(format!("the host is longer than {HOST_MAX} characters"));
    }
    if host.starts_with('-') {
        return Err("the host may not start with '-'".to_owned());
    }
    if let Some(bad) = host.chars().find(|c| !is_host_char(*c)) {
        return Err(format!(
            "the host contains a character that is not allowed ({bad:?}) — a hostname or an IP address, nothing else"
        ));
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
    if user.len() > USER_MAX {
        return Err(format!("the user is longer than {USER_MAX} characters"));
    }
    if user.starts_with('-') {
        return Err("the user may not start with '-'".to_owned());
    }
    if let Some(bad) = user.chars().find(|c| !is_user_char(*c)) {
        return Err(format!(
            "the user contains a character that is not allowed ({bad:?})"
        ));
    }
    if command.trim().is_empty() {
        return Err("no command".to_owned());
    }
    if command.chars().count() > COMMAND_MAX {
        return Err(format!(
            "the command is longer than {COMMAND_MAX} characters — put a longer one in a file and run that"
        ));
    }
    Ok(Target {
        host: host.to_owned(),
        user,
        port,
    })
}

/// What is sent to the far machine as the one trailing argv element.
fn remote_command(command: &str, shell: Shell) -> String {
    match shell {
        Shell::Cmd => command.to_owned(),
        Shell::PowerShell => {
            // UTF-8 back to this machine: PowerShell writes in the console
            // code page unless told otherwise, which mangles accents.
            let wrapped = format!(
                "try {{ [Console]::OutputEncoding = [Text.Encoding]::UTF8 }} catch {{ }}; {command}"
            );
            let utf16: Vec<u8> = wrapped.encode_utf16().flat_map(u16::to_le_bytes).collect();
            use base64::Engine as _;
            let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
            format!("powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}")
        }
    }
}

/// The whole ssh command line: fixed options first, then the login, the
/// host, and the remote command as the last element.
fn ssh_argv(key: &Path, known_hosts: &Path, target: &Target, remote_command: &str) -> Vec<String> {
    vec![
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
        // path with spaces needs no quoting.
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        "-o".to_owned(),
        format!("ConnectTimeout={CONNECT_TIMEOUT_SECS}"),
        // ssh's own first-contact notice would otherwise land on stderr.
        "-o".to_owned(),
        "LogLevel=ERROR".to_owned(),
        "-l".to_owned(),
        target.user.clone(),
        target.host.clone(),
        remote_command.to_owned(),
    ]
}

/// Add what exit code 255 means: ssh itself failed — the machine was not
/// reached, this machine's key is not allowed there, or its host key
/// changed. The stderr above the line says which.
fn decorate(report: &str, public_key: &Path) -> String {
    if report.starts_with("exit code 255") {
        let public_key = public_key.display();
        format!(
            "{report}\nssh itself failed. Check the stderr above: the machine may be off or \
             unreachable, this machine's key may not be allowed there (its public key is \
             {public_key}), or its host key may have changed."
        )
    } else {
        report.to_owned()
    }
}

/// `<app data>\ssh` — the same directory resolution the chat history and
/// the audit rail use.
pub fn ssh_dir(app: &AppHandle) -> PathBuf {
    let dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    dir.join("ssh")
}

/// One key generation at a time per process, so the first launch (the
/// worker makes the key) and a first `ssh_run` cannot both generate.
static KEY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The assistant's private key: `<dir>\id_ed25519` (+ `.pub`), made with
/// `ssh-keygen` when missing. An existing key is never replaced — other
/// machines may already allow it.
pub fn ensure_key(dir: &Path) -> Result<PathBuf, String> {
    let key = dir.join("id_ed25519");
    if key.is_file() {
        return Ok(key);
    }
    let _one_at_a_time = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if key.is_file() {
        return Ok(key);
    }
    let keygen = open_ssh_dir().join("ssh-keygen.exe");
    if !keygen.is_file() {
        return Err(format!(
            "OpenSSH Client is not installed on this machine (no {})",
            keygen.display()
        ));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
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
    let public = key.with_extension("pub");
    let comment = format!(
        "deepflux@{}",
        std::env::var("COMPUTERNAME").unwrap_or_default()
    );
    let mut cmd = std::process::Command::new(&keygen);
    cmd.args(["-q", "-t", "ed25519", "-N", "", "-C"])
        .arg(&comment)
        .arg("-f")
        .arg(&tmp);
    let out = tools::run_command(&mut cmd, Duration::from_secs(30))?;
    if !out.starts_with("exit code 0") {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&tmp_pub);
        return Err(format!("ssh-keygen failed: {out}"));
    }
    // An existing private key is never replaced — other machines may
    // already allow it — so it is published only if nobody produced one
    // meanwhile, and its public half only then.
    let published = if key.is_file() {
        Ok(())
    } else {
        std::fs::rename(&tmp, &key)
            .map_err(|e| format!("{}: {e}", key.display()))
            .and_then(|()| {
                let _ = std::fs::rename(&tmp_pub, &public);
                Ok(())
            })
    };
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&tmp_pub);
    published.map(|()| key)
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
    let dir = ssh_dir(app);
    let key = ensure_key(&dir)?;
    let ssh = open_ssh_dir().join("ssh.exe");
    if !ssh.is_file() {
        return Err(format!(
            "OpenSSH Client is not installed on this machine (no {})",
            ssh.display()
        ));
    }
    let remote_command = remote_command(command, shell);
    let mut cmd = std::process::Command::new(&ssh);
    cmd.args(ssh_argv(
        &key,
        &dir.join("known_hosts"),
        target,
        &remote_command,
    ));
    Ok(tools::run_command(&mut cmd, timeout)
        .map(|report| decorate(&report, &key.with_extension("pub")))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: &str, user: &str, port: u64, command: &str) -> Result<Target, String> {
        validate(host, user, port, command)
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
            assert!(
                target(host, "", 22, "echo hi").is_err(),
                "{host:?} must be refused"
            );
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
    fn the_cmd_shell_command_travels_verbatim() {
        let tricky = "echo a & rem \"quoted\" | more >nul 2>&1";
        assert_eq!(remote_command(tricky, Shell::Cmd), tricky);
    }

    #[test]
    fn the_powershell_command_is_encoded_so_no_quoting_survives_two_shells() {
        let command = "Write-Output \"héllo (x & y)\"";
        let built = remote_command(command, Shell::PowerShell);
        let (head, encoded) = built.split_once(' ').expect("program, then one argument");
        assert_eq!(head, "powershell.exe");
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
        let wide: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let decoded = String::from_utf16(&wide).expect("UTF-16");
        assert!(decoded.ends_with(command), "{decoded}");
        assert!(decoded.contains("OutputEncoding"));
    }

    #[test]
    fn ssh_never_prompts_and_keeps_its_host_keys_in_its_own_file() {
        let target = validate("host-a", "alice", 2222, "echo hi").expect("passes");
        let argv = ssh_argv(
            Path::new("C:\\Keys With Space\\id_ed25519"),
            Path::new("C:\\App Data\\known hosts"),
            &target,
            "echo hi",
        );
        assert_eq!(argv.first().map(String::as_str), Some("-T"));
        assert_eq!(argv.last().map(String::as_str), Some("echo hi"));
        // Exactly one positional before the command, right after `-l`.
        let (host_index, _) = argv
            .iter()
            .enumerate()
            .find(|(_, arg)| arg.as_str() == "host-a")
            .expect("the host is on the line");
        assert_eq!(host_index, argv.len() - 2);
        assert_eq!(argv[host_index - 1], "-l");
        assert_eq!(argv[host_index - 2], "alice");
        let after = |flag: &str| {
            argv.windows(2)
                .find(|pair| pair[0] == flag)
                .map(|pair| pair[1].clone())
                .expect("flag present")
        };
        assert_eq!(after("-i"), "C:\\Keys With Space\\id_ed25519");
        assert_eq!(after("-p"), "2222");
        let joined = argv.join("\n");
        for option in [
            "BatchMode=yes",
            "StrictHostKeyChecking=accept-new",
            "IdentitiesOnly=yes",
            "UserKnownHostsFile=C:\\App Data\\known hosts",
            "LogLevel=ERROR",
        ] {
            assert!(joined.contains(&format!("\n{option}\n")), "{option}");
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
    fn exit_255_is_explained_and_other_codes_left_alone() {
        let key = Path::new("C:\\keys\\id_ed25519.pub");
        let plain = "exit code 0\n--- stdout ---\nok\n--- stderr ---\n";
        assert_eq!(decorate(plain, key), plain);
        let failed = decorate(
            "exit code 255\n--- stdout ---\n\n--- stderr ---\nPermission denied",
            key,
        );
        assert!(failed.starts_with("exit code 255"));
        assert!(failed.contains("ssh itself failed"));
        assert!(failed.contains(&key.display().to_string()));
    }

    #[test]
    fn the_app_key_is_made_once_and_never_replaced() {
        let dir = std::env::temp_dir().join(format!("df-ssh-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        if !open_ssh_dir().join("ssh-keygen.exe").is_file() {
            eprintln!("ssh-keygen is not installed here — this test cannot run");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let key = ensure_key(&dir).expect("the first call makes the key");
        assert_eq!(key, dir.join("id_ed25519"));
        let public = std::fs::read_to_string(key.with_extension("pub")).expect("public key");
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
        let left: Vec<_> = std::fs::read_dir(&dir)
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(left.len(), 2, "no temporary files left behind: {left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
