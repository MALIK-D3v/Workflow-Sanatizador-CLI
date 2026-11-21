//! Hardened air-gapped Linux Bubblewrap sandbox with minimal read-only allowlist,
//! zero host sockets (/run tmpfs), bounded pipe reads, and process-group timeout kill.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::OrchestratorError;

const MAX_STDOUT_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB
const MAX_STDERR_BYTES: u64 = 256 * 1024; // 256 KiB
const TRUSTED_BWRAP_PATHS: [&str; 2] = ["/usr/bin/bwrap", "/bin/bwrap"];
const TRUSTED_UNSHARE_PATHS: [&str; 2] = ["/usr/bin/unshare", "/bin/unshare"];
const TRUSTED_TRUE_PATHS: [&str; 2] = ["/usr/bin/true", "/bin/true"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxBackend {
    Bubblewrap,
    UnshareNet,
    UnsafeDirect,
}

impl SandboxBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bubblewrap => "bubblewrap",
            Self::UnshareNet => "unshare-net",
            Self::UnsafeDirect => "unsafe-direct",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub backend: SandboxBackend,
    pub writable_dir: PathBuf,
    pub ro_extra_binds: Vec<PathBuf>,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct SandboxOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

fn find_trusted_binary(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| p.is_file())
}

fn probe_bwrap(bwrap_bin: &Path) -> bool {
    let Some(true_bin) = find_trusted_binary(&TRUSTED_TRUE_PATHS) else {
        return false;
    };
    Command::new(bwrap_bin)
        .args([
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--ro-bind-try",
            "/bin",
            "/bin",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
            "--unshare-all",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--die-with-parent",
            "--",
        ])
        .arg(true_bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn probe_unshare(unshare_bin: &Path) -> bool {
    let Some(true_bin) = find_trusted_binary(&TRUSTED_TRUE_PATHS) else {
        return false;
    };
    Command::new(unshare_bin)
        .args(["-r", "-n", "--"])
        .arg(true_bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Detect the strongest available kernel isolation backend on this Linux host.
pub fn detect_sandbox_backend() -> SandboxBackend {
    if let Some(bwrap) = find_trusted_binary(&TRUSTED_BWRAP_PATHS) {
        if probe_bwrap(&bwrap) {
            return SandboxBackend::Bubblewrap;
        }
    }
    if let Some(unshare) = find_trusted_binary(&TRUSTED_UNSHARE_PATHS) {
        if probe_unshare(&unshare) {
            return SandboxBackend::UnshareNet;
        }
    }
    SandboxBackend::UnsafeDirect
}

fn build_bwrap_command(
    program: &Path,
    args: &[&str],
    policy: &SandboxPolicy,
) -> Result<Command, OrchestratorError> {
    let bwrap = find_trusted_binary(&TRUSTED_BWRAP_PATHS).ok_or_else(|| {
        OrchestratorError::SandboxError(
            "trusted bubblewrap binary not found in /usr/bin or /bin".to_string(),
        )
    })?;
    let wdir = policy.writable_dir.to_string_lossy().into_owned();

    let mut cmd = Command::new(bwrap);
    cmd.env_clear();
    // Explicit minimal read-only allowlist — NEVER mount host `/`, `/home`, or `/run`!
    cmd.args([
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--ro-bind-try",
        "/sbin",
        "/sbin",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--ro-bind-try",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf",
        "--ro-bind-try",
        "/etc/ld.so.conf.d",
        "/etc/ld.so.conf.d",
        "--ro-bind-try",
        "/etc/fonts",
        "/etc/fonts",
        "--ro-bind-try",
        "/etc/alternatives",
        "/etc/alternatives",
        "--ro-bind-try",
        "/etc/libreoffice",
        "/etc/libreoffice",
        "--ro-bind-try",
        "/etc/ssl/certs",
        "/etc/ssl/certs",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--bind",
        &wdir,
        &wdir,
    ]);

    for extra in &policy.ro_extra_binds {
        if let Ok(canon) = std::fs::canonicalize(extra) {
            let s = canon.to_string_lossy().into_owned();
            cmd.args(["--ro-bind", &s, &s]);
        }
    }
    if let Ok(prog_canon) = std::fs::canonicalize(program) {
        let prog_str = prog_canon.to_string_lossy().into_owned();
        if !prog_str.starts_with("/usr/") && !prog_str.starts_with("/bin/") {
            cmd.args(["--ro-bind", &prog_str, &prog_str]);
        }
    }

    cmd.args([
        "--unshare-all",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--hostname",
        "opsec-sandbox",
        "--die-with-parent",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        &wdir,
        "--setenv",
        "TMPDIR",
        &wdir,
        "--setenv",
        "XDG_CONFIG_HOME",
        &wdir,
        "--setenv",
        "XDG_CACHE_HOME",
        &wdir,
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "PYTHONNOUSERSITE",
        "1",
        "--",
    ]);
    cmd.arg(program);
    cmd.args(args);
    Ok(cmd)
}

fn build_sandboxed_command(
    program: &Path,
    args: &[&str],
    policy: &SandboxPolicy,
) -> Result<Command, OrchestratorError> {
    let wdir = policy.writable_dir.to_string_lossy().into_owned();
    let mut cmd = match policy.backend {
        SandboxBackend::Bubblewrap => build_bwrap_command(program, args, policy)?,
        SandboxBackend::UnshareNet => {
            let unshare = find_trusted_binary(&TRUSTED_UNSHARE_PATHS).ok_or_else(|| {
                OrchestratorError::SandboxError("trusted 'unshare' binary not found".to_string())
            })?;
            let mut c = Command::new(unshare);
            c.env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &wdir)
                .env("TMPDIR", &wdir)
                .env("XDG_CONFIG_HOME", &wdir)
                .env("XDG_CACHE_HOME", &wdir)
                .env("LANG", "C.UTF-8")
                .env("PYTHONNOUSERSITE", "1")
                .args(["-r", "-n", "--"])
                .arg(program)
                .args(args);
            c
        }
        SandboxBackend::UnsafeDirect => {
            let mut c = Command::new(program);
            c.env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &wdir)
                .env("TMPDIR", &wdir)
                .env("XDG_CONFIG_HOME", &wdir)
                .env("XDG_CACHE_HOME", &wdir)
                .env("LANG", "C.UTF-8")
                .env("PYTHONNOUSERSITE", "1")
                .args(args);
            c
        }
    };
    // Place child in its own process group so timeout kills every descendant process cleanly.
    cmd.process_group(0);
    Ok(cmd)
}

fn kill_process_group(child: &mut std::process::Child) {
    let pid = child.id() as libc::pid_t;
    if pid > 0 {
        // Safe: sends SIGKILL to the child's dedicated process group created via process_group(0).
        let _ = std::process::Command::new("/usr/bin/kill")
            .args(["-9", &format!("-{pid}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Spawn `program` inside the configured sandbox, pipe `stdin_data` asynchronously,
/// bound stdout/stderr reads, and enforce strict timeout with process-group termination.
pub fn run_in_sandbox(
    program: &Path,
    args: &[&str],
    stdin_data: &[u8],
    policy: &SandboxPolicy,
) -> Result<SandboxOutput, OrchestratorError> {
    let mut cmd = build_sandboxed_command(program, args, policy)?;
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| OrchestratorError::SandboxError(format!("failed to spawn sandbox: {e}")))?;

    let stdin_payload = stdin_data.to_vec();
    let stdin_pipe = child.stdin.take();
    let in_handle = thread::spawn(move || {
        if let Some(mut w) = stdin_pipe {
            let _ = w.write_all(&stdin_payload);
            let _ = w.flush();
        }
    });

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let out_handle = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(r) = stdout_pipe {
            let _ = r.take(MAX_STDOUT_BYTES).read_to_end(&mut buf);
        }
        buf
    });
    let err_handle = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(r) = stderr_pipe {
            let _ = r.take(MAX_STDERR_BYTES).read_to_end(&mut buf);
        }
        buf
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if start.elapsed() >= policy.timeout {
                    kill_process_group(&mut child);
                    let _ = in_handle.join();
                    let _ = out_handle.join();
                    let _ = err_handle.join();
                    return Err(OrchestratorError::SandboxError(
                        "sandboxed worker exceeded execution timeout".to_string(),
                    ));
                }
                thread::sleep(Duration::from_millis(15));
            }
            Err(e) => {
                kill_process_group(&mut child);
                return Err(OrchestratorError::SandboxError(format!(
                    "error waiting for sandboxed worker: {e}"
                )));
            }
        }
    };

    let _ = in_handle.join();
    let stdout_bytes = out_handle.join().unwrap_or_default();
    let stderr_bytes = err_handle.join().unwrap_or_default();

    Ok(SandboxOutput {
        exit_code: status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
    })
}
