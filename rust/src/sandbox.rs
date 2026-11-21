//! Air-gapped Linux process sandbox (Bubblewrap / unshare) with scrubbed env and timeout.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::OrchestratorError;

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
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct SandboxOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

fn binary_exists(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn probe_bwrap(bwrap_bin: &Path) -> bool {
    Command::new(bwrap_bin)
        .args([
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--unshare-net",
            "--unshare-pid",
            "--die-with-parent",
            "--",
            "/usr/bin/true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn probe_unshare(unshare_bin: &Path) -> bool {
    Command::new(unshare_bin)
        .args(["-r", "-n", "/usr/bin/true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Detect the strongest available kernel isolation backend on this Linux host.
pub fn detect_sandbox_backend() -> SandboxBackend {
    if let Some(bwrap) = binary_exists("bwrap") {
        if probe_bwrap(&bwrap) {
            return SandboxBackend::Bubblewrap;
        }
    }
    if let Some(unshare) = binary_exists("unshare") {
        if probe_unshare(&unshare) {
            return SandboxBackend::UnshareNet;
        }
    }
    SandboxBackend::UnsafeDirect
}

fn build_sandboxed_command(
    program: &Path,
    args: &[&str],
    policy: &SandboxPolicy,
) -> Result<Command, OrchestratorError> {
    let wdir = policy.writable_dir.to_string_lossy().into_owned();
    let path_env = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());

    match policy.backend {
        SandboxBackend::Bubblewrap => {
            let bwrap = binary_exists("bwrap").ok_or_else(|| {
                OrchestratorError::SandboxError("bubblewrap ('bwrap') binary not found".to_string())
            })?;
            let mut cmd = Command::new(bwrap);
            cmd.env_clear();
            cmd.args([
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--tmpfs",
                "/tmp",
                "--bind",
                &wdir,
                &wdir,
            ]);
            if let Ok(prog_canon) = std::fs::canonicalize(program) {
                let prog_str = prog_canon.to_string_lossy().into_owned();
                cmd.args(["--ro-bind", &prog_str, &prog_str]);
            }
            cmd.args([
                "--unshare-net",
                "--unshare-pid",
                "--die-with-parent",
                "--clearenv",
                "--setenv",
                "PATH",
                &path_env,
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
        SandboxBackend::UnshareNet => {
            let unshare = binary_exists("unshare").ok_or_else(|| {
                OrchestratorError::SandboxError("'unshare' binary not found".to_string())
            })?;
            let mut cmd = Command::new(unshare);
            cmd.env_clear()
                .env("PATH", &path_env)
                .env("HOME", &wdir)
                .env("TMPDIR", &wdir)
                .env("XDG_CONFIG_HOME", &wdir)
                .env("XDG_CACHE_HOME", &wdir)
                .env("LANG", "C.UTF-8")
                .env("PYTHONNOUSERSITE", "1")
                .args(["-r", "-n", "--"])
                .arg(program)
                .args(args);
            Ok(cmd)
        }
        SandboxBackend::UnsafeDirect => {
            let mut cmd = Command::new(program);
            cmd.env_clear()
                .env("PATH", &path_env)
                .env("HOME", &wdir)
                .env("TMPDIR", &wdir)
                .env("XDG_CONFIG_HOME", &wdir)
                .env("XDG_CACHE_HOME", &wdir)
                .env("LANG", "C.UTF-8")
                .env("PYTHONNOUSERSITE", "1")
                .args(args);
            Ok(cmd)
        }
    }
}

/// Spawn `program` inside the configured sandbox, pipe `stdin_data`, and enforce timeout.
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

    if let Some(mut child_in) = child.stdin.take() {
        let _ = child_in.write_all(stdin_data);
    }

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let out_handle = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(mut r) = stdout_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });
    let err_handle = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(mut r) = stderr_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if start.elapsed() >= policy.timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_handle.join();
                    let _ = err_handle.join();
                    return Err(OrchestratorError::SandboxError(
                        "sandboxed worker exceeded execution timeout".to_string(),
                    ));
                }
                thread::sleep(Duration::from_millis(15));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(OrchestratorError::SandboxError(format!(
                    "error waiting for sandboxed worker: {e}"
                )));
            }
        }
    };

    let stdout_bytes = out_handle.join().unwrap_or_default();
    let stderr_bytes = err_handle.join().unwrap_or_default();

    Ok(SandboxOutput {
        exit_code: status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
    })
}
