use std::path::Path;
use std::time::Duration;

use opsec_orchestrator::error::OrchestratorError;
use opsec_orchestrator::ipc::{WorkerRequest, WorkerResponse, PROTOCOL_VERSION};
use opsec_orchestrator::sandbox::{detect_sandbox_backend, run_in_sandbox, SandboxBackend, SandboxPolicy};
use tempfile::tempdir;

#[test]
fn ipc_request_and_response_roundtrip_protocol_v1() {
    let req = WorkerRequest {
        protocol_version: PROTOCOL_VERSION,
        input_path: "/dev/shm/opsec/in.pdf".to_string(),
        output_path: Some("/dev/shm/opsec/out.pdf".to_string()),
        dpi: 200,
        padding_px: 4,
        enable_ocr: true,
        ocr_scan_inputs: true,
        paranoid_denoise: false,
        dry_run: false,
        redact_filenames: false,
        ner_mode: "heuristic".to_string(),
        deny_list: vec!["Alias".to_string()],
        allow_list: vec![],
    };

    let json = serde_json::to_string(&req).ok();
    assert!(json.is_some());
    let resp_raw = r#"{"protocol_version":1,"ok":false,"error_code":"FORENSIC_LEAK","message":"residual metadata"}"#;
    let resp: Result<WorkerResponse, _> = serde_json::from_str(resp_raw);
    assert!(resp.is_ok());
    if let Ok(parsed) = resp {
        assert!(!parsed.ok);
        assert_eq!(parsed.error_code.as_deref(), Some("FORENSIC_LEAK"));
    }
}

#[test]
fn bubblewrap_sandbox_blocks_network_and_host_writes_outside_staging() {
    let backend = detect_sandbox_backend();
    assert_eq!(backend, SandboxBackend::Bubblewrap);

    let staging = tempdir().ok();
    let outside = tempdir().ok();
    assert!(staging.is_some() && outside.is_some());
    let staging_path = staging.as_ref().map(|d| d.path()).unwrap_or_else(|| unreachable!());
    let outside_path = outside.as_ref().map(|d| d.path()).unwrap_or_else(|| unreachable!());

    let policy = SandboxPolicy {
        backend: SandboxBackend::Bubblewrap,
        writable_dir: staging_path.to_path_buf(),
        timeout: Duration::from_secs(10),
    };

    // 1. Inside bwrap, writing to staging succeeds, writing outside fails with Read-Only FS,
    //    and outbound TCP connection fails with ENETUNREACH!
    let probe = format!(
        "import os, socket, sys; \
         open({staging:?} + '/ok.txt', 'w').write('ok'); \
         ro_blocked = False\n\
         try:\n\
             open({outside:?} + '/escape.txt', 'w').write('bad')\n\
         except OSError:\n\
             ro_blocked = True\n\
         net_blocked = False\n\
         try:\n\
             s = socket.socket(); s.settimeout(1.0); s.connect(('1.1.1.1', 80))\n\
         except OSError:\n\
             net_blocked = True\n\
         print(f'ro={{ro_blocked}} net={{net_blocked}}')\n\
         sys.exit(0 if (ro_blocked and net_blocked) else 9)",
        staging = staging_path.to_string_lossy(),
        outside = outside_path.to_string_lossy(),
    );

    let out = run_in_sandbox(
        Path::new("/usr/bin/python3"),
        &["-c", &probe],
        b"",
        &policy,
    );
    assert!(out.is_ok(), "sandbox run failed: {out:?}");
    if let Ok(res) = out {
        assert_eq!(res.exit_code, 0, "stderr: {}", res.stderr);
        assert!(res.stdout.contains("ro=True net=True"), "stdout: {}", res.stdout);
    }
    assert!(staging_path.join("ok.txt").exists());
    assert!(!outside_path.join("escape.txt").exists());
}

#[test]
fn sandbox_enforces_execution_timeout() {
    let staging = tempdir().ok();
    assert!(staging.is_some());
    let staging_path = staging.as_ref().map(|d| d.path()).unwrap_or_else(|| unreachable!());

    let policy = SandboxPolicy {
        backend: detect_sandbox_backend(),
        writable_dir: staging_path.to_path_buf(),
        timeout: Duration::from_millis(400),
    };

    let res = run_in_sandbox(
        Path::new("/usr/bin/python3"),
        &["-c", "import time; time.sleep(5)"],
        b"",
        &policy,
    );
    assert!(matches!(res, Err(OrchestratorError::SandboxError(_))));
}
