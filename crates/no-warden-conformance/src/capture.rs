//! Private, bounded capture for an unmodified external CLI on Unix.
//!
//! Stdout is an unlinked regular file so immediate process exit cannot discard a
//! pending pipe write. `prlimit` bounds regular files, including CLI cache files,
//! and disables core dumps. Stderr is counted and discarded, never retained.
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt,
    path::{Path, PathBuf},
    process::ExitStatus,
    time::Duration,
};

pub const DEFAULT_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);

pub struct Captured {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr_bytes: usize,
}

impl fmt::Debug for Captured {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Captured")
            .field("status", &self.status)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr_bytes)
            .finish()
    }
}

impl fmt::Display for Captured {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CLI capture (status={}, stdout_bytes={}, stderr_bytes={})",
            self.status,
            self.stdout.len(),
            self.stderr_bytes
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureErrorKind {
    UnsupportedPlatform,
    InvalidLimits,
    Setup,
    Spawn,
    Monitor,
    StdoutLimit,
    StderrLimit,
    TimedOut,
    StdoutChanged,
    Cleanup,
}

/// Diagnostics intentionally exclude executable names, arguments, environment,
/// OS error messages, and captured bytes. Never attach a raw process error.
pub struct CaptureError {
    pub kind: CaptureErrorKind,
    pub status: Option<ExitStatus>,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

impl CaptureError {
    fn new(kind: CaptureErrorKind) -> Self {
        Self {
            kind,
            status: None,
            stdout_bytes: 0,
            stderr_bytes: 0,
        }
    }
}

impl fmt::Debug for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureError")
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("stdout_bytes", &self.stdout_bytes)
            .field("stderr_bytes", &self.stderr_bytes)
            .finish()
    }
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            CaptureErrorKind::UnsupportedPlatform => "CLI capture requires Unix",
            CaptureErrorKind::InvalidLimits => "Invalid CLI capture limits",
            CaptureErrorKind::Setup => "CLI capture setup failed",
            CaptureErrorKind::Spawn => "CLI capture could not start",
            CaptureErrorKind::Monitor => "CLI capture monitoring failed",
            CaptureErrorKind::StdoutLimit => "CLI stdout exceeded its capture limit",
            CaptureErrorKind::StderrLimit => "CLI stderr exceeded its capture limit",
            CaptureErrorKind::TimedOut => "CLI capture timed out",
            CaptureErrorKind::StdoutChanged => "CLI stdout changed while reading its capture",
            CaptureErrorKind::Cleanup => "CLI capture cleanup failed",
        };
        write!(
            f,
            "{message} (status={:?}, stdout_bytes={}, stderr_bytes={})",
            self.status, self.stdout_bytes, self.stderr_bytes
        )
    }
}

impl std::error::Error for CaptureError {}

#[derive(Clone)]
pub struct CaptureLimits {
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    /// Optional private parent directory; no named stdout survives child startup.
    pub temp_directory: Option<PathBuf>,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            stdout_bytes: DEFAULT_OUTPUT_LIMIT,
            stderr_bytes: DEFAULT_OUTPUT_LIMIT,
            temp_directory: None,
        }
    }
}

/// The environment map replaces the inherited environment. A nonzero child exit
/// is a successful capture whose status the caller must inspect.
pub fn run(
    program: &Path,
    args: &[OsString],
    environment: &BTreeMap<OsString, OsString>,
    timeout: Duration,
) -> Result<Captured, CaptureError> {
    run_with_limits(
        program,
        args,
        environment,
        timeout,
        &CaptureLimits::default(),
    )
}

pub fn run_with_limits(
    program: &Path,
    args: &[OsString],
    environment: &BTreeMap<OsString, OsString>,
    timeout: Duration,
    limits: &CaptureLimits,
) -> Result<Captured, CaptureError> {
    #[cfg(unix)]
    {
        unix::run(program, args, environment, timeout, limits)
    }
    #[cfg(not(unix))]
    {
        let _ = (program, args, environment, timeout, limits);
        Err(CaptureError::new(CaptureErrorKind::UnsupportedPlatform))
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::{
        fs::{self, File, OpenOptions, Permissions},
        os::unix::{
            fs::{FileExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
        process::{Child, ChildStderr, Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::Instant,
    };

    const POLL: Duration = Duration::from_millis(5);

    // A separate process group contains any ordinary subprocesses the CLI starts.
    // Use an external utility because this crate deliberately forbids unsafe code.
    fn kill_group(id: u32) {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{id}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    struct Running {
        child: Child,
        status: Option<ExitStatus>,
        stopped_group: bool,
    }

    impl Running {
        fn stop_group(&mut self) {
            if !self.stopped_group {
                kill_group(self.child.id());
                self.stopped_group = true;
            }
        }

        fn stop(&mut self) {
            self.stop_group();
            if self.status.is_none() {
                let _ = self.child.kill();
                self.status = self.child.wait().ok();
            }
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.stop();
        }
    }

    enum StderrEnd {
        Eof,
        Overflow,
        Failed,
    }

    fn count_stderr(
        stderr: ChildStderr,
        limit: usize,
        count: &AtomicUsize,
        cancelled: &AtomicBool,
    ) -> StderrEnd {
        use tokio::io::AsyncReadExt;
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
        else {
            return StderrEnd::Failed;
        };
        runtime.block_on(async {
            let Ok(mut stderr) = tokio::process::ChildStderr::from_std(stderr) else {
                return StderrEnd::Failed;
            };
            let mut buffer = [0_u8; 8192];
            let mut total = 0_usize;
            loop {
                if cancelled.load(Ordering::Relaxed) {
                    return StderrEnd::Failed;
                }
                let length = limit
                    .saturating_sub(total)
                    .saturating_add(1)
                    .min(buffer.len());
                match tokio::time::timeout(POLL, stderr.read(&mut buffer[..length])).await {
                    Ok(Ok(0)) => return StderrEnd::Eof,
                    Ok(Ok(read)) => {
                        total = total.saturating_add(read);
                        count.store(total, Ordering::Relaxed);
                        if total > limit {
                            return StderrEnd::Overflow;
                        }
                    }
                    Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Ok(Err(_)) => return StderrEnd::Failed,
                    Err(_) => continue,
                }
            }
        })
    }

    fn stdout_len(file: &File) -> usize {
        file.metadata()
            .map(|m| usize::try_from(m.len()).unwrap_or(usize::MAX))
            .unwrap_or(0)
    }

    pub(super) fn run(
        program: &Path,
        args: &[OsString],
        environment: &BTreeMap<OsString, OsString>,
        timeout: Duration,
        limits: &CaptureLimits,
    ) -> Result<Captured, CaptureError> {
        let quota = limits
            .stdout_bytes
            .checked_add(1)
            .ok_or_else(|| CaptureError::new(CaptureErrorKind::InvalidLimits))?;
        let started = Instant::now();
        let deadline = started
            .checked_add(timeout)
            .ok_or_else(|| CaptureError::new(CaptureErrorKind::InvalidLimits))?;
        let mut builder = tempfile::Builder::new();
        builder.prefix("no-warden-cli-output-");
        let directory = match &limits.temp_directory {
            Some(root) => builder.tempdir_in(root),
            None => builder.tempdir(),
        }
        .map_err(|_| CaptureError::new(CaptureErrorKind::Setup))?;
        let result = capture(
            program,
            args,
            environment,
            deadline,
            limits,
            quota,
            directory.path(),
        );
        match (result, directory.close()) {
            (Ok(captured), Ok(())) => Ok(captured),
            (Err(error), _) => Err(error),
            (Ok(captured), Err(_)) => Err(CaptureError {
                kind: CaptureErrorKind::Cleanup,
                status: Some(captured.status),
                stdout_bytes: captured.stdout.len(),
                stderr_bytes: captured.stderr_bytes,
            }),
        }
    }

    fn capture(
        program: &Path,
        args: &[OsString],
        environment: &BTreeMap<OsString, OsString>,
        deadline: Instant,
        limits: &CaptureLimits,
        quota: usize,
        directory: &Path,
    ) -> Result<Captured, CaptureError> {
        let setup = || CaptureError::new(CaptureErrorKind::Setup);
        // Correct umask-restricted modes explicitly, including umask 0777.
        fs::set_permissions(directory, Permissions::from_mode(0o700)).map_err(|_| setup())?;
        let path = directory.join("stdout");
        let stdout = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| setup())?;
        stdout
            .set_permissions(Permissions::from_mode(0o600))
            .map_err(|_| setup())?;
        fs::remove_file(path).map_err(|_| setup())?;
        let output = stdout.try_clone().map_err(|_| setup())?;
        let child = Command::new("prlimit")
            .arg(format!("--fsize={quota}:{quota}"))
            .args(["--core=0:0", "--"])
            .arg(program)
            .args(args)
            .env_clear()
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::from(output))
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|_| CaptureError::new(CaptureErrorKind::Spawn))?;
        let mut running = Running {
            child,
            status: None,
            stopped_group: false,
        };
        let stderr = running.child.stderr.take().ok_or_else(setup)?;
        let count = Arc::new(AtomicUsize::new(0));
        let reader_count = Arc::clone(&count);
        let cancelled = Arc::new(AtomicBool::new(false));
        let reader_cancelled = Arc::clone(&cancelled);
        let stderr_limit = limits.stderr_bytes;
        let (sender, receiver) = mpsc::channel();
        let reader = thread::Builder::new()
            .name("cli-stderr-count".into())
            .spawn(move || {
                let end = count_stderr(stderr, stderr_limit, &reader_count, &reader_cancelled);
                let _ = sender.send(end);
            })
            .map_err(|_| setup())?;
        let mut stderr_done = false;
        let failure = loop {
            match stdout.metadata() {
                Ok(metadata) if metadata.len() > limits.stdout_bytes as u64 => {
                    break Some(CaptureErrorKind::StdoutLimit);
                }
                Err(_) => break Some(CaptureErrorKind::Monitor),
                _ => {}
            }
            if !stderr_done {
                match receiver.try_recv() {
                    Ok(StderrEnd::Eof) => stderr_done = true,
                    Ok(StderrEnd::Overflow) => break Some(CaptureErrorKind::StderrLimit),
                    Ok(StderrEnd::Failed) | Err(mpsc::TryRecvError::Disconnected) => {
                        break Some(CaptureErrorKind::Monitor);
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
            if running.status.is_none() {
                match running.child.try_wait() {
                    Ok(status) => running.status = status,
                    Err(_) => break Some(CaptureErrorKind::Monitor),
                }
            }
            if running.status.is_some() {
                running.stop_group();
                if stderr_done {
                    break None;
                }
            }
            let now = Instant::now();
            if now >= deadline {
                break Some(CaptureErrorKind::TimedOut);
            }
            thread::sleep(POLL.min(deadline.saturating_duration_since(now)));
        };
        running.stop();
        // Killing the owned group closes its stderr writers. Never let joining a
        // reader extend a process timeout indefinitely if a subprocess escaped it.
        let drain_deadline = Instant::now() + Duration::from_millis(250);
        while !reader.is_finished() && Instant::now() < drain_deadline {
            thread::sleep(POLL);
        }
        let reader_finished = reader.is_finished();
        cancelled.store(true, Ordering::Relaxed);
        let _ = reader.join();
        let bytes = stdout_len(&stdout);
        let stderr_bytes = count.load(Ordering::Relaxed);
        let fail = |kind| CaptureError {
            kind,
            status: running.status,
            stdout_bytes: bytes,
            stderr_bytes,
        };
        if bytes > limits.stdout_bytes {
            return Err(fail(CaptureErrorKind::StdoutLimit));
        }
        if stderr_bytes > limits.stderr_bytes {
            return Err(fail(CaptureErrorKind::StderrLimit));
        }
        if let Some(kind) = failure {
            return Err(fail(kind));
        }
        if !reader_finished {
            return Err(fail(CaptureErrorKind::Monitor));
        }
        let status = running
            .status
            .ok_or_else(|| fail(CaptureErrorKind::Monitor))?;
        let mut output = vec![0_u8; bytes];
        // The inherited descriptor's offset is now at EOF; use explicit offsets.
        stdout
            .read_exact_at(&mut output, 0)
            .map_err(|_| fail(CaptureErrorKind::StdoutChanged))?;
        if stdout.metadata().map(|m| m.len()).ok() != Some(bytes as u64) {
            return Err(fail(CaptureErrorKind::StdoutChanged));
        }
        Ok(Captured {
            status,
            stdout: output,
            stderr_bytes,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::{fs::MetadataExt, process::CommandExt},
        process::{Child, Command, Stdio},
        thread,
        time::Instant,
    };

    const CASE: &str = "NO_WARDEN_CAPTURE_TEST_CASE";
    const ROOT: &str = "NO_WARDEN_CAPTURE_TEST_ROOT";
    const MARKER: &str = "NO_WARDEN_CAPTURE_TEST_MARKER";
    const SIZE: &str = "NO_WARDEN_CAPTURE_TEST_SIZE";

    fn environment(case: &str) -> BTreeMap<OsString, OsString> {
        let mut env: BTreeMap<_, _> = std::env::vars_os().collect();
        env.insert(CASE.into(), case.into());
        env
    }

    fn child_args() -> Vec<OsString> {
        [
            "--ignored",
            "--exact",
            "capture::tests::fixture_child",
            "--nocapture",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    fn capture(
        case: &str,
        size: usize,
        quota: usize,
        timeout: Duration,
    ) -> (Result<Captured, CaptureError>, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let mut env = environment(case);
        env.insert(ROOT.into(), root.path().as_os_str().to_owned());
        env.insert(SIZE.into(), size.to_string().into());
        let limits = CaptureLimits {
            stdout_bytes: quota,
            temp_directory: Some(root.path().to_owned()),
            ..CaptureLimits::default()
        };
        let result = run_with_limits(
            &std::env::current_exe().unwrap(),
            &child_args(),
            &env,
            timeout,
            &limits,
        );
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            0,
            "Capture directories must be removed"
        );
        (result, root)
    }

    // The helper is this Rust test binary, so no additional scripting runtime is
    // needed. Directly opening its existing stdout FD bypasses test-harness output.
    #[test]
    #[ignore = "subprocess fixture, invoked by the capture security tests"]
    fn fixture_child() {
        let Ok(case) = std::env::var(CASE) else {
            return;
        };
        if case == "capture_parent" || case == "umask_parent" {
            let mut env = environment(if case == "capture_parent" {
                "marker_sleep"
            } else {
                "inspect"
            });
            let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
            env.insert(ROOT.into(), root.as_os_str().to_owned());
            let limits = CaptureLimits {
                temp_directory: Some(root),
                ..CaptureLimits::default()
            };
            let result = run_with_limits(
                &std::env::current_exe().unwrap(),
                &child_args(),
                &env,
                Duration::from_secs(5),
                &limits,
            );
            let success = result.is_ok_and(|capture| {
                capture.status.success()
                    && (case == "capture_parent" || capture.stdout == b"true:600:700:0:0")
            });
            std::process::exit(if success { 0 } else { 1 });
        }
        let mut stdout = OpenOptions::new()
            .write(true)
            .open("/proc/self/fd/1")
            .unwrap();
        stdout.set_len(0).unwrap();
        let size = std::env::var(SIZE)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        match case.as_str() {
            "bytes" => {
                let _ = stdout.write_all(&vec![b'x'; size]);
            }
            "inspect" => {
                let metadata = stdout.metadata().unwrap();
                let directory = fs::read_dir(std::env::var_os(ROOT).unwrap())
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path();
                write!(
                    stdout,
                    "{}:{:o}:{:o}:{}:{}",
                    metadata.is_file(),
                    metadata.mode() & 0o777,
                    fs::metadata(&directory).unwrap().mode() & 0o777,
                    metadata.nlink(),
                    fs::read_dir(directory).unwrap().count()
                )
                .unwrap();
            }
            "stderr" => {
                let _ = std::io::stderr().write_all(&vec![b'e'; size]);
            }
            "exit" => {
                stdout.write_all(b"partial").unwrap();
                std::io::stderr().write_all(b"test error").unwrap();
                std::process::exit(7);
            }
            "sleep" => thread::sleep(Duration::from_secs(60)),
            "marker_sleep" => {
                stdout.write_all(b"public capture marker").unwrap();
                fs::write(
                    std::env::var_os(MARKER).unwrap(),
                    std::process::id().to_string(),
                )
                .unwrap();
                thread::sleep(Duration::from_secs(60));
            }
            "descendant" => {
                let mut child = Command::new("/bin/sh")
                    .args(["-c", "sleep 60"])
                    .spawn()
                    .unwrap();
                fs::write(std::env::var_os(MARKER).unwrap(), child.id().to_string()).unwrap();
                let _ = child.wait();
            }
            _ => std::process::exit(2),
        }
        std::process::exit(0);
    }

    #[test]
    fn captures_complete_large_payload_before_immediate_exit() {
        let bytes = 2 * 1024 * 1024;
        let (result, _root) = capture("bytes", bytes, DEFAULT_OUTPUT_LIMIT, Duration::from_secs(5));
        let result = result.unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout.len(), bytes);
        assert!(result.stdout.iter().all(|byte| *byte == b'x'));
        assert_eq!(result.stderr_bytes, 0);
    }

    #[test]
    fn stdout_is_unlinked_regular_0600_in_an_empty_0700_directory() {
        let (result, _root) = capture("inspect", 0, DEFAULT_OUTPUT_LIMIT, Duration::from_secs(5));
        let result = result.unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"true:600:700:0:0");
    }

    #[test]
    fn rejects_stdout_over_default_quota_without_reading_the_payload() {
        let (result, _root) = capture(
            "bytes",
            DEFAULT_OUTPUT_LIMIT + 1,
            DEFAULT_OUTPUT_LIMIT,
            Duration::from_secs(5),
        );
        let error = result.unwrap_err();
        assert_eq!(error.kind, CaptureErrorKind::StdoutLimit);
        assert_eq!(error.stdout_bytes, DEFAULT_OUTPUT_LIMIT + 1);
    }

    #[test]
    fn kernel_limits_regular_file_writes_to_quota_plus_one_detection_byte() {
        let (result, _root) = capture("bytes", 16 * 1024, 1024, Duration::from_secs(5));
        let error = result.unwrap_err();
        assert_eq!(error.kind, CaptureErrorKind::StdoutLimit);
        assert_eq!(error.stdout_bytes, 1025);
    }

    #[test]
    fn accepts_exact_stdout_quota() {
        let (result, _root) = capture("bytes", 1024, 1024, Duration::from_secs(5));
        let result = result.unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, vec![b'x'; 1024]);
    }

    #[test]
    fn kills_reaps_and_cleans_up_after_stderr_overflow() {
        let (result, _root) = capture(
            "stderr",
            DEFAULT_OUTPUT_LIMIT + 1,
            DEFAULT_OUTPUT_LIMIT,
            Duration::from_secs(5),
        );
        let error = result.unwrap_err();
        assert_eq!(error.kind, CaptureErrorKind::StderrLimit);
        assert_eq!(error.stderr_bytes, DEFAULT_OUTPUT_LIMIT + 1);
        assert!(error.status.is_some());
    }

    #[test]
    fn preserves_failed_exit_status_and_stderr_count() {
        let (result, _root) = capture("exit", 0, DEFAULT_OUTPUT_LIMIT, Duration::from_secs(5));
        let result = result.unwrap();
        assert_eq!(result.status.code(), Some(7));
        assert_eq!(result.stdout, b"partial");
        assert_eq!(result.stderr_bytes, 10);
    }

    #[test]
    fn missing_executable_preserves_prlimit_status_and_cleans_up() {
        let root = tempfile::tempdir().unwrap();
        let limits = CaptureLimits {
            temp_directory: Some(root.path().to_owned()),
            ..CaptureLimits::default()
        };
        let result = run_with_limits(
            &root.path().join("missing-executable"),
            &[],
            &environment("unused"),
            Duration::from_secs(5),
            &limits,
        )
        .unwrap();
        assert_eq!(result.status.code(), Some(127));
        assert!(result.stdout.is_empty());
        assert!(result.stderr_bytes > 0);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn timeout_kills_reaps_and_cleans_up() {
        let started = Instant::now();
        let (result, _root) = capture("sleep", 0, DEFAULT_OUTPUT_LIMIT, Duration::from_millis(100));
        let error = result.unwrap_err();
        assert_eq!(error.kind, CaptureErrorKind::TimedOut);
        assert!(error.status.is_some_and(|status| !status.success()));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn restrictive_umask_is_tested_only_in_an_isolated_process() {
        let root = tempfile::tempdir().unwrap();
        let mut env = environment("umask_parent");
        env.insert(ROOT.into(), root.path().as_os_str().to_owned());
        let status = Command::new("/bin/sh")
            .args(["-c", "umask 0777; exec \"$@\"", "capture-umask-test"])
            .arg(std::env::current_exe().unwrap())
            .args(child_args())
            .env_clear()
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    struct FixtureProcess {
        child: Child,
        marker: PathBuf,
    }

    fn signal_group(id: u32) {
        assert!(id > 1 && id != std::process::id());
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{id}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    impl Drop for FixtureProcess {
        fn drop(&mut self) {
            if let Some(pid) = fs::read_to_string(&self.marker)
                .ok()
                .and_then(|text| text.parse::<u32>().ok())
            {
                signal_group(pid);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn wait_marker(path: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !path.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        fs::read_to_string(path)
            .expect("Public child readiness marker was not created")
            .parse()
            .unwrap()
    }

    #[test]
    fn terminated_parent_leaves_only_an_empty_directory_never_named_stdout() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        fs::create_dir(&cache).unwrap();
        let marker = root.path().join("public-pid");
        let mut env = environment("capture_parent");
        env.insert(ROOT.into(), cache.as_os_str().to_owned());
        env.insert(MARKER.into(), marker.as_os_str().to_owned());
        let child = Command::new(std::env::current_exe().unwrap())
            .args(child_args())
            .env_clear()
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut fixture = FixtureProcess {
            child,
            marker: marker.clone(),
        };
        let _pid = wait_marker(&marker);
        fixture.child.kill().unwrap();
        assert!(!fixture.child.wait().unwrap().success());
        let directories: Vec<_> = fs::read_dir(&cache)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(directories.len(), 1);
        assert_eq!(fs::read_dir(&directories[0]).unwrap().count(), 0);
    }

    #[test]
    fn timeout_also_stops_descendant_stderr_writers() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("public-descendant-pid");
        let mut env = environment("descendant");
        env.insert(MARKER.into(), marker.as_os_str().to_owned());
        let result = run(
            &std::env::current_exe().unwrap(),
            &child_args(),
            &env,
            Duration::from_millis(300),
        );
        assert_eq!(result.unwrap_err().kind, CaptureErrorKind::TimedOut);
        let pid = wait_marker(&marker);
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"));
        assert!(
            stat.is_err()
                || stat
                    .unwrap()
                    .rsplit_once(')')
                    .unwrap()
                    .1
                    .trim_start()
                    .starts_with('Z'),
            "The descendant must stop executing"
        );
    }

    #[test]
    fn diagnostics_redact_stdout_and_never_include_credentials() {
        use std::os::unix::process::ExitStatusExt;
        let captured = Captured {
            status: ExitStatus::from_raw(7 << 8),
            stdout: b"test-private-vault-output".to_vec(),
            stderr_bytes: 10,
        };
        let diagnostic = format!("{captured:?} {captured}");
        assert!(!diagnostic.contains("test-private-vault-output"));
        assert!(diagnostic.contains("stdout_bytes"));
        let error = CaptureError {
            kind: CaptureErrorKind::TimedOut,
            status: Some(captured.status),
            stdout_bytes: captured.stdout.len(),
            stderr_bytes: 10,
        };
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("test-private-vault-output"));
        assert!(diagnostic.contains("stderr_bytes"));
    }
}
