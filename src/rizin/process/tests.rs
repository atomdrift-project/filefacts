//! Containment of one run: the output cap, descendants that outlive the
//! leader, the deadline, shutdown, and the Linux launch paths' limits.

#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use super::*;
#[cfg(unix)]
use crate::rizin::tests::{shim_attempt, stage_script, unique_shim_dir, warm_shim_exec};
#[cfg(unix)]
use crate::rizin::{RIZIN_TIMEOUT, Supervisor, lock};

#[test]
#[cfg(unix)]
fn output_cap_kills_the_group_from_the_supervisor_and_keeps_the_prefix() {
    // Writes forever, under a deadline far longer than any test run: only
    // the cap can end it, and a deadline kill would read as `TimedOut`.
    let dir = stage_script(
        unique_shim_dir("filefacts-rizin-floodshim"),
        "yes rizin-output\n",
    );
    let outcome = Supervisor::new().run(
        Command::new(dir.join("rizin")),
        Duration::from_secs(3600),
        64 * 1024,
        ChildSetup::Native,
    );
    let RunOutcome::Exited {
        status,
        stdout,
        cap_hit,
    } = outcome
    else {
        panic!("a capped run still exits");
    };
    assert!(cap_hit);
    assert!(!status.success());
    assert_eq!(stdout.len(), 64 * 1024, "the prefix up to the cap is kept");
    let _ = std::fs::remove_dir_all(dir);
}

/// Output of exactly the cap is complete, not an overflow; one byte more is.
#[test]
#[cfg(unix)]
fn output_of_exactly_the_cap_is_not_an_overflow() {
    let run = |cap| {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "printf abcd"]);
        match Supervisor::new().run(cmd, Duration::from_secs(3600), cap, ChildSetup::Native) {
            RunOutcome::Exited {
                status,
                stdout,
                cap_hit,
            } => (status.success(), stdout, cap_hit),
            _ => panic!("printf did not exit"),
        }
    };
    assert_eq!(run(4), (true, b"abcd".to_vec(), false));
    let (_, stdout, cap_hit) = run(3);
    assert!(cap_hit);
    assert_eq!(stdout, b"abc");
}

#[cfg(unix)]
fn process_exists(pid: i32) -> bool {
    // SAFETY: signal 0 performs existence/permission probing only.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// `pid`, read from the file a shim wrote it to.
#[cfg(unix)]
fn read_pid(path: &Path) -> i32 {
    std::fs::read_to_string(path)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// Whether `pid` is gone, allowing a killed process a moment to be reaped by
/// init (it can stay a zombie for a scheduler tick after its group is
/// killed).
#[cfg(unix)]
fn gone_soon(pid: i32) -> bool {
    for _ in 0..500 {
        if !process_exists(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// A helper that inherits stdout and outlives the leader must neither keep
/// the reader (and so the caller's worker) waiting nor survive the run. The
/// helper sleeps far past [`DRAIN_GRACE`], so a run that failed to kill it
/// would show as an abandoned reader rather than a slow return.
#[test]
#[cfg(unix)]
fn exited_rizin_cannot_leave_descendant_holding_worker() {
    let dir = unique_shim_dir("filefacts-rizin-descendantshim");
    let descendant_pid = dir.join("descendant.pid");
    let dir = stage_script(
        dir,
        &format!(
            "sleep 3600 &\nprintf '%s\\n' \"$!\" > '{}'\nexit 1\n",
            descendant_pid.display()
        ),
    );
    let supervisor = Supervisor::new();
    let attempt = shim_attempt(&supervisor, &dir, RIZIN_TIMEOUT);
    assert!(
        attempt.recovery.is_none(),
        "failed Rizin must not emit partial facts"
    );
    assert!(!attempt.timed_out);
    assert_eq!(
        supervisor.stats().abandoned_drains,
        0,
        "the descendant held the reader until it was abandoned"
    );
    assert!(
        gone_soon(read_pid(&descendant_pid)),
        "Rizin descendant survived its leader's exit"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Windows counterpart of the descendant test: a shim that backgrounds a
/// helper which inherits stdout and then exits must not retain its caller.
///
/// The leader is reaped, but `read_to_end` cannot return while a descendant
/// holds the pipe's write end; the job object is what kills that helper.
/// The helper sleeps far past [`DRAIN_GRACE`], so an uncontained one shows
/// as an abandoned reader.
#[test]
#[cfg(windows)]
fn windows_descendant_holding_stdout_does_not_retain_worker() {
    use crate::rizin::tests::unique_shim_dir;
    use crate::rizin::{RIZIN_TIMEOUT, Supervisor, analysis_script};

    let dir = unique_shim_dir("filefacts-rizin-winshim");
    std::fs::create_dir_all(&dir).unwrap();
    let shim = dir.join("rizin.cmd");
    let marker = dir.join("shim-ran.txt");

    // `start /b` hands the helper an inherited copy of stdout and does not
    // wait for it, so the leader exits while the pipe stays open.
    let script = [
        "@echo off".to_string(),
        format!("echo ran > \"{}\"", marker.display()),
        "start /b \"\" powershell -NoProfile -Command \"Start-Sleep -Seconds 3600\"".to_string(),
        "exit 1".to_string(),
    ]
    .join("\r\n");
    std::fs::write(&shim, script).unwrap();

    let supervisor = Supervisor::new();
    let bytes = b"windows descendant fixture";
    let attempt = supervisor.attempt(
        &shim,
        bytes,
        analysis_script(bytes, 0, false),
        RIZIN_TIMEOUT,
    );

    assert!(
        marker.exists(),
        "shim never executed — the assertions below would be vacuous"
    );
    assert!(
        attempt.recovery.is_none(),
        "failed Rizin must not emit partial facts"
    );
    assert_eq!(
        supervisor.stats().abandoned_drains,
        0,
        "descendant holding stdout retained the worker"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(unix)]
fn timeout_kills_process_group_joins_reader_and_returns_worker() {
    let dir = unique_shim_dir("filefacts-rizin-timeoutshim");
    let leader_pid = dir.join("leader.pid");
    let descendant_pid = dir.join("descendant.pid");
    // The shim only ever ends by being killed: it waits on a helper that
    // sleeps for an hour.
    let dir = stage_script(
        dir,
        &format!(
            "[ \"$1\" = warmup ] && exit 0\n\
             printf '%s\\n' \"$$\" > '{}'\n\
             sleep 3600 &\n\
             descendant=$!\n\
             printf '%s\\n' \"$descendant\" > '{}'\n\
             wait \"$descendant\"\n",
            leader_pid.display(),
            descendant_pid.display()
        ),
    );
    warm_shim_exec(&dir.join("rizin"));

    let supervisor = Supervisor::new();
    let started = Instant::now();
    let attempt = shim_attempt(&supervisor, &dir, Duration::from_secs(1));
    // Load only ever makes a run slower, so the lower bound cannot flake.
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "a one-second deadline fired early"
    );
    assert!(attempt.timed_out, "only the deadline could end this run");
    assert!(
        attempt.recovery.is_none(),
        "timed-out Rizin must not emit partial facts"
    );
    assert_eq!(supervisor.stats().timeouts, 1);
    assert_eq!(supervisor.stats().abandoned_drains, 0);

    let leader = read_pid(&leader_pid);
    let descendant = read_pid(&descendant_pid);
    assert!(gone_soon(leader), "Rizin group leader was not reaped");
    assert!(
        gone_soon(descendant),
        "Rizin descendant survived the process-group timeout"
    );
    assert!(
        !lock(&supervisor.pgids).contains(&leader),
        "timed-out Rizin remained in the live-process registry"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
fn launch_probe_command(wait: bool, setup: ChildSetup) -> Command {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = match setup {
        ChildSetup::Native | ChildSetup::Watchdog => Command::new(&exe),
        ChildSetup::ExternalLinux => linux_launcher().unwrap().command(&exe).unwrap(),
    };
    cmd.args([
        "--exact",
        if wait {
            "rizin::process::tests::linux_waiting_child_probe"
        } else {
            "rizin::process::tests::linux_child_limits_probe"
        },
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    cmd
}

#[test]
#[ignore = "subprocess fixture for Linux launch tests"]
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn linux_child_limits_probe() {
    let mut a = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let mut d = a;
    let mut signal: libc::c_int = 0;
    // SAFETY: live writable storage for these resource/signal queries.
    let (pid, parent, group) = unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_AS, &raw mut a), 0);
        assert_eq!(libc::getrlimit(libc::RLIMIT_DATA, &raw mut d), 0);
        assert_eq!(libc::prctl(libc::PR_GET_PDEATHSIG, &raw mut signal), 0);
        (libc::getpid(), libc::getppid(), libc::getpgrp())
    };
    println!(
        "FILEFACTS_LIMITS {pid} {parent} {group} {signal} {} {} {} {}",
        a.rlim_cur, a.rlim_max, d.rlim_cur, d.rlim_max
    );
}

/// Both Linux launch paths give the child this process's limits capped at
/// [`MEMORY_LIMIT_BYTES`] — never raised — and a parent-death signal.
#[test]
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn linux_launch_modes_keep_limits_and_parent_death_signal() {
    let mut setups = vec![ChildSetup::Native];
    if linux_launcher().is_some() {
        setups.push(ChildSetup::ExternalLinux);
    }
    let limited = |resource| {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: live writable rlimit storage, for a supported resource.
        assert_eq!(unsafe { libc::getrlimit(resource, &raw mut lim) }, 0);
        [
            lim.rlim_cur.min(MEMORY_LIMIT_BYTES),
            lim.rlim_max.min(MEMORY_LIMIT_BYTES),
        ]
    };
    let expected = [limited(libc::RLIMIT_AS), limited(libc::RLIMIT_DATA)].concat();
    let supervisor = Supervisor::new();
    for setup in setups {
        let result = supervisor.run(
            launch_probe_command(false, setup),
            Duration::from_secs(600),
            64 * 1024,
            setup,
        );
        let RunOutcome::Exited {
            status,
            stdout,
            cap_hit: false,
        } = result
        else {
            panic!("probe did not exit");
        };
        assert!(status.success(), "{}", String::from_utf8_lossy(&stdout));
        let output = String::from_utf8(stdout).unwrap();
        let values: Vec<u64> = output
            .lines()
            .find_map(|line| line.split_once("FILEFACTS_LIMITS "))
            .expect("probe limits")
            .1
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 8);
        assert_eq!(values[0], values[2]);
        assert_eq!(values[1], u64::from(std::process::id()));
        assert_eq!(values[4..], expected);
        // libtest runs the probe on a new thread, where PDEATHSIG is reset.
        // Query the exec'd leader itself with setpriv instead.
        if let Some(setpriv) = crate::tools::resolve("setpriv") {
            let mut cmd = match setup {
                ChildSetup::Native | ChildSetup::Watchdog => Command::new(&setpriv),
                ChildSetup::ExternalLinux => linux_launcher().unwrap().command(&setpriv).unwrap(),
            };
            cmd.arg("--dump");
            let RunOutcome::Exited {
                status,
                stdout,
                cap_hit: false,
            } = supervisor.run(cmd, Duration::from_secs(600), 64 * 1024, setup)
            else {
                panic!("leader signal probe failed");
            };
            assert!(status.success());
            assert!(
                String::from_utf8(stdout)
                    .unwrap()
                    .lines()
                    .any(|line| line.split_whitespace().last() == Some("KILL"))
            );
        }
    }
}

/// [`linux_launch_modes_keep_limits_and_parent_death_signal`] under tighter
/// inherited limits: both soft and hard below the cap, and a soft limit
/// alone below it with the inherited hard limit above. The second is the
/// one a fixed 4 GiB soft limit would raise.
#[test]
#[cfg(target_os = "linux")]
fn linux_launch_modes_keep_tighter_inherited_limits() {
    let Some(prlimit) = crate::tools::resolve("prlimit") else {
        return;
    };
    for limits in [
        ["--as=1073741824:2147483648", "--data=536870912:1073741824"],
        ["--as=1073741824:", "--data=536870912:"],
    ] {
        let output = Command::new(&prlimit)
            .args(limits)
            .arg("--")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "rizin::process::tests::linux_launch_modes_keep_limits_and_parent_death_signal",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{limits:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
#[ignore = "subprocess fixture for parent-death test"]
#[cfg(target_os = "linux")]
fn linux_waiting_child_probe() {
    use std::io::Write;
    println!("FILEFACTS_CHILD {}", std::process::id());
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "subprocess fixture that exits without cleanup"]
#[cfg(target_os = "linux")]
fn linux_parent_death_driver() {
    use std::io::{BufRead, Write};
    let mut cmd = launch_probe_command(true, ChildSetup::ExternalLinux);
    crate::tools::scrub_env(&mut cmd);
    apply_unix_hardening(&mut cmd, ChildSetup::ExternalLinux).unwrap();
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for line in std::io::BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        if let Some((_, pid)) = line.split_once("FILEFACTS_CHILD ") {
            println!("FILEFACTS_ORPHAN {pid}");
            std::io::stdout().flush().unwrap();
            std::process::exit(0);
        }
    }
    let _ = child.wait();
    panic!("child never became ready");
}

#[test]
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn linux_launcher_kills_child_after_parent_exit() {
    if linux_launcher().is_none() {
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "rizin::process::tests::linux_parent_death_driver",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let output = String::from_utf8(output.stdout).unwrap();
    let pid: i32 = output
        .lines()
        .find_map(|line| line.split_once("FILEFACTS_ORPHAN "))
        .expect("orphan pid")
        .1
        .trim()
        .parse()
        .unwrap();
    // The kernel delivers the parent-death signal at once; the bound only
    // stops a broken launcher from hanging the suite.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let dead = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat.rsplit(')').next().unwrap().trim().starts_with('Z'),
            Err(_) => true,
        };
        if dead {
            break;
        }
        if Instant::now() >= deadline {
            // SAFETY: private process group of this fixture.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            panic!("child survived parent exit");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[cfg(target_os = "linux")]
fn linux_launcher_keeps_arguments_literal() {
    let Some(launcher) = linux_launcher() else {
        return;
    };
    let value = "quotes '\" $() ; spaces";
    let mut cmd = launcher.command(Path::new(LAUNCHER_SHELL)).unwrap();
    cmd.args(["-c", "printf '%s' \"$1\"", "fixture", value]);
    let RunOutcome::Exited {
        status,
        stdout,
        cap_hit: false,
    } = Supervisor::new().run(
        cmd,
        Duration::from_secs(600),
        1024,
        ChildSetup::ExternalLinux,
    )
    else {
        panic!("literal-argument probe failed");
    };
    assert!(status.success());
    assert_eq!(stdout, value.as_bytes());
}

#[test]
#[cfg(unix)]
fn shutdown_refuses_later_launches() {
    let supervisor = Supervisor::new();
    supervisor.kill_all();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "echo should-not-launch"]);
    assert!(matches!(
        supervisor.run(command, Duration::from_secs(600), 1024, ChildSetup::Native),
        RunOutcome::Failed
    ));
}

/// The independent watchdog path still ends a run at its deadline, and
/// reports it as a timeout even when the watchdog, which shares the
/// deadline, kills the group before the supervising loop notices: `sleep`
/// left alone would exit successfully after an hour.
#[test]
#[cfg(unix)]
fn independent_watchdog_launch_path_is_bounded() {
    for _ in 0..3 {
        let mut command = Command::new("/bin/sleep");
        command.arg("3600");
        let out = Supervisor::new().run(
            command,
            Duration::from_millis(200),
            1024,
            ChildSetup::Watchdog,
        );
        assert!(matches!(out, RunOutcome::TimedOut));
    }
}

/// Shutdown during concurrent launches: every child that started is killed
/// and none that had not yet started is admitted. The children's deadline is
/// an hour, so a `TimedOut` can only mean a child the shutdown missed.
#[test]
#[cfg(unix)]
fn shutdown_cleans_up_concurrent_launches() {
    let supervisor = Supervisor::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(scope.spawn(|| {
                let mut command = Command::new("/bin/sleep");
                command.arg("3600");
                supervisor.run(command, Duration::from_secs(3600), 1024, ChildSetup::Native)
            }));
        }
        // A hang guard only: a launch is normally admitted in milliseconds.
        let deadline = Instant::now() + Duration::from_secs(120);
        while lock(&supervisor.pgids).is_empty() {
            assert!(Instant::now() < deadline, "no launch was admitted");
            std::thread::sleep(Duration::from_millis(1));
        }
        supervisor.kill_all();
        for handle in handles {
            match handle.join().unwrap() {
                RunOutcome::Failed => {}
                RunOutcome::Exited { status, .. } => assert!(!status.success()),
                RunOutcome::TimedOut => panic!("shutdown missed a child"),
            }
        }
    });
    assert!(lock(&supervisor.pgids).is_empty());
    assert!(*lock(&supervisor.shutdown));
}
