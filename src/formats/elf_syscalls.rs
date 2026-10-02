//! ELF **direct** syscall inventory — syscalls issued via a raw `syscall`/`svc`
//! instruction rather than a libc wrapper.
//!
//! Direct syscalls are neutral capabilities, including those in static libc.
//! Emit resolved numbers even when their ABI name is unknown. Each record has
//! a file offset and constant arguments; trait rules supply behavioral meaning.
//! x86-64 decoding follows instruction boundaries within executable regions.
//! Work is bounded by the file size and records by MAX_CANDIDATES.

use crate::metric;
use crate::value_key;
use goblin::elf::Elf;
use goblin::elf::header::{EM_AARCH64, EM_X86_64};
use goblin::elf::section_header::{SHF_EXECINSTR, SHT_NOBITS};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;

use crate::output::{Metrics, Values};

/// Cap on emitted sites per binary. Decoding and counting remain file-size bounded.
const MAX_CANDIDATES: usize = 4096;

/// Number of argument registers tracked (the Linux syscall ABI arg count).
const N_ARGS: usize = 6;

/// Resolved operands at one direct-syscall site: the syscall number and up to
/// six argument-register immediates (`None` when an argument isn't a clean
/// constant — a computed address, a value from a prior call, etc.).
#[derive(Default)]
struct Resolved {
    number: Option<u32>,
    args: [Option<u64>; N_ARGS],
}

/// One instruction site, keyed by file offset to avoid duplicate overlapping regions.
struct Site {
    name: &'static str,
    number: u32,
    args: [Option<u64>; N_ARGS],
}
type Sites = BTreeMap<u64, Site>;

pub(super) fn emit(elf: &Elf<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let mut sites = Sites::new();

    // The generic `syscall()` wrapper takes a runtime number we can't resolve;
    // note its presence (an unresolved computed-number site) but nothing more.
    let indirect = elf
        .dynsyms
        .iter()
        .any(|sym| sym.st_shndx == 0 && elf.dynstrtab.get_at(sym.st_name) == Some("syscall"));

    // Direct syscall instructions, including legitimate static runtime wrappers.
    // The arch label rides along with its scan: syscall numbers are
    // arch-specific, so the label is only meaningful for the table that
    // resolved these names (cleave's `SyscallInfo.arch`).
    let scanned = match elf.header.e_machine {
        EM_X86_64 => Some(("x86_64", scan_x86_64(elf, bytes, &mut sites))),
        EM_AARCH64 => Some(("aarch64", scan_aarch64(elf, bytes, &mut sites))),
        _ => None,
    };
    if let Some((arch, direct)) = scanned {
        if !sites.is_empty() {
            let arr = sites.iter().map(site_json).collect();
            values.insert_key(value_key!("elf.syscalls_direct"), JsonValue::Array(arr));
            values.insert_key(value_key!("elf.syscalls_arch"), arch.into());
        }
        if direct > 0 {
            metrics.insert(metric!("elf.direct_syscall_count"), direct as f64);
        }
    }
    if indirect {
        metrics.insert(metric!("elf.has_indirect_syscall"), 1.0);
    }
}

/// `{ "name": <str>, "number": <u32>, "offset": <u64>, "args": [<u64|null>, …] }`,
/// trailing unresolved args trimmed. Consumers index `args` positionally (arg 0
/// = `rdi`/`x0`, …), read `number` against this scan's `elf.syscalls_arch`, and
/// treat `offset` as a byte offset into the file.
fn site_json((&offset, site): (&u64, &Site)) -> JsonValue {
    let end = site
        .args
        .iter()
        .rposition(Option::is_some)
        .map_or(0, |i| i + 1);
    let vals: Vec<JsonValue> = site
        .args
        .iter()
        .take(end)
        .map(|a| a.map_or(JsonValue::Null, JsonValue::from))
        .collect();
    serde_json::json!({
        "name": site.name,
        "number": site.number,
        "offset": offset,
        "args": vals,
    })
}

/// Executable file-backed sections, or executable PT_LOAD segments when section
/// metadata is absent. Sort and clip overlaps so no file byte is scanned twice.
/// Invalid ranges are ignored and emitted offsets always refer to file bytes.
fn exec_regions<'a>(elf: &'a Elf<'_>, bytes: &'a [u8]) -> impl Iterator<Item = (usize, &'a [u8])> {
    let mut ranges: Vec<(usize, usize, ())> = elf
        .section_headers
        .iter()
        .filter(|sh| sh.sh_flags & u64::from(SHF_EXECINSTR) != 0 && sh.sh_type != SHT_NOBITS)
        .filter_map(|sh| {
            Some((
                usize::try_from(sh.sh_offset).ok()?,
                usize::try_from(sh.sh_size).ok()?,
                (),
            ))
        })
        .collect();
    if ranges.is_empty() {
        ranges = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD && ph.is_executable())
            .filter_map(|ph| {
                Some((
                    usize::try_from(ph.p_offset).ok()?,
                    usize::try_from(ph.p_filesz).ok()?,
                    (),
                ))
            })
            .collect();
    }
    super::common::disjoint_file_ranges(ranges, bytes.len())
        .into_iter()
        .filter_map(|(range, ())| Some((range.start, bytes.get(range)?)))
}

fn scan_x86_64(elf: &Elf<'_>, bytes: &[u8], sites: &mut Sites) -> u64 {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};
    let mut direct = 0;
    for (offset, region) in exec_regions(elf, bytes) {
        let mut decoder = Decoder::with_ip(64, region, offset as u64, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut state = X86State::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.mnemonic() == Mnemonic::Syscall {
                direct += 1;
                if direct <= MAX_CANDIDATES as u64 {
                    let res = state.resolved();
                    if let Some(number) = res.number {
                        sites.insert(
                            instruction.ip(),
                            Site {
                                name: x86_64_syscall_name(number).unwrap_or("unknown"),
                                number,
                                args: res.args,
                            },
                        );
                    }
                }
            }
            state.step(&instruction);
        }
    }
    direct
}

struct X86State {
    registers: [Option<u64>; 16],
    info: iced_x86::InstructionInfoFactory,
}

impl Default for X86State {
    fn default() -> Self {
        Self {
            registers: [None; 16],
            info: iced_x86::InstructionInfoFactory::new(),
        }
    }
}

fn register_slot(register: iced_x86::Register) -> Option<usize> {
    use iced_x86::Register;
    let full = register.full_register();
    (Register::RAX <= full && full <= Register::R15).then(|| full as usize - Register::RAX as usize)
}

impl X86State {
    fn value(&self, register: iced_x86::Register) -> Option<u64> {
        let value = self
            .registers
            .get(register_slot(register)?)
            .copied()
            .flatten()?;
        match register.size() {
            8 => Some(value),
            4 => Some(value & 0xffff_ffff),
            _ => None,
        }
    }

    fn resolved(&self) -> Resolved {
        use iced_x86::Register::{R8, R9, R10, RAX, RDI, RDX, RSI};
        Resolved {
            number: self.value(RAX).and_then(|n| u32::try_from(n).ok()),
            args: [RDI, RSI, RDX, R10, R8, R9].map(|r| self.value(r)),
        }
    }

    fn step(&mut self, instruction: &iced_x86::Instruction) {
        use iced_x86::{FlowControl, Mnemonic, OpAccess, OpKind};
        if instruction.is_invalid() || instruction.flow_control() != FlowControl::Next {
            self.registers.fill(None);
            return;
        }
        let destination = instruction.op0_register();
        let value = match instruction.mnemonic() {
            Mnemonic::Mov if instruction.op1_kind() == OpKind::Register => {
                self.value(instruction.op1_register())
            }
            Mnemonic::Mov => instruction.try_immediate(1).ok(),
            Mnemonic::Xor if destination == instruction.op1_register() => Some(0),
            _ => None,
        };
        // Use actual write semantics: CMP/TEST preserve constants, implicit and
        // partial writes invalidate them instead of leaving stale full registers.
        for used in self.info.info(instruction).used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                if let Some(slot) =
                    register_slot(used.register()).and_then(|slot| self.registers.get_mut(slot))
                {
                    *slot = None;
                }
            }
        }
        if matches!(instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Xor) {
            if let Some(slot) =
                register_slot(destination).and_then(|slot| self.registers.get_mut(slot))
            {
                *slot = match destination.size() {
                    8 => value,
                    4 => value.map(|v| v & 0xffff_ffff),
                    _ => None,
                };
            }
        }
    }
}

#[cfg(test)]
fn resolve_x86_syscall(region: &[u8], syscall_pos: usize) -> Resolved {
    let mut state = X86State::default();
    let mut decoder =
        iced_x86::Decoder::new(64, &region[..syscall_pos], iced_x86::DecoderOptions::NONE);
    while decoder.can_decode() {
        state.step(&decoder.decode());
    }
    state.resolved()
}

/// aarch64: fixed-width 4-byte instructions. Scan aligned words for `svc #0`
/// (`0xD4000001`); resolve the number (`x8`) and arguments (`x0..x5`) from
/// preceding `movz Xd, #imm16` loads.
fn scan_aarch64(elf: &Elf<'_>, bytes: &[u8], sites: &mut Sites) -> u64 {
    const SVC0: u32 = 0xD400_0001;
    let mut direct = 0u64;
    let mut budget = MAX_CANDIDATES;
    for (region_off, region) in exec_regions(elf, bytes) {
        for (word, insn) in region.as_chunks::<4>().0.iter().enumerate() {
            if u32::from_le_bytes([insn[0], insn[1], insn[2], insn[3]]) != SVC0 {
                continue;
            }
            direct += 1;
            if budget == 0 {
                continue;
            }
            budget -= 1;
            let res = resolve_aarch64_syscall(region, word * 4);
            if let Some(number) = res.number {
                sites.insert(
                    (region_off + word * 4) as u64,
                    Site {
                        name: aarch64_syscall_name(number).unwrap_or("unknown"),
                        number,
                        args: res.args,
                    },
                );
            }
        }
    }
    direct
}

/// Look back a small window for `movz Xd, #imm16` (no shift) into the number
/// register (`x8`) or an argument register (`x0..x5`), later writes winning.
/// Shifted `movz`/`movk` chains (immediates above 16 bits) aren't reconstructed,
/// so large argument constants may stay unresolved on aarch64.
fn resolve_aarch64_syscall(region: &[u8], svc_pos: usize) -> Resolved {
    const WINDOW_WORDS: usize = 12;
    let mut res = Resolved::default();
    let Some(window) = region.get(svc_pos.saturating_sub(WINDOW_WORDS * 4)..svc_pos) else {
        return res;
    };
    for insn in window.as_chunks::<4>().0 {
        let w = u32::from_le_bytes([insn[0], insn[1], insn[2], insn[3]]);
        // MOVZ (64-bit), hw = 0: bits [31:21] == 0xD2800000; Rd = w[4:0],
        // imm16 = w[20:5].
        if w & 0xFFE0_0000 != 0xD280_0000 {
            // Unknown writes/control flow must not preserve stale constants.
            if w != 0xD503_201F {
                res = Resolved::default();
            } // NOP
            continue;
        }
        let imm = (w >> 5) & 0xFFFF;
        match (w & 0x1F) as usize {
            rd @ 0..=5 => {
                if let Some(arg) = res.args.get_mut(rd) {
                    *arg = Some(u64::from(imm));
                }
            }
            8 => res.number = Some(imm),
            _ => {}
        }
    }
    res
}

// Linux ABI names from libc 0.2.189, src/unix/linux_like/linux/gnu/b64,
// indexed by syscall number (8 per row, the row's first number in the
// comment); `""` marks a number with no name in that table.
// Keep unknown numbers in the inventory; table completeness is not a match gate.
fn x86_64_syscall_name(nr: u32) -> Option<&'static str> {
    syscall_name(&X86_64_SYSCALLS, nr)
}

fn aarch64_syscall_name(nr: u32) -> Option<&'static str> {
    syscall_name(&AARCH64_SYSCALLS, nr)
}

fn syscall_name(table: &'static [&'static str], nr: u32) -> Option<&'static str> {
    let name = *table.get(usize::try_from(nr).ok()?)?;
    (!name.is_empty()).then_some(name)
}

#[rustfmt::skip]
static X86_64_SYSCALLS: [&str; 463] = [
    /*   0 */ "read", "write", "open", "close", "stat", "fstat", "lstat", "poll",
    /*   8 */ "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    /*  16 */ "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select",
    /*  24 */ "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
    /*  32 */ "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid",
    /*  40 */ "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg",
    /*  48 */ "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt",
    /*  56 */ "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname",
    /*  64 */ "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl",
    /*  72 */ "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd",
    /*  80 */ "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink",
    /*  88 */ "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask",
    /*  96 */ "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog",
    /* 104 */ "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
    /* 112 */ "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid",
    /* 120 */ "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending",
    /* 128 */ "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality",
    /* 136 */ "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam",
    /* 144 */ "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall",
    /* 152 */ "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex",
    /* 160 */ "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon",
    /* 168 */ "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module",
    /* 176 */ "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall",
    /* 184 */ "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr",
    /* 192 */ "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr",
    /* 200 */ "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy",
    /* 208 */ "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old",
    /* 216 */ "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime",
    /* 224 */ "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group",
    /* 232 */ "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy",
    /* 240 */ "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid",
    /* 248 */ "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch",
    /* 256 */ "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat",
    /* 264 */ "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
    /* 272 */ "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages",
    /* 280 */ "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime",
    /* 288 */ "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv",
    /* 296 */ "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at",
    /* 304 */ "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev",
    /* 312 */ "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create",
    /* 320 */ "kexec_file_load", "bpf", "execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2",
    /* 328 */ "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx", "", "rseq", "",
    /* 336 */ "", "", "", "", "", "", "", "",
    /* 344 */ "", "", "", "", "", "", "", "",
    /* 352 */ "", "", "", "", "", "", "", "",
    /* 360 */ "", "", "", "", "", "", "", "",
    /* 368 */ "", "", "", "", "", "", "", "",
    /* 376 */ "", "", "", "", "", "", "", "",
    /* 384 */ "", "", "", "", "", "", "", "",
    /* 392 */ "", "", "", "", "", "", "", "",
    /* 400 */ "", "", "", "", "", "", "", "",
    /* 408 */ "", "", "", "", "", "", "", "",
    /* 416 */ "", "", "", "", "", "", "", "",
    /* 424 */ "pidfd_send_signal", "io_uring_setup", "io_uring_enter", "io_uring_register", "open_tree", "move_mount", "fsopen", "fsconfig",
    /* 432 */ "fsmount", "fspick", "pidfd_open", "clone3", "close_range", "openat2", "pidfd_getfd", "faccessat2",
    /* 440 */ "process_madvise", "epoll_pwait2", "mount_setattr", "quotactl_fd", "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self", "memfd_secret",
    /* 448 */ "process_mrelease", "futex_waitv", "set_mempolicy_home_node", "", "fchmodat2", "", "", "",
    /* 456 */ "", "", "", "", "", "", "mseal",
];

#[rustfmt::skip]
static AARCH64_SYSCALLS: [&str; 463] = [
    /*   0 */ "io_setup", "io_destroy", "io_submit", "io_cancel", "io_getevents", "setxattr", "lsetxattr", "fsetxattr",
    /*   8 */ "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr",
    /*  16 */ "fremovexattr", "getcwd", "lookup_dcookie", "eventfd2", "epoll_create1", "epoll_ctl", "epoll_pwait", "dup",
    /*  24 */ "dup3", "fcntl", "inotify_init1", "inotify_add_watch", "inotify_rm_watch", "ioctl", "ioprio_set", "ioprio_get",
    /*  32 */ "flock", "mknodat", "mkdirat", "unlinkat", "symlinkat", "linkat", "", "umount2",
    /*  40 */ "mount", "pivot_root", "nfsservctl", "statfs", "fstatfs", "truncate", "ftruncate", "fallocate",
    /*  48 */ "faccessat", "chdir", "fchdir", "chroot", "fchmod", "fchmodat", "fchownat", "fchown",
    /*  56 */ "openat", "close", "vhangup", "pipe2", "quotactl", "getdents64", "lseek", "read",
    /*  64 */ "write", "readv", "writev", "pread64", "pwrite64", "preadv", "pwritev", "sendfile",
    /*  72 */ "pselect6", "ppoll", "signalfd4", "vmsplice", "splice", "tee", "readlinkat", "newfstatat",
    /*  80 */ "fstat", "sync", "fsync", "fdatasync", "", "timerfd_create", "timerfd_settime", "timerfd_gettime",
    /*  88 */ "utimensat", "acct", "capget", "capset", "personality", "exit", "exit_group", "waitid",
    /*  96 */ "set_tid_address", "unshare", "futex", "set_robust_list", "get_robust_list", "nanosleep", "getitimer", "setitimer",
    /* 104 */ "kexec_load", "init_module", "delete_module", "timer_create", "timer_gettime", "timer_getoverrun", "timer_settime", "timer_delete",
    /* 112 */ "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "syslog", "ptrace", "sched_setparam", "sched_setscheduler",
    /* 120 */ "sched_getscheduler", "sched_getparam", "sched_setaffinity", "sched_getaffinity", "sched_yield", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval",
    /* 128 */ "restart_syscall", "kill", "tkill", "tgkill", "sigaltstack", "rt_sigsuspend", "rt_sigaction", "rt_sigprocmask",
    /* 136 */ "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigreturn", "setpriority", "getpriority", "reboot", "setregid",
    /* 144 */ "setgid", "setreuid", "setuid", "setresuid", "getresuid", "setresgid", "getresgid", "setfsuid",
    /* 152 */ "setfsgid", "times", "setpgid", "getpgid", "getsid", "setsid", "getgroups", "setgroups",
    /* 160 */ "uname", "sethostname", "setdomainname", "", "", "getrusage", "umask", "prctl",
    /* 168 */ "getcpu", "gettimeofday", "settimeofday", "adjtimex", "getpid", "getppid", "getuid", "geteuid",
    /* 176 */ "getgid", "getegid", "gettid", "sysinfo", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
    /* 184 */ "mq_notify", "mq_getsetattr", "msgget", "msgctl", "msgrcv", "msgsnd", "semget", "semctl",
    /* 192 */ "semtimedop", "semop", "shmget", "shmctl", "shmat", "shmdt", "socket", "socketpair",
    /* 200 */ "bind", "listen", "accept", "connect", "getsockname", "getpeername", "sendto", "recvfrom",
    /* 208 */ "setsockopt", "getsockopt", "shutdown", "sendmsg", "recvmsg", "readahead", "brk", "munmap",
    /* 216 */ "mremap", "add_key", "request_key", "keyctl", "clone", "execve", "mmap", "fadvise64",
    /* 224 */ "swapon", "swapoff", "mprotect", "msync", "mlock", "munlock", "mlockall", "munlockall",
    /* 232 */ "mincore", "madvise", "remap_file_pages", "mbind", "get_mempolicy", "set_mempolicy", "migrate_pages", "move_pages",
    /* 240 */ "rt_tgsigqueueinfo", "perf_event_open", "accept4", "recvmmsg", "", "", "", "",
    /* 248 */ "", "", "", "", "", "", "", "",
    /* 256 */ "", "", "", "", "wait4", "prlimit64", "fanotify_init", "fanotify_mark",
    /* 264 */ "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", "setns", "sendmmsg", "process_vm_readv", "process_vm_writev",
    /* 272 */ "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create",
    /* 280 */ "bpf", "execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2", "pwritev2",
    /* 288 */ "pkey_mprotect", "pkey_alloc", "pkey_free", "statx", "", "rseq", "kexec_file_load", "",
    /* 296 */ "", "", "", "", "", "", "", "",
    /* 304 */ "", "", "", "", "", "", "", "",
    /* 312 */ "", "", "", "", "", "", "", "",
    /* 320 */ "", "", "", "", "", "", "", "",
    /* 328 */ "", "", "", "", "", "", "", "",
    /* 336 */ "", "", "", "", "", "", "", "",
    /* 344 */ "", "", "", "", "", "", "", "",
    /* 352 */ "", "", "", "", "", "", "", "",
    /* 360 */ "", "", "", "", "", "", "", "",
    /* 368 */ "", "", "", "", "", "", "", "",
    /* 376 */ "", "", "", "", "", "", "", "",
    /* 384 */ "", "", "", "", "", "", "", "",
    /* 392 */ "", "", "", "", "", "", "", "",
    /* 400 */ "", "", "", "", "", "", "", "",
    /* 408 */ "", "", "", "", "", "", "", "",
    /* 416 */ "", "", "", "", "", "", "", "",
    /* 424 */ "pidfd_send_signal", "io_uring_setup", "io_uring_enter", "io_uring_register", "open_tree", "move_mount", "fsopen", "fsconfig",
    /* 432 */ "fsmount", "fspick", "pidfd_open", "clone3", "close_range", "openat2", "pidfd_getfd", "faccessat2",
    /* 440 */ "process_madvise", "epoll_pwait2", "mount_setattr", "quotactl_fd", "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self", "memfd_secret",
    /* 448 */ "process_mrelease", "futex_waitv", "set_mempolicy_home_node", "", "", "", "", "",
    /* 456 */ "", "", "", "", "", "", "mseal",
];

#[cfg(test)]
mod tests;
