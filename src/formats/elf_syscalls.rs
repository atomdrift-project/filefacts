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
    let mut ranges: Vec<(usize, usize)> = elf
        .section_headers
        .iter()
        .filter(|sh| sh.sh_flags & u64::from(SHF_EXECINSTR) != 0 && sh.sh_type != SHT_NOBITS)
        .filter_map(|sh| {
            Some((
                usize::try_from(sh.sh_offset).ok()?,
                usize::try_from(sh.sh_size).ok()?,
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
                ))
            })
            .collect();
    }
    ranges.sort_unstable();
    let mut covered = 0;
    ranges.into_iter().filter_map(move |(start, size)| {
        // A truncated file still holds the head of its code; scan what is
        // present rather than dropping the whole region.
        let end = start.checked_add(size)?.min(bytes.len());
        if end <= start || end <= covered {
            return None;
        }
        let start = start.max(covered);
        let region = bytes.get(start..end)?;
        covered = end;
        Some((start, region))
    })
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

// Linux ABI names from libc 0.2.189, src/unix/linux_like/linux/gnu/b64.
// Keep unknown numbers in the inventory; table completeness is not a match gate.
fn x86_64_syscall_name(nr: u32) -> Option<&'static str> {
    Some(match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        15 => "rt_sigreturn",
        16 => "ioctl",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        21 => "access",
        22 => "pipe",
        23 => "select",
        24 => "sched_yield",
        25 => "mremap",
        26 => "msync",
        27 => "mincore",
        28 => "madvise",
        29 => "shmget",
        30 => "shmat",
        31 => "shmctl",
        32 => "dup",
        33 => "dup2",
        34 => "pause",
        35 => "nanosleep",
        36 => "getitimer",
        37 => "alarm",
        38 => "setitimer",
        39 => "getpid",
        40 => "sendfile",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        48 => "shutdown",
        49 => "bind",
        50 => "listen",
        51 => "getsockname",
        52 => "getpeername",
        53 => "socketpair",
        54 => "setsockopt",
        55 => "getsockopt",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        63 => "uname",
        64 => "semget",
        65 => "semop",
        66 => "semctl",
        67 => "shmdt",
        68 => "msgget",
        69 => "msgsnd",
        70 => "msgrcv",
        71 => "msgctl",
        72 => "fcntl",
        73 => "flock",
        74 => "fsync",
        75 => "fdatasync",
        76 => "truncate",
        77 => "ftruncate",
        78 => "getdents",
        79 => "getcwd",
        80 => "chdir",
        81 => "fchdir",
        82 => "rename",
        83 => "mkdir",
        84 => "rmdir",
        85 => "creat",
        86 => "link",
        87 => "unlink",
        88 => "symlink",
        89 => "readlink",
        90 => "chmod",
        91 => "fchmod",
        92 => "chown",
        93 => "fchown",
        94 => "lchown",
        95 => "umask",
        96 => "gettimeofday",
        97 => "getrlimit",
        98 => "getrusage",
        99 => "sysinfo",
        100 => "times",
        101 => "ptrace",
        102 => "getuid",
        103 => "syslog",
        104 => "getgid",
        105 => "setuid",
        106 => "setgid",
        107 => "geteuid",
        108 => "getegid",
        109 => "setpgid",
        110 => "getppid",
        111 => "getpgrp",
        112 => "setsid",
        113 => "setreuid",
        114 => "setregid",
        115 => "getgroups",
        116 => "setgroups",
        117 => "setresuid",
        118 => "getresuid",
        119 => "setresgid",
        120 => "getresgid",
        121 => "getpgid",
        122 => "setfsuid",
        123 => "setfsgid",
        124 => "getsid",
        125 => "capget",
        126 => "capset",
        127 => "rt_sigpending",
        128 => "rt_sigtimedwait",
        129 => "rt_sigqueueinfo",
        130 => "rt_sigsuspend",
        131 => "sigaltstack",
        132 => "utime",
        133 => "mknod",
        134 => "uselib",
        135 => "personality",
        136 => "ustat",
        137 => "statfs",
        138 => "fstatfs",
        139 => "sysfs",
        140 => "getpriority",
        141 => "setpriority",
        142 => "sched_setparam",
        143 => "sched_getparam",
        144 => "sched_setscheduler",
        145 => "sched_getscheduler",
        146 => "sched_get_priority_max",
        147 => "sched_get_priority_min",
        148 => "sched_rr_get_interval",
        149 => "mlock",
        150 => "munlock",
        151 => "mlockall",
        152 => "munlockall",
        153 => "vhangup",
        154 => "modify_ldt",
        155 => "pivot_root",
        156 => "_sysctl",
        157 => "prctl",
        158 => "arch_prctl",
        159 => "adjtimex",
        160 => "setrlimit",
        161 => "chroot",
        162 => "sync",
        163 => "acct",
        164 => "settimeofday",
        165 => "mount",
        166 => "umount2",
        167 => "swapon",
        168 => "swapoff",
        169 => "reboot",
        170 => "sethostname",
        171 => "setdomainname",
        172 => "iopl",
        173 => "ioperm",
        174 => "create_module",
        175 => "init_module",
        176 => "delete_module",
        177 => "get_kernel_syms",
        178 => "query_module",
        179 => "quotactl",
        180 => "nfsservctl",
        181 => "getpmsg",
        182 => "putpmsg",
        183 => "afs_syscall",
        184 => "tuxcall",
        185 => "security",
        186 => "gettid",
        187 => "readahead",
        188 => "setxattr",
        189 => "lsetxattr",
        190 => "fsetxattr",
        191 => "getxattr",
        192 => "lgetxattr",
        193 => "fgetxattr",
        194 => "listxattr",
        195 => "llistxattr",
        196 => "flistxattr",
        197 => "removexattr",
        198 => "lremovexattr",
        199 => "fremovexattr",
        200 => "tkill",
        201 => "time",
        202 => "futex",
        203 => "sched_setaffinity",
        204 => "sched_getaffinity",
        205 => "set_thread_area",
        206 => "io_setup",
        207 => "io_destroy",
        208 => "io_getevents",
        209 => "io_submit",
        210 => "io_cancel",
        211 => "get_thread_area",
        212 => "lookup_dcookie",
        213 => "epoll_create",
        214 => "epoll_ctl_old",
        215 => "epoll_wait_old",
        216 => "remap_file_pages",
        217 => "getdents64",
        218 => "set_tid_address",
        219 => "restart_syscall",
        220 => "semtimedop",
        221 => "fadvise64",
        222 => "timer_create",
        223 => "timer_settime",
        224 => "timer_gettime",
        225 => "timer_getoverrun",
        226 => "timer_delete",
        227 => "clock_settime",
        228 => "clock_gettime",
        229 => "clock_getres",
        230 => "clock_nanosleep",
        231 => "exit_group",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        234 => "tgkill",
        235 => "utimes",
        236 => "vserver",
        237 => "mbind",
        238 => "set_mempolicy",
        239 => "get_mempolicy",
        240 => "mq_open",
        241 => "mq_unlink",
        242 => "mq_timedsend",
        243 => "mq_timedreceive",
        244 => "mq_notify",
        245 => "mq_getsetattr",
        246 => "kexec_load",
        247 => "waitid",
        248 => "add_key",
        249 => "request_key",
        250 => "keyctl",
        251 => "ioprio_set",
        252 => "ioprio_get",
        253 => "inotify_init",
        254 => "inotify_add_watch",
        255 => "inotify_rm_watch",
        256 => "migrate_pages",
        257 => "openat",
        258 => "mkdirat",
        259 => "mknodat",
        260 => "fchownat",
        261 => "futimesat",
        262 => "newfstatat",
        263 => "unlinkat",
        264 => "renameat",
        265 => "linkat",
        266 => "symlinkat",
        267 => "readlinkat",
        268 => "fchmodat",
        269 => "faccessat",
        270 => "pselect6",
        271 => "ppoll",
        272 => "unshare",
        273 => "set_robust_list",
        274 => "get_robust_list",
        275 => "splice",
        276 => "tee",
        277 => "sync_file_range",
        278 => "vmsplice",
        279 => "move_pages",
        280 => "utimensat",
        281 => "epoll_pwait",
        282 => "signalfd",
        283 => "timerfd_create",
        284 => "eventfd",
        285 => "fallocate",
        286 => "timerfd_settime",
        287 => "timerfd_gettime",
        288 => "accept4",
        289 => "signalfd4",
        290 => "eventfd2",
        291 => "epoll_create1",
        292 => "dup3",
        293 => "pipe2",
        294 => "inotify_init1",
        295 => "preadv",
        296 => "pwritev",
        297 => "rt_tgsigqueueinfo",
        298 => "perf_event_open",
        299 => "recvmmsg",
        300 => "fanotify_init",
        301 => "fanotify_mark",
        302 => "prlimit64",
        303 => "name_to_handle_at",
        304 => "open_by_handle_at",
        305 => "clock_adjtime",
        306 => "syncfs",
        307 => "sendmmsg",
        308 => "setns",
        309 => "getcpu",
        310 => "process_vm_readv",
        311 => "process_vm_writev",
        312 => "kcmp",
        313 => "finit_module",
        314 => "sched_setattr",
        315 => "sched_getattr",
        316 => "renameat2",
        317 => "seccomp",
        318 => "getrandom",
        319 => "memfd_create",
        320 => "kexec_file_load",
        321 => "bpf",
        322 => "execveat",
        323 => "userfaultfd",
        324 => "membarrier",
        325 => "mlock2",
        326 => "copy_file_range",
        327 => "preadv2",
        328 => "pwritev2",
        329 => "pkey_mprotect",
        330 => "pkey_alloc",
        331 => "pkey_free",
        332 => "statx",
        334 => "rseq",
        424 => "pidfd_send_signal",
        425 => "io_uring_setup",
        426 => "io_uring_enter",
        427 => "io_uring_register",
        428 => "open_tree",
        429 => "move_mount",
        430 => "fsopen",
        431 => "fsconfig",
        432 => "fsmount",
        433 => "fspick",
        434 => "pidfd_open",
        435 => "clone3",
        436 => "close_range",
        437 => "openat2",
        438 => "pidfd_getfd",
        439 => "faccessat2",
        440 => "process_madvise",
        441 => "epoll_pwait2",
        442 => "mount_setattr",
        443 => "quotactl_fd",
        444 => "landlock_create_ruleset",
        445 => "landlock_add_rule",
        446 => "landlock_restrict_self",
        447 => "memfd_secret",
        448 => "process_mrelease",
        449 => "futex_waitv",
        450 => "set_mempolicy_home_node",
        452 => "fchmodat2",
        462 => "mseal",
        _ => return None,
    })
}

fn aarch64_syscall_name(nr: u32) -> Option<&'static str> {
    Some(match nr {
        0 => "io_setup",
        1 => "io_destroy",
        2 => "io_submit",
        3 => "io_cancel",
        4 => "io_getevents",
        5 => "setxattr",
        6 => "lsetxattr",
        7 => "fsetxattr",
        8 => "getxattr",
        9 => "lgetxattr",
        10 => "fgetxattr",
        11 => "listxattr",
        12 => "llistxattr",
        13 => "flistxattr",
        14 => "removexattr",
        15 => "lremovexattr",
        16 => "fremovexattr",
        17 => "getcwd",
        18 => "lookup_dcookie",
        19 => "eventfd2",
        20 => "epoll_create1",
        21 => "epoll_ctl",
        22 => "epoll_pwait",
        23 => "dup",
        24 => "dup3",
        25 => "fcntl",
        26 => "inotify_init1",
        27 => "inotify_add_watch",
        28 => "inotify_rm_watch",
        29 => "ioctl",
        30 => "ioprio_set",
        31 => "ioprio_get",
        32 => "flock",
        33 => "mknodat",
        34 => "mkdirat",
        35 => "unlinkat",
        36 => "symlinkat",
        37 => "linkat",
        39 => "umount2",
        40 => "mount",
        41 => "pivot_root",
        42 => "nfsservctl",
        43 => "statfs",
        44 => "fstatfs",
        45 => "truncate",
        46 => "ftruncate",
        47 => "fallocate",
        48 => "faccessat",
        49 => "chdir",
        50 => "fchdir",
        51 => "chroot",
        52 => "fchmod",
        53 => "fchmodat",
        54 => "fchownat",
        55 => "fchown",
        56 => "openat",
        57 => "close",
        58 => "vhangup",
        59 => "pipe2",
        60 => "quotactl",
        61 => "getdents64",
        62 => "lseek",
        63 => "read",
        64 => "write",
        65 => "readv",
        66 => "writev",
        67 => "pread64",
        68 => "pwrite64",
        69 => "preadv",
        70 => "pwritev",
        71 => "sendfile",
        72 => "pselect6",
        73 => "ppoll",
        74 => "signalfd4",
        75 => "vmsplice",
        76 => "splice",
        77 => "tee",
        78 => "readlinkat",
        79 => "newfstatat",
        80 => "fstat",
        81 => "sync",
        82 => "fsync",
        83 => "fdatasync",
        85 => "timerfd_create",
        86 => "timerfd_settime",
        87 => "timerfd_gettime",
        88 => "utimensat",
        89 => "acct",
        90 => "capget",
        91 => "capset",
        92 => "personality",
        93 => "exit",
        94 => "exit_group",
        95 => "waitid",
        96 => "set_tid_address",
        97 => "unshare",
        98 => "futex",
        99 => "set_robust_list",
        100 => "get_robust_list",
        101 => "nanosleep",
        102 => "getitimer",
        103 => "setitimer",
        104 => "kexec_load",
        105 => "init_module",
        106 => "delete_module",
        107 => "timer_create",
        108 => "timer_gettime",
        109 => "timer_getoverrun",
        110 => "timer_settime",
        111 => "timer_delete",
        112 => "clock_settime",
        113 => "clock_gettime",
        114 => "clock_getres",
        115 => "clock_nanosleep",
        116 => "syslog",
        117 => "ptrace",
        118 => "sched_setparam",
        119 => "sched_setscheduler",
        120 => "sched_getscheduler",
        121 => "sched_getparam",
        122 => "sched_setaffinity",
        123 => "sched_getaffinity",
        124 => "sched_yield",
        125 => "sched_get_priority_max",
        126 => "sched_get_priority_min",
        127 => "sched_rr_get_interval",
        128 => "restart_syscall",
        129 => "kill",
        130 => "tkill",
        131 => "tgkill",
        132 => "sigaltstack",
        133 => "rt_sigsuspend",
        134 => "rt_sigaction",
        135 => "rt_sigprocmask",
        136 => "rt_sigpending",
        137 => "rt_sigtimedwait",
        138 => "rt_sigqueueinfo",
        139 => "rt_sigreturn",
        140 => "setpriority",
        141 => "getpriority",
        142 => "reboot",
        143 => "setregid",
        144 => "setgid",
        145 => "setreuid",
        146 => "setuid",
        147 => "setresuid",
        148 => "getresuid",
        149 => "setresgid",
        150 => "getresgid",
        151 => "setfsuid",
        152 => "setfsgid",
        153 => "times",
        154 => "setpgid",
        155 => "getpgid",
        156 => "getsid",
        157 => "setsid",
        158 => "getgroups",
        159 => "setgroups",
        160 => "uname",
        161 => "sethostname",
        162 => "setdomainname",
        165 => "getrusage",
        166 => "umask",
        167 => "prctl",
        168 => "getcpu",
        169 => "gettimeofday",
        170 => "settimeofday",
        171 => "adjtimex",
        172 => "getpid",
        173 => "getppid",
        174 => "getuid",
        175 => "geteuid",
        176 => "getgid",
        177 => "getegid",
        178 => "gettid",
        179 => "sysinfo",
        180 => "mq_open",
        181 => "mq_unlink",
        182 => "mq_timedsend",
        183 => "mq_timedreceive",
        184 => "mq_notify",
        185 => "mq_getsetattr",
        186 => "msgget",
        187 => "msgctl",
        188 => "msgrcv",
        189 => "msgsnd",
        190 => "semget",
        191 => "semctl",
        192 => "semtimedop",
        193 => "semop",
        194 => "shmget",
        195 => "shmctl",
        196 => "shmat",
        197 => "shmdt",
        198 => "socket",
        199 => "socketpair",
        200 => "bind",
        201 => "listen",
        202 => "accept",
        203 => "connect",
        204 => "getsockname",
        205 => "getpeername",
        206 => "sendto",
        207 => "recvfrom",
        208 => "setsockopt",
        209 => "getsockopt",
        210 => "shutdown",
        211 => "sendmsg",
        212 => "recvmsg",
        213 => "readahead",
        214 => "brk",
        215 => "munmap",
        216 => "mremap",
        217 => "add_key",
        218 => "request_key",
        219 => "keyctl",
        220 => "clone",
        221 => "execve",
        222 => "mmap",
        223 => "fadvise64",
        224 => "swapon",
        225 => "swapoff",
        226 => "mprotect",
        227 => "msync",
        228 => "mlock",
        229 => "munlock",
        230 => "mlockall",
        231 => "munlockall",
        232 => "mincore",
        233 => "madvise",
        234 => "remap_file_pages",
        235 => "mbind",
        236 => "get_mempolicy",
        237 => "set_mempolicy",
        238 => "migrate_pages",
        239 => "move_pages",
        240 => "rt_tgsigqueueinfo",
        241 => "perf_event_open",
        242 => "accept4",
        243 => "recvmmsg",
        260 => "wait4",
        261 => "prlimit64",
        262 => "fanotify_init",
        263 => "fanotify_mark",
        264 => "name_to_handle_at",
        265 => "open_by_handle_at",
        266 => "clock_adjtime",
        267 => "syncfs",
        268 => "setns",
        269 => "sendmmsg",
        270 => "process_vm_readv",
        271 => "process_vm_writev",
        272 => "kcmp",
        273 => "finit_module",
        274 => "sched_setattr",
        275 => "sched_getattr",
        276 => "renameat2",
        277 => "seccomp",
        278 => "getrandom",
        279 => "memfd_create",
        280 => "bpf",
        281 => "execveat",
        282 => "userfaultfd",
        283 => "membarrier",
        284 => "mlock2",
        285 => "copy_file_range",
        286 => "preadv2",
        287 => "pwritev2",
        288 => "pkey_mprotect",
        289 => "pkey_alloc",
        290 => "pkey_free",
        291 => "statx",
        293 => "rseq",
        294 => "kexec_file_load",
        424 => "pidfd_send_signal",
        425 => "io_uring_setup",
        426 => "io_uring_enter",
        427 => "io_uring_register",
        428 => "open_tree",
        429 => "move_mount",
        430 => "fsopen",
        431 => "fsconfig",
        432 => "fsmount",
        433 => "fspick",
        434 => "pidfd_open",
        435 => "clone3",
        436 => "close_range",
        437 => "openat2",
        438 => "pidfd_getfd",
        439 => "faccessat2",
        440 => "process_madvise",
        441 => "epoll_pwait2",
        442 => "mount_setattr",
        443 => "quotactl_fd",
        444 => "landlock_create_ruleset",
        445 => "landlock_add_rule",
        446 => "landlock_restrict_self",
        447 => "memfd_secret",
        448 => "process_mrelease",
        449 => "futex_waitv",
        450 => "set_mempolicy_home_node",
        462 => "mseal",
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
