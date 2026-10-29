# Security policy

filefacts exists to parse files an attacker controls. A bug that lets such a
file misbehave the parser is a security bug, and we want to hear about it.

## Reporting a vulnerability

Report privately through GitHub's
[security advisories](https://github.com/atomdrift-project/filefacts/security/advisories/new)
("Report a vulnerability" on the repository's Security tab). Please do not
open a public issue, pull request or discussion for a suspected vulnerability.

Include the filefacts version or commit, the platform, the command or API
call, and the smallest input that reproduces the problem. Attach malicious or
very large inputs compressed (zstd, gzip or a password-protected zip with the
password in the report). If an input is a live malware specimen, say so.

We aim to acknowledge a report within a week, agree on a fix and disclosure
date with you, and credit you in the advisory unless you prefer otherwise.

## Scope

In scope is anything a hostile input can cause in the library or the
`filefacts` CLI:

- **Panics** that escape into the caller, or aborts of the process (for
  example a stack overflow), on any input.
- **Hangs**: an input that runs past its work or time budget, or makes the
  cost of a parse grow super-linearly in its size.
- **Unbounded memory**: an allocation driven by a file-supplied length or
  count, or a decompression that ignores its cap.
- **rizin sandbox escapes**: the optional rizin subprocess outliving its
  timeout or resource limits, escaping its process group or job, inheriting
  environment or descriptors it should not, or writing outside its temporary
  input.
- **Signature verdict errors**: a code-signing result (Authenticode, CMS,
  Mach-O code signature, APK, CRX, JAR and similar) reported as verified or
  trusted when the signature, digest or chain does not support it.
- **Fact forgery**: an input that makes filefacts report a fact that belongs to
  filefacts itself, such as file hashes, identity or registry data, rather
  than to the file's contents.
- **Disk cache corruption**: a cache entry that makes a later open return
  another file's facts.

Out of scope:

- Facts that are merely incomplete or imprecise on unusual but benign input.
  These are ordinary bugs; open an issue.
- Behaviour of rizin itself, beyond the containment filefacts applies to it.
- Vulnerabilities in dependencies that filefacts does not reach; report those
  upstream. We track advisories with `cargo audit` in CI, and the accepted
  exceptions, with their reasons, are in `.cargo/audit.toml`.

## Supported versions

Security fixes land on `main` and in the next release. Only the latest release
receives them.
