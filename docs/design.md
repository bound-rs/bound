# Design

## Partial application for processes

A process invocation has five inputs:

```text
(program, argv, files, env, cwd)
```

bound fixes some of them now and produces a new program that takes the
rest later, the way partial application turns `f(a, b)` into `g(b)`:

| Input | Bound now | Supplied later |
|---|---|---|
| program | external name or embedded file | — |
| argv | literal arguments, `@file:` paths | run-time arguments at `@args` (or the end) |
| files | `@file:`, `--include` | — |
| env | `--env` bindings | the caller's environment |
| cwd | `--cwd bundle` | the caller's directory (`--cwd inherit`) |

Everything else follows from taking this model literally:

* The result must *be* a program: a native executable that runs anywhere
  the original invocation could, without bound installed.
* The core knows nothing about Python, Node, shells or any other tool.
  `grep`, `python`, `powershell.exe` and a custom binary are all just
  "executable + argv + environment + files". A script needs its interpreter
  exactly as it would on the command line.
* Arguments are data, never code: no shell is ever involved, and argument
  boundaries survive exactly.
* Binding is explicit: bound embeds what you name and nothing else, and
  `bound inspect` shows what the artifact still needs from the system.

## Architecture

```text
             build time                                  run time
  ┌───────────────────────────────┐          ┌──────────────────────────────────┐
  │ bound (CLI)                   │          │ artifact = launcher + bundle     │
  │  parse invocation, directives │          │  1. read own file, footer        │
  │  collect resources            │  writes  │  2. validate manifest            │
  │  choose launcher (platform)   │ ───────▶ │  3. materialize (verify hashes)  │
  │  write launcher+payload+      │          │  4. plan argv/env/cwd            │
  │        manifest+footer        │          │  5. exec (Unix) or spawn+wait    │
  └───────────────────────────────┘          └──────────────────────────────────┘
               │                                          │
               ▼                                          ▼
      bound-format (shared) ◀──── same parser, validator ──── bound-runtime
               │                                          │
               └──────────────▶ bound-platform ◀──────────┘
                     (the only OS-specific code)
```

| Crate | Responsibility |
|---|---|
| `bound-format` | The on-disk format: footer, manifest types, resource names, platform strings, hashing, reading (streaming, verifying), writing (deterministic), full verification. No OS calls beyond reading and writing a stream. |
| `bound-platform` | Narrow OS layer: private directories and trusted locations, exclusive file creation, cloning, safe input opening, symlink creation, tree removal, entry classification, opening the running executable, program lookup (`execvp`-style on Unix, `CreateProcess`-style on Windows), `exec`, the reaper, supervised spawn in a job object with console handling (Windows), set-ID refusal. `unix.rs` and `windows.rs` implement it. |
| `bound-runtime` | The launcher's logic: open self, validate, materialize (with the cache), plan, launch; and the cache itself. |
| `bound` | CLI parsing, build pipeline (parallel), launcher discovery, `inspect`, `verify`, `cache`, and the two binaries `bound` and `bound-launcher`. |
| `bound-tests` | End-to-end tests and the `bound-fixture` target program. |

Shared code never calls platform APIs directly and never assumes Unix
semantics. Paths travel as `Path`/`OsStr`; resource names are
platform-neutral (`ResourcePath`) and become native paths only at the
moment a file is created, through a conversion that re-checks Windows
naming rules on Windows.

## The artifact

An artifact is the launcher executable with the bundle appended (see
`docs/format.md`):

```text
[launcher][payload][manifest][footer]
```

Appending keeps the executable valid on all three formats: loaders map
only what the headers describe. The fixed-size footer at the end of the
bound regions locates everything else, so the launcher finds its data by
reading 88 bytes near the end of its own file. Only code signing needs
header changes: a Mach-O artifact's `__LINKEDIT` segment is extended over
the bundle and the whole file is signed ad hoc, and platform signatures
(Mach-O, Authenticode) may follow the footer, with the few header fields
they rewrite left out of the launcher's hash (see "Code signatures" in
`docs/format.md`).

The launcher is a separate small binary (`bound-launcher`, about 0.6 MB)
rather than a copy of `bound` itself. This keeps artifacts small, keeps the
build logic out of every artifact, and makes the launcher an input like any
other: the CLI picks one, identifies its platform from its executable
header, and records that platform in the manifest. Output naming (`.exe`)
and file-name rules follow the *launcher's* platform, not the host's. The
release profile optimizes for size (`opt-level = "s"`, `panic = "abort"`):
measured against `opt-level = 3`, the launcher is 22% smaller and no
slower, since launches spend their time in system calls, hashing and
decompression.

### Cross-platform builds

Today bound uses the launcher installed next to it, which is built for the
host. Because the platform is read from the launcher and everything after
the launcher is platform-independent, cross-target builds need no format
change, only a way to choose another launcher:

```sh
bound --launcher path/to/windows/bound-launcher.exe -o tool -- …   # works today
bound --target x86_64-pc-windows-msvc -o tool -- …                  # future: picks a launcher by target triple
```

A future `--target` would map a target triple to a launcher shipped with
bound (for example `lib/bound/launchers/<triple>/`). Inputs that depend on
the build host would then need care: executable bits read on Windows,
program lookup in the host's `PATH` for `--embed-program`, and platform
strings that are valid on one platform but not another (the manifest
validator already rejects those).

## Build pipeline

1. **Parse** the invocation. The first word is the program; each following
   argument is a literal, `@args`, `@file:PATH`, or `@@`-escaped literal.
   If `@args` is absent it is appended, so every manifest states exactly
   where run-time arguments go.
2. **Resolve the program.** External: recorded as written; the build warns
   if a bare name is not found in `PATH` on this machine, or if a relative
   path (`./tool`) would be resolved against the run-time working
   directory. Embedded: a path is read as is; a bare name is looked up in
   `PATH` now (and the build says which file it embedded). For Windows
   targets the embedded program is named with `.exe` if it has no
   extension.
3. **Collect resources** from `@file:` arguments and environment values,
   `--include` and `--include-as`. Each input is placed by a simple rule
   (its relative path, or its final name when it lies outside the current
   directory), trees are walked without following links, and conflicts are
   rejected: the same place claimed twice (unless by the same file), a
   file where a directory is needed, names differing only by case.
4. **Validate the tree** (names under the target platform's rules,
   symlink resolution) before any content is written.
5. **Check the output**: append `.exe` for Windows targets, refuse to
   overwrite without `--force`, and refuse outputs that are inputs or lie
   inside an included directory (compared on canonical paths,
   case-insensitively on Windows and macOS).
6. **Write** to a private temporary file next to the output: launcher, then
   each distinct content compressed once, then the manifest and footer.
   Files are read, hashed and compressed by up to 8 threads, in batches of
   consecutive files (at most 32 MiB or 1,024 files each), and written in
   manifest order, so the output is the same with any number of threads;
   files of 8 MiB or more are streamed instead, and zstd compresses them
   with threads of its own. Each input is opened without following a final
   link unless the user named it, never blocking on special files, and
   must still be the file found while walking (same device and inode on
   Unix). The writer fills in the launcher, payload and blob tables itself,
   validates the manifest, and decodes what it wrote back before writing
   the footer (and, for Mach-O, the signature). Finally the file gets its permissions (executable by all that
   the umask allows), is synced and moved into place: a hard link when not
   forcing (which fails if anything appeared at the destination
   meanwhile), falling back to a rename that refuses to replace
   (`renameat2(RENAME_NOREPLACE)`, `renamex_np(RENAME_EXCL)`,
   `MoveFileExW`) where hard links are unsupported; a rename when forcing.

## Run-time lifecycle

1. **Refuse set-ID** execution (Unix).
2. **Open self**: `/proc/self/exe` on Linux, the path the OS reports
   elsewhere. Read the footer, the manifest (bounded), check its hash,
   decode strictly, validate completely, applying the stricter of the artifact's
   and the host's file-name rules.
3. **Run-time arguments** are rejected if the template has no `@args`.
4. **Provide the bundle directory** if the artifact has resources or uses
   `--cwd bundle`:
   * **Private** (the default): create a new private directory
     (`bound-` + 16 random hex digits) in the temporary directory; start
     the reaper that will remove it (see below); create directories and
     files in manifest order (parents first), each with an exclusive
     create, streaming and hashing the content (any mismatch aborts and
     removes the directory); create symlinks last. Contents of 1 MiB or
     more come from the cache when it has them (cloned or copied), and are
     put there otherwise.
   * **Shared** (`--bundle shared`): use the artifact's directory in the
     cache (keyed by the manifest digest) if it is sealed: a real
     directory of this user that nobody can write to. Otherwise
     materialize into a staging directory next to it, flush everything,
     make it read-only and rename it into place; a concurrent run that
     wins the race is simply used. Flushing is done as a group, because
     file-by-file flushes cost a device cache flush (macOS) or a journal
     commit (Linux) each, which made first runs of bundles with thousands
     of files take many seconds: Linux flushes the file system once
     (`syncfs`), macOS sends each file to the device (`fsync`) and then
     flushes the device's cache once (`F_FULLFSYNC`). Windows offers no
     grouped flush to unprivileged processes, and flushing file by file
     also triggers another antivirus scan of each file (a minute for
     10,000 files), so Windows relies on the NTFS journal alone. Without a usable cache, fall back to a
     private directory.
5. **Plan** the invocation (pure function, unit-tested): substitute
   resources with absolute native paths under the root, splice in run-time
   arguments, apply environment bindings, set or remove `BOUND_ROOT`,
   choose the working directory.
6. **Launch**. A bare program name is looked up as the platform would
   (`execvp`'s rules on Unix, `CreateProcess`'s on Windows), passing over
   the artifact itself and any copy of it, recognized by its manifest
   digest in the footer. So an artifact named like the program it wraps
   runs the next one in `PATH` instead of itself.
   * Unix: `exec`. The program takes over the process: same PID, parent,
     signals, terminal and exit status. `argv[0]` is the name as written,
     as with `execvp`.
   * Windows: spawn in a kill-on-close job, wait, exit with the program's
     exit code.
7. Errors before the program starts exit with 125, 126 (not executable)
   or 127 (not found), with a message naming the artifact.

### The reaper

Cleaning up after `exec` needs a process that outlives the launcher. On
Unix the reaper is started with a double fork before anything is
extracted, so it covers every way the run can end: the program exiting,
the launcher failing, a signal during extraction, even `SIGKILL`. On
Windows it is a detached second copy of the artifact, started on a
background thread once the program runs (two process creations at once
would delay the program); if the program is done before the reaper is up,
the launcher removes the directory itself. It is invisible to the program: not its
child, in another session, holding none of the caller's descriptors or
handles. It learns that the process has exited through a pidfd, kqueue, a
process handle, or (on old Linux kernels) by polling the process's start
time, which also guards against PID reuse. Removal therefore happens after
the caller has seen the exit status, which also makes large bundles cheaper
for the caller: cleaning up 10,000 files no longer delays it.

### Why fresh directories, and the cache

Resources are immutable sources: by default each run gets its own copy, so
a program that modifies or deletes its files affects only that run,
concurrent runs never interfere, and a crashed run cannot corrupt the next
one. The cost is extraction on every run. Two cache features reduce it
without giving up those properties where they matter:

* **Large contents** (1 MiB or more) are decoded once into a per-user,
  content-addressed cache (keyed by SHA-256) and cloned from there
  (`clonefile` on APFS, `FICLONE` on Btrfs and XFS) or copied. A clone is
  copy-on-write, so the run's copy stays private. Entries are written
  under a staging name, verified as always, flushed and renamed into
  place, so an entry that exists is complete; they are trusted afterwards
  (the cache is private to the user; same-user attackers are outside the
  threat model, see `docs/security.md`).
* **Shared bundles** trade the private copy for zero extraction: one
  read-only directory per artifact and user, which later runs `exec` into
  directly. This is opt-in, because a program must not modify its bundle.

The cache is never required: if it is turned off (`BOUND_CACHE=0`), or
cannot be created or trusted, everything is read from the artifact. It
does not evict entries on its own; `bound cache clean` does.

### Bundle root

`BOUND_ROOT` is the only channel by which a program learns where its
bundle is. It is set exactly when a bundle directory exists, and removed
otherwise, so a nested artifact never sees its parent's root. Its value is
an ordinary absolute path (canonical on Unix, a normal drive path on
Windows), identical to the working directory when `--cwd bundle` is used.

## Process semantics per platform

The launcher aims to be invisible: the program should behave as if it had
been started directly.

**Unix.** The launcher always `exec`s: there is no relaying, and nothing
to get wrong. The program has the caller's signal mask and dispositions
(`SIGPIPE` included: its original disposition is captured by a constructor
before Rust's runtime replaces it, and restored for the program), the
caller's file descriptors, process group and terminal. Cleanup is the
reaper's job.

**Windows.** The program is a child sharing the console. The launcher
ignores Ctrl+C and Ctrl+Break while it runs (every process on the console
receives them), waits, and exits with the program's exact 32-bit code. The
program runs in a job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
(and silent breakaway for its own children), so terminating the launcher
terminates the program, as with `py.exe`. Program lookup follows the order
of `CreateProcess` in the Rust standard library, plus a `PATHEXT` fallback
over absolute `PATH` entries so that `npm` finds `npm.cmd` as it would in a
shell. Arguments go through the standard
library's MSVC quoting, and batch files through its hardened `cmd.exe`
escaping.

## Composition

A bound artifact is an executable, so binding one again just works:

```sh
bound -o reliable-curl -- curl --retry 5
bound --embed-program -o api-curl -- ./reliable-curl -H @file:headers.txt
```

At run time the outer launcher materializes `reliable-curl` and
`headers.txt`, then runs the inner artifact, whose launcher runs `curl`.
`bound inspect` recognizes an embedded bound artifact and explains the
chain ("embedded bound artifact … which runs external program curl").

**Flattening** (a future optimization) would merge the chain into one
artifact: the inner manifest's argument template is substituted into the
outer program position, environment bindings are merged (inner first,
outer overriding), and the resource trees are merged under separate
prefixes. The manifest already carries everything needed; `inspect`
already parses nested artifacts. Flattening changes only how many
launcher processes run, not the semantics.

## Decisions and assumptions

* **Separate launcher binary** (instead of copying `bound` itself):
  smaller artifacts, no build logic in artifacts, explicit platform choice.
  The cost is that `bound` and `bound-launcher` must be installed together.
* **Binary manifest (postcard)**: compact (about a quarter of the size of
  the same manifest in JSON, which matters for bundles of many small
  files), in a serde format with a published wire-format specification,
  and simple to decode strictly: lists are bounded before they are read,
  and exactly one encoding is accepted. `bound inspect --json` shows it as
  JSON. Non-Unicode strings keep explicit raw forms, so nothing is lossy.
* **zstd per blob**: one frame per content, so each file decodes
  independently; identical contents are stored once. Artifacts are written
  with the reference C library (level 9: better ratios than DEFLATE at
  similar or better speed, and several times faster decoding) and read
  with `ruzstd`, a pure-Rust decoder, so the code that parses untrusted
  input in every artifact and in `inspect`/`verify` is memory-safe, and
  verification uses an independent implementation. Windows are capped at
  8 MiB, which bounds decoding memory.
* **Resource placement by relative path**: the bundle root mirrors the
  directory bound ran in, so `--cwd bundle` lets a program find its files
  where it found them during development. `--include-as` covers the rest.
* **Whole-argument directives only**: `--config=@file:x` is literal. This
  keeps the syntax unambiguous; interpolation can be added later as a new
  argument element type (with a format version bump).
* **`@@` escaping** for literal arguments that begin with `@`.
* **Runtime arguments without `@args` are appended**; a template with no
  `runtime_args` element (not produced by the CLI yet) rejects them, which
  reserves room for sealed interfaces.
* **Links**: preserved when relative and inside the bundle, on every
  platform. On Windows, where creating symbolic links needs a privilege
  (or Developer Mode), a user without it gets junctions for directories
  and hard links for files instead: what pnpm does, and what Node.js and
  other programs follow like links. A junction holds an absolute path,
  so the one of a shared bundle points where the bundle is moved once
  complete, not to its staging directory.
* **Output naming**: `.exe` appended for Windows targets only, never
  anything else.
* **Exit codes 125/126/127** for launcher failures, as `env(1)`,
  `timeout(1)` and shells do.
* **One reaper per run, no global sweeping**: every private directory has
  a reaper watching the run that created it, so later runs never need to
  decide whether another run's directory is abandoned. A directory is
  left behind only if the reaper itself is killed (or on Windows, if files
  stay in use).

## Future work

The format and code are arranged so that these can be added without
redesign:

* **Sealed argument interfaces** (`@arg:input`): a new argument element
  naming a run-time parameter, with the template rejecting anything else.
* **More bundle modes**: `persistent` (state kept between runs), and
  per-resource modes (a shared read-only tree with a few private files).
* **Cache eviction**: a size limit, or pruning of entries unused for a
  while, done by the launcher or a periodic `bound cache clean --unused`.
* **Dependency capture**: higher-level commands that bundle an
  interpreter, a virtual environment, `node_modules`, or a native program's
  shared libraries (`ldd`/`otool -L`/PE imports), expressed as ordinary
  resources plus environment bindings (`PYTHONHOME`, `LD_LIBRARY_PATH`,
  `DYLD_LIBRARY_PATH`, `PATH`).
* **bound-level signatures**: `bound sign` / `bound verify-signature`
  over the manifest digest, for platforms without embedded code signatures
  (Linux) and for checking an artifact for another platform. Platform
  code signing (Developer ID, Authenticode) is supported today.
* **Flattening** of nested artifacts, as described above.
* **Cross-target builds** with `--target`, as described above.
* **A GUI-subsystem launcher** on Windows, so GUI programs do not open a
  console window.
