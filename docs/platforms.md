# Platforms

bound exposes one model everywhere: an artifact is a program, arguments,
environment, working directory and files, partially applied. How that
model is carried out depends on each operating system's native process and
file-system semantics. This document describes the differences that matter.

| | Linux | macOS | Windows |
|---|---|---|---|
| Executable format | ELF | Mach-O | PE |
| Artifact name | as given | as given | `.exe` appended if missing |
| Launch | `execve` (same PID) | `execve` (same PID) | child process in a kill-on-close job, launcher waits |
| Removal of private bundle directories | reaper process | reaper process | reaper process |
| Argument transport | `argv` array | `argv` array | one command line, MSVC quoting |
| Temporary directory | `$TMPDIR`, else `/tmp` | `$TMPDIR` (per-user) | `GetTempPath2W` / `%TEMP%` |
| Private directory | mode `0700` | mode `0700` | protected DACL (user + SYSTEM) |
| Executable bit | preserved | preserved | not applicable (name and format decide); recognized by content for Unix bundles built on Windows |
| Links in bundles | symbolic links (relative, inside) | symbolic links (relative, inside) | symbolic links (relative, inside), or junctions and hard links for users who may not create symbolic links |
| Shared bundle seal | no write permission | no write permission | read-only attribute on the bundle directory |
| Location checks (temporary directory, cache) | no directory above writable by others unless sticky, none owned by another user | same | no directory above whose access list lets another account delete, rename or re-permission its entries, none owned by another account |
| Signals, job control, exit status | the program's own | the program's own | exit code passed through; console events reach both |
| Cache (`bound cache dir`) | `$XDG_CACHE_HOME/bound` or `~/.cache/bound` | `~/Library/Caches/bound` | `%LOCALAPPDATA%\bound\cache` |
| Cloning cached contents | Btrfs, XFS (`FICLONE`); copy elsewhere | APFS (`clonefile`) | copy |
| List separator (`--env-prepend`, `--env-append`) | `:` | `:` | `;` |
| Environment names | case-sensitive | case-sensitive | case-insensitive |

A list variable's entries go around the caller's value of that variable,
which the launcher looks up as the platform compares names
(case-insensitively on Windows, where `PATH` and `Path` are one variable).
Names in a manifest compare case-insensitively on every platform, so an
artifact never binds two spellings of one name. A caller without the
variable gets only the bound entries: for `PATH`, the default search path
the system would otherwise use is not. A `PATH` the artifact binds is also
the one the launcher searches for a bare program name, so a bundled
directory listed there is searched first.

Artifacts are platform- and architecture-specific: the launcher at the
start of the file is a native executable for one platform. The rest of the
format is platform-independent, so `bound inspect` and `bound verify` work
on artifacts for any platform. bound currently builds artifacts for the
platform it runs on (see "Cross-platform builds" in `docs/design.md`).

## Linux

* **Launcher**: an ELF executable. The appended data lies outside every
  loadable segment, so the kernel ignores it. The launcher reads its own
  image through `/proc/self/exe`, which refers to the running file even if
  its path was replaced or deleted.
* **Executable bits**: preserved for bundled files (`0700` for executables,
  `0600` otherwise; directories `0700`). An embedded program is always
  executable.
* **Process behavior**: the launcher always `exec`s the program, which then
  has the launcher's PID, parent, process group, session, terminal, signal
  mask and signal dispositions: signals, job control and exit statuses are
  exactly those of the program started directly. See "Processes and
  signals" below for how the bundle directory is removed.
* **Temporary directory**: `TMPDIR` if set, else `/tmp`. If it is mounted
  `noexec`, an embedded program cannot run from it; the launcher's error
  message says so, and setting `TMPDIR` to an executable location fixes it.
  `TMPDIR` must be a location no other user can alter: it and every
  directory above it must belong to the user or to root, and must not be
  writable by others unless they have the sticky bit (as `/tmp` does).
  Otherwise the launcher refuses it, since another user could replace the
  private directory it creates there. An empty `TMPDIR` means `/tmp`.
* **Non-UTF-8 data**: arguments, environment values and file names that
  are not valid UTF-8 are preserved byte for byte.

## macOS

* **Launcher**: a Mach-O executable for Apple silicon (arm64; Intel Macs
  are not supported). Every executable must be signed there, so bound
  signs every artifact ad hoc: it extends the launcher's `__LINKEDIT`
  segment over the bundle and replaces the linker's signature, which
  covered the launcher only, with one that covers every byte (see "Code
  signatures" in `docs/format.md`).
  Artifacts pass `codesign --verify --strict`.
* **Signing for distribution**: sign the artifact with a Developer ID
  (with the hardened runtime, which notarization requires) and notarize
  it:

  ```sh
  codesign --sign "Developer ID Application: NAME (TEAM)" --options runtime --timestamp --force ./tool
  ditto -c -k --keepParent ./tool tool.zip
  xcrun notarytool submit tool.zip --keychain-profile PROFILE --wait
  ```

  `codesign` replaces the ad-hoc signature; the artifact keeps working and
  keeps its digest, and `bound inspect` shows who signed it. A notarization
  ticket cannot be stapled to a bare executable, so Gatekeeper looks it up
  online. An embedded program is extracted and started as an executable of
  its own, with its own signature: sign it before bundling it if it is not
  signed yet. Rebuilding writes an ad-hoc-signed artifact again.
* **Gatekeeper and quarantine**: artifacts you build locally carry no
  quarantine attribute and run normally. An artifact downloaded through a
  browser is quarantined, and Gatekeeper blocks it unless it is signed with
  a Developer ID and notarized, like any other executable
  (`xattr -d com.apple.quarantine FILE` removes the attribute).
* **Temporary directory**: `$TMPDIR`, a per-user directory under
  `/var/folders`. `BOUND_ROOT` is the canonical path (`/private/var/…`), so
  it matches what `getcwd` reports inside it.
* **File names**: APFS is case-insensitive by default and normalization-
  insensitive; bundles with names differing only by case are rejected, and
  extraction fails instead of overwriting on any other collision.
* **Access control lists**: a new bundle directory would inherit ACL
  entries from `TMPDIR` that its mode does not limit; the launcher removes
  them before writing anything into it.
* **Processes and signals**: as on Linux.

## Processes and signals (Linux and macOS)

The launcher never stays between the caller and the program: it validates
the artifact, prepares the bundle directory if there is one, and `exec`s
the program. The caller's `wait`, `kill` and job control act on the
program itself, with no relaying and no second process in the way.

* Everything the program gets is what the caller gave the launcher: the
  signal mask, ignored signals, file descriptors (the launcher's own are
  closed on `exec`), the process group and the controlling terminal.
  `SIGPIPE` keeps the disposition the caller set (Rust programs ignore
  `SIGPIPE` internally; bound captures the original disposition before that
  happens and restores it for the program).
* A signal that arrives while the launcher is still extracting files kills
  it as it would kill the program, and the reaper removes the directory.

**The reaper.** A private bundle directory must be removed after the
program exits, and nothing of the launcher remains after `exec`, so before
it extracts anything the launcher starts a *reaper*: a small process,
double-forked so that it is not the program's child (the program has
exactly the children it creates, and its `wait` never sees the reaper), in
a session of its own (terminal signals and hangups never reach it), holding
none of the caller's file descriptors (a reader of the program's output
sees end-of-file when the program exits) and ignoring termination signals.
It watches the PID the program runs as (with a pidfd on Linux 5.3 and
later, kqueue on macOS, and by polling the process's start time on older
kernels) and removes the directory once that process has exited, whatever
the reason, including `SIGKILL`. The directory therefore disappears shortly
after the program exits, not before its caller sees the exit status. On
Linux the reaper is named `bound-reaper` in `ps`.

A program that is PID 1 of a container adopts the reaper, since orphans are
reparented to PID 1; when PID 1 exits the kernel ends the container and the
reaper with it. Shared bundles (`--bundle shared`) need no reaper.

## Windows

* **Launcher**: a PE executable (x86_64 or aarch64). Data after
  the last section (an "overlay") is ignored by the loader, as it is for
  self-extracting archives and installers. The artifact is a normal console
  program that runs without bound installed.
* **`.exe` naming**: executables need the `.exe` extension to be run by
  name, so when the target is Windows, `-o tool` writes `tool.exe` (with a
  note) and `-o tool.exe` is kept as is. No other extension is ever added.
  An embedded program without an extension is stored as `NAME.exe`.
* **Process creation**: Windows has no `exec`; the launcher always starts
  the program as a child with `CreateProcessW`, waits for it, and exits
  with its exact 32-bit exit code (e.g. `0xC0000005` comes through
  unchanged). The program inherits exactly the handles its caller passed
  to the artifact: the same inheritable handles, with the same values, and
  the same standard handles (given through its startup information, as
  Windows gives them). It shares the launcher's console, or, if the
  artifact was started without one, has none either. (The C runtime's
  extra file descriptors, which some runtimes pass in the undocumented
  `lpReserved2` startup field, are not passed on: a program sees its
  standard streams and inherited handles, not descriptors 3 and above.)
  The program runs in a job object that terminates it
  if the launcher is terminated (from Task Manager, or by a caller's
  `TerminateProcess`), as launchers such as `py.exe` do; processes the
  program starts break away from that job, so only the program itself is
  tied to the launcher. The program's process ID is not the launcher's.
* **Argument quoting**: `CreateProcessW` takes one command line, which the
  program splits again. The launcher builds it with the Rust standard
  library's implementation of the MSVC rules, which round-trip spaces,
  quotes, backslashes, trailing backslashes, empty strings and Unicode for
  every program using the standard parser (C/C++, Rust, Go, Python, .NET).
  Programs that parse their command line differently (some built-in
  Windows tools) may see different boundaries. `cmd.exe` is never involved
  unless the program *is* a batch file (`.bat`/`.cmd`), in which case
  Windows requires `cmd.exe` and the standard library escapes the arguments
  for it, refusing any it cannot pass safely.
* **Program lookup**: a bare name like `findstr` is resolved as
  `CreateProcess` does (through the Rust standard library's rules): the
  directory containing the artifact, the system directories, then `PATH`,
  trying `.exe` when the name has no extension. The current directory is
  never searched. If nothing is found, the launcher also tries each
  `PATHEXT` extension (`.COM;.EXE;.BAT;.CMD` by default) in each absolute
  `PATH` directory, as `cmd.exe` would, so `npm` finds `npm.cmd`. The
  artifact itself, and copies of it, are skipped: an artifact `tool.exe`
  that wraps `tool` never starts itself, even though Windows searches the
  artifact's own directory first.
* **Unicode**: arguments, environment and paths use the wide-character
  APIs throughout. Values that are not valid UTF-16 are preserved exactly.
* **Temporary directory**: `GetTempPath2W` (`%TEMP%`, typically
  `C:\Users\NAME\AppData\Local\Temp`). The bundle directory is created
  atomically with a protected DACL that grants access only to the current
  user and SYSTEM, inherited by everything inside. Paths given to the
  program are ordinary drive paths, never `\\?\` paths, and are spelled
  natively: the temporary directory and the cache (`BOUND_CACHE_DIR`
  included) are made absolute with `GetFullPathNameW`, so `C:/Users/…`, as
  Git Bash writes it, reaches the program as `C:\Users\…`. Drive letters,
  junctions and 8.3 names stay as spelled, which is how Windows reports a
  started program's own path. The cache is in
  `%LOCALAPPDATA%\bound\cache`, created with the same protected DACL.
* **File names**: bundles for Windows reject names Windows would
  reinterpret: reserved device names (`CON`, `NUL`, `COM1`, `aux.txt`, …),
  `:` (drives and alternate data streams), `< > " | ? *`, and trailing dots
  or spaces. File systems are usually case-insensitive; names that differ
  only by case are rejected everywhere.
* **Links**: a bundle's links are created as relative symbolic links
  when the user may create them (an administrator, or any user with
  Developer Mode). Otherwise, as pnpm does, a link to a directory becomes
  a junction (which any user can create) to the directory where the bundle
  is used, and a link to a file a hard link to it (a copy on file systems
  without hard links). Programs, Node.js's module resolution among them,
  follow junctions like links. Relative symbolic links in an included
  directory are bundled as links; junctions and absolute links, which
  point outside it, are rejected.
* **Reparse points**: extraction never follows one (`CREATE_NEW` with
  `FILE_FLAG_OPEN_REPARSE_POINT`). When bundling, a reparse point that is
  not a link (such as a cloud file's placeholder) is read through the file
  system filter that serves its content, and must be the same file (same
  volume and file index); one no filter serves cannot be read and is
  reported. Devices and pipes (`\\.\pipe\NAME`) are never read.
* **Executable bits of Unix bundles**: Windows file systems have none, so
  when bound builds a bundle for Linux or macOS on Windows, files whose
  content is a `#!` script or an ELF or Mach-O program or library are
  recorded executable.
* **Shared bundles**: sealed with the read-only attribute on every entry,
  the bundle directory included. Windows does not enforce the attribute on
  directories, but whoever clears it (to change a file, say) unseals the
  bundle, which the next run extracts again.
* **Location checks**: before creating a private directory in the
  temporary directory, or using the cache, bound checks every directory
  above it: its owner must be the user, SYSTEM, Administrators or
  TrustedInstaller, and its access list must not let any other account
  delete, rename or re-permission its entries (delete-child, delete,
  write-DAC, write-owner or full control). An existing cache directory
  that lets other accounts in is made private again, with what it
  contains.
* **The launcher's own DLLs**: the MSVC build links with
  `/DEPENDENTLOADFLAG:0x800`, so the launcher resolves its imports (such as
  `bcryptprimitives.dll`, which is not a KnownDLL) from System32 only, and
  a DLL planted next to an artifact in, say, Downloads is never loaded.
* **DLL dependencies**: an embedded program loads its DLLs from the
  destination system (application directory, system directories, `PATH`),
  and since the program runs from the bundle directory, DLLs it expects
  next to itself must be bundled alongside it with `--include`.
* **Ctrl+C and Ctrl+Break**: console control events go to every process
  attached to the console. The launcher ignores them while the program
  runs, so the program decides how to react and the launcher then reports
  its exit code. An event received while files are still being extracted
  stops the launch with `STATUS_CONTROL_C_EXIT`. Closing the console
  window, logging off and shutting down terminate the launcher normally
  (and the program with it); the reaper then removes the bundle directory.
* **Cleanup**: a private bundle directory is removed by a reaper, a second
  copy of the artifact started detached from the console, in its own
  process group, with no inherited handles and outside the caller's job
  where that is allowed. It is started as soon as the directory exists,
  on another thread while the files are extracted (process creation is
  slow on Windows), and the program starts only once it runs, so that
  terminating the launcher at any point after that leaves nothing behind.
  It waits for the launcher (identified by process ID and creation time)
  to exit, then removes the directory, retrying for a few seconds while
  files are still in use (antivirus scanners often hold new files for a
  moment). A directory still in use after that, for example by a
  background process the program started, is left in `%TEMP%`. If the
  reaper cannot be started, the launcher removes the directory itself
  after the program.
* **Consoles**: the program shares the launcher's console, including one
  without a window (`CREATE_NO_WINDOW`, as services and GUI programs start
  tools). An artifact started without a console (detached) starts its
  program without one too: a console program would otherwise be given a
  new console, and a window the caller did not ask for.
* **Replacing a running artifact**: Windows locks running executables, so
  `bound --force -o tool.exe` fails with an explanatory error while
  `tool.exe` runs.
* **GUI programs** can be bound and are started normally, but the
  launcher is a console program, so starting an artifact from Explorer
  opens a console window for the duration.
* **Authenticode**: artifacts are written unsigned (a signature on the
  launcher would cover the launcher only, so it is removed). Sign the
  finished artifact like any executable; the signature covers the bundle:

  ```powershell
  signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a tool.exe
  # or
  Set-AuthenticodeSignature tool.exe -Certificate $cert -HashAlgorithm SHA256 -TimestampServer http://timestamp.digicert.com
  ```

  The artifact keeps working and keeps its digest; `bound inspect` shows
  the signature, and `signtool verify /pa tool.exe` or
  `Get-AuthenticodeSignature tool.exe` checks it. Rebuilding writes an
  unsigned artifact again.
* **Arm64**: the code has no architecture-specific parts; Windows on Arm
  builds are checked in CI, and tested where an Arm runner is available.

## The cache

Contents of 1 MiB or more are kept in a per-user cache, and every run of a
private bundle then takes them from there instead of decoding them from the
artifact again. The copy a run gets is independent of the cache entry: a
copy-on-write clone where the file system supports it (APFS on macOS;
Btrfs and XFS on Linux, when the temporary directory is on the same file
system as the cache), an ordinary copy otherwise (always on Windows). Shared
bundles (`--bundle shared`) live in the same cache and are used in place.

The cache directory must be private to the user, like `TMPDIR` (see
above); if it is not, or cannot be created, the launcher does not use it and
reads everything from the artifact. `BOUND_CACHE_DIR` moves it and
`BOUND_CACHE=0` turns it off. `bound cache list` shows what it holds and
`bound cache clean [--unused DAYS]` removes entries; nothing removes them
automatically. Shared bundles are read-only by permissions (Unix modes, the
Windows read-only attribute); a program running as root or Administrator
can still change them. On Unix a shared bundle found writable (and so
possibly modified) is extracted again; on Windows only the files' read-only
attributes protect it.
