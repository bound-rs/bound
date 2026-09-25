# Security

## What bound is, and is not

A bound artifact is a program. Running one is exactly as trustworthy as
running the program it wraps: the launcher starts that program with the
caller's privileges, environment and standard streams. **bound is not a
sandbox** and does not restrict what the program does.

What bound does guarantee is narrower and checkable:

1. Reading, inspecting and verifying an artifact is safe, whatever its
   contents: a crafted artifact cannot make `bound inspect`, `bound verify`
   or the launcher crash, allocate unbounded memory, loop forever, or read
   or write outside the file.
2. Materializing an artifact's resources never writes outside the fresh
   private directory created for that run (or, for shared bundles, the
   artifact's staging directory in the user's cache), whatever the
   manifest says.
3. A modified artifact is detected: the launcher refuses to run a program
   whose bundled files do not match their recorded SHA-256, and
   `bound verify` detects any modified byte.
4. Nothing is interpreted by a shell. Arguments are passed as a list, and
   bound itself never runs `sh -c`, `cmd.exe /C` or `powershell -Command`.

## Bundled content is not secret

Everything in an artifact (files, arguments, environment values, the
program) is stored in the file, compressed but not encrypted, and is
written to disk when the program runs. Anyone who can read the artifact can
read all of it: `bound inspect` lists names and hashes, and extracting the
contents is straightforward. **Never bundle passwords, tokens or keys.**

`bound inspect` prints argument and environment values because they are
literally part of the artifact; it never prints file contents or the
caller's environment.

## Threat model

Build time: the inputs (the command line and the files it names) are
controlled by the person running `bound`. bound still walks included
directories defensively: it does not follow symbolic links inside them, it
rejects special files (FIFOs, sockets, devices; on Windows, devices, pipes
and reparse points no file system filter serves), it refuses links that
point outside the bundle (junctions included), and it detects bind-mount
loops.

Inspection and run time: the artifact may have been crafted by an
attacker. Every field is validated before use (see `docs/format.md`):

| Threat | Defense |
|---|---|
| Path traversal (`../x`, `a/../../x`, `..\x`, mixed separators) | Resource paths are validated per component: no `.`/`..`, no `/` or `\` inside a component, no empty components. Validation happens on the manifest, not on a normalized form, so nothing is resolved before it is checked. |
| Absolute paths (`/etc/x`, `C:\x`, `\\server\share`, `\\?\C:\x`) | No component may start a path: `/`, `\`, and on Windows `:` are rejected. |
| Windows device names, alternate data streams, trailing dots/spaces | Rejected for Windows artifacts, and always rejected by the Windows launcher regardless of what the manifest claims. Conversion to a native path re-checks these rules on Windows. |
| Case-insensitive collisions (`Readme` vs `README`) | Rejected in manifests for macOS and Windows, and whenever the reader materializes on Windows (Linux artifacts may contain both names, which are distinct files there). Extraction uses exclusive creation, so any collision the check does not cover (Unicode normalization on APFS, a case-insensitive file system on Linux) fails instead of overwriting. |
| Symlinks pointing out of the bundle | Link targets must be relative and are resolved against the bundle tree exactly as the kernel would resolve them after extraction (following other links, applying `..` to the resolved location); anything that escapes, dangles, loops or ends at the root is rejected. Links are created last, after every file, so nothing is ever written through one. Resolution is memoized, so adversarial link graphs cannot cause exponential work. |
| Pre-existing files, planted links, junctions and reparse points in the extraction directory | The directory is new for every run, created with `mkdir` / `CreateDirectoryW`, which fail on any existing entry. Files are created with `O_CREAT\|O_EXCL\|O_NOFOLLOW` (Unix) or `CREATE_NEW` with `FILE_FLAG_OPEN_REPARSE_POINT` (Windows). Existing entries are never reused or followed. |
| Other users reading or modifying extracted files | The directory is private: mode `0700` with files `0600`/`0700` on Unix; on Windows a protected DACL granting access only to the current user and SYSTEM, set atomically at creation. On macOS, access control entries the new directory inherits from `TMPDIR` (which its mode does not limit) are removed before anything is written into it, and the directory must still be empty afterwards. |
| Predictable temporary names | Directory names use 64 bits from the operating system's random number generator; creation fails rather than reusing an existing name. |
| A temporary directory other users can alter | Another user who can rename entries in the temporary directory, or in any directory above it, could replace the private directory with their own and redirect the program's reads and writes. The launcher refuses a temporary directory unless it and every directory above it belong to the user or a trusted account (root on Unix; SYSTEM, Administrators or TrustedInstaller on Windows) and let no one else rename their entries: not writable by others without the sticky bit (as `/tmp`) on Unix, no access control entry granting another account delete-child, delete, write-DAC, write-owner or full control on Windows. The same check applies to the cache directory, which is also made private again (mode `0700`, or a protected access list, applied to what it contains) if it lets anyone else in. |
| Terminal escape injection | Strings from the manifest (program names, arguments, resource names) are printed with control characters and bidirectional-override characters escaped, by the launcher's error messages as well as by `inspect` and `verify`; decoding errors never quote the input. Resource names may not contain control characters at all (C0, DEL, C1). |
| DLL planting next to an artifact (Windows) | Artifacts are often run from folders like Downloads. The MSVC build links the launcher and `bound` with `/DEPENDENTLOADFLAG:0x800`, so their own DLL imports resolve from System32 only. (Programs the artifact starts load DLLs by their own rules.) |
| Corrupt or malicious footer | Offsets and lengths are checked with overflow checks against the real file length; the regions must tile the file exactly, up to its end or to a code signature that the executable's header names and that ends the file. |
| A code signature hiding changes | Only the few header fields that signing rewrites (listed in `docs/format.md`) are left out of the launcher's hash; every other byte of the launcher, payload, manifest and footer is hashed. A signature counts only if the header names it and it ends the file, after at most 15 zero bytes of padding. bound never relies on a signature: it verifies integrity itself and leaves signature checks to the platform. |
| Excessive allocation | The manifest is limited to 64 MiB, and each list's length is checked against its limit before any element is decoded (1,000,000 resources and blobs, 100,000 arguments and environment bindings), which bounds the memory a crafted manifest can make a reader use. Contents are streamed through fixed buffers, never loaded whole. |
| Decompression bombs and decoder memory | A blob must decode to exactly its declared size (reading stops there); declared sizes above zstd's maximum expansion are rejected up front; a zstd frame may require at most an 8 MiB window, checked before any memory is allocated for it. Decoding is done by `ruzstd`, a pure-Rust (memory-safe) decoder. |
| Malformed or ambiguous manifests | Strict decoding of the binary manifest (unknown variants, malformed values and trailing bytes are errors), a check that its bytes are exactly the canonical encoding of what was decoded, so that other encodings of the same meaning (such as over-long integers) are rejected, and whole-manifest validation before anything acts on it. |
| Truncated or modified contents | Every extracted file is hashed while it is written; a mismatch aborts before the program starts, and the directory is removed. The last bytes of a content are handed out only after its hash has been checked, and a failed check stays failed. |
| Inspecting hostile artifacts | `inspect` examines nested artifacts at most 8 levels deep and 256 MiB in total, aligns listings on at most 60 columns and streams its output; `inspect` and `verify` refuse anything but a regular file without blocking (a named pipe would otherwise wait forever). |
| A program shadowed by another in the bundle (Windows) | Windows runs `NAME.exe` in preference to a program path `NAME`; a Windows artifact whose embedded program `NAME` sits next to a `NAME.exe` is rejected, so the program that runs is the one `inspect` shows. |
| Set-user-ID abuse | The launcher refuses to run with set-user-ID or set-group-ID privileges on Unix, since it reads `TMPDIR` and `PATH` from the caller. |
| Argument injection | Arguments are kept as a vector from manifest to process creation. On Windows the Rust standard library applies the MSVC quoting rules (and refuses arguments it cannot quote safely for batch files). |
| An artifact running itself | A bare program name never resolves to the artifact itself or a copy of it (recognized by its manifest digest), so an artifact named like the program it wraps cannot start itself in a loop. |
| Build inputs swapped while bundling | Files are opened without blocking on special files, a file found by walking a directory is opened without following a final link, and each must still be the file found (same device and inode on Unix; same size and creation time on Windows, and a reparse point that is not a link, read through its file system filter, must have the volume and file index of the one found; a link that replaced a file is refused). The artifact is written to a private temporary file, gets its final permissions only when complete, and never replaces an existing file without `--force` (a hard link, or a rename that refuses to replace). |

The test suite exercises these with crafted artifacts (traversal in every
spelling above, Windows device names, malformed and lying manifests,
absurd footer values, truncations and byte flips at every region).

## Integrity versus authenticity

`bound verify` and the launcher's checks prove that an artifact is
internally consistent and undamaged. They do not prove who built it: an
attacker who can modify an artifact can also recompute its hashes. The
manifest digest shown by `bound inspect` identifies an artifact exactly,
so it can be compared against a digest obtained through a trusted channel.

Authenticity comes from platform code signing, which artifacts support
like any other executable (see "Code signatures" in `docs/format.md`, and
`docs/platforms.md` for the commands). A signature made with a trusted
identity covers every byte of the bound regions, so it authenticates the
program, its arguments and every bundled file:

* **macOS**: every artifact carries an ad-hoc signature over all of its
  bytes and passes `codesign --verify --strict`. An ad-hoc signature proves
  nothing about who built the artifact; sign it with a Developer ID and
  notarize it for distribution. Gatekeeper blocks executables that carry
  the quarantine attribute (for example after a browser download) unless
  they are signed with a Developer ID and notarized.
* **Windows**: artifacts are written unsigned; sign them with `signtool` or
  `Set-AuthenticodeSignature` after building. SmartScreen and antivirus
  products may treat unsigned executables, and executables written to
  `%TEMP%` and run from there, with suspicion.
* **Linux**: executables carry no embedded signatures; publish the
  artifact's digest, or a detached signature (GPG, minisign), through a
  trusted channel.

`bound verify` reports whether an artifact carries a code signature but
does not check it; use the platform's tools (`codesign --verify`,
`signtool verify /pa`, `Get-AuthenticodeSignature`).

## The reaper

A private bundle directory is removed by a reaper process (see
`docs/platforms.md`), started before anything is extracted on Unix, and on
Windows while the files are extracted, running before the program starts. It knows the directory's path from its
own memory (Unix, a forked copy of the launcher) or from a request that
only its parent can give it (Windows: the
request names the launcher's process ID and creation time and is honored
only by a child of that process, and only for a directory named like a
bundle directory that is a real directory, not a link or junction). It
removes the tree without following links. It holds none of the caller's
file descriptors or handles and receives no signals or console events meant
for the program.

## The cache

The cache (see `docs/platforms.md`) holds decoded contents and shared
bundles for one user. It is created private (mode `0700`, or the protected
DACL on Windows), must belong to the user, and is checked like `TMPDIR`
(every directory above it must be one no other user can alter); otherwise
it is not used. Every entry is written under a staging name, verified
against its SHA-256 as it is decoded from the artifact, flushed to disk and
renamed into place, so an entry either is complete or does not exist.
Entries are then trusted without hashing them again, which is what makes
the cache fast: a process running as the same user can change what later
runs of every artifact using an entry receive, which is within what such a
process can do anyway (see "Same-user attackers" below). On Unix a shared
bundle is used only while it is sealed (a directory of the user that nobody
can write to); one found writable is replaced by a fresh extraction. On
Windows it must be a real directory (not a junction), and its files carry
the read-only attribute.

## Residual risks and limitations

* **Same-user attackers.** Another process running as the same user can
  modify the extraction directory while the program runs, modify the
  artifact itself, or modify the user's cache and so what later runs
  receive. Operating systems do not isolate processes of the same user
  from each other; neither does bound. `BOUND_CACHE=0` makes every run read
  everything from the artifact.
* **Programs running as root or Administrator** can write to shared
  bundles despite their read-only permissions; the change goes unnoticed
  unless it also leaves the bundle writable.
* **Leftover directories.** If the reaper is killed (or, on Windows, if a
  file is still in use when it gives up, or if the launcher is terminated
  in the few milliseconds before the reaper process exists), the bundle
  directory is left in the temporary directory. Its contents
  are what the artifact already contains. An interrupted first run of a shared bundle leaves a staging
  directory in the cache, which `bound cache clean` removes.
* **After a system crash** a cache entry could lose data that had not
  reached the disk. On Linux and macOS, bound flushes entries before
  renaming them into place, which prevents this. On Windows it does not:
  flushing file by file costs a device flush and another antivirus scan
  per file (a minute for a 10,000-file shared bundle), and Windows offers
  no grouped flush. A system crash within moments of a shared bundle's
  first extraction can therefore leave it with lost data; `bound cache
  clean` removes it, as it removes any doubt elsewhere.
* **GNU builds on Windows** (`x86_64-pc-windows-gnu`) cannot set the
  dependent-DLL load flag; prefer the MSVC build for distribution.
* **Programs found at run time.** An external program is resolved on the
  destination system with the platform's rules. A `PATH` that includes
  writable or relative directories can substitute a different program. On
  Windows the directory containing the artifact is searched before `PATH`,
  as `CreateProcess` does, but never the current directory. Embed the
  program, or bind an absolute path, when that matters.
* **Embedded native programs** load shared libraries from the destination
  system according to that system's rules; bound does not bundle or pin
  them.
* **Nested artifacts** are run as-is; each level performs its own checks.
