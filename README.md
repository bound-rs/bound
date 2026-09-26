# bound

**bound turns a process invocation into a program.**

```sh
bound -o grep-errors -- grep -n ERROR
./grep-errors server.log          # runs: grep -n ERROR server.log
```

```powershell
bound -o find-errors -- findstr.exe /N ERROR    # writes find-errors.exe
.\find-errors.exe server.log                    # runs: findstr.exe /N ERROR server.log
```

A process invocation is a program, its arguments, some files, an
environment and a working directory. bound lets you fix some of those now
and leave the rest for later: it *partially applies* the invocation and
writes the result as a new native executable.

```text
(program, argv, files, env, cwd)
    → bind some inputs
    → executable
```

The result is one file. It runs without bound installed, carries any files
you bound into it, and accepts the remaining arguments when it runs.

## Examples

### Bind arguments

Arguments given at run time are appended to the bound ones:

```sh
bound -o grep-errors -- grep -n ERROR
./grep-errors a.log b.log         # grep -n ERROR a.log b.log
```

Put them somewhere else with `@args`:

```sh
bound -o jpeg -- convert @args -strip -quality 85 output.jpg
./jpeg input.png                  # convert input.png -strip -quality 85 output.jpg
```

Arguments are passed to the operating system as a list, never through a
shell, so spaces, quotes, backslashes, empty strings, Unicode and characters
like `& | ; $ % ^ !` arrive exactly as given, on Linux, macOS and Windows.

### Bundle files

`@file:PATH` bundles a file into the executable. When the program runs, the
argument is replaced by the path of a fresh copy:

```sh
bound -o migrate -- python migrate.py --schema @file:schema.sql
rm schema.sql                     # not needed any more
./migrate production.db           # python migrate.py --schema /tmp/bound-…/schema.sql production.db
```

Environment variables can point at bundled files too:

```sh
bound -o app --env MODE=production --env CONFIG=@file:config.toml -- ./server
```

### Bundle directories

`--include` bundles files and directory trees that are not arguments. The
program finds them under `$BOUND_ROOT` (`%BOUND_ROOT%` on Windows), at the
same relative path they had when you ran bound:

```sh
bound --include ./templates --include ./assets/logo.png --cwd bundle -o renderer -- ./renderer
# the program sees $BOUND_ROOT/templates/… and $BOUND_ROOT/assets/logo.png,
# and --cwd bundle runs it with $BOUND_ROOT as its working directory
```

Use `--include-as DEST=PATH` to choose the location explicitly, e.g.
`--include-as web=dist/public`. `--cwd @bundle:DIR` runs the program in a
directory of the bundle instead of its root:

```sh
bound --include ./site --cwd @bundle:site/pages -o preview -- ./preview-server
# runs in $BOUND_ROOT/site/pages
```

By default every run gets a new private copy of the files, which the
program may modify and which is removed after it exits. For large bundles
that the program only reads, `--bundle shared` extracts them once, into a
read-only directory in your cache, and every later run starts at once:

```sh
bound --bundle shared --include ./site-packages -o app -- python @file:app.py
```

### Put bundled tools on PATH

`--env-prepend NAME=VALUE` puts an entry before the caller's value of a
list variable such as `PATH`, and `--env-append` after it, joined with the
platform's separator (`:`, or `;` on Windows). An entry can be a bundled
directory, so programs that start other programs by name find the bundled
ones first:

```sh
bound --include-as bin=./tools --env-prepend PATH=@bundle:bin -o build -- make all
# make, and anything it runs by name, looks in $BOUND_ROOT/bin first
```

Repeated entries keep their order. A caller without the variable gets only
the bound entries (for `PATH`, not the system's default search path).

### Scripts

A script needs its interpreter. Bind the interpreter as the program and the
script as a file:

```sh
bound -o report -- python @file:report.py --template @file:report.html
bound -o tool -- node @file:index.js
```

```powershell
bound -o report.exe -- python.exe @file:report.py
bound -o task.exe -- powershell.exe -NoProfile -File @file:task.ps1
```

The interpreter (`python`, `node`, `powershell.exe`) is **not** bundled; it
must be installed where the program runs.

### Bundle the program itself

By default the program is looked up on the destination system when the
artifact runs (`PATH`, and `PATHEXT` on Windows). `--embed-program` puts it
inside the artifact instead:

```sh
bound --embed-program -o wrapped -- ./mytool --foo
rm mytool
./wrapped bar                     # still works: mytool --foo bar
```

```powershell
bound --embed-program -o wrapped.exe -- .\mytool.exe --foo
```

Only the program file is bundled, not the shared libraries (`.so`,
`.dylib`, `.dll`) it loads.

### Compose

A bound executable is a program, so it can be bound again:

```sh
bound -o reliable-curl -- curl --retry 5
bound --embed-program -o api-curl -- ./reliable-curl -H @file:headers.txt
./api-curl https://example.com    # curl --retry 5 -H /tmp/bound-…/headers.txt https://example.com
```

### Complete examples

[examples/](examples/) has three projects, each bound in several ways, with
step-by-step READMEs that work on Linux, macOS and Windows:

* [Node.js](examples/node/): a script with its `node_modules`, a preset,
  an esbuild single-file build, and Node.js itself embedded for a
  self-contained executable.
* [Python](examples/python/): a uv project type-checked with ty, run by
  `uvx` from its wheel, with its dependencies bundled for the destination's
  Python, or with a relocatable CPython embedded.
* [Rust](examples/rust/): one native program turned into several commands,
  each with its own data files, options and environment.

### Build systems

A build system lays the bundle out itself, as the language expects it, and
hands bound the layout in an `--include-list` file: one `DEST=PATH` line per
file or directory, `DEST=@link:TARGET` for links, and the program is the
bundled file that runs (`-- @bundle:python/bin/python3 -I -m app`):

```text
python/bin/python3=external/python_3_12/bin/python3
python/lib/python3.12/os.py=external/python_3_12/lib/python3.12/os.py
python/lib/python3.12/site-packages/app/main.py=src/app/main.py
node_modules/a=@link:.store/a@1.0.0/node_modules/a
```

For Bazel, [rules_bound](https://github.com/bound-rs/rules_bound) does this:
`bound_binary` binds any executable target with its runfiles, and rules for
a language (Python, JavaScript, ...) can lay their programs out their own way
with a few language-agnostic building blocks: an interpreter with the
application in its `site-packages`, `node` with a real `node_modules`, no
runfiles at run time.

### Sign

Artifacts are ordinary executables to code-signing tools. On macOS every
artifact is signed ad hoc, and can be signed with an identity and
notarized for distribution; on Windows, sign it after building:

```sh
codesign --sign "Developer ID Application: NAME (TEAM)" --options runtime --timestamp --force ./report
```

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a report.exe
```

The signature covers everything bundled. `bound inspect` shows it and
`bound verify` still passes; see [docs/platforms.md](docs/platforms.md).

### Look inside

```console
$ bound inspect ./report
Bound artifact: ./report
Format: 1 (bound 0.2.0)
Platform: linux-x86_64 (elf)
Size: 611.6 KiB (launcher 610.0 KiB, payload 1.2 KiB, manifest 324 B)
Digest: 5b0c…
Target:
  Mode: external (not bundled; resolved on the destination system)
  Program: python
Arguments:
  @file:report.py
  --template
  @file:report.html
  @args
Environment:
  (inherited from the caller, plus:)
  BOUND_ROOT=<bundle directory>
Working directory:
  inherit
Resources: 2 file(s), 3.1 KiB
  report.html     1.2 KiB  9f86d081884c7d65…
  report.py       1.9 KiB  2c26b46b68ffc68f…
  materialized in a new private temporary directory on every run
Requires on the destination system:
  program "python" (resolved when the artifact runs, e.g. through PATH)
```

An artifact uses format 1 unless it needs format 2, which added
`--cwd @bundle:DIR` and list variables; bound 0.2.0 and later read both.
`bound inspect --json` prints the same information as a stable, versioned
JSON document. `bound verify` recomputes every hash and exits non-zero if
anything was modified:

```console
$ bound verify ./report
Verifying ./report
  footer     ok (format 1)
  manifest   ok (sha256 5b0c…)
  launcher   ok (610.0 KiB)
  payload    ok (1.2 KiB)
  resources  ok (2 file(s) in 2 stored blob(s))
OK: ./report is intact (integrity only; this is not a signature check)
```

## Installing

Each [release](https://github.com/bound-rs/bound/releases) has binaries for
Linux (static), macOS and Windows: unpack the archive for your platform and
put its directory on `PATH`. With Rust (1.87 or newer):

```sh
cargo install bound-cli
```

The crate is `bound-cli` (the name `bound` belongs to another crate); the
command is `bound`. Building compiles the reference zstd library, so a C
compiler must be available (it always is where Rust itself can build native
code: Xcode's command line tools, `gcc`, or Visual Studio). From a checkout,
`cargo build --release` builds the same into `target/release`.

bound is two executables that belong together: `bound` and
`bound-launcher` (`bound.exe` and `bound-launcher.exe` on Windows). The
launcher is the small program at the start of every artifact; `bound`
looks for it next to itself. Keep them in the same directory, as the
release archives and `cargo install` do, or point `--launcher` /
`BOUND_LAUNCHER` at it. Use the launcher of the same release: an older one
refuses an artifact in a format it does not know (0.1.0's launcher, one that
uses `--cwd @bundle:DIR`, `--env-prepend` or `--env-append`), and `bound
build` cannot catch the mismatch, since a launcher carries no version.

## Reference

```text
bound [build] [OPTIONS] -o OUTPUT [--] PROGRAM [ARGS]...
bound inspect [--json] ARTIFACT
bound verify [--json] ARTIFACT
bound cache dir | list | clean [--unused DAYS]
```

`bound -o …` is short for `bound build -o …`. Everything after `--` (or
after the first argument that is not an option) is the invocation, verbatim.

| Option | Meaning |
|---|---|
| `-o`, `--output PATH` | Executable to write. For Windows targets `.exe` is appended when missing (`-o tool` writes `tool.exe`); nothing is appended elsewhere. |
| `-f`, `--force` | Replace `OUTPUT` if it exists. Without it bound never overwrites anything. |
| `--embed-program` | Bundle `PROGRAM` instead of resolving it at run time. A bare name is looked up in `PATH` now. |
| `--embed-program-as DEST` | Bundle `PROGRAM`, at `DEST` under the bundle root. |
| `--include PATH` | Bundle a file or directory (repeatable). |
| `--include-as DEST=PATH` | Bundle `PATH` at `DEST` under the bundle root (`.` for the root itself). `PATH` may also be one of the sources below. |
| `--include-list FILE` | Bundle every `DEST=PATH` pair listed in `FILE`, one per line, as `--include-as` does: for lists too long for a command line, such as the layouts build systems generate. |
| `--env NAME=VALUE` | Set an environment variable (repeatable). `VALUE` may be `@file:PATH` or `@bundle:PATH`. |
| `--unset NAME` | Remove a variable from the environment the program inherits (repeatable). |
| `--env-prepend NAME=VALUE` | Put `VALUE` before the caller's value of the list variable `NAME`, such as `PATH` (repeatable, in order). `VALUE` may be `@file:PATH` or `@bundle:PATH`, and must not contain the platform's list separator. |
| `--env-append NAME=VALUE` | Put `VALUE` after the caller's value of `NAME` (repeatable, in order). |
| `--cwd inherit\|bundle\|@bundle:DIR` | Run in the caller's directory (default), in the bundle directory, or in the bundled directory `DIR`. |
| `--bundle private\|shared` | A new private copy of the bundled files for every run (default), or one read-only copy in the user's cache, extracted by the first run and shared by every later one. |
| `--launcher PATH` | Build from this launcher executable (default: `bound-launcher` next to `bound`, or `$BOUND_LAUNCHER`). |
| `-q`, `--quiet` | No notes, warnings or summary. |

Directives, recognized only when they are a whole argument:

| Directive | Meaning |
|---|---|
| `@args` | Where run-time arguments go. At most once; if absent they are appended. |
| `@file:PATH` | Bundle `PATH` (file or directory); replaced by the absolute path of its copy at run time. |
| `@bundle:PATH` | Replaced by the absolute path at run time of `PATH` in the bundle directory, where another option bundled something (`--include-as data=/opt/data … @bundle:data/x.csv`). |
| `@@TEXT` | The literal argument `@TEXT` (escapes a leading `@`). |

The program itself may be `@bundle:PATH`: the file at `PATH` in the bundle,
which the other options bundle (`--include-as python=/opt/python … --
@bundle:python/bin/python3 -m app`). It is made executable.

In a `DEST=PATH` pair, `PATH` may also be:

| Source | Meaning |
|---|---|
| `@link:TARGET` | A symbolic link at `DEST` to `TARGET`, relative to `DEST`'s directory (`node_modules/a=@link:.store/a@1.0.0/node_modules/a`). It must resolve inside the bundle. |
| `@readlink:PATH` | A symbolic link with the same target as the link at `PATH` (the link itself, not what it points to). |
| `@dir` | A directory, empty unless something else is bundled in it. |
| `@@PATH` | The path `@PATH` (escapes a leading `@`). |

Two sources may give the same `DEST` when they are the same: the same file,
files with the same content, or links with the same target. On Windows,
links are symbolic links when the user may create them, and otherwise
junctions (to directories) and hard links (to files); see
[docs/platforms.md](docs/platforms.md).

Where bundled inputs are placed under `BOUND_ROOT`: a relative path inside
the current directory keeps its relative path (`./templates` →
`templates`); an absolute path or one outside the current directory is
placed by its final name (`/opt/data` → `data`, `../x.toml` → `x.toml`).
Names that would collide are rejected, including, in artifacts for macOS
and Windows, names that differ only by case.

### What a bound executable does when it runs

1. Reads the manifest from the end of its own file and validates it.
2. If it carries files (or uses `--cwd bundle` or `--cwd @bundle:DIR`),
   provides the bundle directory and sets `BOUND_ROOT` to it; otherwise it
   removes `BOUND_ROOT` from the environment.
   * By default (`--bundle private`) it creates a new private directory in
     the system temporary directory, writes the files and verifies each
     SHA-256. A small detached *reaper* process removes the directory once
     the program has exited, however it exits.
   * With `--bundle shared` it uses the artifact's directory in the user's
     cache, extracting and verifying it only if it is not there yet.
3. Starts the program with the bound arguments, the run-time arguments,
   the caller's environment plus the bindings (a list variable's entries
   around the caller's value), and inherited standard streams. A bare program name is looked up the way the operating system
   would look it up, except that it never resolves to the bound executable
   itself: an executable named like the program it wraps runs the next one
   in `PATH`.

On Linux and macOS the launcher *becomes* the program (`exec`): the program
has the process ID, parent, process group, signals and exit status of the
bound executable itself, exactly as if it had been started directly. On
Windows, which has no `exec`, the launcher starts the program as a child,
waits for it and exits with its exit code; terminating the bound executable
terminates the program.

Exit statuses produced by the launcher itself follow `env(1)`: **127** if
the program was not found, **126** if it could not be started, **125** for
any other launcher failure (for example a damaged artifact). Any other
status comes from the program.

## What is and is not included

* An **external** program (the default) is **not** bundled. It must exist
  on the destination system; `bound inspect` lists it as a dependency.
* An **embedded** program (`--embed-program`) **is** bundled, but the
  shared libraries it loads are not.
* Interpreted scripts still need their interpreter, unless you embed the
  interpreter itself.
* Embedding a file does **not** make it secret. Anyone with the artifact can
  read every bundled file, argument and environment value. Never bundle
  credentials.
* bound is **not a sandbox**. The program runs with the caller's
  privileges and can do anything the caller can.
* Artifacts are **platform-specific**: an artifact built on Linux x86_64
  runs on Linux x86_64. Build on each platform you target.
* Bundled files are **written to disk** when the program runs: in a new
  temporary directory, removed afterwards (the default), or once in the
  user's cache (`--bundle shared`). Contents of 1 MiB or more are also kept
  in the cache, so that later runs can clone or copy them instead of
  decoding them again; `bound cache clean` removes all of it, and
  `BOUND_CACHE=0` turns the cache off.
* Windows and Unix process semantics differ in several details (signals,
  `exec`, argument parsing, file locking). See
  [docs/platforms.md](docs/platforms.md).

## Performance

Measured with `target/release/bound-bench` (medians of 5 to 30 runs; the
program is a trivial one that exits at once). "Run" is the time until the
caller sees the program's exit status; the bundle directory is removed by
the reaper afterwards.

| | Linux arm64 | macOS arm64 | Windows x86_64 |
|---|---:|---:|---:|
| The program started directly | 0.36 ms | 1.5 ms | 10 ms |
| Run, nothing bundled | 0.54 ms | 3.3 ms | 26 ms |
| Run, 1 file (4 KiB) | 1.2 ms | 4.3 ms | 42 ms |
| Run, 1,000 files (4 MiB) | 21 ms | 82 ms | 0.9 s |
| Run, 10,000 files (10 MiB) | 152 ms | 648 ms | 8.7 s |
| Run, 10,000 files, `--bundle shared` | 23 ms | 22 ms | 56–82 ms |
| Run, one 100 MiB file (from the cache) | 14 ms | 6 ms | 0.17 s |
| Build, 10,000 files | 75 ms | 191 ms | 1.4–1.5 s |
| Build, 100 MiB of text (→ 0.6 MiB artifact) | 70 ms | 62 ms | 0.9–1.0 s |
| Verify, 100 MiB | 51–88 ms | 51–99 ms | 0.6–1.3 s |
| Launcher peak memory (10,000 files) | 8.2 MiB | — | 9.0 MiB |

Linux ran in a container on the same Apple M-series machine as macOS;
Windows on a 2-vCPU cloud VM with Microsoft Defender scanning every new
file, which dominates its times (and makes shared bundles especially
worthwhile there). Its first three rows come from `bound-bench --startup`:
a full run writes the inputs of the large cases first, Defender is still
scanning them while the start-up cases are measured, and Windows process
creation times vary widely under load. With files to extract, the
Windows launcher also waits for the reaper to be running before it starts
the program (about 10 ms; see [docs/platforms.md](docs/platforms.md)). On
macOS the kernel reports the program's own peak memory after `exec`, so
the launcher's is not shown.

Where the time goes: launching costs one read of the manifest plus, with
files, extraction, which is dominated by the file system's cost of creating
files (about 15 µs per file on Linux, 60 µs on APFS, and far more under
antivirus scanning). Contents of 1 MiB or more are decoded once into the
cache and then cloned (APFS, Btrfs, XFS) or copied on every run. Shared
bundles skip extraction entirely after the first run. Builds read, hash and
compress files on up to 8 threads; the release binaries are optimized for
size (the launcher is about 0.6 MiB and is part of every artifact).

## Environment variables

| Variable | Meaning |
|---|---|
| `BOUND_ROOT` | Set for the program: the bundle directory. |
| `TMPDIR` (`TEMP` on Windows) | Where private bundle directories are created. |
| `BOUND_CACHE_DIR` | Location of the cache (default: `~/.cache/bound` or `$XDG_CACHE_HOME/bound` on Linux, `~/Library/Caches/bound` on macOS, `%LOCALAPPDATA%\bound\cache` on Windows). |
| `BOUND_CACHE` | `0`, `off`, `no` or `false` turns the cache off: everything is read from the artifact on every run. |
| `BOUND_LAUNCHER` | The launcher `bound build` uses by default. |

## Platforms

Linux (x86_64, aarch64), macOS (Apple silicon) and Windows (x86_64,
aarch64) are supported and tested in CI; Intel Macs are not supported. See [docs/platforms.md](docs/platforms.md)
for the differences that matter.

## Documentation

* [docs/design.md](docs/design.md): architecture and the reasoning behind it
* [docs/format.md](docs/format.md): the artifact format (normative)
* [docs/security.md](docs/security.md): threat model and defenses
* [docs/platforms.md](docs/platforms.md): Linux, macOS and Windows behavior

## Development

```sh
cargo test --workspace        # unit tests, the end-to-end suite and examples/
cargo clippy --workspace --all-targets
scripts/smoke.sh              # README examples against target/release (Unix)
scripts/smoke.ps1             # the same on Windows
cargo build --release -p bound-cli -p bound-tests
target/release/bound-bench    # the benchmarks above (--quick for a short run, --startup for the first rows)
```

Every test runs on every platform, each checking its platform's form of
what it covers (signals or console events, `exec` or a job object, modes or
access lists). The suite needs, besides Rust: an official build of Node.js
with npm (nodejs.org, nvm, fnm, Volta; Homebrew's `node` cannot be embedded,
and `BOUND_EXAMPLE_NODE` can name another), uv, a Python 3 in `PATH`, and
network access for the examples' packages. On Windows it creates symbolic
links, which needs Developer Mode or an administrator.

To release: set the new version in `Cargo.toml` (`[workspace.package]` and
the workspace's own dependencies), commit it with the updated `Cargo.lock`,
and push a tag `vX.Y.Z`. The release workflow checks that the tag matches,
builds and smoke-tests the binaries on every platform, publishes the GitHub
release, and then publishes the crates to crates.io through trusted
publishing. rules_bound then gets the version's checksums
(`scripts/checksums.sh` in that repository).

Fuzzing needs a nightly toolchain and `cargo-fuzz`: `fuzz/seed.sh` builds a
seed corpus, then `cd fuzz && cargo +nightly fuzz run artifact` (or
`manifest`, `names`).

The workspace:

| Crate | Role |
|---|---|
| `crates/bound-format` | The artifact format: footer, manifest, names, hashing, reading, writing, verification. Platform-independent. |
| `crates/bound-platform` | The only OS-specific code: private directories, exclusive file creation, cloning, program lookup, `exec`, the reaper, console events and job objects. |
| `crates/bound-runtime` | The code inside every artifact: materialize resources (with the cache), build the invocation, run it. |
| `crates/bound` (`bound-cli`) | The `bound` command line and the `bound-launcher` stub. |
| `crates/bound-tests` | End-to-end tests and the `bound-fixture` program they bind. |

## License

Apache License 2.0; see [LICENSE](LICENSE).
