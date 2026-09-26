# The bound artifact format, versions 1 and 2

This document is normative. The reference implementation is the
`bound-format` crate; where this document and the code disagree, that is a
bug in one of them.

## Overview

An artifact is a native executable followed by three appended regions and,
optionally, a platform code signature:

```text
offset 0
┌──────────────────────────┐
│ launcher                 │  a normal ELF / Mach-O / PE executable
├──────────────────────────┤  footer.payload_offset
│ payload                  │  stored file contents ("blobs"), back to back
├──────────────────────────┤  footer.manifest_offset
│ manifest                 │  compact binary encoding (postcard)
├──────────────────────────┤  end − 88
│ footer (88 bytes)        │  fixed layout, little-endian
├──────────────────────────┤  end: the end of the bound regions
│ code signature           │  optional, after ≤ 15 zero bytes of padding;
└──────────────────────────┘  see "Code signatures"
```

The launcher, payload, manifest and footer (the *bound regions*) tile the
start of the file exactly: no gaps and no overlap. They end the file,
unless a code signature follows them (see [Code
signatures](#code-signatures)); nothing else may. Operating systems load
executables from their headers and ignore data past the last segment or
section, so the launcher runs unmodified (this is verified on ELF, Mach-O
and PE in the test suite).

The launcher part is platform-specific. The payload, manifest and footer
are not: the same parser reads them on every platform, and an artifact for
any platform can be inspected and verified on any other.

## Footer

The footer occupies the last 88 bytes of the bound regions. All integers
are unsigned and little-endian.

| Offset | Size | Field | Value |
|-------:|-----:|---|---|
| 0 | 8 | `payload_offset` | Start of the payload = length of the launcher. Must be > 0. |
| 8 | 8 | `payload_len` | Length of the payload. |
| 16 | 8 | `manifest_offset` | Start of the manifest. Must equal `payload_offset + payload_len`. |
| 24 | 8 | `manifest_len` | Length of the manifest. Must be > 0 and ≤ 64 MiB, and `manifest_offset + manifest_len` must equal `end − 88`. |
| 32 | 32 | `manifest_sha256` | SHA-256 of the manifest bytes. |
| 64 | 4 | `flags` | Must be 0 (versions 1 and 2). |
| 68 | 2 | `footer_len` | 88 (versions 1 and 2). |
| 70 | 2 | `format_version` | The artifact's version, 1 or 2 (see [Versioning](#versioning)). |
| 72 | 16 | `magic` | The ASCII bytes `<bound-artifact>`. |

All sums are computed with overflow checks; any overflow is an error.

### Identification

A reader identifies an artifact from the last 20 bytes of the bound
regions (`footer_len`, `format_version`, `magic`), a layout that every
future version keeps:

1. Find where the bound regions end at the latest: the start of the code
   signature named by the executable's header, if one ends the file (see
   [Code signatures](#code-signatures)), and otherwise the end of the file.
2. The magic must end there, or be followed only by up to 15 zero bytes
   before it, and end at least 20 bytes into the file. If it does not: not
   an artifact. Its end is `end`.
3. If `format_version` is 0: malformed.
4. If `format_version` is greater than the versions the reader supports:
   report *"unsupported bound artifact format version N"* and stop.
5. Otherwise `footer_len` must match the version (88 for versions 1 and
   2); the reader then reads and checks the whole footer.

## Manifest

The manifest describes the bound invocation and every resource. It is
stored in the [postcard wire format][postcard], a compact positional
binary encoding: there are no field names and no type information, only
the values, in the order of the schema below.

[postcard]: https://postcard.jamesmunns.com/wire-format

| Type | Encoding |
|---|---|
| `u16`, `u64` | Unsigned LEB128 varint: 7 bits per byte, least significant group first, the high bit set on every byte but the last (1000 is `e8 07`). |
| `bool` | One byte, `00` or `01`. |
| `digest` | A SHA-256: 32 bytes, as is. |
| `string` | Varint length in bytes, then that many bytes of UTF-8. |
| `bytes` | Varint length, then that many bytes. |
| `list<T>` | Varint element count, then the elements. |
| `enum` | Varint variant index (the numbers in the schema), then that variant's fields. |
| struct | Its fields in order, nothing else. |

### Schema

```text
Manifest {
  format:    u16
  generator: string
  platform:  Platform { os: string, arch: string, binary_format: string }
  launcher:  Region { size: u64, sha256: digest }
  payload:   Region
  target:    Target
  args:      list<Arg>
  env:       list<Env { name: PlatformString, value: EnvValue }>
  cwd:       enum { 0 Inherit, 1 Bundle, 2 Dir(ResourcePath) }       # Dir: version 2
  bundle:    enum { 0 Private, 1 Shared }
  resources: list<Resource>
  blobs:     list<Blob>
}

Target   = enum { 0 External(program: PlatformString), 1 Embedded(resource: ResourcePath) }
Arg      = enum { 0 Literal(PlatformString), 1 Resource(ResourcePath), 2 RuntimeArgs }
EnvValue = enum { 0 Literal(PlatformString), 1 Resource(ResourcePath), 2 Unset,
                  3 List(before: list<ListEntry>, after: list<ListEntry>) }   # List: version 2
ListEntry = enum { 0 Literal(PlatformString), 1 Resource(ResourcePath) }
Resource = enum {
  0 Dir     { path: ResourcePath }
  1 File    { path: ResourcePath, size: u64, sha256: digest, executable: bool }
  2 Symlink { path: ResourcePath, target: LinkTarget }
}
Blob = { sha256: digest, size: u64, offset: u64, stored_size: u64,
         compression: enum { 0 Stored, 1 Zstd } }

PlatformString = enum { 0 Unicode(string), 1 UnixBytes(bytes), 2 WindowsWide(list<u16>) }
ResourcePath   = bytes
LinkTarget     = bytes
```

For example, this manifest (digests abbreviated to their byte value):

```text
01                                 format 1
0b "bound 0.1.0"                   generator
05 "linux" 06 "x86_64" 03 "elf"    platform
e8 07 aa…aa                        launcher: 1000 bytes, SHA-256
05 bb…bb                           payload: 5 bytes, SHA-256
00 00 04 "grep"                    target: External(Unicode "grep")
03                                 3 arguments:
   00 00 02 "-n"                     Literal(Unicode "-n")
   01 05 "a.txt"                     Resource("a.txt")
   02                                RuntimeArgs
01                                 1 environment binding:
   00 04 "MODE" 00 00 04 "prod"      MODE = Literal(Unicode "prod")
01                                 cwd: Bundle
01                                 bundle: Shared
01                                 1 resource:
   01 05 "a.txt" 05 cc…cc 00         File "a.txt", 5 bytes, SHA-256, not executable
01                                 1 blob:
   cc…cc 05 00 05 00                 SHA-256, size 5, offset 0, stored size 5, Stored
```

Readers decode strictly: an unknown variant index, a malformed varint or
`bool`, invalid UTF-8 in a `string`, a list longer than its limit (checked
before any element is read; see [Limits](#limits)) and bytes after the
manifest are all errors. The values are then checked as described below,
and finally the manifest must be exactly the encoding of what was decoded:
varints must be minimal (postcard decoders otherwise accept, for example,
`81 00` for 1), and a platform string may use a raw form only when it is
not valid Unicode. So one manifest has one encoding, and a manifest digest
identifies one meaning. The manifest is then validated as
a whole before anything acts on it.

`bound inspect --json` shows the manifest's fields in JSON: variants as
`{"type": "file", …}` (`"mode"` for the target), lowercase names for the
other enums, digests as 64 lowercase hex digits, and platform strings and
paths as described below.

### Fields

| Field | Meaning |
|---|---|
| `format` | Must equal the footer's `format_version`, and must be the lowest version that expresses the manifest (see [Versioning](#versioning)). |
| `generator` | The tool that wrote the artifact. Informational; at most 256 bytes, no control characters. |
| `platform` | `os`, `arch`, `binary_format`: lowercase identifiers (`[a-z0-9_-]`, 1–256 bytes) describing the launcher, determined from its executable header (`linux`/`macos`/`windows`…, `x86_64`/`aarch64`…, `elf`/`mach-o`/`pe`). |
| `launcher` | `size` (must equal `payload_offset`) and `sha256` of the launcher region, computed with the fields code signing rewrites taken as zero (see [Code signatures](#code-signatures)). |
| `payload` | `size` (must equal `payload_len`) and `sha256` of the entire payload region, including any bytes decoding would ignore. |
| `target` | The program; see below. |
| `args` | The argument template; see below. |
| `env` | Environment bindings, applied in order. |
| `cwd` | `Inherit` (the caller's directory), `Bundle` (the bundle root) or `Dir` (a directory of the bundle, which must be a `Dir` resource). |
| `bundle` | `Private`: a new private bundle directory for every run, removed after it. `Shared`: one read-only bundle directory per user, in the user's cache, extracted by the first run and used by every later one (readers fall back to `Private` when no cache is usable). Irrelevant when the artifact has no bundle directory. |
| `resources` | Every entry of the bundle tree. |
| `blobs` | Stored contents, in payload order. |

### Platform strings

Program names, arguments and environment names and values are *platform
strings*. Valid Unicode is stored as `Unicode`; anything else in a raw
form, so that no value is ever altered:

| Variant | Meaning | JSON form |
|---|---|---|
| `Unicode` | Valid Unicode; representable on every platform. | `"text"` |
| `UnixBytes` | Bytes that are **not** valid UTF-8 (Unix only). | `{"unix_bytes": "HEX"}` |
| `WindowsWide` | UTF-16 code units that are **not** well-formed UTF-16 (Windows only). | `{"windows_utf16": "HEX"}`, four hex digits per unit, most significant first |

A raw form whose content is valid Unicode is rejected (every value has
exactly one encoding). Platform strings must not contain NUL, and must be
representable on the artifact's platform.

### Target

* **External**: the program is not bundled. The launcher passes `program`
  to the operating system, which resolves it with its native rules (a bare
  name is searched in `PATH`; see `docs/platforms.md`). Must not be empty.
* **Embedded**: the program is the named file resource, which must be
  marked `executable`. The launcher runs its materialized copy by absolute
  path.

### Argument template

| Element | Replaced by |
|---|---|
| `Literal(value)` | The value. |
| `Resource(path)` | The absolute native path of the materialized resource. |
| `RuntimeArgs` | The arguments the artifact was invoked with (zero or more). |

At most one `RuntimeArgs` element may appear. If there is none, the
artifact accepts no run-time arguments and the launcher fails (status 125)
when given any. (`bound build` always writes exactly one.) The template
produces the arguments that follow the program name; the program name
itself (`argv[0]`) is the external program string or the absolute path of
the embedded program.

### Environment bindings

A binding's value is a `Literal` platform string, the absolute native path
of a `Resource`, `Unset`: the variable is removed from the environment the
program inherits, or a `List` (version 2): a list variable such as `PATH`,
whose value is its `before` entries, then the caller's value of the
variable when it is set and not empty (looked up as the platform compares
names), then its `after` entries, joined with the artifact platform's list
separator, `;` for Windows and `:` elsewhere. An entry is a `Literal`
platform string or the absolute native path of a `Resource`. A list has at
least one entry; a literal entry is not empty; neither a literal entry nor
a resource entry's path contains the separator, so that no entry splits
into several. Only the bundle root can still bring a separator at run time
(a temporary directory whose path holds it); the launcher then fails with
status 125. Names must be non-empty and must not contain `=`.
Names must be unique when compared case-insensitively (Windows compares
environment names that way), and `BOUND_ROOT` is reserved. The launcher
starts from the caller's environment, applies the bindings, and then sets
`BOUND_ROOT` to the bundle root if there is one, or removes `BOUND_ROOT`
otherwise.

### Resources

* Resources are sorted by path, bytewise, without duplicates; this places
  every directory before its contents.
* Every resource's parent must be declared as a `Dir` resource.
* In artifacts for macOS and Windows, whose file systems ignore case, no
  two paths may be equal when compared case-insensitively: for UTF-8
  names, after converting to uppercase and then lowercase twice (which
  equates, for example, `ς` with `σ` and `ß` with `ss`); ASCII lowercase
  otherwise. Readers that materialize on Windows apply this rule to every
  artifact. Other artifacts may contain such names (Linux software such as
  the terminfo database does). Unicode normalization is not applied, so
  names that differ only in composition are accepted. Every file is
  created exclusively, so extracting names that a file system considers
  equal fails rather than overwrite.
* A `File`'s `sha256` and `size` describe its uncompressed content; exactly
  one blob with that `sha256` must exist, with the same `size`. Several
  files may share a blob.
* `executable` requests execute permission where the platform has such a
  permission (Unix). It is ignored on Windows.
* A `Symlink`'s target is resolved against the resource tree the way the
  kernel would resolve it after extraction (following other symlinks in the
  tree, applying `..` to the resolved location). The resolution must stay
  inside the bundle, must not end at the bundle root, must not traverse a
  regular file, must not dangle, and may follow at most 40 links. Readers
  that cannot create symbolic links (Windows without the privilege) may
  materialize a link to a directory as a junction to where it resolves,
  and a link to a file as a hard link to (or a copy of) the file it
  resolves to.

A resource that the target, an argument, a binding or a list entry names
must exist, and a `Dir` working directory must name a `Dir` resource (not a
link to one).

### Resource paths

A resource path names an entry relative to the bundle root. It is a
non-empty sequence of components joined by `/`, stored as bytes (UTF-8
when the name is valid Unicode; in JSON, a string, or `{"unix_bytes":
"HEX"}` otherwise). At most 4096 bytes. Every component must be:

* non-empty, at most 255 bytes, and not `.` or `..`;
* free of `/`, `\`, NUL, and control characters (U+0001–U+001F, U+007F,
  and in UTF-8 names also U+0080–U+009F).

When the artifact's platform is Windows, or when the reader materializes on
Windows, every component must additionally be valid UTF-8, must not
contain any of `< > : " | ? *`, must not end in `.` or space, and must not
be a reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`,
`LPT0`–`LPT9`, `COM¹`–`COM³`, `LPT¹`–`LPT³`, `CONIN$`, `CONOUT$`), with or
without an extension, in any case.

These rules guarantee that no path can name anything outside the bundle
root on any platform: absolute paths, drive letters, UNC and device paths,
`..`, mixed separators and alternate data streams are all impossible.

### Link targets

A link target is a relative path written like a resource path, except that
components may also be `.` or `..`. It must not be empty, absolute or
longer than 4096 bytes, and must not contain empty components (`a//b`,
trailing `/`).

### Blobs

* `offset` is relative to the start of the payload. Blobs are listed in
  offset order and tile the payload exactly: the first starts at 0, each
  starts where the previous ends, and the last ends at `payload_len`.
* `sha256` is unique among blobs and must be referenced by at least one
  file.
* `Stored`: the content is stored as is; `size` must equal `stored_size`.
* `Zstd`: the stored bytes are exactly one Zstandard frame (RFC 8878)
  that decodes to `size` bytes, without a dictionary. A frame that ends
  early, overruns `size`, or leaves stored bytes after its end (including a
  second frame) is corrupt. Its window may be at most 8 MiB. `stored_size`
  must be non-zero and `size` must not exceed `32768 × stored_size` (the
  densest zstd encoding, a run-length block, turns 4 bytes into at most
  128 KiB). Frame checksums are optional and not relied on: contents are
  verified with SHA-256.

## Integrity

Every byte of the bound regions is covered by a chain of hashes:

```text
footer ──manifest_sha256──▶ manifest ──┬─ launcher.sha256 ──▶ launcher region
                                       ├─ payload.sha256  ──▶ payload region
                                       └─ blobs[].sha256  ──▶ decoded contents
```

The footer's own fields are protected by the structural checks: any change
to an offset or length breaks the tiling or the manifest hash. The only
launcher bytes left out are the few header fields that code signing
rewrites (see [Code signatures](#code-signatures)).

* Readers (including the launcher) always check the footer structure, the
  manifest hash, and the whole manifest before using any of it.
* The launcher verifies the size and SHA-256 of each content it extracts,
  and refuses to start the program if anything differs.
* `bound verify` additionally hashes the launcher and payload regions, so
  it detects modifications to bytes that do not change any extracted
  content (such as the frame checksum or other redundant bits of a zstd
  frame).

This is integrity, not authenticity: anyone can produce a consistent
artifact. A platform code signature made with a trusted identity provides
authenticity; see below and `docs/security.md`.

## Code signatures

Code signing tools append a signature to the file and name it in the
executable's header. An artifact can carry one after its bound regions:

* **Where.** When the launcher's header names a code signature that ends
  the file, the bound regions end before it, possibly followed by up to 15
  zero bytes of alignment padding. The header is read from the first
  64 KiB of the file:
  * Mach-O (64-bit): the `LC_CODE_SIGNATURE` load command's `dataoff` and
    `datasize`. Signatures are 16-byte aligned.
  * PE: the certificate table, data directory 4 of the optional header,
    whose address is a file offset. Tables are 8-byte aligned.

  A signature that does not end the file is not a signature for this
  purpose: the bound regions must then end the file.
* **What is hashed.** Signing rewrites a few header fields, which
  `launcher.sha256` therefore covers as if they were zero:
  * PE: the checksum (4 bytes at optional header + 64) and the
    certificate table's directory entry (8 bytes);
  * Mach-O: the `__LINKEDIT` segment's `vmsize` and `filesize` (8 bytes
    each, at `LC_SEGMENT_64` + 32 and + 48) and `LC_CODE_SIGNATURE`'s
    `dataoff` and `datasize` (at + 8).

  Every other byte of the bound regions is hashed as usual, so signing
  cannot hide any other change. The signature itself is not part of any
  bound hash: re-signing does not change the manifest digest.
* **Checking** signatures is the platform's job (`codesign --verify`,
  `signtool verify`, Gatekeeper, SmartScreen). bound reports whether one
  is present.

Mach-O artifacts are always signed, because Apple silicon runs no unsigned
code. The reference writer:

1. removes the launcher's own signature (the linker's ad-hoc signature,
   which covers only the launcher), or adds an `LC_CODE_SIGNATURE` command
   in the free space after the load commands if the launcher has none;
2. after the footer, pads the file to a multiple of 16 bytes and extends
   `__LINKEDIT` to the end of the file (`filesize`; `vmsize` rounded up to
   the page size, 16 KiB on arm64 and 4 KiB otherwise), so that the bound
   regions are part of the Mach-O image, which `codesign` requires;
3. appends an ad-hoc signature: a SuperBlob holding one CodeDirectory
   (version 0x20400, flags adhoc and linker-signed, SHA-256 hashes of every
   4 KiB page up to the signature, identifier `bound-` followed by the
   first 16 hex digits of the manifest digest).

Such an artifact passes `codesign --verify --strict`, and `codesign --sign
IDENTITY --force` replaces the ad-hoc signature with one made with an
identity. Mach-O artifacts are limited to 4 GiB, the size a code
directory can cover.

PE artifacts are written unsigned: if the launcher is signed, its
certificate table (which must end the launcher) is removed, and the table's
directory entry and the checksum are zeroed. `signtool sign` or
`Set-AuthenticodeSignature` then signs the finished artifact; Authenticode's hash covers the bound regions (everything but the
checksum, the certificate table entry and the table itself). ELF has no
embedded code signatures.

## Limits

Readers treat every artifact as untrusted and never allocate or loop based
on an unchecked length:

| Limit | Value |
|---|---|
| Manifest size | 64 MiB |
| Resource path / link target | 4096 bytes |
| Path component | 255 bytes |
| Symlink resolution depth | 40 |
| Resources | 1,000,000 |
| Blobs | 1,000,000 |
| Argument template elements | 100,000 |
| Environment bindings | 100,000 |
| List entries, all list bindings together | 100,000 |
| zstd window | 8 MiB |
| zstd expansion | 32768 × stored size |

## Determinism

Writers produce identical bytes for identical inputs: the launcher bytes,
the argument template, the environment bindings, the working-directory and
bundle modes and the resource tree (names, contents and executable bits).
The format records no timestamps, owners, absolute build paths or random
values; blobs are written in resource path order, identical contents once;
and how a content is stored depends only on its bytes. The reference writer
compresses the first 64 KiB with zstd at level 1 as a probe: content that
does not shrink by at least 1/32 (typically media, archives and other
compressed data) is `Stored`, anything else is compressed with zstd at
level 9, keeping the stored form if compression does not help. Contents
smaller than 8 MiB are compressed in one piece, possibly on another thread
(the writer reads, hashes and compresses files in parallel, and writes them
in order); larger ones are streamed through zstd's multithreaded mode, in
fixed 1 MiB pieces, which produces the same frame whatever the number of
threads. The output therefore depends neither on the machine nor on the
number of threads, only on the version of the zstd library, which is
pinned. The Mach-O signature is computed from the bytes before it, so it is
deterministic too.

## Versioning

The version-independent 20-byte tail lets any reader recognize an artifact
and name its version. A reader rejects versions it does not know. Any change
an older reader would misinterpret (a new field, a new variant, a reordered
variant, a new footer flag) requires a new format version. Adding new
`platform` values does not, as those are open identifiers.

Version 2 added the `Dir` working directory and `List` bindings; nothing
else differs. An artifact records the lowest version that expresses it: 2
exactly when its manifest uses one of those variants, and 1 otherwise, so
that readers of version 1 still read it. A version-1 manifest using a
version-2 variant is rejected, and so is a version-2 manifest using none:
one meaning keeps one encoding. The manifest's `format` must equal the
footer's `format_version`.

## `bound inspect --json`

A stable document derived from the artifact, versioned by
`inspect_format` (currently 1):

| Field | Meaning |
|---|---|
| `inspect_format` | 1. |
| `path` | The artifact path as given (platform string). |
| `size` | File length, including any code signature. |
| `digest` | The manifest's SHA-256, which identifies the artifact. |
| `format`, `generator`, `platform` | From the manifest. |
| `regions` | `launcher`, `payload`, `manifest` (`offset`, `size`, `sha256`) and `footer` (`offset`, `size`). |
| `code_signature` | Present when the artifact carries one: `kind` (`mach_o` or `authenticode`), `offset`, `size`, and for Mach-O `identity` (whether it was made with a signing identity rather than ad hoc). |
| `target`, `args`, `env`, `cwd`, `bundle`, `resources` | The manifest's fields in JSON (see [Manifest](#manifest)). `cwd` is `"inherit"`, `"bundle"` or `{"dir": PATH}`; a list binding's value is `{"type": "list", "before": […], "after": […]}`, with entries `{"type": "literal", "value": …}` and `{"type": "resource", "path": …}`. |
| `nested` | Present when the embedded program is itself a bound artifact: the same document for that artifact. Nested artifacts are examined up to 8 levels deep and 256 MiB in total. |
| `nested_not_examined` | Present (and `true`) when the embedded program was not examined because of those limits. |
| `bundle_directory` | Whether running creates a bundle directory. |
| `external_dependencies` | Programs needed on the destination system (`{"kind": "program", "name": …}`). |

For example, the fields from `target` on of an artifact that runs a
Python script:

```json
{
  "target": { "mode": "external", "program": "python" },
  "args": [
    { "type": "resource", "path": "report.py" },
    { "type": "literal", "value": "--template" },
    { "type": "resource", "path": "report.html" },
    { "type": "runtime_args" }
  ],
  "env": [
    { "name": "MODE", "value": { "type": "literal", "value": "production" } }
  ],
  "cwd": "inherit",
  "bundle": "private",
  "resources": [
    { "type": "file", "path": "report.html", "size": 1210, "sha256": "…", "executable": false },
    { "type": "file", "path": "report.py", "size": 1934, "sha256": "…", "executable": false }
  ]
}
```

`bound verify --json` prints `{"ok", "path", "digest", "problems"}`, where
`problems` lists every failure found (empty when `ok` is true), and
`code_signature` (the kind) when the artifact carries one.
