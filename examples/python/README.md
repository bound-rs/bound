# Python: a uv project as one executable

`report` renders a CSV file as an HTML report, totalling its numeric
columns. It is an ordinary modern Python project:

* managed with [uv](https://docs.astral.sh/uv/): `pyproject.toml` with the
  `uv_build` backend, a `src/` layout, and a lock file (`uv.lock`);
* one dependency, [Jinja2](https://jinja.palletsprojects.com/), which
  brings MarkupSafe, a package with a compiled extension;
* type-checked with [ty](https://docs.astral.sh/ty/) and tested with
  pytest.

```sh
uv sync                      # .venv with the dependencies and the dev tools
uv run ty check              # type check
uv run pytest                # tests
uv run report samples/sales.csv --title "Sales" -o sales.html
```

Running it elsewhere normally means installing Python, creating a virtual
environment and installing the project. bound turns it into one
executable instead, in three ways that differ in what the destination
needs:

| | Needs on the destination | Size (macOS arm64) | First run, then |
|---|---|---:|---|
| [1. The wheel, run by uv](#1-the-wheel-run-by-uv) | uv, and network access once | 0.5 MiB | 0.9 s, then 0.1 s |
| [2. Dependencies bundled](#2-dependencies-bundled-the-destinations-python) | Python 3.13 | 0.7 MiB | 0.7 s, then 0.15 s |
| [3. Self-contained](#3-self-contained-python-included) | nothing | 31 MiB | 2.6 s, then 0.15 s |

The commands below are for Linux and macOS; the Windows (PowerShell)
equivalents follow each one where they differ. bound does not create the
output directory, so start with:

```sh
mkdir -p bin                 # PowerShell: mkdir -Force bin
```

## 1. The wheel, run by uv

Build the wheel and bind [`uvx`](https://docs.astral.sh/uv/guides/tools/)
to it:

```sh
uv build --wheel
bound -o bin/report-uvx --bundle shared -- uvx --from @file:dist/report-0.1.0-py3-none-any.whl report @args
./bin/report-uvx samples/sales.csv --title "Sales" -o sales.html
```

* `@file:dist/report-0.1.0-py3-none-any.whl` bundles the wheel. When the
  executable runs, the argument becomes the path of the wheel's copy, which
  keeps its file name (uv reads the name and version from it).
* `@args` marks where the arguments given at run time go.
* On the first run, uv resolves Jinja2 from PyPI and caches the tool's
  environment; later runs reuse it. `--bundle shared` keeps the wheel at the
  same path from run to run, so that uv recognizes it.

The executable is small, and uv does the rest; the destination needs uv
and, once, network access.

## 2. Dependencies bundled, the destination's Python

Install the project and its dependencies into a directory, and point
`PYTHONPATH` at the copy bound makes of it:

```sh
uv pip install --python 3.13 --target build/site-packages .
bound -o bin/report-py --bundle shared --env PYTHONPATH=@file:build/site-packages -- python3 -m report @args
./bin/report-py samples/sales.csv --title "Sales" -o sales.html
```

```powershell
uv pip install --python 3.13 --target build\site-packages .
bound -o bin\report-py --bundle shared --env PYTHONPATH=@file:build\site-packages -- python -m report @args
.\bin\report-py.exe samples\sales.csv --title "Sales" -o sales.html
```

* `--env NAME=@file:PATH` sets a variable to the path of a bundled file
  or directory.
* The program, `python3` (`python` on Windows), is not bundled: it is
  looked up in `PATH` where the executable runs, like any command.
* Compiled extensions only load in the Python version they were built
  for, so install for the destination's version (`--python 3.13`).
  MarkupSafe would fall back to pure Python on another version, but most
  packages with compiled code, such as NumPy, would not.
* `--bundle shared` extracts the packages once, into your cache, instead
  of for every run.

## 3. Self-contained: Python included

uv installs Python from
[python-build-standalone](https://github.com/astral-sh/python-build-standalone),
whose builds are *relocatable*: they run from any directory. Install one
into the project, install the app into it, and embed it:

```sh
uv python install 3.13 --install-dir build/runtime --no-bin --no-registry
mv build/runtime/cpython-3.13.* build/python
uv pip install --python build/python/bin/python3 --prefix build/python .
build/python/bin/python3 -m compileall -q -j 0 --invalidation-mode checked-hash build/python
bound --embed-program --bundle shared -o bin/report --include build/python -- build/python/bin/python3.13 -I -m report @args
./bin/report samples/sales.csv --title "Sales" -o sales.html
```

```powershell
uv python install 3.13 --install-dir build\runtime --no-bin --no-registry
Move-Item build\runtime\cpython-3.13.* build\python
uv pip install --python build\python\python.exe --prefix build\python .
build\python\python.exe -m compileall -q -j 0 --invalidation-mode checked-hash build\python\Lib
bound --embed-program --bundle shared -o bin\report --include build\python -- build\python\python.exe -I -m report @args
.\bin\report.exe samples\sales.csv --title "Sales" -o sales.html
```

Step by step:

1. `uv python install … --install-dir build/runtime` downloads CPython into
   the project instead of uv's own directory. `--no-bin` and
   `--no-registry` keep uv from adding it to your `PATH` or to the Windows
   registry. The directory name includes the exact version and platform
   (`cpython-3.13.15-macos-aarch64-none`), so move it to a fixed name.
2. `uv pip install --prefix build/python` installs the app and its
   dependencies into that Python's own `site-packages`.
3. `compileall` writes the bytecode Python would otherwise compile on every
   run. Bundled files get new modification times when they are extracted,
   which would make ordinary bytecode look stale; `checked-hash` bytecode
   is checked against the source's contents instead. (On Windows, compile
   `Lib`, which holds the standard library and `site-packages`: the Tcl/Tk
   files elsewhere include Python 2 code that does not compile.)
4. `--include build/python` bundles the whole interpreter, 2,800 files;
   `--embed-program` names the one to run, which is part of that tree
   (`python3.13` rather than the `python3` symlink next to it). The
   interpreter finds its standard library next to itself, wherever the
   bundle is extracted.
5. `-I` (isolated mode) makes Python ignore `PYTHONPATH`, `PYTHONHOME` and
   the user's site-packages, so nothing on the destination interferes.
6. `--bundle shared` extracts the 85 MB tree once, into your cache
   (about 1.5 s); every later run starts in about 0.15 s.

The build directory can then be deleted: the executable carries
everything. To make it smaller, delete what the app does not use from
`build/python` before binding: `include/`, `share/`, and in the standard
library `idlelib`, `tkinter`, `turtledemo` and `ensurepip`, and the Tcl/Tk
libraries.

## Presets: bind the executable again

A bound executable is a program like any other, so it can be bound again
with more arguments. This one always uses another title and template:

```sh
bound --embed-program --bundle shared -o bin/sales-summary -- ./bin/report --title "Sales summary" --template @file:templates/summary.html.j2 @args
./bin/sales-summary samples/sales.csv
```

```powershell
bound --embed-program --bundle shared -o bin\sales-summary -- .\bin\report.exe --title "Sales summary" --template @file:templates\summary.html.j2 @args
.\bin\sales-summary.exe samples\sales.csv
```

The inner executable keeps its own shared bundle, so the Python runtime is
extracted once for both.

## What to look at

```sh
bound inspect bin/report     # what it runs, with which arguments, and every bundled file
bound verify bin/report      # checks every hash
bound cache list             # shared bundles extracted so far
```

`tests/examples.rs` in bound's test suite runs these commands on Linux,
macOS and Windows.
