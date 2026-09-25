# Node.js: a script and its node_modules as one executable

`md2html` renders Markdown as a standalone HTML page. It is a small ES
module project with two dependencies from npm:
[marked](https://marked.js.org/) (Markdown) and
[yaml](https://eemeli.org/yaml/) (the front matter at the top of a page),
and [esbuild](https://esbuild.github.io/) as a development dependency.

```sh
npm ci                       # node_modules, with the dev dependencies
npm test                     # node --test
node src/md2html.js samples/post.md -o post.html
```

The page's variables come from the front matter (`title`, `author`), the
template from `--template FILE`, `$MD2HTML_TEMPLATE` or the built-in
`templates/page.html`, found next to the script.

Running it elsewhere normally means copying the project, installing Node.js
and running `npm ci`. bound turns it into one executable instead, in
several ways:

| | Needs on the destination | Size (macOS arm64) | First run, then |
|---|---|---:|---|
| [1. node_modules bundled](#1-node_modules-bundled) | Node.js 20 or later | 0.9 MiB | 0.4 s, then 0.1 s |
| [2. A preset](#2-a-preset-arguments-bound-too) | Node.js 20 or later | 0.9 MiB | 0.4 s, then 0.1 s |
| [3. One bundled script](#3-one-bundled-script) | Node.js 20 or later | 0.6 MiB | 0.2 s, then 0.05 s |
| [4. Self-contained](#4-self-contained-nodejs-included) | nothing | 32 MiB | 2.8 s, then 0.05 s |

The commands below are for Linux and macOS; the Windows (PowerShell)
equivalents follow each one where they differ. bound does not create the
output directory, so start with:

```sh
mkdir -p bin                 # PowerShell: mkdir -Force bin
```

## 1. node_modules bundled

Install the production dependencies only, and bundle them with the script:

```sh
npm ci --omit=dev
bound -o bin/md2html --bundle shared --include package.json --include node_modules --include templates -- node @file:src/md2html.js @args
./bin/md2html samples/post.md -o post.html
```

* `@file:src/md2html.js` bundles the script; when the executable runs, the
  argument becomes the path of its copy. `@args` marks where the arguments
  given at run time go.
* `--include` bundles files and directories at the same relative paths, so
  Node.js finds everything where it expects it: `node_modules` next to
  `src/` for `import "marked"`, `package.json` for `"type": "module"`, and
  `templates/` for the built-in template.
* `node` is not bundled: it is looked up in `PATH` where the executable
  runs, like any command.
* `--bundle shared` extracts the 250 files of `node_modules` once, into
  your cache, instead of for every run.

## 2. A preset: arguments bound too

Bound arguments can be anything, including more files. This executable
always uses the dark template:

```sh
bound -o bin/md2html-dark --bundle shared --include package.json --include node_modules --include templates -- node @file:src/md2html.js --template @file:templates/dark.html @args
./bin/md2html-dark samples/post.md -o post.html
```

Setting the template through the environment instead,
`--env MD2HTML_TEMPLATE=@file:templates/dark.html`, works the same way.

## 3. One bundled script

A bundler can replace `node_modules`: esbuild writes the script and its
dependencies into one file, `build/md2html.mjs` (see `build.mjs`):

```sh
npm ci
npm run bundle
bound -o bin/md2html-single --include templates -- node @file:build/md2html.mjs @args
./bin/md2html-single samples/post.md -o post.html
```

```powershell
npm ci
npm run bundle
bound -o bin\md2html-single --include templates -- node @file:build\md2html.mjs @args
.\bin\md2html-single.exe samples\post.md -o post.html
```

With two files to extract instead of 250, it starts about as fast as
`node` itself, without a shared bundle.

## 4. Self-contained: Node.js included

`--embed-program` bundles the program itself. `node -p process.execPath`
prints the path of the real `node` executable, even when `node` in your
`PATH` is a version manager's shim:

```sh
bound --embed-program --bundle shared -o bin/md2html-standalone --include templates -- "$(node -p process.execPath)" @file:build/md2html.mjs @args
./bin/md2html-standalone samples/post.md -o post.html
```

```powershell
bound --embed-program --bundle shared -o bin\md2html-standalone --include templates -- (node -p process.execPath) @file:build\md2html.mjs @args
.\bin\md2html-standalone.exe samples\post.md -o post.html
```

The executable runs where Node.js is not installed at all. `--bundle
shared` extracts the 120 MB `node` binary once; every later run starts at
once.

This needs an official build of Node.js, from
[nodejs.org](https://nodejs.org/) or a version manager that installs those
(nvm, fnm, Volta, mise, or `actions/setup-node` in GitHub Actions): it is a
single executable. bound bundles only the program file, not the shared
libraries it loads, and some builds of Node.js load their own: Homebrew's,
and those of many Linux distributions. To check, list what `node` loads;
only system libraries should appear:

```sh
otool -L "$(node -p process.execPath)"      # macOS
ldd "$(node -p process.execPath)"           # Linux
```

## What to look at

```sh
bound inspect bin/md2html    # what it runs, with which arguments, and every bundled file
bound verify bin/md2html     # checks every hash
```

`tests/examples.rs` in bound's test suite runs these commands on Linux,
macOS and Windows.
