# Native: one program, many commands

`wordstats` counts the words of texts and prints the most frequent ones,
leaving out *stopwords* ("the", "and", "of"…). It is a native program, a
small Rust project with no dependencies, that is configured three ways:

* options: `--stopwords FILE` (repeatable), `--lang LANG`, `--top N`,
  `--format text|json`;
* data files: stopword lists, one word per line, in `stopwords/`;
* the environment: `WORDSTATS_FORMAT` sets the default output format, and
  `WORDSTATS_DATA` names the directory where `--lang fr` finds `fr.txt`.

```sh
cargo test
cargo build --release
./target/release/wordstats --stopwords stopwords/en.txt --top 3 samples/lighthouse.txt
#      8  keeper
#      5  ships
#      4  fog
```

A native program needs no interpreter, but a useful command is rarely just
the program: here it is the program, a stopword list and some options.
bound makes each such combination a command of its own, which carries its
data and runs anywhere the program does.

The commands below are for Linux and macOS. On Windows (PowerShell), the
program is `.\target\release\wordstats.exe`, the artifacts are written
with `.exe` appended (`bin\topwords.exe`), and paths may use `\`. bound
does not create the output directory, so start with:

```sh
mkdir -p bin                 # PowerShell: mkdir -Force bin
```

## 1. A preset: program, data and options

```sh
bound --embed-program -o bin/topwords -- ./target/release/wordstats --stopwords @file:stopwords/en.txt @args
./bin/topwords samples/lighthouse.txt
./bin/topwords --top 1 samples/lighthouse.txt
```

```powershell
bound --embed-program -o bin\topwords -- .\target\release\wordstats.exe --stopwords @file:stopwords\en.txt @args
.\bin\topwords.exe samples\lighthouse.txt
```

* `--embed-program` bundles the program itself: `topwords` runs on a
  machine where `wordstats` is not installed.
* `@file:stopwords/en.txt` bundles the list; when `topwords` runs, the
  argument becomes the path of its copy.
* `@args` marks where the arguments given at run time go: after the bound
  ones, so they can add to them or, as with `--top 1`, override them.

## 2. More presets from the same program

```sh
bound --embed-program -o bin/topwords-fr -- ./target/release/wordstats --stopwords @file:stopwords/fr.txt --top 3 @args
./bin/topwords-fr samples/phare.txt
#      6  gardien
#      4  brouillard
#      4  navires
```

## 3. Configuration through the environment

```sh
bound --embed-program -o bin/topwords-json --env WORDSTATS_FORMAT=json -- ./target/release/wordstats --stopwords @file:stopwords/en.txt @args
./bin/topwords-json --top 2 samples/lighthouse.txt
# [{"word":"keeper","count":8},{"word":"ships","count":5}]
```

`--env NAME=VALUE` sets a variable for the program. Variables the caller
sets reach the program too, but the bound ones take precedence.

## 4. A data directory

`--env NAME=@file:DIR` sets a variable to the path of a bundled directory.
This command carries every stopword list and lets the user choose:

```sh
bound --embed-program -o bin/wordstats --env WORDSTATS_DATA=@file:stopwords -- ./target/release/wordstats @args
./bin/wordstats --lang fr --top 3 samples/phare.txt
./bin/wordstats --lang en --lang de samples/lighthouse.txt
```

A program can also find its bundled files through `BOUND_ROOT`, which
bound sets to the directory it extracts them into (`--include stopwords`
places them at `$BOUND_ROOT/stopwords`).

## 5. Composition

An executable made by bound is a program, so it can be bound again:

```sh
bound --embed-program -o bin/top3 -- ./bin/topwords --top 3
./bin/top3 samples/lighthouse.txt
```

```powershell
bound --embed-program -o bin\top3 -- .\bin\topwords.exe --top 3
.\bin\top3.exe samples\lighthouse.txt
```

## 6. The program installed on the destination

Without `--embed-program`, the program is looked up in `PATH` when the
executable runs, like any command. The executable is then smaller, and uses
whatever version of `wordstats` is installed:

```sh
cargo install --path .
bound -o bin/topwords-installed -- wordstats --stopwords @file:stopwords/en.txt @args
```

`bound inspect bin/topwords-installed` lists `wordstats` among the
programs the destination needs.

## What to look at

```sh
bound inspect bin/topwords   # the program, the arguments, the bundled files
bound verify bin/topwords    # checks every hash
```

The build products can be deleted afterwards: every executable in `bin/`
carries what it needs. `tests/examples.rs` in bound's test suite runs
these commands on Linux, macOS and Windows.
