# Examples

Three small but real projects, each turned into single executables in
several ways. Each directory's README describes the project and every
command.

| Example | The project | What bound does with it |
|---|---|---|
| [node](node/) | A Markdown-to-HTML command in JavaScript, with dependencies in `node_modules` | Bundles the script with its `node_modules`; binds a template as a preset; bundles an esbuild single-file build instead; embeds Node.js itself for a self-contained executable |
| [python](python/) | A CSV-to-HTML report generator, a uv project (`pyproject.toml`, `uv.lock`, src layout) type-checked with ty, with Jinja2 as a dependency | Runs the wheel with `uvx`; bundles the dependencies for the destination's Python through `PYTHONPATH`; embeds a relocatable CPython with the app installed for a self-contained executable; builds presets by binding the result again |
| [rust](rust/) | A native word-frequency counter configured by options, data files and environment variables | Turns one program into several commands (presets with their own data and options), sets configuration through the environment, bundles a data directory, composes executables, and leaves the program external |

Every example works on Linux, macOS and Windows; each README gives the
PowerShell commands where they differ. bound's test suite builds and runs
all of them the way the READMEs describe
([crates/bound-tests/tests/examples.rs](../crates/bound-tests/tests/examples.rs)):

```sh
cargo test -p bound-tests --test examples -- --ignored
```

This needs Rust, Node.js with npm, uv, and network access for the npm and
PyPI packages and the CPython build.
