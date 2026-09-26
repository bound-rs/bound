//! The `bound` command line.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use bound_format::{BundleMode, CwdMode};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::build::{self, BuildRequest, Diagnostic};
use crate::error::CliError;
use crate::{cache, inspect, style, verify};

const ABOUT: &str = "Turn a process invocation into a program";

const LONG_ABOUT: &str = "\
bound turns a process invocation into a program.

It partially applies a command: the program, some of its arguments, files,
environment variables and working directory are bound now, and the result
is a new native executable that accepts the remaining arguments later.

    (program, argv, files, env, cwd) + partial binding -> new executable";

const EXAMPLES: &str = "\
Examples:
  bound -o grep-errors -- grep -n ERROR
  ./grep-errors server.log                # runs: grep -n ERROR server.log

  bound -o migrate -- python migrate.py --schema @file:schema.sql
  bound -o jpeg -- convert @args -strip -quality 85 out.jpg
  bound inspect ./migrate
  bound verify ./migrate

  # PowerShell
  bound -o find-errors.exe -- findstr.exe /N ERROR
  .\\find-errors.exe server.log

`bound [OPTIONS] -- PROGRAM ...` is short for `bound build [OPTIONS] -- PROGRAM ...`.";

const BUILD_AFTER_HELP: &str = "\
Directives (recognized only as whole arguments):
  @args          where arguments given at run time go (default: at the end)
  @file:PATH     bundle PATH; replaced by the path of the bundled copy at run time
  @bundle:PATH   the path at run time of PATH in the bundle, bundled by other options
                 (as the program: run that bundled file)
  @@TEXT         the literal argument @TEXT (escapes a leading @)

In DEST=PATH pairs (--include-as, --include-list), PATH may also be:
  @link:TARGET     a symbolic link to TARGET, relative to DEST's directory (Unix)
  @readlink:PATH   a symbolic link with the same target as the link at PATH (Unix)
  @dir             a directory, empty unless something else goes in it
  @@PATH           the path @PATH (escapes a leading @)

Files are materialized in a new private temporary directory on each run,
removed after the program exits; with --bundle shared, in a read-only
directory in the user's cache that every run reuses (see `bound cache`).
The program finds the directory through the BOUND_ROOT environment variable.
Bundled files are readable by anyone who has the artifact: never bundle secrets.";

#[derive(Debug, Parser)]
#[command(
    name = "bound",
    version,
    about = ABOUT,
    long_about = LONG_ABOUT,
    after_help = EXAMPLES,
    arg_required_else_help = true,
    subcommand_required = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

// Parsed once per process: the size of the build variant does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Bind a program and some of its inputs into a new executable (the default command)
    Build(BuildArgs),
    /// Show what an artifact runs, with which arguments, and what it contains
    Inspect(InspectArgs),
    /// Check an artifact's integrity by recomputing every hash
    Verify(VerifyArgs),
    /// Show or clean the cache of bundled files
    Cache(CacheArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BundleArg {
    /// A new private directory for every run, removed after it
    Private,
    /// One read-only directory in the user's cache, reused by every run
    Shared,
}

#[derive(Debug, Args)]
#[command(after_help = BUILD_AFTER_HELP)]
pub struct BuildArgs {
    /// Executable to create (for Windows targets ".exe" is appended when missing)
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Replace OUTPUT if it already exists
    #[arg(short, long)]
    pub force: bool,

    /// Bundle PROGRAM itself instead of resolving it on the destination system
    #[arg(long)]
    pub embed_program: bool,

    /// Bundle PROGRAM itself, at DEST under BOUND_ROOT (implies --embed-program)
    #[arg(long = "embed-program-as", value_name = "DEST")]
    pub embed_program_as: Option<String>,

    /// Bundle a file or directory under BOUND_ROOT at its relative path (repeatable)
    #[arg(long = "include", value_name = "PATH")]
    pub include: Vec<PathBuf>,

    /// Bundle a file or directory at DEST under BOUND_ROOT ("." for the root; repeatable)
    #[arg(long = "include-as", value_name = "DEST=PATH")]
    pub include_as: Vec<OsString>,

    /// Bundle every DEST=PATH listed in FILE, one per line, as --include-as does (repeatable)
    #[arg(long = "include-list", value_name = "FILE")]
    pub include_list: Vec<PathBuf>,

    /// Set an environment variable; VALUE may be @file:PATH or @bundle:PATH (repeatable)
    #[arg(long = "env", value_name = "NAME=VALUE")]
    pub env: Vec<OsString>,

    /// Remove a variable from the environment the program inherits (repeatable)
    #[arg(long = "unset", value_name = "NAME")]
    pub unset: Vec<OsString>,

    /// Put VALUE before the caller's value of the list variable NAME, such as PATH; VALUE may be @file:PATH or @bundle:PATH (repeatable, in order)
    #[arg(long = "env-prepend", value_name = "NAME=VALUE")]
    pub env_prepend: Vec<OsString>,

    /// Put VALUE after the caller's value of the list variable NAME (repeatable, in order)
    #[arg(long = "env-append", value_name = "NAME=VALUE")]
    pub env_append: Vec<OsString>,

    /// Working directory of the program: inherit (the caller's), bundle (BOUND_ROOT) or @bundle:DIR (a directory in the bundle)
    #[arg(long, value_name = "MODE", default_value = "inherit", value_parser = cwd_arg)]
    pub cwd: CwdMode,

    /// How bundled files are provided at run time (shared: extracted once, read-only)
    #[arg(long, value_enum, value_name = "MODE", default_value_t = BundleArg::Private)]
    pub bundle: BundleArg,

    /// Launcher executable to build from [default: bound-launcher next to bound, or $BOUND_LAUNCHER]
    #[arg(long, value_name = "PATH")]
    pub launcher: Option<PathBuf>,

    /// Do not print notes, warnings or the summary line
    #[arg(short, long)]
    pub quiet: bool,

    /// The invocation to bind: a program followed by its arguments
    #[arg(value_name = "PROGRAM [ARGS]", trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Print a stable JSON document instead of a report
    #[arg(long)]
    pub json: bool,

    /// The artifact to inspect
    #[arg(value_name = "ARTIFACT")]
    pub artifact: PathBuf,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Print a JSON result instead of a report
    #[arg(long)]
    pub json: bool,

    /// The artifact to verify
    #[arg(value_name = "ARTIFACT")]
    pub artifact: PathBuf,
}

#[derive(Debug, Args)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub command: CacheCommand,
}

#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    /// Print the location of the cache
    Dir,
    /// List what the cache holds
    List,
    /// Remove cached files (those of running programs included)
    Clean {
        /// Only remove what has not been used for this many days
        #[arg(long, value_name = "DAYS")]
        unused: Option<u32>,
    },
}

const SUBCOMMANDS: [&str; 9] = ["build", "inspect", "verify", "cache", "help", "-h", "--help", "-V", "--version"];

/// Makes `build` the default subcommand: `bound -o x -- cmd` means
/// `bound build -o x -- cmd`.
pub fn with_implicit_build(mut args: Vec<OsString>) -> Vec<OsString> {
    if let Some(first) = args.get(1) {
        if !SUBCOMMANDS.iter().any(|known| first == known) {
            args.insert(1, "build".into());
        }
    }
    args
}

/// Entry point of the `bound` executable.
pub fn main() -> ExitCode {
    let args = with_implicit_build(std::env::args_os().collect());
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2));
        }
    };
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            report_error(&error);
            ExitCode::FAILURE
        }
    }
}

fn report_error(error: &CliError) {
    eprintln!("{} {}", style::error_label(), error.message);
    if let Some(hint) = &error.hint {
        eprintln!("{} {hint}", style::hint_label());
    }
}

pub fn run(cli: Cli) -> Result<ExitCode, CliError> {
    match cli.command {
        Command::Build(args) => run_build(args),
        Command::Inspect(args) => {
            let inspection = inspect::inspect(&args.artifact)?;
            let mut out = std::io::BufWriter::new(std::io::stdout().lock());
            let written = if args.json {
                inspect::render_json(&inspection, &mut out)
            } else {
                inspect::render(&inspection, &mut out)
            };
            match written.and_then(|()| std::io::Write::flush(&mut out)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                // The reader went away (`bound inspect x | head`): not an error.
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(ExitCode::SUCCESS),
                Err(e) => Err(CliError::new(format!("cannot write the report: {e}"))),
            }
        }
        Command::Verify(args) => run_verify(args),
        Command::Cache(args) => cache::run(args.command),
    }
}

/// Parses `--cwd` for clap.
fn cwd_arg(value: &str) -> Result<CwdMode, String> {
    build::parse_cwd(value).map_err(|e| e.message)
}

fn run_build(args: BuildArgs) -> Result<ExitCode, CliError> {
    let request = BuildRequest {
        output: args.output,
        force: args.force,
        embed_program: args.embed_program || args.embed_program_as.is_some(),
        program_as: args.embed_program_as,
        includes: args.include,
        includes_as: args.include_as,
        include_lists: args.include_list,
        env: args.env,
        unset: args.unset,
        env_prepend: args.env_prepend,
        env_append: args.env_append,
        cwd: args.cwd,
        bundle: match args.bundle {
            BundleArg::Private => BundleMode::Private,
            BundleArg::Shared => BundleMode::Shared,
        },
        launcher: args.launcher,
        command: args.command,
    };
    let outcome = build::build(&request)?;
    if !args.quiet {
        for diagnostic in &outcome.diagnostics {
            match diagnostic {
                Diagnostic::Warning(text) => eprintln!("{} {text}", style::warning_label()),
                Diagnostic::Note(text) => eprintln!("{} {text}", style::note_label()),
            }
        }
        eprintln!(
            "bound: wrote {} ({}, {}; runs {})",
            outcome.output.display(),
            style::size(outcome.size),
            outcome.manifest.platform,
            inspect::summarize_target(&outcome.manifest, None)
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn run_verify(args: VerifyArgs) -> Result<ExitCode, CliError> {
    let report = match verify::verify(&args.artifact) {
        Ok(report) => report,
        Err(error) if args.json => {
            print!("{}", verify::render_json_error(&args.artifact, &error));
            return Ok(ExitCode::FAILURE);
        }
        Err(error) => return Err(error),
    };
    if args.json {
        print!("{}", verify::render_json(&args.artifact, &report));
    } else {
        print!("{}", verify::render(&args.artifact, &report));
        if !report.is_ok() {
            eprintln!("{} {} failed verification:", style::error_label(), args.artifact.display());
            for problem in report.problems() {
                eprintln!("  {problem}");
            }
        }
    }
    Ok(if report.is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn build_is_the_default_subcommand() {
        assert_eq!(with_implicit_build(args(&["bound", "-o", "x", "--", "grep"]))[1], "build");
        assert_eq!(with_implicit_build(args(&["bound", "inspect", "x"]))[1], "inspect");
        assert_eq!(with_implicit_build(args(&["bound", "--help"]))[1], "--help");
        assert_eq!(with_implicit_build(args(&["bound"])).len(), 1);
    }

    #[test]
    fn command_after_double_dash_is_verbatim() {
        let cli = Cli::try_parse_from(with_implicit_build(args(&[
            "bound", "-o", "out", "--force", "--", "grep", "-n", "--force", "-o", "@args",
        ])))
        .unwrap();
        let Command::Build(build) = cli.command else { panic!("expected build") };
        assert!(build.force);
        assert_eq!(build.output, Some(PathBuf::from("out")));
        assert_eq!(build.command, args(&["grep", "-n", "--force", "-o", "@args"]));
    }

    #[test]
    fn command_without_double_dash_starts_at_the_program() {
        let cli = Cli::try_parse_from(with_implicit_build(args(&["bound", "-o", "out", "grep", "-n", "-q"]))).unwrap();
        let Command::Build(build) = cli.command else { panic!("expected build") };
        assert!(!build.quiet);
        assert_eq!(build.command, args(&["grep", "-n", "-q"]));
    }

    #[test]
    fn repeatable_options() {
        let cli = Cli::try_parse_from(with_implicit_build(args(&[
            "bound",
            "--include",
            "a",
            "--include",
            "b",
            "--env",
            "X=1",
            "--env",
            "Y=@file:y",
            "--env-prepend",
            "PATH=@bundle:bin",
            "--env-prepend",
            "PATH=/opt/bin",
            "--env-append",
            "PATH=/usr/local/bin",
            "--cwd",
            "bundle",
            "-o",
            "o",
            "--",
            "p",
        ])))
        .unwrap();
        let Command::Build(build) = cli.command else { panic!("expected build") };
        assert_eq!(build.include, vec![PathBuf::from("a"), PathBuf::from("b")]);
        assert_eq!(build.env, args(&["X=1", "Y=@file:y"]));
        assert_eq!(build.env_prepend, args(&["PATH=@bundle:bin", "PATH=/opt/bin"]));
        assert_eq!(build.env_append, args(&["PATH=/usr/local/bin"]));
        assert_eq!(build.cwd, CwdMode::Bundle);
    }

    #[test]
    fn working_directory_options() {
        let parse = |cwd: &str| {
            Cli::try_parse_from(with_implicit_build(args(&["bound", "--cwd", cwd, "-o", "o", "--", "p"]))).map(|cli| {
                match cli.command {
                    Command::Build(build) => build.cwd,
                    _ => panic!("expected build"),
                }
            })
        };
        assert_eq!(parse("inherit").unwrap(), CwdMode::Inherit);
        assert_eq!(parse("@bundle:app").unwrap(), CwdMode::Dir(bound_format::ResourcePath::new("app").unwrap()));
        let err = parse("elsewhere").unwrap_err().to_string();
        assert!(err.contains("expected inherit, bundle or @bundle:DIR"), "{err}");
        let default = Cli::try_parse_from(with_implicit_build(args(&["bound", "-o", "o", "--", "p"]))).unwrap();
        let Command::Build(build) = default.command else { panic!("expected build") };
        assert_eq!(build.cwd, CwdMode::Inherit);
    }
}
