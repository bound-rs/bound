//! The `bound` command line, built inside the test package so that tests
//! can always run it (it is identical to the shipped `bound` binary).

fn main() -> std::process::ExitCode {
    bound_cli::cli::main()
}
