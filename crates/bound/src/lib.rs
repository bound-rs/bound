//! bound turns a process invocation into a program.
//!
//! ```text
//! (program, argv, files, env, cwd) + partial binding -> new executable
//! ```
//!
//! This crate is the `bound` command-line tool: it creates artifacts
//! ([`build`]), explains them ([`inspect`]), checks their integrity
//! ([`verify`]) and manages the cache of bundled files ([`cache`]). The artifact format lives in `bound-format`, the code that
//! runs inside artifacts in `bound-runtime`, and OS-specific operations in
//! `bound-platform`.

#![forbid(unsafe_code)]

pub mod build;
pub mod cache;
pub mod cli;
pub mod error;
pub mod inspect;
pub mod launcher;
pub mod style;
pub mod verify;

pub use error::CliError;
