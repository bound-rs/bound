//! The platform layer of bound.
//!
//! Everything that behaves differently on Unix and Windows lives here,
//! behind small functions with a platform-neutral contract:
//!
//! * [`fs`]: private directories, exclusive file creation, executable bits,
//!   symlinks, entry classification and robust tree removal;
//! * [`exe`]: opening the running executable to read its own payload;
//! * [`process`]: launching the target (Unix `exec`, or a supervised child
//!   with signal / console-control handling), mirroring its exit status, and
//!   program lookup;
//! * [`privilege`]: refusing to run with elevated set-ID privileges.
//!
//! Shared code (format, runtime, CLI) never calls OS APIs directly.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod exe;
pub mod fs;
pub mod privilege;
pub mod process;
mod random;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use random::random_hex;
