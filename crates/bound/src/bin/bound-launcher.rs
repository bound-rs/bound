//! The launcher stub embedded at the start of every bound artifact.
//!
//! Run on its own (without an appended payload) it reports that it is not a
//! bound artifact and exits with status 125.

fn main() {
    bound_runtime::main()
}
