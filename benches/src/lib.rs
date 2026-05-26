//! Criterion end-to-end protocol benchmarks and shared harness utilities.
//!
//! This crate is for local performance measurement only; the harness API is
//! intentionally undocumented beyond module-level notes in [`harness`].

#![allow(missing_docs)]

pub mod harness;

pub use harness::*;
