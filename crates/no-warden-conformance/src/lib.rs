//! Host-only conformance support. This crate may allocate; the API core never does.
//!
//! Rust runners exercise the official CLI and portable HTTP protocol contracts.
#![forbid(unsafe_code)]

pub mod capture;
pub mod cli;
pub mod fixture;
pub mod folders;
pub mod transport;
