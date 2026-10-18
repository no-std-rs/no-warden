//! Host-only conformance support. This crate may allocate; the API core never does.
//!
//! The current CLI harness still uses the JavaScript entry points in `tools`.
#![forbid(unsafe_code)]

pub mod capture;
pub mod cli;
pub mod fixture;
pub mod transport;
