//! Transport-independent, allocation-free building blocks for a Bitwarden-compatible server.
//!
//! This crate deliberately does not implement encryption, password hashing, token signing,
//! networking, or persistence. Ciphertext stays opaque. Applications supply authenticated
//! account identifiers and a storage adapter, and are responsible for checking credentials.
//! Request collections have explicit limits, so hostile input cannot cause unbounded allocation.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod account_keys;
pub mod account_profile;
pub mod attachment;
pub mod auth_requests;
pub mod auth_responses;
pub mod bounded;
pub mod bulk;
pub mod device_push;
pub mod devices;
pub mod domains;
pub mod error;
pub mod identity;
pub mod import;
pub mod route;
pub mod service;
pub mod validation;
pub mod wire;

pub use error::{ApiError, ErrorKind};
pub use service::{Storage, VaultService};

#[cfg(test)]
extern crate std;
