//! Host-only conformance support. This crate may allocate; the API core never does.
//!
//! Rust runners exercise the official CLI and portable HTTP protocol contracts.
#![forbid(unsafe_code)]

pub mod account_deletion;
pub mod account_kdf;
pub mod account_keys;
pub mod account_password;
pub mod account_profile;
pub mod account_security;
pub mod auth_login;
pub mod auth_requests;
pub mod auth_responses;
pub mod capture;
pub mod cli;
pub mod device_tokens;
pub mod devices;
pub mod domains;
pub mod fixture;
pub mod folders;
pub mod purge;
pub mod registration;
pub mod transport;
pub mod webauthn_credentials;
