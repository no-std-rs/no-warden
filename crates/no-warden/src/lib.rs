//! Transport-independent, allocation-free building blocks for a Bitwarden-compatible server.
//!
//! This crate deliberately does not implement encryption, password hashing, token signing,
//! networking, or persistence. Ciphertext stays opaque. Applications supply authenticated
//! account identifiers and a storage adapter, and are responsible for checking credentials.
//! Request collections have explicit limits, so hostile input cannot cause unbounded allocation.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod account_deletion;
pub mod account_kdf;
pub mod account_key_id;
pub mod account_keys;
pub mod account_password;
pub mod account_profile;
pub mod account_security;
pub mod attachment;
pub mod auth_login;
pub mod auth_requests;
pub mod auth_responses;
pub mod bounded;
pub mod bulk;
pub mod cipher_reads;
pub mod device_push;
pub mod devices;
pub mod domains;
pub mod error;
pub mod identity;
pub mod import;
pub mod organization_bulk_member_status;
pub mod organization_cipher_bulk_sharing;
pub mod organization_cipher_collections;
pub mod organization_cipher_partial;
pub mod organization_cipher_sharing;
pub mod organization_collection_mutations;
pub mod organization_collections;
pub mod organization_confirmations;
pub mod organization_invitations;
pub mod organization_member_mini_details;
pub mod organization_member_public_keys;
pub mod organization_member_removal;
pub mod organization_member_status;
pub mod organization_member_update;
pub mod organization_members;
pub mod organization_web_reads;
pub mod organizations;
pub mod password_login;
pub mod prelogin;
pub mod purge;
pub mod refresh;
pub mod registration;
pub mod route;
pub mod sends;
pub mod service;
pub mod validation;
pub mod wire;

pub use error::{ApiError, ErrorKind};
pub use service::{Storage, VaultService};

#[cfg(test)]
extern crate std;
