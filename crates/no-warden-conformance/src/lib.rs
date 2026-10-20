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
pub mod cipher_reads;
pub mod cli;
pub mod device_tokens;
pub mod devices;
pub mod domains;
pub mod file_sends;
pub mod file_sends_cli;
pub mod fixture;
pub mod folders;
pub mod organization_bulk_confirmations;
pub mod organization_bulk_confirmations_cli;
pub mod organization_collection_mutations;
pub mod organization_collection_mutations_cli;
pub mod organization_collections;
pub mod organization_collections_cli;
pub mod organization_confirmations;
pub mod organization_confirmations_cli;
pub mod organization_invites;
pub mod organization_invites_cli;
pub mod organization_member_removal;
pub mod organization_member_removal_cli;
pub mod organization_members;
pub mod organization_members_cli;
pub mod organization_owner;
pub mod organization_owner_cli;
pub mod password_login;
pub mod prelogin;
pub mod prelogin_cli;
pub mod purge;
pub mod refresh_grants;
pub mod registration;
pub mod text_sends;
pub mod text_sends_cli;
pub mod transport;
pub mod user_key_id;
pub mod user_key_id_cli;
pub mod webauthn_credentials;
