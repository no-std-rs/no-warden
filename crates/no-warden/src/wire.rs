//! Borrowed JSON models for the personal-vault API.
//!
//! Strings borrow the decoder's input. JSON decoders that cannot borrow escaped strings
//! should use a caller-owned decoding buffer. Cipher payload strings are encrypted by clients.
use crate::bounded::BoundedList;
use serde::{Deserialize, Serialize};

pub const MAX_URIS: usize = 32;
pub const MAX_FIELDS: usize = 64;
pub const MAX_PASSWORD_HISTORY: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginRequest<'a> {
    pub email: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserKeyIdRequest<'a> {
    pub user_key_id: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: u32,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

impl Default for PreloginResponse {
    fn default() -> Self {
        Self {
            kdf: 0,
            kdf_iterations: 600_000,
            kdf_memory: None,
            kdf_parallelism: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKeys<'a> {
    pub public_key: &'a str,
    pub encrypted_private_key: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest<'a> {
    pub email: &'a str,
    pub name: Option<&'a str>,
    pub master_password_hash: &'a str,
    pub master_password_hint: Option<&'a str>,
    pub key: &'a str,
    #[serde(default)]
    pub kdf: u32,
    #[serde(default = "default_kdf_iterations")]
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
    #[serde(borrow)]
    pub keys: Option<AccountKeys<'a>>,
}

const fn default_kdf_iterations() -> u32 {
    600_000
}

impl RegisterRequest<'_> {
    pub const fn prelogin(&self) -> PreloginResponse {
        PreloginResponse {
            kdf: self.kdf,
            kdf_iterations: self.kdf_iterations,
            kdf_memory: self.kdf_memory,
            kdf_parallelism: self.kdf_parallelism,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct FolderRequest<'a> {
    pub name: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderResponse<'a> {
    pub object: &'a str,
    pub id: &'a str,
    pub name: &'a str,
    pub revision_date: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri<'a> {
    pub uri: Option<&'a str>,
    #[serde(rename = "match")]
    pub match_type: Option<u8>,
    pub uri_checksum: Option<&'a str>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Login<'a> {
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub totp: Option<&'a str>,
    #[serde(borrow)]
    pub uris: Option<BoundedList<LoginUri<'a>, MAX_URIS>>,
    pub password_revision_date: Option<&'a str>,
    pub autofill_on_page_load: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNote {
    #[serde(rename = "type")]
    pub kind: u8,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card<'a> {
    pub cardholder_name: Option<&'a str>,
    pub brand: Option<&'a str>,
    pub number: Option<&'a str>,
    pub exp_month: Option<&'a str>,
    pub exp_year: Option<&'a str>,
    pub code: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity<'a> {
    pub title: Option<&'a str>,
    pub first_name: Option<&'a str>,
    pub middle_name: Option<&'a str>,
    pub last_name: Option<&'a str>,
    pub address1: Option<&'a str>,
    pub address2: Option<&'a str>,
    pub address3: Option<&'a str>,
    pub city: Option<&'a str>,
    pub state: Option<&'a str>,
    pub postal_code: Option<&'a str>,
    pub country: Option<&'a str>,
    pub company: Option<&'a str>,
    pub email: Option<&'a str>,
    pub phone: Option<&'a str>,
    pub ssn: Option<&'a str>,
    pub username: Option<&'a str>,
    pub passport_number: Option<&'a str>,
    pub license_number: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKey<'a> {
    pub private_key: &'a str,
    pub public_key: &'a str,
    pub key_fingerprint: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Field<'a> {
    pub name: Option<&'a str>,
    pub value: Option<&'a str>,
    #[serde(rename = "type")]
    pub kind: u8,
    pub linked_id: Option<u32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistory<'a> {
    pub password: &'a str,
    pub last_used_date: &'a str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequest<'a> {
    #[serde(rename = "type")]
    pub kind: u8,
    pub name: &'a str,
    pub notes: Option<&'a str>,
    pub folder_id: Option<&'a str>,
    pub organization_id: Option<&'a str>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: u8,
    #[serde(borrow)]
    pub login: Option<Login<'a>>,
    pub secure_note: Option<SecureNote>,
    #[serde(borrow)]
    pub card: Option<Card<'a>>,
    #[serde(borrow)]
    pub identity: Option<Identity<'a>>,
    #[serde(borrow)]
    pub ssh_key: Option<SshKey<'a>>,
    #[serde(borrow)]
    pub fields: Option<BoundedList<Field<'a>, MAX_FIELDS>>,
    #[serde(borrow)]
    pub password_history: Option<BoundedList<PasswordHistory<'a>, MAX_PASSWORD_HISTORY>>,
    pub last_known_revision_date: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse<'a, T: Serialize> {
    pub object: &'static str,
    pub data: &'a [T],
    pub continuation_token: Option<&'a str>,
}

impl<'a, T: Serialize> ListResponse<'a, T> {
    pub const fn new(data: &'a [T]) -> Self {
        Self {
            object: "list",
            data,
            continuation_token: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn borrowed_requests_and_bitwarden_field_names() {
        let request: RegisterRequest<'_> = serde_json::from_str(
            r#"{"email":"a@example.com","masterPasswordHash":"hash","key":"key"}"#,
        )
        .unwrap();
        assert_eq!(request.prelogin(), PreloginResponse::default());
        let request: CipherRequest<'_> = serde_json::from_str(
            r#"{"type":1,"name":"encrypted","login":{"uris":[{"uri":"encrypted","match":0}]}}"#,
        )
        .unwrap();
        assert_eq!(
            request
                .login
                .unwrap()
                .uris
                .unwrap()
                .get(0)
                .unwrap()
                .match_type,
            Some(0)
        );
        assert_eq!(
            serde_json::to_value(ListResponse::<u8>::new(&[])).unwrap()["object"],
            "list"
        );
    }
}
