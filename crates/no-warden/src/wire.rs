//! Borrowed JSON models for the personal-vault API.
//!
//! Strings borrow the decoder's input. JSON decoders that cannot borrow escaped strings
//! should use a caller-owned decoding buffer. Cipher payload strings are encrypted by clients.
use crate::bounded::BoundedList;
use serde::{Deserialize, Serialize};

pub const MAX_URIS: usize = 32;
pub const MAX_FIELDS: usize = 64;
pub const MAX_PASSWORD_HISTORY: usize = 32;
pub const MAX_FIDO2_CREDENTIALS: usize = 16;
pub const MAX_COLLECTION_IDS: usize = 64;

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

/// An imported folder may reference an existing folder owned by the importing account.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ImportFolderRequest<'a> {
    pub id: Option<&'a str>,
    pub name: &'a str,
}

/// Indices into the import's cipher and folder sequences, respectively.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct FolderRelationship {
    pub key: usize,
    pub value: usize,
}

/// Allocation-free import decoder with capacities chosen by its caller.
///
/// These are decoder capacities, not protocol batch limits. Applications with their own
/// decoding/storage strategy can pass borrowed slices through `service::ImportView`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest<'a, const F: usize, const C: usize, const R: usize> {
    #[serde(borrow)]
    pub folders: BoundedList<ImportFolderRequest<'a>, F>,
    #[serde(borrow)]
    pub ciphers: BoundedList<CipherRequest<'a>, C>,
    pub folder_relationships: BoundedList<FolderRelationship, R>,
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
    #[serde(borrow)]
    pub fido2_credentials: Option<BoundedList<Fido2Credential<'a>, MAX_FIDO2_CREDENTIALS>>,
}

/// Stored passkey material is already encrypted by the client. Creation time is plaintext.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fido2Credential<'a> {
    pub credential_id: Option<&'a str>,
    pub key_type: Option<&'a str>,
    pub key_algorithm: Option<&'a str>,
    pub key_curve: Option<&'a str>,
    pub key_value: Option<&'a str>,
    pub rp_id: Option<&'a str>,
    pub rp_name: Option<&'a str>,
    pub counter: Option<&'a str>,
    pub user_handle: Option<&'a str>,
    pub user_name: Option<&'a str>,
    pub user_display_name: Option<&'a str>,
    pub discoverable: Option<&'a str>,
    pub creation_date: Option<&'a str>,
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
    pub name: Option<&'a str>,
    /// Opaque sealed JSON string used by blob-encryption clients.
    pub data: Option<&'a str>,
    pub notes: Option<&'a str>,
    pub folder_id: Option<&'a str>,
    #[serde(alias = "organizationID")]
    pub organization_id: Option<&'a str>,
    /// Account whose key material the client used to encrypt this cipher.
    pub encrypted_for: Option<&'a str>,
    /// Opaque identifier of the client key material used for encryption.
    pub encrypted_by_key_id: Option<&'a str>,
    /// Optional per-cipher key wrapped with the account's user key.
    pub key: Option<&'a str>,
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
    pub archived_date: Option<&'a str>,
}

/// The clone/create endpoint wraps the cipher instead of accepting it directly.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherCreateRequest<'a> {
    #[serde(borrow, alias = "Cipher")]
    pub cipher: CipherRequest<'a>,
    #[serde(borrow, default, alias = "CollectionIds")]
    pub collection_ids: Option<BoundedList<&'a str, MAX_COLLECTION_IDS>>,
}

/// The selected-ID body shared by cipher lifecycle and archive endpoints.
///
/// The caller chooses the decoder capacity. IDs are exact strings, without UUID
/// canonicalization; duplicate IDs are collapsed by `VaultService::bulk_ciphers`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CipherIdsRequest<'a, const N: usize> {
    #[serde(borrow)]
    pub ids: BoundedList<&'a str, N>,
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
    use std::string::ToString;
    #[test]
    fn selected_cipher_ids_are_required_exact_strings_with_caller_selected_capacity() {
        let input = r#"{"ids":["opaque:One/id","opaque:One/id","opaque:one/id"]}"#;
        let request: CipherIdsRequest<'_, 3> = serde_json::from_str(input).unwrap();
        assert_eq!(request.ids.get(0), Some(&"opaque:One/id"));
        assert_eq!(request.ids.get(1), request.ids.get(0));
        assert_eq!(request.ids.get(2), Some(&"opaque:one/id"));
        assert_eq!(serde_json::to_string(&request).unwrap(), input);
        assert!(serde_json::from_str::<CipherIdsRequest<'_, 2>>(input).is_err());
        assert!(serde_json::from_str::<CipherIdsRequest<'_, 0>>(r#"{"ids":[]}"#).is_ok());
        for invalid in [
            "{}",
            r#"{"ids":null}"#,
            r#"{"ids":"id"}"#,
            r#"{"ids":[null]}"#,
            r#"{"ids":[7]}"#,
        ] {
            assert!(serde_json::from_str::<CipherIdsRequest<'_, 3>>(invalid).is_err());
        }
    }
    #[test]
    fn import_decoder_capacities_are_independent_and_caller_selected() {
        let input = r#"{"folders":[],"ciphers":[{"type":1,"data":"sealed","encryptedFor":"alice","encryptedByKeyId":"opaque:key/id"}],"folderRelationships":[{"key":0,"value":99}]}"#;
        let request: ImportRequest<'_, 0, 1, 1> = serde_json::from_str(input).unwrap();
        assert_eq!(request.ciphers.get(0).unwrap().data, Some("sealed"));
        assert_eq!(
            request.ciphers.get(0).unwrap().encrypted_by_key_id,
            Some("opaque:key/id")
        );
        assert_eq!(request.folder_relationships.get(0).unwrap().value, 99);
        assert!(serde_json::from_str::<ImportRequest<'_, 0, 0, 1>>(input).is_err());
        assert!(serde_json::from_str::<ImportRequest<'_, 0, 1, 0>>(input).is_err());
        assert!(
            serde_json::from_str::<ImportRequest<'_, 0, 0, 0>>(
                r#"{"folders":[],"ciphers":[],"folderRelationships":[]}"#
            )
            .is_ok()
        );
        for missing in [
            r#"{"ciphers":[],"folderRelationships":[]}"#,
            r#"{"folders":[],"folderRelationships":[]}"#,
            r#"{"folders":[],"ciphers":[]}"#,
        ] {
            assert!(serde_json::from_str::<ImportRequest<'_, 1, 1, 1>>(missing).is_err());
        }
    }
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
        assert!(request.encrypted_for.is_none());
        assert!(request.encrypted_by_key_id.is_none());
        assert!(request.key.is_none());
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

    #[test]
    fn modern_cipher_key_metadata_round_trips_without_rewriting_identifiers() {
        let input = r#"{"type":2,"name":"ciphertext","secureNote":{"type":0},"encryptedFor":"alice","encryptedByKeyId":"opaque:key/id","key":"wrapped-cipher-key","archivedDate":"2026-01-01T00:00:00Z"}"#;
        let request: CipherRequest<'_> = serde_json::from_str(input).unwrap();
        assert_eq!(request.encrypted_for, Some("alice"));
        assert_eq!(request.encrypted_by_key_id, Some("opaque:key/id"));
        assert_eq!(request.key, Some("wrapped-cipher-key"));
        let serialized = serde_json::to_value(request).unwrap();
        assert_eq!(serialized["encryptedFor"], "alice");
        assert_eq!(serialized["encryptedByKeyId"], "opaque:key/id");
        assert_eq!(serialized["key"], "wrapped-cipher-key");
        assert_eq!(serialized["archivedDate"], "2026-01-01T00:00:00Z");
    }

    #[test]
    fn stored_passkeys_are_bounded_and_lossless() {
        let credential = serde_json::json!({"credentialId":"opaque","keyType":"type","keyAlgorithm":"algorithm","keyCurve":"curve","keyValue":"key","rpId":"rp","rpName":"name","counter":"counter","userHandle":"handle","userName":"username","userDisplayName":"display","discoverable":"discoverable","creationDate":"2026-01-01T00:00:00Z"});
        let input=serde_json::json!({"type":1,"name":"encrypted","login":{"fido2Credentials":[credential.clone()]}}).to_string();
        let request: CipherRequest<'_> = serde_json::from_str(&input).unwrap();
        let output = serde_json::to_value(&request).unwrap();
        assert_eq!(output["login"]["fido2Credentials"][0], credential);
        let too_many=serde_json::json!({"type":1,"login":{"fido2Credentials":std::vec![credential;MAX_FIDO2_CREDENTIALS+1]}}).to_string();
        assert!(serde_json::from_str::<CipherRequest<'_>>(&too_many).is_err());
    }

    #[test]
    fn blob_payload_borrows_a_callers_decoded_scratch_buffer() {
        let blob = r#"{"format_version":1,"wrapped_cek":"opaque","envelope":"opaque"}"#;
        let scratch = serde_json::json!({"type":1,"name":null,"data":blob});
        let request = CipherRequest::deserialize(&scratch).unwrap();
        assert!(request.name.is_none());
        assert_eq!(request.data, Some(blob));
        assert_eq!(serde_json::to_value(&request).unwrap()["data"], blob);
        assert!(crate::validation::validate_cipher(&request).is_ok());
        let wrapped = serde_json::json!({"Cipher":scratch,"CollectionIds":[]});
        let request = CipherCreateRequest::deserialize(&wrapped).unwrap();
        assert_eq!(request.cipher.data, Some(blob));
    }
}
