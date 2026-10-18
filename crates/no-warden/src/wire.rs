//! Borrowed JSON models for the personal-vault API.
//!
//! Strings borrow the decoder's input. JSON decoders that cannot borrow escaped strings
//! should use a caller-owned decoding buffer. Cipher payload strings are encrypted by clients.
use crate::{bounded::BoundedList, identity::Secret};
use serde::{Deserialize, Serialize};

pub const MAX_URIS: usize = 32;
pub const MAX_FIELDS: usize = 64;
pub const MAX_PASSWORD_HISTORY: usize = 32;
pub const MAX_FIDO2_CREDENTIALS: usize = 16;
pub const MAX_COLLECTION_IDS: usize = 64;

/// V2 reservation metadata. Encrypted filename/key strings are kept opaque.
///
/// `fileSize` accepts a signed JSON integer or an integer string without allocation.
/// Deserializing that union requires a decoder with `deserialize_any` support;
/// `serde-json-core` 0.6 consumers can construct this request after typed decoding.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRequest<'a> {
    pub key: &'a str,
    pub file_name: &'a str,
    #[serde(deserialize_with = "attachment_size")]
    pub file_size: i64,
    pub admin_request: Option<bool>,
}

impl core::fmt::Debug for AttachmentRequest<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AttachmentRequest")
            .field("file_size", &self.file_size)
            .field("admin_request", &self.admin_request)
            .finish_non_exhaustive()
    }
}

fn attachment_size<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    struct Size;
    impl serde::de::Visitor<'_> for Size {
        type Value = i64;
        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("a signed integer or an integer string")
        }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<i64, E> {
            Ok(value)
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<i64, E> {
            i64::try_from(value).map_err(E::custom)
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<i64, E> {
            value.parse::<i64>().map_err(E::custom)
        }
    }
    deserializer.deserialize_any(Size)
}

/// Metadata extracted by a host multipart decoder. `file_size` is measured from the
/// actual encrypted bytes, not copied from an untrusted multipart declaration.
#[derive(Clone, Copy)]
pub struct LegacyAttachmentRequest<'a> {
    pub file_name: Option<&'a str>,
    pub key: Option<&'a str>,
    pub file_size: u64,
}

impl core::fmt::Debug for LegacyAttachmentRequest<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LegacyAttachmentRequest")
            .field("file_size", &self.file_size)
            .finish_non_exhaustive()
    }
}

/// Explicit response boundary for a scoped download URL and encrypted metadata.
pub struct AttachmentResponse<'a> {
    pub id: &'a str,
    pub url: Secret<'a>,
    pub file_name: &'a str,
    pub size: &'a str,
    pub size_name: &'a str,
    pub key: Option<&'a str>,
}

impl core::fmt::Debug for AttachmentResponse<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AttachmentResponse")
            .field("id", &self.id)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl Serialize for AttachmentResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut response = serializer.serialize_struct("AttachmentResponse", 7)?;
        response.serialize_field("id", self.id)?;
        response.serialize_field("url", self.url.expose_secret())?;
        response.serialize_field("fileName", self.file_name)?;
        response.serialize_field("size", self.size)?;
        response.serialize_field("sizeName", self.size_name)?;
        response.serialize_field("key", &self.key)?;
        response.serialize_field("object", "attachment")?;
        response.end()
    }
}

/// V2 direct-upload response with the correct regular/admin cipher response key.
pub struct AttachmentUploadResponse<'a, C: Serialize> {
    attachment_id: &'a str,
    url: Secret<'a>,
    cipher: C,
    admin_request: bool,
}

impl<'a, C: Serialize> AttachmentUploadResponse<'a, C> {
    pub const fn direct(
        attachment_id: &'a str,
        url: Secret<'a>,
        cipher: C,
        admin_request: bool,
    ) -> Self {
        Self {
            attachment_id,
            url,
            cipher,
            admin_request,
        }
    }
}

impl<C: Serialize> core::fmt::Debug for AttachmentUploadResponse<'_, C> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AttachmentUploadResponse")
            .field("attachment_id", &self.attachment_id)
            .field("admin_request", &self.admin_request)
            .finish_non_exhaustive()
    }
}

impl<C: Serialize> Serialize for AttachmentUploadResponse<'_, C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut response = serializer.serialize_struct("AttachmentUploadResponse", 5)?;
        response.serialize_field("object", "attachment-fileUpload")?;
        response.serialize_field("attachmentId", self.attachment_id)?;
        response.serialize_field("url", self.url.expose_secret())?;
        response.serialize_field("fileUploadType", &0_u8)?;
        response.serialize_field(
            if self.admin_request {
                "cipherMiniResponse"
            } else {
                "cipherResponse"
            },
            &self.cipher,
        )?;
        response.end()
    }
}

/// Exactly one proof must be supplied. The password field is the client's server-
/// authorization hash; `otp` is a protected-action proof, not an account TOTP code.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOrOtpRequest<'a> {
    #[serde(borrow, alias = "MasterPasswordHash")]
    pub master_password_hash: Option<Secret<'a>>,
    #[serde(borrow)]
    pub otp: Option<Secret<'a>>,
}

/// Deliberate secret-bearing response for the authenticated API-key management endpoints.
///
/// This response is the explicit serialization boundary. `Secret` itself does not implement
/// `Serialize`, and formatting this response redacts its key.
#[derive(Debug)]
pub struct ApiKeyResponse<'a> {
    pub api_key: Secret<'a>,
    pub revision_date: &'a str,
}

impl Serialize for ApiKeyResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut response = serializer.serialize_struct("ApiKeyResponse", 3)?;
        response.serialize_field("apiKey", self.api_key.expose_secret())?;
        response.serialize_field("revisionDate", self.revision_date)?;
        response.serialize_field("object", "apiKey")?;
        response.end()
    }
}

/// Borrowed user API-key grant fields after transport decoding.
///
/// Missing fields remain distinguishable from present blank strings. Device fields retain
/// their raw values, including nonnumeric device types; normalization is a host concern.
#[derive(Debug, Deserialize)]
pub struct ClientCredentialsRequest<'a> {
    pub grant_type: Option<&'a str>,
    pub client_id: Option<&'a str>,
    #[serde(borrow)]
    pub client_secret: Option<Secret<'a>>,
    pub scope: Option<&'a str>,
    #[serde(rename = "deviceIdentifier", alias = "device_identifier")]
    pub device_identifier: Option<&'a str>,
    #[serde(rename = "deviceName", alias = "device_name")]
    pub device_name: Option<&'a str>,
    #[serde(rename = "deviceType", alias = "device_type")]
    pub device_type: Option<&'a str>,
}

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

/// Profile mutation input. The service checks UTF-8 byte length without normalization.
#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct ProfileUpdateRequest<'a> {
    pub name: &'a str,
}

impl core::fmt::Debug for ProfileUpdateRequest<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProfileUpdateRequest([REDACTED])")
    }
}

/// An omitted/null object field or positional `[null]` clears the avatar.
/// An empty positional array is invalid. Present string values remain opaque.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarUpdateRequest<'a> {
    pub avatar_color: Option<&'a str>,
}

impl core::fmt::Debug for AvatarUpdateRequest<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AvatarUpdateRequest([REDACTED])")
    }
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

/// Borrowed registration/initialization input. Positional JSON sequences put the
/// encrypted private key first, matching the pinned upstream `KeysData` declaration.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKeys<'a> {
    pub encrypted_private_key: &'a str,
    pub public_key: &'a str,
}

impl core::fmt::Debug for AccountKeys<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AccountKeys([REDACTED])")
    }
}

/// Owner-only account-key response with the pinned legacy SDK key-pair projection.
/// Sensitive fields serialize only at this explicit response boundary.
pub struct AccountKeysResponse<'a> {
    pub key: Option<Secret<'a>>,
    pub public_key: &'a str,
    pub private_key: Secret<'a>,
}

impl core::fmt::Debug for AccountKeysResponse<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AccountKeysResponse([REDACTED])")
    }
}

impl Serialize for AccountKeysResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct EncryptionKeyPair<'a> {
            wrapped_private_key: &'a str,
            public_key: &'a str,
            signed_public_key: Option<()>,
            object: &'static str,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct PrivateKeys<'a> {
            public_key_encryption_key_pair: EncryptionKeyPair<'a>,
            security_state: Option<()>,
            signature_key_pair: Option<()>,
            object: &'static str,
        }
        let mut response = serializer.serialize_struct("AccountKeysResponse", 5)?;
        response.serialize_field("key", &self.key.as_ref().map(Secret::expose_secret))?;
        response.serialize_field("publicKey", self.public_key)?;
        response.serialize_field("privateKey", self.private_key.expose_secret())?;
        response.serialize_field(
            "accountKeys",
            &PrivateKeys {
                public_key_encryption_key_pair: EncryptionKeyPair {
                    wrapped_private_key: self.private_key.expose_secret(),
                    public_key: self.public_key,
                    signed_public_key: None,
                    object: "publicKeyEncryptionKeyPair",
                },
                security_state: None,
                signature_key_pair: None,
                object: "privateKeys",
            },
        )?;
        response.serialize_field("object", "keys")?;
        response.end()
    }
}

/// Initialization returns only the stored pair and object discriminator.
pub struct InitializedAccountKeysResponse<'a> {
    pub public_key: &'a str,
    pub private_key: Secret<'a>,
}

impl core::fmt::Debug for InitializedAccountKeysResponse<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("InitializedAccountKeysResponse([REDACTED])")
    }
}

impl Serialize for InitializedAccountKeysResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut response = serializer.serialize_struct("InitializedAccountKeysResponse", 3)?;
        response.serialize_field("privateKey", self.private_key.expose_secret())?;
        response.serialize_field("publicKey", self.public_key)?;
        response.serialize_field("object", "keys")?;
        response.end()
    }
}

/// Authenticated lookup that exposes only the requested user's public key.
pub struct UserPublicKeyResponse<'a> {
    pub user_id: &'a str,
    pub public_key: &'a str,
}

impl core::fmt::Debug for UserPublicKeyResponse<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UserPublicKeyResponse")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

impl Serialize for UserPublicKeyResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut response = serializer.serialize_struct("UserPublicKeyResponse", 3)?;
        response.serialize_field("userId", self.user_id)?;
        response.serialize_field("publicKey", self.public_key)?;
        response.serialize_field("object", "userKey")?;
        response.end()
    }
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

/// Folder CRUD wire input. The optional body ID is decoded but has no authority:
/// creation uses a host-generated ID, and updates use the authenticated route ID.
/// Keep it separate from `FolderRequest` so existing embedding constructors stay stable.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct FolderWriteRequest<'a> {
    pub name: &'a str,
    #[serde(default)]
    pub id: Option<&'a str>,
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
    fn profile_requests_borrow_raw_names_and_keep_upstream_single_field_sequence_shape() {
        for input in [r#"{"name":"  café 🔐  "}"#, r#"["  café 🔐  "]"#] {
            let request: ProfileUpdateRequest<'_> = serde_json::from_str(input).unwrap();
            assert_eq!(request.name, "  café 🔐  ");
            let start = input.as_ptr() as usize;
            assert!((start..start + input.len()).contains(&(request.name.as_ptr() as usize)));
            assert_eq!(
                serde_json::to_value(request).unwrap(),
                serde_json::json!({"name":"  café 🔐  "})
            );
            assert!(!std::format!("{request:?}").contains("café"));
        }
        let document = serde_json::json!({"name":"quoted\"\n\t雪"});
        assert_eq!(
            ProfileUpdateRequest::deserialize(&document).unwrap().name,
            "quoted\"\n\t雪"
        );
        for input in [
            "{}",
            "[]",
            "null",
            r#"{"name":null}"#,
            r#"{"name":7}"#,
            r#"["name",null]"#,
        ] {
            assert!(serde_json::from_str::<ProfileUpdateRequest<'_>>(input).is_err());
        }
    }

    #[test]
    fn avatar_requests_distinguish_opaque_present_values_from_missing_or_null_clears() {
        for input in ["{}", r#"{"avatarColor":null}"#, "[null]"] {
            let request: AvatarUpdateRequest<'_> = serde_json::from_str(input).unwrap();
            assert_eq!(request.avatar_color, None);
            assert_eq!(
                serde_json::to_value(request).unwrap(),
                serde_json::json!({"avatarColor":null})
            );
        }
        for input in [r#"{"avatarColor":"aé🔐"}"#, r#"["aé🔐"]"#] {
            let request: AvatarUpdateRequest<'_> = serde_json::from_str(input).unwrap();
            assert_eq!(request.avatar_color, Some("aé🔐"));
            assert!(!std::format!("{request:?}").contains("aé🔐"));
        }
        for input in [
            "[]",
            "null",
            r#"{"avatarColor":7}"#,
            r#"{"avatarColor":false}"#,
            r#"{"avatarColor":[]}"#,
            r#"{"avatarColor":{}}"#,
            r#"[null,null]"#,
        ] {
            assert!(serde_json::from_str::<AvatarUpdateRequest<'_>>(input).is_err());
        }
        assert_eq!(
            serde_json::from_str::<AvatarUpdateRequest<'_>>("[]")
                .unwrap_err()
                .classify(),
            serde_json::error::Category::Data,
        );
        assert_eq!(
            serde_json::from_str::<AvatarUpdateRequest<'_>>("[null,null]")
                .unwrap_err()
                .classify(),
            serde_json::error::Category::Syntax,
        );
    }

    #[test]
    fn account_key_requests_borrow_opaque_strings_and_use_private_then_public_sequence_order() {
        let input = r#"["opaque-private:future","opaque-public:future"]"#;
        let request: AccountKeys<'_> = serde_json::from_str(input).unwrap();
        assert_eq!(request.encrypted_private_key, "opaque-private:future");
        assert_eq!(request.public_key, "opaque-public:future");
        let start = input.as_ptr() as usize;
        for value in [request.encrypted_private_key, request.public_key] {
            assert!((start..start + input.len()).contains(&(value.as_ptr() as usize)));
        }
        assert!(!std::format!("{request:?}").contains("opaque-private"));
        let large = "opaque".repeat(250_000);
        let document =
            serde_json::json!({"publicKey":large,"encryptedPrivateKey":"quoted\"\n雪 🔐"});
        let request = AccountKeys::deserialize(&document).unwrap();
        assert_eq!(request.encrypted_private_key, "quoted\"\n雪 🔐");
        assert_eq!(request.public_key.len(), 1_500_000);
        let request: AccountKeys<'_> = serde_json::from_str(r#"["",""]"#).unwrap();
        assert!(request.encrypted_private_key.is_empty() && request.public_key.is_empty());
        for input in [
            "{}",
            r#"{"publicKey":"p"}"#,
            r#"{"publicKey":"p","encryptedPrivateKey":null}"#,
            r#"{"publicKey":7,"encryptedPrivateKey":"p"}"#,
            r#"["private"]"#,
            r#"["private",null]"#,
            r#"["private","public",0]"#,
        ] {
            assert!(serde_json::from_str::<AccountKeys<'_>>(input).is_err());
        }
    }

    #[test]
    fn account_key_responses_keep_exact_nulls_shapes_and_redacted_debug() {
        let response = AccountKeysResponse {
            key: None,
            public_key: "opaque-public",
            private_key: Secret::new("opaque-private"),
        };
        let expected = serde_json::json!({
            "key":null,"publicKey":"opaque-public","privateKey":"opaque-private",
            "accountKeys":{
                "publicKeyEncryptionKeyPair":{
                    "wrappedPrivateKey":"opaque-private","publicKey":"opaque-public",
                    "signedPublicKey":null,"object":"publicKeyEncryptionKeyPair"
                },
                "securityState":null,"signatureKeyPair":null,"object":"privateKeys"
            },"object":"keys"
        });
        assert_eq!(serde_json::to_value(&response).unwrap(), expected);
        assert_eq!(
            std::format!("{response:?}"),
            "AccountKeysResponse([REDACTED])"
        );
        let initialized = InitializedAccountKeysResponse {
            public_key: "opaque-public",
            private_key: Secret::new("opaque-private"),
        };
        assert_eq!(
            serde_json::to_value(&initialized).unwrap(),
            serde_json::json!({"publicKey":"opaque-public","privateKey":"opaque-private","object":"keys"})
        );
        assert!(!std::format!("{initialized:?}").contains("opaque-private"));
        let public = UserPublicKeyResponse {
            user_id: "Other/Raw:ID",
            public_key: "opaque-public",
        };
        assert_eq!(
            serde_json::to_value(&public).unwrap(),
            serde_json::json!({"userId":"Other/Raw:ID","publicKey":"opaque-public","object":"userKey"})
        );
        assert!(!std::format!("{public:?}").contains("opaque-public"));
    }

    #[test]
    fn attachment_wire_sizes_accept_integers_and_integer_strings_without_losing_opaque_metadata() {
        for value in [
            serde_json::json!(17),
            serde_json::json!("17"),
            serde_json::json!("+17"),
        ] {
            let document = serde_json::json!({"key":"opaque wrapped key","fileName":"opaque encrypted filename","fileSize":value,"adminRequest":true,"lastKnownRevisionDate":"ignored source revision"});
            let request = AttachmentRequest::deserialize(&document).unwrap();
            assert_eq!(request.file_size, 17);
            assert_eq!(request.key, "opaque wrapped key");
            assert_eq!(request.file_name, "opaque encrypted filename");
            assert_eq!(request.admin_request, Some(true));
            assert!(!std::format!("{request:?}").contains("opaque"));
        }
        for value in [
            serde_json::json!(1.0),
            serde_json::json!(true),
            serde_json::json!(null),
            serde_json::json!("1.0"),
            serde_json::json!(" 17"),
            serde_json::json!(u64::MAX),
        ] {
            let document = serde_json::json!({"key":"key","fileName":"name","fileSize":value});
            assert!(AttachmentRequest::deserialize(&document).is_err());
        }
        let document = serde_json::json!({"key":"","fileName":"","fileSize":"-1"});
        assert_eq!(
            AttachmentRequest::deserialize(&document).unwrap().file_size,
            -1
        );
    }

    #[test]
    fn attachment_response_serialization_is_explicit_and_debug_redacts_urls_and_keys() {
        let response = AttachmentResponse {
            id: "attachment",
            url: Secret::new(
                "https://host/attachments/cipher/attachment?token=download-capability",
            ),
            file_name: "encrypted-name",
            size: "17",
            size_name: "17 B",
            key: Some("wrapped-key"),
        };
        let debug = std::format!("{response:?}");
        assert!(!debug.contains("download-capability"));
        assert!(!debug.contains("wrapped-key"));
        let output = serde_json::to_value(response).unwrap();
        assert_eq!(output["object"], "attachment");
        assert_eq!(output["size"], "17");
        assert_eq!(output["fileName"], "encrypted-name");
        assert_eq!(output["key"], "wrapped-key");
        assert!(
            output["url"]
                .as_str()
                .unwrap()
                .ends_with("token=download-capability")
        );
        for admin in [false, true] {
            let response = AttachmentUploadResponse::direct(
                "attachment",
                Secret::new("presigned-upload-capability"),
                serde_json::json!({"id":"cipher"}),
                admin,
            );
            assert!(!std::format!("{response:?}").contains("presigned-upload-capability"));
            let output = serde_json::to_value(response).unwrap();
            assert_eq!(output["fileUploadType"], 0);
            assert_eq!(output["object"], "attachment-fileUpload");
            assert_eq!(output["attachmentId"], "attachment");
            assert!(
                output
                    .get(if admin {
                        "cipherMiniResponse"
                    } else {
                        "cipherResponse"
                    })
                    .is_some()
            );
            assert!(
                output
                    .get(if admin {
                        "cipherResponse"
                    } else {
                        "cipherMiniResponse"
                    })
                    .is_none()
            );
        }
    }
    #[test]
    fn identity_requests_borrow_raw_secrets_and_explicit_responses_reveal_only_their_contract() {
        let proof: PasswordOrOtpRequest<'_> =
            serde_json::from_str(r#"{"MasterPasswordHash":"authorization-hash"}"#).unwrap();
        assert_eq!(
            proof.master_password_hash.as_ref().unwrap().expose_secret(),
            "authorization-hash"
        );
        let proof_debug = std::format!("{proof:?}");
        assert!(proof_debug.contains("REDACTED"));
        assert!(!proof_debug.contains("authorization-hash"));

        let response = ApiKeyResponse {
            api_key: Secret::new("test-only-secret"),
            revision_date: "revision",
        };
        assert!(!std::format!("{response:?}").contains("test-only-secret"));
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({"apiKey":"test-only-secret","revisionDate":"revision","object":"apiKey"})
        );

        let large_secret = "opaque-input".repeat(8192);
        let document = serde_json::json!({
            "grant_type":"client_credentials", "client_id":"user.opaque:User/Case",
            "client_secret":large_secret, "scope":"api", "deviceIdentifier":"",
            "deviceName":"", "deviceType":"iOS"
        });
        let request = ClientCredentialsRequest::deserialize(&document).unwrap();
        assert_eq!(request.client_id, Some("user.opaque:User/Case"));
        assert_eq!(request.device_identifier, Some(""));
        assert_eq!(request.device_type, Some("iOS"));
        assert_eq!(
            request
                .client_secret
                .as_ref()
                .unwrap()
                .expose_secret()
                .len(),
            large_secret.len()
        );
        assert!(!std::format!("{request:?}").contains("opaque-input"));
        assert!(serde_json::from_str::<PasswordOrOtpRequest<'_>>(r#"{"otp":7}"#).is_err());
        assert!(
            serde_json::from_str::<ClientCredentialsRequest<'_>>(r#"{"client_secret":7}"#).is_err()
        );
    }
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
    fn folder_write_requests_decode_optional_body_ids_without_coercion() {
        for (input, expected) in [
            (r#"{"name":"café 🔐"}"#, None),
            (r#"{"name":"café 🔐","id":null}"#, None),
            (r#"{"name":"café 🔐","id":""}"#, Some("")),
            (
                r#"{"name":"café 🔐","id":"Untrusted/Body:ID"}"#,
                Some("Untrusted/Body:ID"),
            ),
        ] {
            let request: FolderWriteRequest<'_> = serde_json::from_str(input).unwrap();
            assert_eq!(request.id, expected);
            assert_eq!(request.name, "café 🔐");
            let start = input.as_ptr() as usize;
            assert!((start..start + input.len()).contains(&(request.name.as_ptr() as usize)));
        }
        let document = serde_json::json!({"name":"quoted\" and line\n 🔐","id":"ignored"});
        let request = FolderWriteRequest::deserialize(&document).unwrap();
        assert_eq!(request.name, "quoted\" and line\n 🔐");
        for input in [
            r#"{"name":"","id":1}"#,
            r#"{"name":"","id":false}"#,
            r#"{"name":"","id":[]}"#,
            r#"{"name":"","id":{}}"#,
            r#"{"id":"ignored"}"#,
            r#"{"name":null}"#,
            r#"{"name":7}"#,
        ] {
            assert!(serde_json::from_str::<FolderWriteRequest<'_>>(input).is_err());
        }
        // Existing programmatic callers need no optional-ID field.
        let old_request = FolderRequest { name: "" };
        assert_eq!(old_request.name, "");
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
