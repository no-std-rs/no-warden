//! Borrowed JSON models for the personal-vault API.
//!
//! Strings borrow the decoder's input. JSON decoders that cannot borrow escaped strings
//! should use a caller-owned decoding buffer. Cipher payload strings are encrypted by clients.
use crate::{bounded::BoundedList, identity::Secret};
use serde::{Deserialize, Serialize};

/// Password-only verification. This hash is the client server-authorization proof, not
/// a plaintext master password. The PascalCase alias used by PasswordOrOtpRequest does
/// not belong to this endpoint. Empty strings remain opaque provider-verified inputs.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretVerificationRequest<'a> {
    #[serde(borrow)]
    pub master_password_hash: Secret<'a>,
}

/// Known organization master-password policy fields. This is distinct from the local
/// plaintext PasswordPolicy validator and from the server password-verifier cost policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordPolicy {
    pub min_complexity: Option<u8>,
    pub min_length: Option<u32>,
    pub require_lower: bool,
    pub require_upper: bool,
    pub require_numbers: bool,
    pub require_special: bool,
    pub enforce_on_login: bool,
}

/// Verification returns an Object-only marker when no policy applies. A known policy
/// emits all seven camelCase fields, including nullable numbers, plus PascalCase Object.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MasterPasswordPolicyResponse {
    pub policy: Option<MasterPasswordPolicy>,
}
impl Serialize for MasterPasswordPolicyResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut response = serializer.serialize_struct(
            "MasterPasswordPolicyResponse",
            if self.policy.is_some() { 8 } else { 1 },
        )?;
        if let Some(policy) = self.policy {
            response.serialize_field("minComplexity", &policy.min_complexity)?;
            response.serialize_field("minLength", &policy.min_length)?;
            response.serialize_field("requireLower", &policy.require_lower)?;
            response.serialize_field("requireUpper", &policy.require_upper)?;
            response.serialize_field("requireNumbers", &policy.require_numbers)?;
            response.serialize_field("requireSpecial", &policy.require_special)?;
            response.serialize_field("enforceOnLogin", &policy.enforce_on_login)?;
        }
        response.serialize_field("Object", "masterPasswordPolicy")?;
        response.end()
    }
}

/// Public no-SMTP registration verification input. Names and emails remain opaque here;
/// the verified claim's name length is checked only when registration is finished.
#[derive(Deserialize)]
pub struct RegistrationVerificationRequest<'a> {
    pub email: &'a str,
    pub name: Option<&'a str>,
}
impl core::fmt::Debug for RegistrationVerificationRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegistrationVerificationRequest")
            .finish_non_exhaustive()
    }
}

/// Signed upstream KDF metadata, separate from the existing strict embedding policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationKdf {
    #[serde(alias = "kdfType")]
    pub kdf: i32,
    #[serde(alias = "iterations")]
    pub kdf_iterations: i32,
    #[serde(alias = "memory")]
    pub kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    pub kdf_parallelism: Option<i32>,
}

/// KDF-change authentication fields, in the upstream positional order. These aliases are
/// deliberately narrower than the separate registration authentication representation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKdfAuthentication<'a> {
    #[serde(alias = "Salt")]
    pub salt: &'a str,
    #[serde(alias = "Kdf")]
    pub kdf: RegistrationKdf,
    #[serde(borrow, alias = "MasterPasswordAuthenticationHash")]
    pub master_password_authentication_hash: Secret<'a>,
}
impl core::fmt::Debug for AccountKdfAuthentication<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountKdfAuthentication")
            .finish_non_exhaustive()
    }
}

/// Canonical-only KDF-change unlock fields, preserving opaque wrapped keys verbatim.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKdfUnlock<'a> {
    pub salt: &'a str,
    pub kdf: RegistrationKdf,
    #[serde(borrow)]
    pub master_key_wrapped_user_key: Secret<'a>,
}
impl core::fmt::Debug for AccountKdfUnlock<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountKdfUnlock").finish_non_exhaustive()
    }
}

/// Nested-only `/accounts/kdf` request. Field order matches positional Serde input.
/// All three top-level fields are required; legacy flattened credentials are not a fallback.
/// Borrowed decoding supports unescaped strings; an adapter can decode escaped strings into
/// owned/caller-provided storage before constructing this view. Credentials have no Serialize.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKdfRequest<'a> {
    #[serde(borrow)]
    pub authentication_data: AccountKdfAuthentication<'a>,
    #[serde(borrow)]
    pub unlock_data: AccountKdfUnlock<'a>,
    #[serde(borrow)]
    pub master_password_hash: Secret<'a>,
}
impl core::fmt::Debug for AccountKdfRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountKdfRequest").finish_non_exhaustive()
    }
}

/// Password-change fields in the upstream positional order. A complete nested pair wins
/// over legacy credentials; a partial nested pair can fall back to the complete legacy pair.
/// Optional fields have no explicit serde default: omitted object fields work, but positional
/// arrays must include all six slots. Required old proof and all supplied strings stay opaque.
/// As with other borrowed DTOs, escaped strings require adapter-owned decoded storage.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountPasswordRequest<'a> {
    #[serde(borrow)]
    pub master_password_hash: Secret<'a>,
    pub master_password_hint: Option<&'a str>,
    #[serde(borrow)]
    pub authentication_data: Option<AccountKdfAuthentication<'a>>,
    #[serde(borrow)]
    pub unlock_data: Option<AccountKdfUnlock<'a>>,
    #[serde(borrow)]
    pub new_master_password_hash: Option<Secret<'a>>,
    #[serde(borrow)]
    pub key: Option<Secret<'a>>,
}
impl core::fmt::Debug for AccountPasswordRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountPasswordRequest")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
pub struct RegistrationAuthentication<'a> {
    #[serde(alias = "Kdf")]
    pub kdf: RegistrationKdf,
    #[serde(alias = "Salt")]
    pub salt: &'a str,
    #[serde(
        borrow,
        alias = "masterPasswordAuthenticationHash",
        alias = "MasterPasswordAuthenticationHash"
    )]
    pub hash: Secret<'a>,
}
impl core::fmt::Debug for RegistrationAuthentication<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegistrationAuthentication")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
pub struct RegistrationUnlock<'a> {
    pub kdf: RegistrationKdf,
    pub salt: &'a str,
    #[serde(borrow, alias = "masterKeyWrappedUserKey")]
    pub key: Secret<'a>,
}
impl core::fmt::Debug for RegistrationUnlock<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegistrationUnlock").finish_non_exhaustive()
    }
}

/// Explicit semantic selection after transport decoding. The pinned flattened, untagged
/// JSON union tries a valid legacy representation first; adapters must preserve that order.
/// This enum deliberately does not derive Deserialize with alloc-dependent buffering.
pub enum RegistrationCredentials<'a> {
    Legacy {
        kdf: RegistrationKdf,
        master_password_hash: Secret<'a>,
        key: Secret<'a>,
    },
    Nested {
        authentication: RegistrationAuthentication<'a>,
        unlock: RegistrationUnlock<'a>,
    },
}
impl core::fmt::Debug for RegistrationCredentials<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegistrationCredentials")
            .finish_non_exhaustive()
    }
}

/// Borrowed ordinary-registration semantic view, not a full RegisterData JSON decoder.
///
/// The adapter resolves aliases/legacy-first union selection and the verification-proof
/// tuple. Only a sole email-verification token maps to Some; missing, mixed or unsupported
/// organization/emergency proof shapes map to None. Keep credentials even in those cases
/// so nested format errors retain their upstream precedence over a missing proof. Finish
/// body names have no authority and are deliberately absent from this view.
pub struct RegistrationFinishRequest<'a> {
    pub email: &'a str,
    pub credentials: RegistrationCredentials<'a>,
    pub email_verification_token: Option<Secret<'a>>,
    pub keys: Option<AccountKeys<'a>>,
    pub master_password_hint: Option<&'a str>,
}
impl core::fmt::Debug for RegistrationFinishRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegistrationFinishRequest")
            .finish_non_exhaustive()
    }
}

/// Deliberate token transport boundary. JSON serializes a bare string; an HTTP adapter
/// can explicitly expose the same value for a plain-text response after Accept negotiation.
/// Debug is redacted independently of the provider token type's formatting capabilities.
pub struct RegistrationVerificationToken<T: AsRef<str>> {
    token: T,
}
impl<T: AsRef<str>> RegistrationVerificationToken<T> {
    pub const fn new(token: T) -> Self {
        Self { token }
    }
    pub fn expose_token(&self) -> &str {
        self.token.as_ref()
    }
}
impl<T: AsRef<str>> core::fmt::Debug for RegistrationVerificationToken<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegistrationVerificationToken")
            .finish_non_exhaustive()
    }
}
impl<T: AsRef<str>> Serialize for RegistrationVerificationToken<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose_token())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RegistrationFinishResponse;
impl Serialize for RegistrationFinishResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("RegistrationFinishResponse", 1)?;
        value.serialize_field("object", "registerFinish")?;
        value.end()
    }
}

/// Semantic SendData view after the adapter's full schema/date decoder. It deliberately
/// accepts any caller-owned serializable text payload, without a collection/string cap.
/// Timestamp parsing, JSON field order/aliases and ignored file/id fields remain adapter
/// responsibilities. Credentials and payloads never appear in Debug or implicit Serialize.
pub struct TextSendRequest<'a, P: ?Sized> {
    pub kind: i32,
    pub key: &'a str,
    pub password: Option<Secret<'a>>,
    pub max_access_count: Option<crate::sends::SendNumber<'a>>,
    pub expiration_ns: Option<i128>,
    pub deletion_ns: i128,
    pub disabled: bool,
    pub hide_email: Option<bool>,
    pub emails: Option<&'a str>,
    pub name: &'a str,
    pub notes: Option<&'a str>,
    pub text: Option<&'a P>,
}
impl<P: ?Sized> core::fmt::Debug for TextSendRequest<'_, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TextSendRequest").finish_non_exhaustive()
    }
}

/// File-Send semantic view after the adapter's complete JSON/date decoder.
/// `common.text` is ignored. File metadata is required for reservation and immutable
/// during update; file_length is consulted only by the reservation service.
pub struct FileSendRequest<'a, P: ?Sized> {
    pub common: TextSendRequest<'a, P>,
    pub file: Option<&'a P>,
    pub file_length: Option<crate::sends::SendNumber<'a>>,
}

/// A minimal borrowed encrypted file payload. The generic file-Send service also
/// accepts richer caller-owned payloads; this is not the complete HTTP SendData decoder.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendFileData<'a> {
    pub file_name: &'a str,
}
impl core::fmt::Debug for SendFileData<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendFileData").finish_non_exhaustive()
    }
}
impl<P: ?Sized> core::fmt::Debug for FileSendRequest<'_, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileSendRequest").finish_non_exhaustive()
    }
}

/// Borrowed send_access form view. Missing/duplicate Option field semantics and complete
/// form/root-name decoding belong to the HTTP adapter; opaque password input is not decoded.
#[derive(Deserialize)]
pub struct SendAccessTokenRequest<'a> {
    pub grant_type: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub send_id: Option<&'a str>,
    #[serde(borrow)]
    pub password_hash_b64: Option<Secret<'a>>,
}
impl core::fmt::Debug for SendAccessTokenRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendAccessTokenRequest")
            .finish_non_exhaustive()
    }
}

pub struct SendOwnerResponse<'a, P: Serialize> {
    pub(crate) record: crate::sends::SendRecord<'a, P>,
    pub(crate) kind: i32,
}
impl<P: Serialize> core::fmt::Debug for SendOwnerResponse<'_, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendOwnerResponse").finish_non_exhaustive()
    }
}
impl<P: Serialize> Serialize for SendOwnerResponse<'_, P> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let r = &self.record;
        let mut value = serializer.serialize_struct("SendOwnerResponse", 18)?;
        value.serialize_field("id", r.id)?;
        value.serialize_field("accessId", r.access_id)?;
        value.serialize_field("type", &self.kind)?;
        value.serialize_field("name", r.name)?;
        value.serialize_field("notes", &r.notes)?;
        value.serialize_field("text", &if self.kind == 0 { Some(&r.text) } else { None })?;
        value.serialize_field("file", &if self.kind == 1 { Some(&r.text) } else { None })?;
        value.serialize_field("key", r.key)?;
        value.serialize_field("maxAccessCount", &r.max_access_count)?;
        value.serialize_field("accessCount", &r.access_count)?;
        value.serialize_field("password", &r.password_hash)?;
        value.serialize_field(
            "authType",
            &if r.password_hash.is_some() { 1_i32 } else { 2 },
        )?;
        value.serialize_field("disabled", &r.disabled)?;
        value.serialize_field("hideEmail", &r.hide_email.unwrap_or(false))?;
        value.serialize_field("revisionDate", r.revision_date)?;
        value.serialize_field("expirationDate", &r.expiration_date)?;
        value.serialize_field("deletionDate", r.deletion_date)?;
        value.serialize_field("object", "send")?;
        value.end()
    }
}

pub struct SendRecipientResponse<'a, P: Serialize> {
    pub(crate) record: crate::sends::SendRecord<'a, P>,
    pub(crate) kind: i32,
}
impl<P: Serialize> core::fmt::Debug for SendRecipientResponse<'_, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendRecipientResponse")
            .finish_non_exhaustive()
    }
}
impl<P: Serialize> Serialize for SendRecipientResponse<'_, P> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let r = &self.record;
        let mut value = serializer.serialize_struct("SendRecipientResponse", 8)?;
        value.serialize_field("id", r.access_id)?;
        value.serialize_field("type", &self.kind)?;
        value.serialize_field("name", r.name)?;
        value.serialize_field("text", &if self.kind == 0 { Some(&r.text) } else { None })?;
        value.serialize_field("file", &if self.kind == 1 { Some(&r.text) } else { None })?;
        value.serialize_field("expirationDate", &r.expiration_date)?;
        value.serialize_field(
            "creatorIdentifier",
            &if r.hide_email == Some(true) {
                None
            } else {
                r.creator_identifier
            },
        )?;
        value.serialize_field("object", "send-access")?;
        value.end()
    }
}

pub struct SendListResponse<'a, L: crate::sends::SendListData<'a>> {
    pub(crate) data: L,
    pub(crate) marker: core::marker::PhantomData<&'a ()>,
}
impl<'a, L: crate::sends::SendListData<'a>> core::fmt::Debug for SendListResponse<'a, L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendListResponse").finish_non_exhaustive()
    }
}
impl<'a, L: crate::sends::SendListData<'a>> Serialize for SendListResponse<'a, L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeSeq, SerializeStruct};
        struct Entries<'a, 'b, L: crate::sends::SendListData<'a>> {
            list: &'b L,
            marker: core::marker::PhantomData<&'a ()>,
        }
        impl<'a, L: crate::sends::SendListData<'a>> Serialize for Entries<'a, '_, L> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut values = serializer.serialize_seq(Some(self.list.len()))?;
                for index in 0..self.list.len() {
                    let record = self
                        .list
                        .get(index)
                        .ok_or_else(|| serde::ser::Error::custom("Invalid Send list view"))?;
                    let kind = self
                        .list
                        .kind(index)
                        .ok_or_else(|| serde::ser::Error::custom("Invalid Send list type"))?;
                    values.serialize_element(&SendOwnerResponse { record, kind })?;
                }
                values.end()
            }
        }
        let mut value = serializer.serialize_struct("SendListResponse", 3)?;
        value.serialize_field(
            "data",
            &Entries {
                list: &self.data,
                marker: core::marker::PhantomData,
            },
        )?;
        value.serialize_field("object", "list")?;
        value.serialize_field("continuationToken", &None::<()>)?;
        value.end()
    }
}

/// Explicit owner upload transport response. Debug never exposes its URL or keys.
pub struct SendFileUploadResponse<'a, P: Serialize, U: AsRef<str>> {
    pub(crate) response: SendOwnerResponse<'a, P>,
    pub(crate) url: U,
}
impl<P: Serialize, U: AsRef<str>> core::fmt::Debug for SendFileUploadResponse<'_, P, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendFileUploadResponse")
            .finish_non_exhaustive()
    }
}
impl<P: Serialize, U: AsRef<str>> Serialize for SendFileUploadResponse<'_, P, U> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("SendFileUploadResponse", 4)?;
        value.serialize_field("fileUploadType", &0_i32)?;
        value.serialize_field("object", "send-fileUpload")?;
        value.serialize_field("url", self.url.as_ref())?;
        value.serialize_field("sendResponse", &self.response)?;
        value.end()
    }
}

/// Capability URL returned only after a successful file access reservation.
pub struct SendFileDownloadResponse<'a, U: AsRef<str>> {
    pub(crate) file_id: &'a str,
    pub(crate) url: U,
}
impl<U: AsRef<str>> core::fmt::Debug for SendFileDownloadResponse<'_, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SendFileDownloadResponse")
            .finish_non_exhaustive()
    }
}
impl<U: AsRef<str>> Serialize for SendFileDownloadResponse<'_, U> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("SendFileDownloadResponse", 3)?;
        value.serialize_field("object", "send-fileDownload")?;
        value.serialize_field("id", self.file_id)?;
        value.serialize_field("url", self.url.as_ref())?;
        value.end()
    }
}

/// Refresh fields after form decoding. The proof stays opaque and is never serialized.
/// This convenience decoder is not the complete HTTP form/root-name/alias parser;
/// optional duplicate-field handling and guards belong to the transport. Missing client
/// ID defaults to "undefined" during authorization; a present empty ID stays empty.
#[derive(Deserialize)]
pub struct RefreshTokenRequest<'a> {
    pub grant_type: Option<&'a str>,
    #[serde(borrow, alias = "refreshtoken")]
    pub refresh_token: Option<Secret<'a>>,
    #[serde(alias = "clientid")]
    pub client_id: Option<&'a str>,
}
impl core::fmt::Debug for RefreshTokenRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RefreshTokenRequest")
            .finish_non_exhaustive()
    }
}

/// Ordinary password-grant fields after form decoding. This borrowed convenience decoder
/// is not the complete HTTP form/root-name/alias parser. Presence checks accept blank
/// strings; an `auth_request` must instead be dispatched to authentication-request login.
/// The proof cannot be serialized and Debug redacts every field.
#[derive(Deserialize)]
pub struct PasswordLoginRequest<'a> {
    pub grant_type: Option<&'a str>,
    pub client_id: Option<&'a str>,
    #[serde(borrow)]
    pub password: Option<Secret<'a>>,
    pub scope: Option<&'a str>,
    pub username: Option<&'a str>,
    #[serde(rename = "deviceIdentifier", alias = "device_identifier")]
    pub device_identifier: Option<&'a str>,
    #[serde(rename = "deviceName", alias = "device_name")]
    pub device_name: Option<&'a str>,
    #[serde(rename = "deviceType", alias = "device_type")]
    pub device_type: Option<&'a str>,
    #[serde(rename = "authRequest")]
    pub auth_request: Option<&'a str>,
}
impl core::fmt::Debug for PasswordLoginRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordLoginRequest")
            .finish_non_exhaustive()
    }
}

/// Authentication-request password-grant fields after form decoding. All fields must be
/// present, including an opaque access code in `password`; present blank strings are not
/// missing fields. This convenience decoder is not a complete HTTP form/alias parser.
/// No Serialize implementation is provided, and Debug redacts every field.
#[derive(Deserialize)]
pub struct AuthRequestLoginRequest<'a> {
    pub grant_type: Option<&'a str>,
    #[serde(borrow)]
    pub password: Option<Secret<'a>>,
    #[serde(rename = "authRequest")]
    pub auth_request: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub username: Option<&'a str>,
    #[serde(rename = "deviceIdentifier", alias = "device_identifier")]
    pub device_identifier: Option<&'a str>,
    #[serde(rename = "deviceName", alias = "device_name")]
    pub device_name: Option<&'a str>,
    #[serde(rename = "deviceType", alias = "device_type")]
    pub device_type: Option<&'a str>,
}
impl core::fmt::Debug for AuthRequestLoginRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequestLoginRequest")
            .finish_non_exhaustive()
    }
}

/// Opaque authentication-request decision in upstream positional order. Optional hash
/// omission/null is accepted in objects; positional sequences must include its slot.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequestUpdateRequest<'a> {
    pub device_identifier: &'a str,
    pub key: &'a str,
    pub master_password_hash: Option<&'a str>,
    pub request_approved: bool,
}
impl core::fmt::Debug for AuthRequestUpdateRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequestUpdateRequest")
            .finish_non_exhaustive()
    }
}

/// Opaque public authentication-request input, in pinned positional field order.
/// Required strings can be empty. Borrow escaped strings from decoded caller-owned scratch.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequestCreateRequest<'a> {
    pub access_code: &'a str,
    pub device_identifier: &'a str,
    pub email: &'a str,
    pub public_key: &'a str,
}
impl core::fmt::Debug for AuthRequestCreateRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequestCreateRequest")
            .finish_non_exhaustive()
    }
}

/// Explicit eleven-field projection. Internal access code, owner and device ID never appear.
pub struct AuthRequestResponse<'a> {
    record: crate::auth_requests::AuthRequestRecord<'a>,
    origin: &'a str,
    created: bool,
}
impl<'a> AuthRequestResponse<'a> {
    /// Creation forces requestApproved=false and null key/hash/responseDate, independently
    /// of the stored optional approval state. Supply an already-authorized provider record.
    pub const fn created(
        record: crate::auth_requests::AuthRequestRecord<'a>,
        origin: &'a str,
    ) -> Self {
        Self {
            record,
            origin,
            created: true,
        }
    }
    /// Authenticated retrieval preserves all stored optional response fields exactly.
    pub const fn stored(
        record: crate::auth_requests::AuthRequestRecord<'a>,
        origin: &'a str,
    ) -> Self {
        Self {
            record,
            origin,
            created: false,
        }
    }
}
impl core::fmt::Debug for AuthRequestResponse<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequestResponse")
            .finish_non_exhaustive()
    }
}
impl Serialize for AuthRequestResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("AuthRequestResponse", 11)?;
        value.serialize_field("id", self.record.id)?;
        value.serialize_field("publicKey", self.record.public_key)?;
        value.serialize_field(
            "requestDeviceType",
            crate::auth_requests::device_type_name(self.record.device_type),
        )?;
        value.serialize_field("requestIpAddress", self.record.request_ip)?;
        value.serialize_field("key", &if self.created { None } else { self.record.key })?;
        value.serialize_field(
            "masterPasswordHash",
            &if self.created {
                None
            } else {
                self.record.master_password_hash
            },
        )?;
        value.serialize_field("creationDate", self.record.creation_date)?;
        value.serialize_field(
            "responseDate",
            &if self.created {
                None
            } else {
                self.record.response_date
            },
        )?;
        value.serialize_field(
            "requestApproved",
            &if self.created {
                Some(false)
            } else {
                self.record.approved
            },
        )?;
        value.serialize_field("origin", self.origin)?;
        value.serialize_field("object", "auth-request")?;
        value.end()
    }
}

/// Streaming pending-only list. None is pending; both Some(false) and Some(true) are omitted.
pub struct AuthRequestListResponse<'a, D: crate::auth_requests::AuthRequestListData> {
    records: D,
    origin: &'a str,
}
impl<'a, D: crate::auth_requests::AuthRequestListData> AuthRequestListResponse<'a, D> {
    /// Supply a stable owner-authorized view; VaultService validates it before projection.
    pub const fn new(records: D, origin: &'a str) -> Self {
        Self { records, origin }
    }
}
impl<D: crate::auth_requests::AuthRequestListData> core::fmt::Debug
    for AuthRequestListResponse<'_, D>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequestListResponse")
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}
impl<D: crate::auth_requests::AuthRequestListData> Serialize for AuthRequestListResponse<'_, D> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq, SerializeStruct};
        struct Entries<'a, D> {
            records: &'a D,
            origin: &'a str,
        }
        impl<D: crate::auth_requests::AuthRequestListData> Serialize for Entries<'_, D> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut count = 0;
                for index in 0..self.records.len() {
                    let record = self
                        .records
                        .get(index)
                        .ok_or_else(|| S::Error::custom("The auth request view is incomplete."))?;
                    if record.approved.is_none() {
                        count += 1;
                    }
                }
                let mut entries = serializer.serialize_seq(Some(count))?;
                for index in 0..self.records.len() {
                    let record = self
                        .records
                        .get(index)
                        .ok_or_else(|| S::Error::custom("The auth request view is incomplete."))?;
                    if record.approved.is_none() {
                        entries
                            .serialize_element(&AuthRequestResponse::stored(record, self.origin))?;
                    }
                }
                entries.end()
            }
        }
        let mut value = serializer.serialize_struct("AuthRequestListResponse", 3)?;
        value.serialize_field(
            "data",
            &Entries {
                records: &self.records,
                origin: self.origin,
            },
        )?;
        value.serialize_field("object", "list")?;
        value.serialize_field("continuationToken", &None::<&str>)?;
        value.end()
    }
}

/// Required opaque push token. Empty strings are values, not absence or a clear operation.
/// Borrow escaped JSON strings from caller-owned decoded scratch storage when needed.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePushTokenRequest<'a> {
    pub push_token: &'a str,
}
impl core::fmt::Debug for DevicePushTokenRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevicePushTokenRequest")
            .finish_non_exhaustive()
    }
}

/// Public known-device input after adapter base64url/UTF-8 header decoding.
/// There is no JSON body and this type deliberately does not serialize account metadata.
#[derive(Clone, Copy)]
pub struct KnownDeviceRequest<'a> {
    pub email: &'a str,
    pub identifier: &'a str,
}
impl core::fmt::Debug for KnownDeviceRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KnownDeviceRequest").finish_non_exhaustive()
    }
}

/// The known-device endpoint returns a bare JSON boolean.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct KnownDeviceResponse(pub bool);

/// Explicit seven-field projection, omitting internal ownership and pending-auth state.
pub struct DeviceResponse<'a> {
    record: crate::devices::DeviceRecord<'a>,
}
impl<'a> DeviceResponse<'a> {
    /// Direct serializers must supply an already-authorized record; VaultService checks it.
    pub const fn new(record: crate::devices::DeviceRecord<'a>) -> Self {
        Self { record }
    }
}
impl core::fmt::Debug for DeviceResponse<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceResponse").finish_non_exhaustive()
    }
}
impl Serialize for DeviceResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_device(self.record, serializer, false)
    }
}

fn serialize_device<S: serde::Serializer>(
    record: crate::devices::DeviceRecord<'_>,
    serializer: S,
    list_entry: bool,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct;
    // The local projection borrows metadata without serializing the provider record.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PendingResponse<'a> {
        id: &'a str,
        creation_date: &'a str,
    }
    let mut value =
        serializer.serialize_struct("DeviceResponse", if list_entry { 10 } else { 7 })?;
    value.serialize_field("id", record.identifier)?;
    value.serialize_field("name", record.name)?;
    value.serialize_field("type", &record.device_type)?;
    value.serialize_field("identifier", record.identifier)?;
    value.serialize_field("creationDate", record.creation_date)?;
    if list_entry {
        value.serialize_field(
            "devicePendingAuthRequest",
            &record.pending_auth_request.map(|pending| PendingResponse {
                id: pending.id,
                creation_date: pending.creation_date,
            }),
        )?;
        value.serialize_field("encryptedPublicKey", &None::<&str>)?;
        value.serialize_field("encryptedUserKey", &None::<&str>)?;
    }
    value.serialize_field("isTrusted", &false)?;
    value.serialize_field("object", "device")?;
    value.end()
}

/// Streaming ten-field list entries over a stable, caller/provider-owned view.
/// This does not allocate a response collection or impose a fixed device-count limit.
pub struct DeviceListResponse<D: crate::devices::DeviceListData> {
    devices: D,
}
impl<D: crate::devices::DeviceListData> DeviceListResponse<D> {
    /// Direct serializers must supply an already-authorized view; VaultService checks it.
    pub const fn new(devices: D) -> Self {
        Self { devices }
    }
}
impl<D: crate::devices::DeviceListData> core::fmt::Debug for DeviceListResponse<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceListResponse")
            .field("count", &self.devices.len())
            .finish_non_exhaustive()
    }
}
impl<D: crate::devices::DeviceListData> Serialize for DeviceListResponse<D> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq, SerializeStruct};
        struct Entries<'a, D>(&'a D);
        struct Entry<'a>(crate::devices::DeviceRecord<'a>);
        impl Serialize for Entry<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serialize_device(self.0, serializer, true)
            }
        }
        impl<D: crate::devices::DeviceListData> Serialize for Entries<'_, D> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut entries = serializer.serialize_seq(Some(self.0.len()))?;
                for index in 0..self.0.len() {
                    let record = self
                        .0
                        .get(index)
                        .ok_or_else(|| S::Error::custom("The device list view is incomplete."))?;
                    entries.serialize_element(&Entry(record))?;
                }
                entries.end()
            }
        }
        let mut value = serializer.serialize_struct("DeviceListResponse", 3)?;
        value.serialize_field("data", &Entries(&self.devices))?;
        value.serialize_field("object", "list")?;
        value.serialize_field("continuationToken", &None::<&str>)?;
        value.end()
    }
}

pub const MAX_URIS: usize = 32;
pub const MAX_FIELDS: usize = 64;
pub const MAX_PASSWORD_HISTORY: usize = 32;
pub const MAX_FIDO2_CREDENTIALS: usize = 16;
pub const MAX_COLLECTION_IDS: usize = 64;

/// Configurable domain-settings decoder. Capacities are caller policy, not protocol limits.
/// Fields follow upstream positional order. Object omission/null clears each setting;
/// positional arrays still require both fields, for example `[null, null]`.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainSettingsRequest<'a, const E: usize, const G: usize, const D: usize> {
    pub excluded_global_equivalent_domains: Option<BoundedList<i32, E>>,
    #[serde(borrow)]
    pub equivalent_domains: Option<BoundedList<BoundedList<&'a str, D>, G>>,
}

impl<const E: usize, const G: usize, const D: usize> core::fmt::Debug
    for DomainSettingsRequest<'_, E, G, D>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DomainSettingsRequest")
            .field(
                "excluded_global_count",
                &self
                    .excluded_global_equivalent_domains
                    .as_ref()
                    .map_or(0, |v| v.len()),
            )
            .field(
                "equivalent_group_count",
                &self.equivalent_domains.as_ref().map_or(0, |v| v.len()),
            )
            .finish_non_exhaustive()
    }
}

/// Borrowed response over any provider view and adapter-supplied global catalog.
/// GET includes flagged groups; the sync projection omits them without reordering.
pub struct DomainSettingsResponse<
    'a,
    D: crate::domains::DomainSettingsData,
    C: crate::domains::GlobalDomainCatalog + ?Sized,
> {
    settings: D,
    catalog: &'a C,
    projection: crate::domains::DomainProjection,
}
impl<'a, D: crate::domains::DomainSettingsData, C: crate::domains::GlobalDomainCatalog + ?Sized>
    DomainSettingsResponse<'a, D, C>
{
    pub const fn new(
        settings: D,
        catalog: &'a C,
        projection: crate::domains::DomainProjection,
    ) -> Self {
        Self {
            settings,
            catalog,
            projection,
        }
    }
}
impl<D: crate::domains::DomainSettingsData, C: crate::domains::GlobalDomainCatalog + ?Sized>
    core::fmt::Debug for DomainSettingsResponse<'_, D, C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DomainSettingsResponse")
            .field(
                "equivalent_group_count",
                &self.settings.equivalent_group_count(),
            )
            .field("global_group_count", &self.catalog.group_count())
            .field("projection", &self.projection)
            .finish_non_exhaustive()
    }
}
impl<D: crate::domains::DomainSettingsData, C: crate::domains::GlobalDomainCatalog + ?Sized>
    Serialize for DomainSettingsResponse<'_, D, C>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::domains::{DomainProjection, DomainSettingsData, GlobalDomainCatalog};
        use serde::ser::{Error, SerializeSeq, SerializeStruct};
        fn missing<E: Error>() -> E {
            E::custom("Incomplete domain settings or catalog view")
        }
        fn excluded<D: DomainSettingsData + ?Sized, E: Error>(
            data: &D,
            kind: i32,
        ) -> Result<bool, E> {
            for i in 0..data.excluded_global_count() {
                if data.excluded_global(i).ok_or_else(missing)? == kind {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        struct DomainStrings<'a, D: ?Sized>(&'a D, usize);
        impl<D: DomainSettingsData + ?Sized> Serialize for DomainStrings<'_, D> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let count = self.0.equivalent_domain_count(self.1).ok_or_else(missing)?;
                let mut seq = s.serialize_seq(Some(count))?;
                for i in 0..count {
                    seq.serialize_element(
                        self.0.equivalent_domain(self.1, i).ok_or_else(missing)?,
                    )?;
                }
                seq.end()
            }
        }
        struct Groups<'a, D: ?Sized>(&'a D);
        impl<D: DomainSettingsData + ?Sized> Serialize for Groups<'_, D> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut seq = s.serialize_seq(Some(self.0.equivalent_group_count()))?;
                for g in 0..self.0.equivalent_group_count() {
                    seq.serialize_element(&DomainStrings(self.0, g))?;
                }
                seq.end()
            }
        }
        struct CatalogStrings<'a, C: ?Sized>(&'a C, usize);
        impl<C: GlobalDomainCatalog + ?Sized> Serialize for CatalogStrings<'_, C> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let count = self.0.domain_count(self.1).ok_or_else(missing)?;
                let mut seq = s.serialize_seq(Some(count))?;
                for i in 0..count {
                    seq.serialize_element(self.0.domain(self.1, i).ok_or_else(missing)?)?;
                }
                seq.end()
            }
        }
        struct GlobalGroup<'a, C: ?Sized> {
            catalog: &'a C,
            index: usize,
            kind: i32,
            excluded: bool,
        }
        impl<C: GlobalDomainCatalog + ?Sized> Serialize for GlobalGroup<'_, C> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut row = s.serialize_struct("GlobalDomain", 3)?;
                row.serialize_field("type", &self.kind)?;
                row.serialize_field("domains", &CatalogStrings(self.catalog, self.index))?;
                row.serialize_field("excluded", &self.excluded)?;
                row.end()
            }
        }
        struct Globals<'a, D: ?Sized, C: ?Sized> {
            data: &'a D,
            catalog: &'a C,
            projection: DomainProjection,
        }
        impl<D: DomainSettingsData + ?Sized, C: GlobalDomainCatalog + ?Sized> Serialize
            for Globals<'_, D, C>
        {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut count = 0;
                for g in 0..self.catalog.group_count() {
                    let kind = self.catalog.kind(g).ok_or_else(missing)?;
                    if self.projection == DomainProjection::All
                        || !excluded::<_, S::Error>(self.data, kind)?
                    {
                        count += 1;
                    }
                }
                let mut seq = s.serialize_seq(Some(count))?;
                for g in 0..self.catalog.group_count() {
                    let kind = self.catalog.kind(g).ok_or_else(missing)?;
                    let excluded = excluded::<_, S::Error>(self.data, kind)?;
                    if self.projection == DomainProjection::All || !excluded {
                        seq.serialize_element(&GlobalGroup {
                            catalog: self.catalog,
                            index: g,
                            kind,
                            excluded,
                        })?;
                    }
                }
                seq.end()
            }
        }
        let mut response = serializer.serialize_struct("DomainSettingsResponse", 3)?;
        response.serialize_field("equivalentDomains", &Groups(&self.settings))?;
        response.serialize_field(
            "globalEquivalentDomains",
            &Globals {
                data: &self.settings,
                catalog: self.catalog,
                projection: self.projection,
            },
        )?;
        response.serialize_field("object", "domains")?;
        response.end()
    }
}

/// Successful settings mutations return exactly an empty JSON object.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct DomainSettingsUpdateResponse {}

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

/// One-time user-key identifier migration. The value is opaque, including an empty string.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserKeyIdRequest<'a> {
    pub user_key_id: &'a str,
}

impl core::fmt::Debug for UserKeyIdRequest<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("UserKeyIdRequest([REDACTED])")
    }
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

/// Signed account KDF metadata returned by prelogin without registration-policy filtering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginKdfSettings {
    pub iterations: i32,
    pub kdf_type: i32,
    pub memory: Option<i32>,
    pub parallelism: Option<i32>,
}

/// The complete six-field discovery response used by both identity prelogin routes.
///
/// Construction keeps the legacy and nested projections identical and the salt null.
/// `PreloginResponse` remains available for existing unsigned four-field consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletePreloginResponse {
    settings: PreloginKdfSettings,
}

impl CompletePreloginResponse {
    pub(crate) const fn from_settings(settings: PreloginKdfSettings) -> Self {
        Self { settings }
    }

    pub const fn settings(&self) -> PreloginKdfSettings {
        self.settings
    }
}

impl Serialize for CompletePreloginResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut response = serializer.serialize_struct("CompletePreloginResponse", 6)?;
        response.serialize_field("kdf", &self.settings.kdf_type)?;
        response.serialize_field("kdfIterations", &self.settings.iterations)?;
        response.serialize_field("kdfMemory", &self.settings.memory)?;
        response.serialize_field("kdfParallelism", &self.settings.parallelism)?;
        response.serialize_field("kdfSettings", &self.settings)?;
        response.serialize_field("salt", &Option::<&str>::None)?;
        response.end()
    }
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

/// Pinned Vaultwarden credential metadata intentionally contains no credentials.
/// This fixed projection does not implement passkey registration or login.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WebAuthnCredentialsResponse;

impl Serialize for WebAuthnCredentialsResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut response = serializer.serialize_struct("WebAuthnCredentialsResponse", 3)?;
        response.serialize_field("object", "list")?;
        response.serialize_field("data", &[] as &[()])?;
        response.serialize_field("continuationToken", &None::<&str>)?;
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

/// The ignored organization plan remains a required integer-or-string input.
#[derive(Clone, Copy)]
pub enum OrganizationPlanType<'a> {
    Integer(i64),
    String(&'a str),
}
impl core::fmt::Debug for OrganizationPlanType<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationPlanType([REDACTED])")
    }
}
impl<'de: 'a, 'a> Deserialize<'de> for OrganizationPlanType<'a> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PlanVisitor<'a>(core::marker::PhantomData<&'a str>);
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for PlanVisitor<'a> {
            type Value = OrganizationPlanType<'a>;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a signed 64-bit integer or borrowed string")
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(OrganizationPlanType::Integer(value))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                i64::try_from(value)
                    .map(OrganizationPlanType::Integer)
                    .map_err(|_| E::custom("Plan integer exceeds i64"))
            }
            fn visit_borrowed_str<E: serde::de::Error>(
                self,
                value: &'de str,
            ) -> Result<Self::Value, E> {
                Ok(OrganizationPlanType::String(value))
            }
        }
        deserializer.deserialize_any(PlanVisitor(core::marker::PhantomData))
    }
}

/// Borrowed owner creation input. Dynamic number/string decoding needs a deserializer
/// with deserialize_any support; adapters can construct this view after owned decoding.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationCreateRequest<'a> {
    pub billing_email: &'a str,
    pub collection_name: &'a str,
    #[serde(borrow)]
    pub key: Secret<'a>,
    pub name: &'a str,
    #[serde(borrow)]
    pub keys: Option<AccountKeys<'a>>,
    #[serde(borrow)]
    pub plan_type: OrganizationPlanType<'a>,
}
impl core::fmt::Debug for OrganizationCreateRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationCreateRequest([REDACTED])")
    }
}

/// Exact ordinary organization projection, excluding wrapped/private/public key strings.
#[derive(Debug)]
pub struct OrganizationResponse<'a> {
    record: crate::organizations::OrganizationRecord<'a>,
}
impl<'a> OrganizationResponse<'a> {
    pub(crate) const fn new(record: crate::organizations::OrganizationRecord<'a>) -> Self {
        Self { record }
    }
    pub const fn id(&self) -> &'a str {
        self.record.id
    }
}
impl Serialize for OrganizationResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(47))?;
        let row = self.record;
        for (name, value) in [
            ("allowAdminAccessToAllCollectionItems", true),
            ("limitCollectionCreation", true),
            ("limitCollectionDeletion", true),
            ("limitItemDeletion", false),
            ("selfHost", true),
            ("use2fa", true),
            ("useApi", true),
            ("useCustomPermissions", true),
            ("useDirectory", false),
            ("useDisableSMAdsForUsers", true),
            ("useInviteLinks", false),
            ("useKeyConnector", false),
            ("useMyItems", false),
            ("useOrganizationDomains", false),
            ("usePam", false),
            ("usePasswordManager", true),
            ("usePhishingBlocker", false),
            ("usePolicies", true),
            ("useScim", false),
            ("useSecretsManager", false),
            ("useSso", false),
            ("useTotp", true),
            ("usersGetPremium", true),
        ] {
            map.serialize_entry(name, &value)?;
        }
        for name in [
            "seats",
            "maxCollections",
            "businessAddress1",
            "businessAddress2",
            "businessAddress3",
            "businessCountry",
            "businessTaxNumber",
            "maxAutoscaleSeats",
            "maxAutoscaleSmSeats",
            "maxAutoscaleSmServiceAccounts",
            "secretsManagerPlan",
            "smSeats",
            "smServiceAccounts",
        ] {
            map.serialize_entry(name, &Option::<&str>::None)?;
        }
        map.serialize_entry("id", row.id)?;
        map.serialize_entry("name", row.name)?;
        map.serialize_entry("businessName", row.name)?;
        map.serialize_entry("billingEmail", row.billing_email)?;
        map.serialize_entry("object", "organization")?;
        map.serialize_entry("planType", &6)?;
        map.serialize_entry("maxStorageGb", &32767)?;
        map.serialize_entry("hasPublicAndPrivateKeys", &row.has_public_and_private_keys)?;
        map.serialize_entry("useEvents", &row.features.events)?;
        map.serialize_entry("useGroups", &row.features.groups)?;
        map.serialize_entry("useResetPassword", &row.features.mail)?;
        map.end()
    }
}

#[derive(Debug)]
pub struct CollectionResponse<'a> {
    record: crate::organizations::CollectionRecord<'a>,
}
impl<'a> CollectionResponse<'a> {
    pub(crate) const fn new(record: crate::organizations::CollectionRecord<'a>) -> Self {
        Self { record }
    }
}
impl Serialize for CollectionResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(7))?;
        map.serialize_entry("id", self.record.id)?;
        map.serialize_entry("organizationId", self.record.organization_id)?;
        map.serialize_entry("name", self.record.name)?;
        map.serialize_entry("externalId", &self.record.external_id)?;
        map.serialize_entry("type", &0)?;
        map.serialize_entry("defaultUserCollectionEmail", &Option::<&str>::None)?;
        map.serialize_entry("object", "collection")?;
        map.end()
    }
}

#[derive(Debug)]
pub struct CollectionDetailsResponse<'a> {
    record: crate::organizations::UserCollectionRecord<'a>,
}
impl Serialize for CollectionDetailsResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(10))?;
        let row = self.record;
        map.serialize_entry("id", row.collection.id)?;
        map.serialize_entry("organizationId", row.collection.organization_id)?;
        map.serialize_entry("name", row.collection.name)?;
        map.serialize_entry("externalId", &row.collection.external_id)?;
        map.serialize_entry("type", &0)?;
        map.serialize_entry("defaultUserCollectionEmail", &Option::<&str>::None)?;
        map.serialize_entry("object", "collectionDetails")?;
        map.serialize_entry("readOnly", &row.read_only)?;
        map.serialize_entry("hidePasswords", &row.hide_passwords)?;
        map.serialize_entry("manage", &row.manage)?;
        map.end()
    }
}

/// Basic collection list envelope. details() borrows the same authorized stable view
/// as a bare collectionDetails array for an adapter's sync response.
pub struct UserCollectionListResponse<L> {
    records: L,
}
impl<L> UserCollectionListResponse<L> {
    pub(crate) const fn new(records: L) -> Self {
        Self { records }
    }
    pub const fn details(&self) -> UserCollectionDetails<'_, L> {
        UserCollectionDetails {
            records: &self.records,
        }
    }
}
impl<L> core::fmt::Debug for UserCollectionListResponse<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UserCollectionListResponse([REDACTED])")
    }
}
impl<L: crate::organizations::UserCollectionListData> Serialize for UserCollectionListResponse<L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry(
            "data",
            &CollectionArray {
                records: &self.records,
                details: false,
            },
        )?;
        map.serialize_entry("object", "list")?;
        map.serialize_entry("continuationToken", &Option::<&str>::None)?;
        map.end()
    }
}
pub struct UserCollectionDetails<'a, L> {
    records: &'a L,
}
impl<L> core::fmt::Debug for UserCollectionDetails<'_, L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UserCollectionDetails([REDACTED])")
    }
}
impl<L: crate::organizations::UserCollectionListData> Serialize for UserCollectionDetails<'_, L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        CollectionArray {
            records: self.records,
            details: true,
        }
        .serialize(serializer)
    }
}
struct CollectionArray<'a, L> {
    records: &'a L,
    details: bool,
}
impl<L: crate::organizations::UserCollectionListData> Serialize for CollectionArray<'_, L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.records.len()))?;
        for index in 0..self.records.len() {
            let row = self
                .records
                .get(index)
                .ok_or_else(|| serde::ser::Error::custom("Incomplete collection view"))?;
            if self.details {
                seq.serialize_element(&CollectionDetailsResponse { record: row })?;
            } else {
                seq.serialize_element(&CollectionResponse::new(row.collection))?;
            }
        }
        seq.end()
    }
}

/// Explicit projection of one member's wrapped organization key and metadata.
#[derive(Debug)]
pub struct OrganizationProfileResponse<'a> {
    record: crate::organizations::OrganizationProfileRecord<'a>,
}
impl Serialize for OrganizationProfileResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(59))?;
        let row = self.record;
        for (name, value) in [
            ("accessSecretsManager", false),
            ("allowAdminAccessToAllCollectionItems", true),
            ("enabled", true),
            ("familySponsorshipAvailable", false),
            ("keyConnectorEnabled", false),
            ("limitCollectionDeletion", true),
            ("limitItemDeletion", false),
            ("selfHost", true),
            ("ssoBound", false),
            ("use2fa", true),
            ("useActivateAutofillPolicy", false),
            ("useAdminSponsoredFamilies", false),
            ("useApi", true),
            ("useCustomPermissions", true),
            ("useDirectory", false),
            ("useDisableSMAdsForUsers", true),
            ("useInviteLinks", false),
            ("useKeyConnector", false),
            ("useMyItems", false),
            ("useOrganizationDomains", false),
            ("usePam", false),
            ("usePasswordManager", true),
            ("usePhishingBlocker", false),
            ("usePolicies", true),
            ("useRiskInsights", false),
            ("useScim", false),
            ("useSecretsManager", false),
            ("useSso", false),
            ("useTotp", true),
            ("userIsClaimedByOrganization", false),
            ("usersGetPremium", true),
        ] {
            map.serialize_entry(name, &value)?;
        }
        for name in [
            "identifier",
            "maxCollections",
            "providerId",
            "providerName",
            "providerType",
            "familySponsorshipFriendlyName",
            "keyConnectorUrl",
            "familySponsorshipLastSyncDate",
            "familySponsorshipValidUntil",
            "familySponsorshipToDelete",
        ] {
            map.serialize_entry(name, &Option::<&str>::None)?;
        }
        map.serialize_entry("id", row.organization.id)?;
        map.serialize_entry("name", row.organization.name)?;
        map.serialize_entry("organizationUserId", row.membership_id)?;
        map.serialize_entry("userId", row.membership.user_id)?;
        map.serialize_entry("key", row.key)?;
        map.serialize_entry("object", "profileOrganization")?;
        map.serialize_entry("seats", &20)?;
        map.serialize_entry("productTierType", &3)?;
        map.serialize_entry("maxStorageGb", &32767)?;
        map.serialize_entry("status", &row.membership.status)?;
        map.serialize_entry(
            "type",
            &if row.membership.role == 3 {
                4
            } else {
                row.membership.role
            },
        )?;
        map.serialize_entry(
            "hasPublicAndPrivateKeys",
            &row.organization.has_public_and_private_keys,
        )?;
        map.serialize_entry("useEvents", &row.organization.features.events)?;
        map.serialize_entry("useGroups", &row.organization.features.groups)?;
        map.serialize_entry("useResetPassword", &row.organization.features.mail)?;
        map.serialize_entry("resetPasswordEnrolled", &row.reset_password_enrolled)?;
        map.serialize_entry(
            "limitCollectionCreation",
            &(!row.access_all || !matches!(row.membership.role, 0 | 1 | 3)),
        )?;
        map.serialize_entry(
            "permissions",
            &OrganizationPermissions {
                collection_manager: row.membership.role == 3 && row.access_all,
            },
        )?;
        map.end()
    }
}
struct OrganizationPermissions {
    collection_manager: bool,
}
impl Serialize for OrganizationPermissions {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(12))?;
        for name in [
            "accessEventLogs",
            "accessImportExport",
            "accessReports",
            "manageGroups",
            "managePolicies",
            "manageSso",
            "manageUsers",
            "manageResetPassword",
            "manageScim",
        ] {
            map.serialize_entry(name, &false)?;
        }
        for name in [
            "createNewCollections",
            "editAnyCollection",
            "deleteAnyCollection",
        ] {
            map.serialize_entry(name, &self.collection_manager)?;
        }
        map.end()
    }
}

pub struct OrganizationProfileListResponse<L> {
    records: L,
}
impl<L> OrganizationProfileListResponse<L> {
    pub(crate) const fn new(records: L) -> Self {
        Self { records }
    }
    pub const fn confirmed(&self) -> OrganizationProfileArray<'_, L> {
        OrganizationProfileArray {
            records: &self.records,
            accepted: false,
        }
    }
    pub const fn accepted_and_confirmed(&self) -> OrganizationProfileArray<'_, L> {
        OrganizationProfileArray {
            records: &self.records,
            accepted: true,
        }
    }
}
impl<L> core::fmt::Debug for OrganizationProfileListResponse<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationProfileListResponse([REDACTED])")
    }
}
impl<L: crate::organizations::OrganizationProfileListData> Serialize
    for OrganizationProfileListResponse<L>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.confirmed().serialize(serializer)
    }
}
pub struct OrganizationProfileArray<'a, L> {
    records: &'a L,
    accepted: bool,
}
impl<L> core::fmt::Debug for OrganizationProfileArray<'_, L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationProfileArray([REDACTED])")
    }
}
impl<L: crate::organizations::OrganizationProfileListData> Serialize
    for OrganizationProfileArray<'_, L>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(None)?;
        for index in 0..self.records.len() {
            let row = self
                .records
                .get(index)
                .ok_or_else(|| serde::ser::Error::custom("Incomplete organization profile view"))?;
            if row.membership.status == 2 || (self.accepted && row.membership.status == 1) {
                seq.serialize_element(&OrganizationProfileResponse { record: row })?;
            }
        }
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webauthn_credentials_response_is_exactly_the_sealed_empty_envelope() {
        let response = serde_json::to_value(WebAuthnCredentialsResponse).unwrap();
        assert_eq!(
            response,
            serde_json::json!({"object":"list","data":[],"continuationToken":null})
        );
        assert_eq!(response.as_object().unwrap().len(), 3);
    }

    #[test]
    fn account_password_wire_preserves_optional_branches_positional_order_and_redaction() {
        let input = r#"{"masterPasswordHash":"private-old","masterPasswordHint":"private-hint雪","authenticationData":{"Salt":"private-salt","Kdf":{"kdfType":-7,"iterations":-8,"memory":-9,"parallelism":-10},"MasterPasswordAuthenticationHash":"private-nested-proof"},"unlockData":{"salt":"private-salt","kdf":{"kdf":-7,"kdfIterations":-8,"kdfMemory":-9,"kdfParallelism":-10},"masterKeyWrappedUserKey":"private-nested-key"},"newMasterPasswordHash":"private-legacy-proof","key":"private-legacy-key","ignored":{"future":true}}"#;
        let request: AccountPasswordRequest<'_> = serde_json::from_str(input).unwrap();
        let authentication = request.authentication_data.as_ref().unwrap();
        let unlock = request.unlock_data.as_ref().unwrap();
        assert_eq!(authentication.kdf, unlock.kdf);
        assert!(request.master_password_hash.expose_secret() == "private-old");
        assert!(request.master_password_hint == Some("private-hint雪"));
        for value in [
            request.master_password_hash.expose_secret(),
            request.master_password_hint.unwrap(),
            authentication.salt,
            authentication
                .master_password_authentication_hash
                .expose_secret(),
            unlock.master_key_wrapped_user_key.expose_secret(),
            request
                .new_master_password_hash
                .as_ref()
                .unwrap()
                .expose_secret(),
            request.key.as_ref().unwrap().expose_secret(),
        ] {
            let pointer = value.as_ptr() as usize;
            assert!(
                (input.as_ptr() as usize..input.as_ptr() as usize + input.len()).contains(&pointer)
            );
        }
        assert!(!std::format!("{request:?}").contains("private"));
        let legacy: AccountPasswordRequest<'_> =
            serde_json::from_str(r#"["old","hint",null,null,"new","key"]"#).unwrap();
        assert!(legacy.authentication_data.is_none() && legacy.unlock_data.is_none());
        assert!(legacy.master_password_hint == Some("hint"));
        assert!(legacy.new_master_password_hash.unwrap().expose_secret() == "new");
        assert!(legacy.key.unwrap().expose_secret() == "key");
        let nested: AccountPasswordRequest<'_> = serde_json::from_str(r#"["old",null,["salt",[-7,-8,null,null],"new"],["salt",[-7,-8,null,null],"key"],null,null]"#).unwrap();
        assert!(nested.new_master_password_hash.is_none() && nested.key.is_none());
        assert!(
            nested
                .authentication_data
                .unwrap()
                .master_password_authentication_hash
                .expose_secret()
                == "new"
        );
        let empty: AccountPasswordRequest<'_> =
            serde_json::from_str(r#"["",null,null,null,"",""]"#).unwrap();
        assert!(empty.master_password_hash.expose_secret().is_empty());
        assert!(
            empty
                .new_master_password_hash
                .unwrap()
                .expose_secret()
                .is_empty()
        );
        assert!(empty.key.unwrap().expose_secret().is_empty());
    }

    #[test]
    fn account_password_wire_distinguishes_unknown_outer_aliases_and_invalid_known_schema() {
        for input in [
            r#"{"masterPasswordHash":"old"}"#,
            r#"{"masterPasswordHash":"old","masterPasswordHint":null,"authenticationData":null,"unlockData":null,"newMasterPasswordHash":null,"key":null}"#,
            r#"{"masterPasswordHash":"old","AuthenticationData":{},"UnlockData":{},"NewMasterPasswordHash":7,"Key":7}"#,
        ] {
            let request: AccountPasswordRequest<'_> = serde_json::from_str(input).unwrap();
            assert!(request.master_password_hint.is_none());
            assert!(request.authentication_data.is_none() && request.unlock_data.is_none());
            assert!(request.new_master_password_hash.is_none() && request.key.is_none());
        }
        for input in [
            "{}",
            "[]",
            r#"["old"]"#,
            r#"["old",null,null,null,"new"]"#,
            r#"["old",null,null,null,"new","key",null]"#,
            r#"{"MasterPasswordHash":"old","newMasterPasswordHash":"new","key":"key"}"#,
            r#"{"masterPasswordHash":null}"#,
            r#"{"masterPasswordHash":7}"#,
            r#"{"masterPasswordHash":"old","masterPasswordHash":"duplicate"}"#,
            r#"{"masterPasswordHash":"old","newMasterPasswordHash":7}"#,
            r#"{"masterPasswordHash":"old","masterPasswordHint":7}"#,
            r#"{"masterPasswordHash":"old","authenticationData":{},"newMasterPasswordHash":"new","key":"key"}"#,
            r#"{"masterPasswordHash":"old","unlockData":{"Salt":"s","kdf":{"kdf":0,"kdfIterations":100000},"masterKeyWrappedUserKey":"key"},"newMasterPasswordHash":"new","key":"key"}"#,
        ] {
            assert!(serde_json::from_str::<AccountPasswordRequest<'_>>(input).is_err());
        }
        let state = crate::account_password::AccountPasswordState {
            salt: "private-stored-salt",
            password_hints_allowed: true,
        };
        assert!(!std::format!("{state:?}").contains("private"));
    }

    #[test]
    fn account_kdf_wire_preserves_nested_aliases_positional_order_and_borrowing() {
        let input = r#"{"authenticationData":{"Salt":"private-salt雪","Kdf":{"kdfType":-2,"iterations":-3,"memory":4,"parallelism":5},"MasterPasswordAuthenticationHash":"private-new"},"unlockData":{"salt":"private-salt雪","kdf":{"kdf":-2,"kdfIterations":-3,"kdfMemory":4,"kdfParallelism":5},"masterKeyWrappedUserKey":"private-key"},"masterPasswordHash":"private-old","ignored":{"future":true}}"#;
        let request: AccountKdfRequest<'_> = serde_json::from_str(input).unwrap();
        assert_eq!(request.authentication_data.kdf, request.unlock_data.kdf);
        assert!(request.authentication_data.salt == "private-salt雪");
        assert!(request.master_password_hash.expose_secret() == "private-old");
        assert!(
            request
                .authentication_data
                .master_password_authentication_hash
                .expose_secret()
                == "private-new"
        );
        assert!(
            request
                .unlock_data
                .master_key_wrapped_user_key
                .expose_secret()
                == "private-key"
        );
        for value in [
            request.authentication_data.salt,
            request.master_password_hash.expose_secret(),
            request
                .authentication_data
                .master_password_authentication_hash
                .expose_secret(),
            request
                .unlock_data
                .master_key_wrapped_user_key
                .expose_secret(),
        ] {
            let pointer = value.as_ptr() as usize;
            assert!(
                (input.as_ptr() as usize..input.as_ptr() as usize + input.len()).contains(&pointer)
            );
        }
        for rendered in [
            std::format!("{request:?}"),
            std::format!("{:?}", request.authentication_data),
            std::format!("{:?}", request.unlock_data),
        ] {
            assert!(!rendered.contains("private"));
        }
        let input = r#"[["",[-2147483648,-2147483648,null,null],""],["",[-2147483648,-2147483648,null,null],""],""]"#;
        let request: AccountKdfRequest<'_> = serde_json::from_str(input).unwrap();
        assert!(request.authentication_data.salt.is_empty());
        assert!(
            request
                .authentication_data
                .master_password_authentication_hash
                .expose_secret()
                .is_empty()
        );
        assert!(
            request
                .unlock_data
                .master_key_wrapped_user_key
                .expose_secret()
                .is_empty()
        );
        assert!(request.master_password_hash.expose_secret().is_empty());
        assert_eq!(request.unlock_data.kdf.kdf, i32::MIN);
        let input = r#"{"authenticationData":{"salt":"salt","kdf":{"kdf":0,"kdfIterations":100000},"masterPasswordAuthenticationHash":"new"},"unlockData":{"salt":"salt","kdf":{"kdf":0,"kdfIterations":100000},"masterKeyWrappedUserKey":"key"},"masterPasswordHash":"old"}"#;
        assert!(serde_json::from_str::<AccountKdfRequest<'_>>(input).is_ok());
    }

    #[test]
    fn account_kdf_wire_rejects_legacy_and_registration_aliases_missing_or_duplicate_fields() {
        use std::string::String;

        let authentication = r#"{"salt":"salt","kdf":{"kdf":0,"kdfIterations":100000},"masterPasswordAuthenticationHash":"new"}"#;
        let unlock = r#"{"salt":"salt","kdf":{"kdf":0,"kdfIterations":100000},"masterKeyWrappedUserKey":"key"}"#;
        let canonical = std::format!(
            r#"{{"authenticationData":{authentication},"unlockData":{unlock},"masterPasswordHash":"old"}}"#
        );
        for invalid in [
            String::from("{}"),
            String::from("[]"),
            String::from(
                r#"{"kdf":0,"kdfIterations":100000,"key":"key","newMasterPasswordHash":"new","masterPasswordHash":"old"}"#,
            ),
            canonical.replace("authenticationData", "AuthenticationData"),
            canonical.replace("unlockData", "UnlockData"),
            canonical.replace("masterPasswordHash", "MasterPasswordHash"),
            canonical.replace("masterPasswordAuthenticationHash", "hash"),
            canonical.replace("masterKeyWrappedUserKey", "key"),
            canonical.replace(r#""unlockData":{"salt""#, r#""unlockData":{"Salt""#),
            canonical.replace(
                r#""unlockData":{"salt":"salt","kdf""#,
                r#""unlockData":{"salt":"salt","Kdf""#,
            ),
            canonical.replace(
                r#""masterPasswordHash":"old""#,
                r#""masterPasswordHash":null"#,
            ),
            canonical.replace(r#""masterPasswordHash":"old""#, r#""masterPasswordHash":7"#),
            canonical.replace(
                r#""masterPasswordHash":"old""#,
                r#""masterPasswordHash":"old","masterPasswordHash":"other""#,
            ),
            canonical.replace(
                r#""salt":"salt","kdf""#,
                r#""salt":"salt","Salt":"other","kdf""#,
            ),
            canonical.replace("100000", "2147483648"),
            std::format!(r#"[{authentication},{unlock}]"#),
            std::format!(r#"[{authentication},{unlock},"old",null]"#),
        ] {
            assert!(serde_json::from_str::<AccountKdfRequest<'_>>(&invalid).is_err());
        }
    }

    #[test]
    fn password_verification_wire_requires_only_canonical_hash_and_redacts_opaque_proofs() {
        let input = r#"{"masterPasswordHash":"private-proof雪","otp":{"ignored":true},"MasterPasswordHash":"also-ignored"}"#;
        let request: SecretVerificationRequest<'_> = serde_json::from_str(input).unwrap();
        assert!(request.master_password_hash.expose_secret() == "private-proof雪");
        let pointer = request.master_password_hash.expose_secret().as_ptr() as usize;
        assert!(
            (input.as_ptr() as usize..input.as_ptr() as usize + input.len()).contains(&pointer)
        );
        assert!(!std::format!("{request:?}").contains("private-proof"));
        for input in [r#"{"masterPasswordHash":""}"#, r#"[""]"#] {
            let request: SecretVerificationRequest<'_> = serde_json::from_str(input).unwrap();
            assert!(request.master_password_hash.expose_secret().is_empty());
        }
        for input in [
            "{}",
            "[]",
            r#"{"otp":"proof"}"#,
            r#"{"MasterPasswordHash":"proof"}"#,
            r#"{"masterPasswordHash":null}"#,
            r#"{"masterPasswordHash":1}"#,
            r#"{"masterPasswordHash":"one","masterPasswordHash":"two"}"#,
            r#"["proof","surplus"]"#,
        ] {
            assert!(serde_json::from_str::<SecretVerificationRequest<'_>>(input).is_err());
        }
    }

    #[test]
    fn password_policy_response_keeps_pascal_object_and_distinguishes_absent_from_nullable_fields()
    {
        let empty = serde_json::to_value(MasterPasswordPolicyResponse::default()).unwrap();
        assert_eq!(empty, serde_json::json!({"Object":"masterPasswordPolicy"}));
        let nullable = serde_json::to_value(MasterPasswordPolicyResponse {
            policy: Some(MasterPasswordPolicy::default()),
        })
        .unwrap();
        assert_eq!(
            nullable,
            serde_json::json!({"minComplexity":null,"minLength":null,"requireLower":false,"requireUpper":false,"requireNumbers":false,"requireSpecial":false,"enforceOnLogin":false,"Object":"masterPasswordPolicy"})
        );
        let policy = MasterPasswordPolicy {
            min_complexity: Some(u8::MAX),
            min_length: Some(u32::MAX),
            require_lower: true,
            require_upper: false,
            require_numbers: true,
            require_special: false,
            enforce_on_login: true,
        };
        let response = serde_json::to_value(MasterPasswordPolicyResponse {
            policy: Some(policy),
        })
        .unwrap();
        assert_eq!(response.as_object().unwrap().len(), 8);
        assert_eq!(response["minComplexity"], u8::MAX);
        assert_eq!(response["minLength"], u32::MAX);
        assert!(response["requireLower"] == true && response["requireUpper"] == false);
        assert!(
            response["requireNumbers"] == true
                && response["requireSpecial"] == false
                && response["enforceOnLogin"] == true
        );
        assert!(response.get("object").is_none() && response.get("policy").is_none());
    }

    #[test]
    fn registration_verification_input_borrows_raw_email_and_defers_name_limits() {
        for input in [
            r#"{"email":" opaque雪 ","name":"","unknown":true}"#,
            r#"[" opaque雪 ",""]"#,
        ] {
            let request: RegistrationVerificationRequest<'_> = serde_json::from_str(input).unwrap();
            assert_eq!(request.email, " opaque雪 ");
            assert_eq!(request.name, Some(""));
            let ptr = request.email.as_ptr() as usize;
            assert!(
                (input.as_ptr() as usize..input.as_ptr() as usize + input.len()).contains(&ptr)
            );
            assert!(!std::format!("{request:?}").contains("opaque雪"));
        }
        let request: RegistrationVerificationRequest<'_> =
            serde_json::from_str(r#"{"email":""}"#).unwrap();
        assert!(request.email.is_empty() && request.name.is_none());
        for input in [
            "{}",
            "[]",
            r#"["email"]"#,
            r#"{"email":null}"#,
            r#"{"email":"e","name":false}"#,
        ] {
            assert!(serde_json::from_str::<RegistrationVerificationRequest<'_>>(input).is_err());
        }
    }

    #[test]
    fn registration_components_keep_signed_kdf_aliases_and_borrowed_opaque_secrets() {
        let canonical =
            r#"{"kdf":-7,"kdfIterations":-2147483648,"kdfMemory":-1,"kdfParallelism":2147483647}"#;
        let aliases =
            r#"{"kdfType":-7,"iterations":-2147483648,"memory":-1,"parallelism":2147483647}"#;
        let kdf: RegistrationKdf = serde_json::from_str(canonical).unwrap();
        assert_eq!(kdf, serde_json::from_str(aliases).unwrap());
        assert_eq!(kdf.kdf_iterations, i32::MIN);
        for input in [
            r#"{"kdf":0,"kdfIterations":2147483648}"#,
            r#"{"kdf":0,"kdfIterations":-2147483649}"#,
            r#"{"kdf":0,"kdfType":1,"kdfIterations":100000}"#,
        ] {
            assert!(serde_json::from_str::<RegistrationKdf>(input).is_err());
        }
        for input in [
            r#"{"Kdf":{"kdfType":0,"iterations":100000},"Salt":"opaque雪","MasterPasswordAuthenticationHash":""}"#,
            r#"{"kdf":{"kdf":0,"kdfIterations":100000},"salt":"opaque雪","masterPasswordAuthenticationHash":""}"#,
        ] {
            let value: RegistrationAuthentication<'_> = serde_json::from_str(input).unwrap();
            assert_eq!(value.salt, "opaque雪");
            assert!(value.hash.expose_secret().is_empty());
            assert!(!std::format!("{value:?}").contains("opaque雪"));
        }
        let value: RegistrationUnlock<'_> = serde_json::from_str(r#"{"kdf":{"kdf":0,"kdfIterations":100000},"salt":"opaque雪","masterKeyWrappedUserKey":"future-key雪"}"#).unwrap();
        assert_eq!(value.key.expose_secret(), "future-key雪");
        assert!(!std::format!("{value:?}").contains("future-key"));
        // Unlock aliases are intentionally narrower than authentication aliases.
        assert!(
            serde_json::from_str::<RegistrationUnlock<'_>>(
                r#"{"Kdf":{"kdf":0,"kdfIterations":100000},"Salt":"salt","key":"key"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn registration_response_serialization_exposes_only_the_explicit_token_or_finish_marker() {
        struct OpaqueToken(&'static str); // No Debug or Serialize implementation required.
        impl AsRef<str> for OpaqueToken {
            fn as_ref(&self) -> &str {
                self.0
            }
        }
        let response = RegistrationVerificationToken::new(OpaqueToken("private-test-token\0雪"));
        assert!(!std::format!("{response:?}").contains("private-test-token"));
        assert!(response.expose_token() == "private-test-token\0雪");
        assert!(
            serde_json::to_value(&response).unwrap() == serde_json::json!("private-test-token\0雪")
        );
        assert_eq!(
            serde_json::to_value(RegistrationFinishResponse).unwrap(),
            serde_json::json!({"object":"registerFinish"})
        );
    }

    #[test]
    fn auth_request_login_input_borrows_opaque_proof_and_preserves_absence_and_form_values() {
        let input = r#"{"grant_type":"password","password":"opaque雪","authRequest":"raw-request","client_id":"cli","scope":"api offline_access","username":" ALICE@example.test ","deviceIdentifier":"","deviceName":" ","deviceType":"nonnumeric","ignored":true}"#;
        let request: AuthRequestLoginRequest<'_> = serde_json::from_str(input).unwrap();
        assert_eq!(
            request.password.as_ref().unwrap().expose_secret(),
            "opaque雪"
        );
        assert_eq!(request.auth_request, Some("raw-request"));
        assert_eq!(request.username, Some(" ALICE@example.test "));
        assert_eq!(request.device_identifier, Some(""));
        assert_eq!(request.device_name, Some(" "));
        assert_eq!(request.device_type, Some("nonnumeric"));
        let proof_ptr = request.password.as_ref().unwrap().expose_secret().as_ptr() as usize;
        assert!(
            (input.as_ptr() as usize..input.as_ptr() as usize + input.len()).contains(&proof_ptr)
        );
        assert!(!std::format!("{request:?}").contains("opaque雪"));
        for input in [
            "{}",
            r#"{"password":null,"authRequest":null,"deviceIdentifier":null}"#,
        ] {
            let request: AuthRequestLoginRequest<'_> = serde_json::from_str(input).unwrap();
            assert!(request.password.is_none());
            assert!(request.auth_request.is_none());
            assert!(request.device_identifier.is_none());
        }
        let request: AuthRequestLoginRequest<'_> = serde_json::from_str(
            r#"{"password":"","device_identifier":"","device_name":"","device_type":""}"#,
        )
        .unwrap();
        assert_eq!(request.password.as_ref().unwrap().expose_secret(), "");
        assert_eq!(request.device_identifier, Some(""));
        assert_eq!(request.device_name, Some(""));
        assert_eq!(request.device_type, Some(""));
        for input in [
            r#"{"password":123}"#,
            r#"{"authRequest":false}"#,
            r#"{"username":[]}"#,
            r#"{"deviceType":14}"#,
            r#"{"password":"first","password":"second"}"#,
            r#"{"deviceIdentifier":"first","device_identifier":"second"}"#,
        ] {
            assert!(serde_json::from_str::<AuthRequestLoginRequest<'_>>(input).is_err());
        }
    }

    #[test]
    fn auth_request_update_wire_keeps_required_opaque_fields_optional_hash_and_positional_order() {
        for (input, device, key, hash, approved) in [
            (r#"["device","key",null,true]"#, "device", "key", None, true),
            (r#"["","","",false]"#, "", "", Some(""), false),
            (
                r#"{"deviceIdentifier":"device","key":"opaque雪","requestApproved":false,"ignored":true}"#,
                "device",
                "opaque雪",
                None,
                false,
            ),
            (
                r#"{"deviceIdentifier":"device","key":"key","masterPasswordHash":"hash","requestApproved":true}"#,
                "device",
                "key",
                Some("hash"),
                true,
            ),
        ] {
            let value: AuthRequestUpdateRequest<'_> = serde_json::from_str(input).unwrap();
            assert_eq!(
                (
                    value.device_identifier,
                    value.key,
                    value.master_password_hash,
                    value.request_approved
                ),
                (device, key, hash, approved)
            );
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!({"deviceIdentifier":device,"key":key,"masterPasswordHash":hash,"requestApproved":approved})
            );
        }
        for input in [
            "{}",
            "[]",
            r#"["d","k"]"#,
            r#"["d","k",true]"#,
            r#"["d","k",null,true,0]"#,
            r#"{"deviceIdentifier":null,"key":"k","requestApproved":true}"#,
            r#"{"deviceIdentifier":"d","key":null,"requestApproved":false}"#,
            r#"{"deviceIdentifier":"d","key":"k"}"#,
            r#"{"deviceIdentifier":"d","key":"k","requestApproved":null}"#,
            r#"{"deviceIdentifier":"d","key":"k","requestApproved":1}"#,
            r#"{"deviceIdentifier":"d","key":"k","masterPasswordHash":false,"requestApproved":true}"#,
            r#"{"deviceIdentifier":"d","key":"k","requestApproved":true,"requestApproved":false}"#,
        ] {
            assert!(serde_json::from_str::<AuthRequestUpdateRequest<'_>>(input).is_err());
        }
        let value = AuthRequestUpdateRequest {
            device_identifier: "hidden-device\0雪",
            key: "hidden-key\"",
            master_password_hash: Some("hidden-hash\0雪"),
            request_approved: false,
        };
        let projected = serde_json::to_value(value).unwrap();
        assert_eq!(projected["key"], value.key);
        assert_eq!(
            projected["masterPasswordHash"],
            value.master_password_hash.unwrap()
        );
        assert!(!std::format!("{value:?}").contains("hidden"));
    }

    #[test]
    fn auth_request_create_wire_keeps_four_required_opaque_strings_and_positional_order() {
        let input = r#"["code","device","email","key"]"#;
        let request: AuthRequestCreateRequest<'_> = serde_json::from_str(input).unwrap();
        assert_eq!(
            (
                request.access_code,
                request.device_identifier,
                request.email,
                request.public_key
            ),
            ("code", "device", "email", "key")
        );
        let empty: AuthRequestCreateRequest<'_> = serde_json::from_str(
            r#"{"accessCode":"","deviceIdentifier":"","email":"","publicKey":"","ignored":true}"#,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(empty).unwrap(),
            serde_json::json!({"accessCode":"","deviceIdentifier":"","email":"","publicKey":""})
        );
        for input in [
            "{}",
            "[]",
            r#"["a","b","c"]"#,
            r#"["a","b","c","d",null]"#,
            r#"{"accessCode":null,"deviceIdentifier":"d","email":"e","publicKey":"p"}"#,
            r#"{"accessCode":"a","deviceIdentifier":7,"email":"e","publicKey":"p"}"#,
            r#"{"accessCode":"a","deviceIdentifier":"d","email":false,"publicKey":"p"}"#,
            r#"{"accessCode":"a","deviceIdentifier":"d","email":"e","publicKey":[]}"#,
            r#"{"accessCode":"a","accessCode":"b","deviceIdentifier":"d","email":"e","publicKey":"p"}"#,
        ] {
            assert!(serde_json::from_str::<AuthRequestCreateRequest<'_>>(input).is_err());
        }
        let opaque = AuthRequestCreateRequest {
            access_code: "hidden-code\0雪",
            public_key: "future:\"hidden-key\n",
            ..request
        };
        let encoded = serde_json::to_value(opaque).unwrap();
        assert_eq!(encoded["accessCode"], opaque.access_code);
        assert_eq!(encoded["publicKey"], opaque.public_key);
        assert!(!std::format!("{opaque:?}").contains("hidden"));
    }

    #[test]
    fn auth_request_response_projections_distinguish_creation_false_from_stored_null_and_hide_internal_fields()
     {
        use crate::auth_requests::{AuthRequestContext, AuthRequestRecord};
        let record = AuthRequestRecord {
            id: "visible-id",
            owner_id: "hidden-owner",
            request_device_identifier: "hidden-device",
            device_type: 25,
            request_ip: "192.0.2.1",
            access_code: "hidden-code",
            public_key: "visible-public-key",
            key: Some("explicit-key"),
            master_password_hash: Some("explicit-hash"),
            approved: None,
            creation_date: "created",
            response_date: Some("responded"),
        };
        let created = AuthRequestResponse::created(record, "configured-origin");
        let value = serde_json::to_value(&created).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"id":"visible-id","publicKey":"visible-public-key","requestDeviceType":"Linux CLI","requestIpAddress":"192.0.2.1","key":null,"masterPasswordHash":null,"creationDate":"created","responseDate":null,"requestApproved":false,"origin":"configured-origin","object":"auth-request"})
        );
        let stored =
            serde_json::to_value(AuthRequestResponse::stored(record, "configured-origin")).unwrap();
        assert_eq!(stored.as_object().unwrap().len(), 11);
        assert!(stored["requestApproved"].is_null());
        assert_eq!(stored["key"], "explicit-key");
        assert_eq!(stored["masterPasswordHash"], "explicit-hash");
        assert_eq!(stored["responseDate"], "responded");
        let records = [
            record,
            AuthRequestRecord {
                approved: Some(false),
                ..record
            },
            AuthRequestRecord {
                approved: Some(true),
                ..record
            },
        ];
        let list = AuthRequestListResponse::new(records.as_slice(), "configured-origin");
        let projected = serde_json::to_value(&list).unwrap();
        assert_eq!(projected.as_object().unwrap().len(), 3);
        assert_eq!(projected["data"], serde_json::json!([stored]));
        assert!(projected["continuationToken"].is_null());
        assert_eq!(projected["object"], "list");
        assert!(!serde_json::to_string(&created).unwrap().contains("hidden"));
        let context = AuthRequestContext {
            device_type: 25,
            request_ip: "hidden-ip",
            origin: "hidden-origin",
        };
        let debug = std::format!("{record:?} {context:?} {created:?} {list:?}");
        assert!(!debug.contains("hidden"));
        assert!(!debug.contains("explicit"));
    }

    #[test]
    fn push_token_requests_require_one_opaque_string_and_redact_debug() {
        for (input, expected) in [
            (r#"{"pushToken":""}"#, ""),
            (
                r#"{"pushToken":"opaque雪","ignored":{"value":true}}"#,
                "opaque雪",
            ),
            (r#"["positional"]"#, "positional"),
        ] {
            let request: DevicePushTokenRequest<'_> = serde_json::from_str(input).unwrap();
            assert_eq!(request.push_token, expected);
            assert_eq!(
                serde_json::to_value(request).unwrap(),
                serde_json::json!({"pushToken":expected})
            );
        }
        for input in [
            "{}",
            "[]",
            "null",
            r#"{"pushToken":null}"#,
            r#"{"pushToken":4}"#,
            r#"{"pushToken":false}"#,
            r#"{"PushToken":"ignored"}"#,
            r#"{"pushToken":"a","pushToken":"b"}"#,
            r#"["a",null]"#,
            "{",
        ] {
            assert!(serde_json::from_str::<DevicePushTokenRequest<'_>>(input).is_err());
        }
        let token = "hidden-token\0\"雪";
        let request = DevicePushTokenRequest { push_token: token };
        assert_eq!(serde_json::to_value(request).unwrap()["pushToken"], token);
        assert!(!std::format!("{request:?}").contains("hidden"));
    }

    #[test]
    fn device_wire_projections_keep_exact_nulls_fields_and_redacted_debug() {
        use crate::devices::{DeviceRecord, DeviceRegistration, PendingDeviceAuthRequest};
        let record = DeviceRecord {
            owner_id: "hidden-owner",
            identifier: "hidden-identifier",
            name: "hidden-name\"雪\0",
            device_type: 14,
            creation_date: "hidden-creation",
            pending_auth_request: Some(PendingDeviceAuthRequest {
                id: "hidden-pending",
                creation_date: "hidden-pending-time",
            }),
        };
        let single = DeviceResponse::new(record);
        let base = serde_json::to_value(&single).unwrap();
        assert_eq!(
            base,
            serde_json::json!({"id":record.identifier,"identifier":record.identifier,"name":record.name,"type":14,"creationDate":record.creation_date,"isTrusted":false,"object":"device"})
        );
        let records = [
            record,
            DeviceRecord {
                pending_auth_request: None,
                ..record
            },
        ];
        let list = DeviceListResponse::new(records.as_slice());
        let value = serde_json::to_value(&list).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["object"], "list");
        assert!(value["continuationToken"].is_null());
        for device in value["data"].as_array().unwrap() {
            assert_eq!(device.as_object().unwrap().len(), 10);
            for (key, expected) in base.as_object().unwrap() {
                assert_eq!(&device[key], expected);
            }
            assert!(device["encryptedPublicKey"].is_null());
            assert!(device["encryptedUserKey"].is_null());
            assert!(device.get("ownerId").is_none());
        }
        assert_eq!(
            value["data"][0]["devicePendingAuthRequest"],
            serde_json::json!({"id":"hidden-pending","creationDate":"hidden-pending-time"})
        );
        assert!(value["data"][1]["devicePendingAuthRequest"].is_null());
        for known in [false, true] {
            assert_eq!(
                serde_json::to_value(KnownDeviceResponse(known)).unwrap(),
                known
            );
        }
        let request = KnownDeviceRequest {
            email: "hidden-email",
            identifier: "hidden-id",
        };
        let registration = DeviceRegistration {
            identifier: "hidden-id",
            name: "hidden-name",
            device_type: 14,
        };
        let debug = std::format!(
            "{request:?} {registration:?} {record:?} {:?} {single:?} {list:?}",
            record.pending_auth_request.unwrap()
        );
        assert!(!debug.contains("hidden"));
    }

    use std::string::ToString;
    #[test]
    fn domain_request_fields_keep_positional_order_null_clears_and_signed_i32_bounds() {
        use crate::domains::DomainSettingsData;
        for input in [
            "{}",
            r#"{"equivalentDomains":null,"excludedGlobalEquivalentDomains":null}"#,
            "[null,null]",
        ] {
            let request: DomainSettingsRequest<'_, 0, 0, 0> = serde_json::from_str(input).unwrap();
            assert_eq!(request.excluded_global_count(), 0);
            assert_eq!(request.equivalent_group_count(), 0);
        }
        let input = r#"[[-2147483648,2147483647,-1,-1],[["opaque","opaque"],[]]]"#;
        let request: DomainSettingsRequest<'_, 4, 2, 2> = serde_json::from_str(input).unwrap();
        assert_eq!(request.excluded_global(0), Some(i32::MIN));
        assert_eq!(request.excluded_global(1), Some(i32::MAX));
        assert_eq!(request.excluded_global(2), request.excluded_global(3));
        assert_eq!(request.equivalent_domain_count(1), Some(0));
        assert_eq!(request.equivalent_domain(0, 1), Some("opaque"));
        assert!(!std::format!("{request:?}").contains("opaque"));
        for input in [
            "[]",
            "[null]",
            r#"{"excludedGlobalEquivalentDomains":[2147483648]}"#,
            r#"{"excludedGlobalEquivalentDomains":[-2147483649]}"#,
            r#"{"excludedGlobalEquivalentDomains":[1.5]}"#,
            r#"{"excludedGlobalEquivalentDomains":["1"]}"#,
            r#"{"equivalentDomains":[null]}"#,
            r#"{"equivalentDomains":[[null]]}"#,
            r#"{"equivalentDomains":[[1]]}"#,
            r#"{"equivalentDomains":[],"equivalentDomains":[]}"#,
        ] {
            assert!(serde_json::from_str::<DomainSettingsRequest<'_, 4, 2, 2>>(input).is_err());
        }
        assert_eq!(
            serde_json::from_str::<DomainSettingsRequest<'_, 0, 0, 0>>("[]")
                .unwrap_err()
                .classify(),
            serde_json::error::Category::Data
        );
        assert_eq!(
            serde_json::from_str::<DomainSettingsRequest<'_, 0, 0, 0>>("[null,null,0]")
                .unwrap_err()
                .classify(),
            serde_json::error::Category::Syntax
        );
    }

    #[test]
    fn domain_decoder_capacities_are_independent_and_strings_remain_opaque() {
        use crate::domains::DomainSettingsData;
        let input = r#"{"excludedGlobalEquivalentDomains":[9,9],"equivalentDomains":[["not a domain","not a domain"],[]]}"#;
        let request: DomainSettingsRequest<'_, 2, 2, 2> = serde_json::from_str(input).unwrap();
        assert_eq!(serde_json::to_string(&request).unwrap(), input);
        assert!(serde_json::from_str::<DomainSettingsRequest<'_, 1, 2, 2>>(input).is_err());
        assert!(serde_json::from_str::<DomainSettingsRequest<'_, 2, 1, 2>>(input).is_err());
        assert!(serde_json::from_str::<DomainSettingsRequest<'_, 2, 2, 1>>(input).is_err());
        let start = input.as_ptr() as usize;
        let domain = request.equivalent_domain(0, 0).unwrap();
        assert!((start..start + input.len()).contains(&(domain.as_ptr() as usize)));
        let document = serde_json::json!({"equivalentDomains":[["","雪\0\"\n","  MIXED.Case  "]]});
        let request = DomainSettingsRequest::<'_, 0, 1, 3>::deserialize(&document).unwrap();
        assert_eq!(request.equivalent_domain(0, 1), Some("雪\0\"\n"));
        assert_eq!(request.equivalent_domain(0, 2), Some("  MIXED.Case  "));
        assert_eq!(
            serde_json::to_value(DomainSettingsUpdateResponse {}).unwrap(),
            serde_json::json!({})
        );
    }

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
