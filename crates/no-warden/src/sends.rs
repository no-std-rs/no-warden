//! Personal Sends, with opaque payloads and provider-owned storage/crypto/clocks.
//!
//! HTTP schema decoding and payload display normalization belong to adapters. SendData
//! accepts arbitrary non-null JSON text data; providers retain it after removing the exact
//! root `response` key. They supply the upstream-normalized display payload separately.
//! File bytes, multipart decoding, cryptography, quotas and notifications stay external.

use core::fmt;
use serde::Serialize;

/// Serialization bound re-export for allocation-free provider implementations.
pub use serde::Serialize as SendPayload;

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    identity::Secret,
    service::require_owner,
    wire::{
        FileSendRequest, SendAccessTokenRequest, SendFileDownloadResponse, SendFileUploadResponse,
        SendListResponse, SendOwnerResponse, SendRecipientResponse, TextSendRequest,
    },
};

pub const SEND_DELETION_WINDOW_NANOS: i128 = 31 * 24 * 60 * 60 * 1_000_000_000;
pub const MAX_SEND_FILE_BYTES: u64 = 525 * 1024 * 1024;

/// Parsed adapter time; no clock or timestamp parser is linked by the core.
#[derive(Clone, Copy, Debug)]
pub struct SendContext {
    pub now_unix_nanos: i128,
}

/// Preserve number/string conversion until its source-ordered business validation step.
#[derive(Clone, Copy)]
pub enum SendNumber<'a> {
    Integer(i64),
    String(&'a str),
}
impl fmt::Debug for SendNumber<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SendNumber([REDACTED])")
    }
}
impl SendNumber<'_> {
    pub fn into_i64(self) -> Result<i64, ApiError> {
        match self {
            Self::Integer(value) => Ok(value),
            Self::String(value) => value
                .parse()
                .map_err(|_| ApiError::invalid("fileLength", "Can't convert to number")),
        }
    }
    pub fn into_i32(self) -> Result<i32, ApiError> {
        match self {
            Self::Integer(value) => i32::try_from(value)
                .map_err(|_| ApiError::invalid("maxAccessCount", "Number does not fit in i32")),
            Self::String(value) => value
                .parse()
                .map_err(|_| ApiError::invalid("maxAccessCount", "Can't convert to number")),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SendPolicy {
    pub can_modify: bool,
    pub can_hide_email: bool,
}

/// Trusted stored metadata; these timestamps/counts must not come from caller authority.
#[derive(Clone, Copy)]
pub struct SendState<'a> {
    pub id: &'a str,
    pub owner_id: &'a str,
    pub kind: i32,
    pub disabled: bool,
    pub max_access_count: Option<i32>,
    pub access_count: i32,
    pub expiration_ns: Option<i128>,
    pub deletion_ns: i128,
    pub password_protected: bool,
}
impl fmt::Debug for SendState<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendState").finish_non_exhaustive()
    }
}
impl SendState<'_> {
    pub fn is_accessible(&self, context: &SendContext) -> bool {
        !self.disabled
            && self
                .expiration_ns
                .is_none_or(|expiration| context.now_unix_nanos < expiration)
            && context.now_unix_nanos < self.deletion_ns
    }
}

/// Internal Send projection. Password hashes are the owner-visible encoded hash,
/// never the supplied password proof. The legacy `text` slot contains provider-normalized
/// text or file display data, selected by trusted stored kind in response wrappers. This
/// can differ from stored raw data. Only explicit owner/recipient wrappers serialize it.
pub struct SendRecord<'a, P: Serialize> {
    pub id: &'a str,
    pub owner_id: &'a str,
    pub access_id: &'a str,
    pub name: &'a str,
    pub notes: Option<&'a str>,
    pub text: P,
    pub key: &'a str,
    pub max_access_count: Option<i32>,
    pub access_count: i32,
    pub password_hash: Option<&'a str>,
    pub disabled: bool,
    pub hide_email: Option<bool>,
    pub revision_date: &'a str,
    pub expiration_date: Option<&'a str>,
    pub deletion_date: &'a str,
    pub creator_identifier: Option<&'a str>,
}
impl<P: Serialize> fmt::Debug for SendRecord<'_, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendRecord").finish_non_exhaustive()
    }
}

/// Stable indexed provider view. Every index below len must exist, and both entries and
/// count must remain stable through validation and response serialization.
pub trait SendListData<'a> {
    type Payload: Serialize;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn get(&self, index: usize) -> Option<SendRecord<'a, Self::Payload>>;
    /// Stored type for this entry. Existing text-only providers retain their default.
    fn kind(&self, index: usize) -> Option<i32> {
        (index < self.len()).then_some(0)
    }
}

/// Trusted decoded canonical file metadata, independent of opaque display normalization.
/// Adapters return None for malformed/non-object metadata instead of treating it as a
/// provider failure. Filename values are opaque and must not be normalized or decrypted.
#[derive(Clone, Copy)]
pub struct SendFileMetadata<'a> {
    pub file_id: &'a str,
    pub file_name: &'a str,
    pub file_size: u64,
}
impl fmt::Debug for SendFileMetadata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendFileMetadata").finish_non_exhaustive()
    }
}

/// Provider-calculated quota after accounting for existing declared file sizes.
/// None uses the protocol ceiling; zero remaining bytes rejects even a zero-byte file.
#[derive(Clone, Copy, Debug)]
pub struct SendFileQuota {
    pub uploads_enabled: bool,
    pub remaining_bytes: Option<u64>,
}
impl Default for SendFileQuota {
    fn default() -> Self {
        Self {
            uploads_enabled: true,
            remaining_bytes: None,
        }
    }
}

/// Measured multipart facts. The version exception flag is supplied only after the
/// adapter identifies one of the protocol's retained CLI versions; it is not client data.
#[derive(Clone, Copy)]
pub struct SendFileUpload<'a> {
    pub file_name: Option<&'a str>,
    pub file_size: u64,
    pub allow_legacy_filename_suffix: bool,
}
impl fmt::Debug for SendFileUpload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendFileUpload").finish_non_exhaustive()
    }
}

/// File reservation/update plan. Update ignores supplied file and length entirely and
/// preserves the stored file ID, metadata, bytes, creation time and access count.
pub struct ValidatedFileSend<'request, 'a, P: ?Sized> {
    request: &'request FileSendRequest<'a, P>,
    maximum: Option<i32>,
    length: Option<u64>,
    creating: bool,
}
impl<P: ?Sized> fmt::Debug for ValidatedFileSend<'_, '_, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedFileSend").finish_non_exhaustive()
    }
}
impl<'request, 'a, P: ?Sized> ValidatedFileSend<'request, 'a, P> {
    pub const fn request(&self) -> &'request FileSendRequest<'a, P> {
        self.request
    }
    pub const fn common(&self) -> &'request TextSendRequest<'a, P> {
        &self.request.common
    }
    pub const fn max_access_count(&self) -> Option<i32> {
        self.maximum
    }
    pub const fn file_length(&self) -> Option<u64> {
        self.length
    }
    pub fn password_change(&self) -> SendPasswordChange<'_, 'a> {
        match self.request.common.password.as_ref() {
            Some(password) => SendPasswordChange::Set(password),
            None if self.creating => SendPasswordChange::Clear,
            None => SendPasswordChange::Preserve,
        }
    }
}

/// Byte publication authority. The staged byte source must have this measured size.
#[derive(Clone, Copy)]
pub struct ValidatedSendFileUpload<'a> {
    id: &'a str,
    file_id: &'a str,
    file_size: u64,
}
impl fmt::Debug for ValidatedSendFileUpload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedSendFileUpload")
            .finish_non_exhaustive()
    }
}
impl<'a> ValidatedSendFileUpload<'a> {
    pub const fn id(&self) -> &'a str {
        self.id
    }
    pub const fn file_id(&self) -> &'a str {
        self.file_id
    }
    pub const fn file_size(&self) -> u64 {
        self.file_size
    }
}

/// Either an authorized URL issuance after count reservation or a verified raw-download
/// capability. Raw binary authorization deliberately does not consult current Send rows.
#[derive(Clone, Copy)]
pub struct AuthorizedSendFileDownload<'a> {
    id: &'a str,
    file_id: &'a str,
}
impl fmt::Debug for AuthorizedSendFileDownload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedSendFileDownload")
            .finish_non_exhaustive()
    }
}
impl<'a> AuthorizedSendFileDownload<'a> {
    pub const fn id(&self) -> &'a str {
        self.id
    }
    pub const fn file_id(&self) -> &'a str {
        self.file_id
    }
    pub const fn expires_in(&self) -> u32 {
        120
    }
}

pub enum SendPasswordChange<'s, 'a> {
    Clear,
    Preserve,
    Set(&'s Secret<'a>),
}
impl fmt::Debug for SendPasswordChange<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SendPasswordChange([REDACTED])")
    }
}

/// Source-validated create/update, including late signed-number conversion and the
/// distinction between omitted create password (clear) and omitted update password (keep).
pub struct ValidatedTextSend<'request, 'a, P: ?Sized> {
    request: &'request TextSendRequest<'a, P>,
    maximum: Option<i32>,
    creating: bool,
}
impl<P: ?Sized> fmt::Debug for ValidatedTextSend<'_, '_, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedTextSend").finish_non_exhaustive()
    }
}
impl<'request, 'a, P: ?Sized> ValidatedTextSend<'request, 'a, P> {
    pub const fn request(&self) -> &'request TextSendRequest<'a, P> {
        self.request
    }
    pub const fn max_access_count(&self) -> Option<i32> {
        self.maximum
    }
    pub fn password_change(&self) -> SendPasswordChange<'_, 'a> {
        match self.request.password.as_ref() {
            Some(password) => SendPasswordChange::Set(password),
            None if self.creating => SendPasswordChange::Clear,
            None => SendPasswordChange::Preserve,
        }
    }
}

/// Recipient state passed only after scoped proof and current availability checks.
/// The provider must atomically enforce current maxAccessCount when incrementing.
pub struct ValidatedSendAccess<'a> {
    id: &'a str,
    now: i128,
}
impl fmt::Debug for ValidatedSendAccess<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedSendAccess")
            .finish_non_exhaustive()
    }
}
impl<'a> ValidatedSendAccess<'a> {
    pub const fn id(&self) -> &'a str {
        self.id
    }
    pub const fn now_unix_nanos(&self) -> i128 {
        self.now
    }
}

/// Scoped recipient-token issuance authority; no owner-vault/session authority is granted.
pub struct AuthorizedSendAccessGrant<I: AsRef<str>> {
    id: I,
}
impl<I: AsRef<str>> fmt::Debug for AuthorizedSendAccessGrant<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedSendAccessGrant")
            .finish_non_exhaustive()
    }
}
impl<I: AsRef<str>> AuthorizedSendAccessGrant<I> {
    pub fn id(&self) -> &str {
        self.id.as_ref()
    }
    pub const fn scope(&self) -> &'static str {
        "api.send.access"
    }
    pub const fn expires_in(&self) -> u32 {
        120
    }
    pub const fn allows_refresh(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendAccessError {
    Api(ApiError),
    InvalidSend,
    PasswordRequired,
    InvalidPassword,
}
impl From<ApiError> for SendAccessError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}
impl fmt::Display for SendAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Api(error) => error.message,
            Self::InvalidSend => "Send does not exist or is no longer available",
            Self::PasswordRequired => "Password required",
            Self::InvalidPassword => "Invalid Send password",
        })
    }
}
impl core::error::Error for SendAccessError {}

pub type SendLookup<T, E> = Result<Option<T>, E>;

/// Opt-in personal TEXT Send persistence and recipient-verification boundary.
///
/// Hold an operation lock/transaction through each service and response projection.
/// Date strings/JSON schema, Unicode normalization, UUID/access-ID decoding, passwords,
/// secure IDs, clocks and token signing remain external. Existing providers may remain
/// text-only; FileSendStorage providers also return file data and trusted list kinds.
/// Preserve arbitrary raw data JSON after removing exactly root `response`.
/// Display payloads follow pinned LowerCase<Value>/size normalization, including null
/// projection for scalar/array roots. Owner listing includes expired/disabled entries.
/// All provider records/counts must remain stable while borrowed by a response.
///
/// Create assigns fresh ID/access ID/timestamps/count=0; update preserves ID/creation/count.
/// Apply the plan's password effect exactly (opaque Some empty still sets protection).
/// Never trust request IDs/owner/counters. Remove-password clears all password verifier
/// state. Mutations preserve unrelated account/vault/foreign state and advance Send/account
/// revisions, including repeated remove-password. Each successful write should commit its
/// complete local state or fail without a partial write; notification/response boundaries
/// remain adapter-owned, and this does not assert whole-operation upstream atomicity.
///
/// resolve_send_access_id decodes base64url-no-pad UUID access IDs into owned canonical IDs.
/// verify_send_password verifies the exact client-derived opaque proof with the password
/// provider, without logging or assuming its format. Token issuance never increments count.
/// verify_send_access_token must verify recipient scope/issuer/authenticity/time, returning
/// only its owned Send ID; ordinary owner access tokens cannot satisfy it. Existing scoped
/// capabilities survive Send password changes/removal, but access rechecks current disabled,
/// deadline and count state. JWT/time/30-second-leeway policy belongs to the adapter.
///
/// register_send_access performs an atomic conditional increment below current max count,
/// updates Send revision and owner revision, and returns false if the count is exhausted.
/// Upstream can advance owner revision even when this CAS returns false: do not infer a
/// no-mutation guarantee from denial. Availability failures before this hook do not write.
/// Successful recipient access also advances owner revision during response processing.
/// File Sends, SMTP/organizations, token rate limiting, expiry cron and notifications remain
/// outside this text service; adapters must enforce required configured policies themselves.
pub trait SendStorage: Storage {
    type SendId: AsRef<str>;
    type Payload<'a>: Serialize
    where
        Self: 'a;
    type Sends<'a>: SendListData<'a, Payload = Self::Payload<'a>>
    where
        Self: 'a;

    fn send_policy(&mut self, owner: &str) -> Result<SendPolicy, Self::Error>;
    fn send_state(&mut self, id: &str) -> SendLookup<SendState<'_>, Self::Error>;
    fn send(&mut self, id: &str) -> SendLookup<SendRecord<'_, Self::Payload<'_>>, Self::Error>;
    fn sends(&mut self, owner: &str) -> Result<Self::Sends<'_>, Self::Error>;
    fn create_text_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        plan: &ValidatedTextSend<'_, '_, P>,
    ) -> Result<Self::SendId, Self::Error>;
    fn update_text_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        id: &str,
        plan: &ValidatedTextSend<'_, '_, P>,
    ) -> Result<(), Self::Error>;
    fn delete_send(&mut self, owner: &str, id: &str) -> Result<(), Self::Error>;
    fn remove_send_password(&mut self, owner: &str, id: &str) -> Result<(), Self::Error>;
    fn resolve_send_access_id(
        &mut self,
        access_id: &str,
    ) -> Result<Option<Self::SendId>, Self::Error>;
    fn verify_send_password(
        &mut self,
        id: &str,
        password: &Secret<'_>,
    ) -> Result<bool, Self::Error>;
    fn verify_send_access_token(
        &mut self,
        token: &Secret<'_>,
    ) -> Result<Option<Self::SendId>, Self::Error>;
    fn register_send_access(&mut self, plan: &ValidatedSendAccess<'_>)
    -> Result<bool, Self::Error>;
}

/// Opt-in modern file-Send storage. Existing text providers need no implementation.
///
/// Hold the operation lock through validation, commit and borrowed projection. Quota
/// accounting uses declared sizes and remains provider-owned; the core enforces the
/// absolute ceiling and the returned remaining capacity. Reservation creates a fresh
/// 64-character lowercase hexadecimal file ID, adds id/size/sizeName to an object
/// payload only, and keeps other payload values opaque. Non-object data can be reserved
/// but cannot pass canonical metadata decoding for an upload or download URL.
///
/// Upload publishes staged encrypted bytes after exact measured size and filename
/// validation. Preserve metadata and Send revision; advance owner revision. A failure
/// retains its reservation. Atomic create-only publication returns true on creation,
/// false if bytes already exist (without replacing them or advancing revision).
/// Updates preserve file metadata and bytes, applying only common fields/password effect.
/// Deletion/account deletion remove stored bytes; personal cipher purge retains Sends.
///
/// Generic file access touches owner revision without changing count or Send revision.
/// URL issuance first reserves count using SendStorage::register_send_access, even if
/// bytes are not uploaded. A missing blob later returns 404 without undoing that count.
/// URL/token creation can fail after reservation; no whole-response rollback is promised.
/// Scoped raw-download tokens use the Send issuer and compound id/file_id subject,
/// 120-second lifetime and adapter-controlled time/leeway/crypto. Verification checks
/// authenticity, purpose, both exact identifiers and time, without row/count/password or
/// availability checks. Only the binary adapter decides whether the bytes still exist.
pub trait FileSendStorage: SendStorage {
    type Url: AsRef<str>;
    fn file_send_quota(&mut self, owner: &str) -> Result<SendFileQuota, Self::Error>;
    fn create_file_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        plan: &ValidatedFileSend<'_, '_, P>,
    ) -> Result<Self::SendId, Self::Error>;
    fn update_file_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        id: &str,
        plan: &ValidatedFileSend<'_, '_, P>,
    ) -> Result<(), Self::Error>;
    fn send_file_metadata(&mut self, id: &str) -> SendLookup<SendFileMetadata<'_>, Self::Error>;
    fn commit_send_file_upload(
        &mut self,
        owner: &str,
        plan: &ValidatedSendFileUpload<'_>,
    ) -> Result<bool, Self::Error>;
    fn touch_file_send_access(&mut self, plan: &ValidatedSendAccess<'_>)
    -> Result<(), Self::Error>;
    fn send_file_upload_url(&mut self, id: &str) -> Result<Self::Url, Self::Error>;
    fn send_file_download_url(
        &mut self,
        grant: &AuthorizedSendFileDownload<'_>,
    ) -> Result<Self::Url, Self::Error>;
    fn verify_send_file_download(
        &mut self,
        id: &str,
        file_id: &str,
        proof: &Secret<'_>,
    ) -> Result<bool, Self::Error>;
}

impl<T: FileSendStorage + ?Sized> FileSendStorage for &mut T {
    type Url = T::Url;
    fn file_send_quota(&mut self, owner: &str) -> Result<SendFileQuota, Self::Error> {
        (**self).file_send_quota(owner)
    }
    fn create_file_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        plan: &ValidatedFileSend<'_, '_, P>,
    ) -> Result<Self::SendId, Self::Error> {
        (**self).create_file_send(owner, plan)
    }
    fn update_file_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        id: &str,
        plan: &ValidatedFileSend<'_, '_, P>,
    ) -> Result<(), Self::Error> {
        (**self).update_file_send(owner, id, plan)
    }
    fn send_file_metadata(&mut self, id: &str) -> SendLookup<SendFileMetadata<'_>, Self::Error> {
        (**self).send_file_metadata(id)
    }
    fn commit_send_file_upload(
        &mut self,
        owner: &str,
        plan: &ValidatedSendFileUpload<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).commit_send_file_upload(owner, plan)
    }
    fn touch_file_send_access(
        &mut self,
        plan: &ValidatedSendAccess<'_>,
    ) -> Result<(), Self::Error> {
        (**self).touch_file_send_access(plan)
    }
    fn send_file_upload_url(&mut self, id: &str) -> Result<Self::Url, Self::Error> {
        (**self).send_file_upload_url(id)
    }
    fn send_file_download_url(
        &mut self,
        grant: &AuthorizedSendFileDownload<'_>,
    ) -> Result<Self::Url, Self::Error> {
        (**self).send_file_download_url(grant)
    }
    fn verify_send_file_download(
        &mut self,
        id: &str,
        file_id: &str,
        proof: &Secret<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).verify_send_file_download(id, file_id, proof)
    }
}

impl<T: SendStorage + ?Sized> SendStorage for &mut T {
    type SendId = T::SendId;
    type Payload<'a>
        = T::Payload<'a>
    where
        Self: 'a;
    type Sends<'a>
        = T::Sends<'a>
    where
        Self: 'a;
    fn send_policy(&mut self, owner: &str) -> Result<SendPolicy, Self::Error> {
        (**self).send_policy(owner)
    }
    fn send_state(&mut self, id: &str) -> SendLookup<SendState<'_>, Self::Error> {
        (**self).send_state(id)
    }
    fn send(&mut self, id: &str) -> SendLookup<SendRecord<'_, Self::Payload<'_>>, Self::Error> {
        (**self).send(id)
    }
    fn sends(&mut self, owner: &str) -> Result<Self::Sends<'_>, Self::Error> {
        (**self).sends(owner)
    }
    fn create_text_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        plan: &ValidatedTextSend<'_, '_, P>,
    ) -> Result<Self::SendId, Self::Error> {
        (**self).create_text_send(owner, plan)
    }
    fn update_text_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        id: &str,
        plan: &ValidatedTextSend<'_, '_, P>,
    ) -> Result<(), Self::Error> {
        (**self).update_text_send(owner, id, plan)
    }
    fn delete_send(&mut self, owner: &str, id: &str) -> Result<(), Self::Error> {
        (**self).delete_send(owner, id)
    }
    fn remove_send_password(&mut self, owner: &str, id: &str) -> Result<(), Self::Error> {
        (**self).remove_send_password(owner, id)
    }
    fn resolve_send_access_id(
        &mut self,
        access_id: &str,
    ) -> Result<Option<Self::SendId>, Self::Error> {
        (**self).resolve_send_access_id(access_id)
    }
    fn verify_send_password(
        &mut self,
        id: &str,
        password: &Secret<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).verify_send_password(id, password)
    }
    fn verify_send_access_token(
        &mut self,
        token: &Secret<'_>,
    ) -> Result<Option<Self::SendId>, Self::Error> {
        (**self).verify_send_access_token(token)
    }
    fn register_send_access(
        &mut self,
        plan: &ValidatedSendAccess<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).register_send_access(plan)
    }
}

fn not_found() -> ApiError {
    ApiError::invalid("send", "Send not found")
}
fn inaccessible() -> ApiError {
    ApiError::new(
        ErrorKind::NotFound,
        "Send does not exist or is no longer available",
    )
}
fn deletion_date(request: i128, context: &SendContext) -> Result<(), ApiError> {
    if context
        .now_unix_nanos
        .checked_add(SEND_DELETION_WINDOW_NANOS)
        .is_none_or(|limit| request > limit)
    {
        return Err(ApiError::invalid(
            "deletionDate",
            "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.",
        ));
    }
    Ok(())
}

impl<S: SendStorage> VaultService<S> {
    fn send_write_policy(&mut self, owner: &str, hide_email: Option<bool>) -> Result<(), ApiError> {
        let policy = self
            .storage_mut()
            .send_policy(owner)
            .map_err(S::map_error)?;
        if !policy.can_modify {
            return Err(ApiError::invalid(
                "send",
                "Due to an Enterprise Policy, you are only able to delete an existing Send.",
            ));
        }
        if hide_email == Some(true) && !policy.can_hide_email {
            return Err(ApiError::invalid(
                "hideEmail",
                "Due to an Enterprise Policy, you are not allowed to hide your email address from recipients when creating or editing a Send.",
            ));
        }
        Ok(())
    }
    fn owned_send_kind(&mut self, owner: &str, id: &str) -> Result<i32, ApiError> {
        let state = self
            .storage_mut()
            .send_state(id)
            .map_err(S::map_error)?
            .ok_or_else(not_found)?;
        if state.id != id || state.owner_id != owner {
            return Err(not_found());
        }
        Ok(state.kind)
    }

    pub fn get_send(
        &mut self,
        owner: &str,
        id: &str,
    ) -> Result<SendOwnerResponse<'_, S::Payload<'_>>, ApiError> {
        require_owner(owner)?;
        let kind = self.owned_send_kind(owner, id)?;
        let record = self
            .storage_mut()
            .send(id)
            .map_err(S::map_error)?
            .ok_or_else(not_found)?;
        if record.id != id || record.owner_id != owner {
            return Err(not_found());
        }
        Ok(SendOwnerResponse { record, kind })
    }
    pub fn list_sends(
        &mut self,
        owner: &str,
    ) -> Result<SendListResponse<'_, S::Sends<'_>>, ApiError> {
        require_owner(owner)?;
        let data = self.storage_mut().sends(owner).map_err(S::map_error)?;
        for index in 0..data.len() {
            let record = data.get(index).ok_or_else(not_found)?;
            if record.owner_id != owner {
                return Err(not_found());
            }
            if !matches!(data.kind(index), Some(0 | 1)) {
                return Err(not_found());
            }
        }
        Ok(SendListResponse {
            data,
            marker: core::marker::PhantomData,
        })
    }
    pub fn create_text_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        request: &TextSendRequest<'_, P>,
        context: &SendContext,
    ) -> Result<SendOwnerResponse<'_, S::Payload<'_>>, ApiError> {
        require_owner(owner)?;
        self.send_write_policy(owner, request.hide_email)?;
        if request.kind == 1 {
            return Err(ApiError::invalid(
                "type",
                "File sends should use /api/sends/file/v2",
            ));
        }
        if request.kind != 0 {
            return Err(ApiError::invalid("type", "Invalid Send type"));
        }
        if request.text.is_none() {
            return Err(ApiError::invalid("text", "Send data not provided"));
        }
        deletion_date(request.deletion_ns, context)?;
        if request.emails.is_some() {
            return Err(ApiError::invalid(
                "emails",
                "Sends with email verification is not supported",
            ));
        }
        let maximum = request
            .max_access_count
            .map(SendNumber::into_i32)
            .transpose()?;
        let plan = ValidatedTextSend {
            request,
            maximum,
            creating: true,
        };
        let id = self
            .storage_mut()
            .create_text_send(owner, &plan)
            .map_err(S::map_error)?;
        self.get_send(owner, id.as_ref())
    }
    pub fn update_text_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        id: &str,
        request: &TextSendRequest<'_, P>,
        context: &SendContext,
    ) -> Result<SendOwnerResponse<'_, S::Payload<'_>>, ApiError> {
        require_owner(owner)?;
        self.send_write_policy(owner, request.hide_email)?;
        let kind = self.owned_send_kind(owner, id)?;
        if request.emails.is_some() {
            return Err(ApiError::invalid(
                "emails",
                "Sends with email verification is not supported",
            ));
        }
        if kind != request.kind {
            return Err(ApiError::invalid("type", "Sends can't change type"));
        }
        if kind != 0 {
            return Err(ApiError::invalid("type", "Only text Sends are supported."));
        }
        deletion_date(request.deletion_ns, context)?;
        if request.text.is_none() {
            return Err(ApiError::invalid("text", "Send data not provided"));
        }
        let maximum = request
            .max_access_count
            .map(SendNumber::into_i32)
            .transpose()?;
        self.storage_mut()
            .update_text_send(
                owner,
                id,
                &ValidatedTextSend {
                    request,
                    maximum,
                    creating: false,
                },
            )
            .map_err(S::map_error)?;
        self.get_send(owner, id)
    }
    pub fn delete_send(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        require_owner(owner)?;
        self.owned_send_kind(owner, id)?;
        self.storage_mut()
            .delete_send(owner, id)
            .map_err(S::map_error)
    }
    pub fn remove_send_password(
        &mut self,
        owner: &str,
        id: &str,
    ) -> Result<SendOwnerResponse<'_, S::Payload<'_>>, ApiError> {
        require_owner(owner)?;
        self.send_write_policy(owner, None)?;
        self.owned_send_kind(owner, id)?;
        self.storage_mut()
            .remove_send_password(owner, id)
            .map_err(S::map_error)?;
        self.get_send(owner, id)
    }
    pub fn authenticate_send_access(
        &mut self,
        request: &SendAccessTokenRequest<'_>,
        context: &SendContext,
    ) -> Result<AuthorizedSendAccessGrant<S::SendId>, SendAccessError> {
        if request.grant_type != Some("send_access") {
            return Err(ApiError::invalid("grant_type", "Unsupported grant type.").into());
        }
        request
            .client_id
            .ok_or_else(|| ApiError::invalid("client_id", "client_id cannot be blank"))?;
        let access_id = request
            .send_id
            .ok_or_else(|| ApiError::invalid("send_id", "send_id cannot be blank"))?;
        let id = self
            .storage_mut()
            .resolve_send_access_id(access_id)
            .map_err(S::map_error)?
            .ok_or(SendAccessError::InvalidSend)?;
        let state = self
            .storage_mut()
            .send_state(id.as_ref())
            .map_err(S::map_error)?
            .ok_or(SendAccessError::InvalidSend)?;
        if state.id != id.as_ref()
            || state
                .max_access_count
                .is_some_and(|maximum| state.access_count >= maximum)
            || !state.is_accessible(context)
        {
            return Err(SendAccessError::InvalidSend);
        }
        if state.password_protected {
            let password = request
                .password_hash_b64
                .as_ref()
                .ok_or(SendAccessError::PasswordRequired)?;
            if !self
                .storage_mut()
                .verify_send_password(id.as_ref(), password)
                .map_err(S::map_error)?
            {
                return Err(SendAccessError::InvalidPassword);
            }
        }
        Ok(AuthorizedSendAccessGrant { id })
    }
    pub fn access_text_send(
        &mut self,
        token: &Secret<'_>,
        context: &SendContext,
    ) -> Result<SendRecipientResponse<'_, S::Payload<'_>>, ApiError> {
        let id = self
            .storage_mut()
            .verify_send_access_token(token)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::new(ErrorKind::Unauthorized, "Invalid Send access token"))?;
        let state = self
            .storage_mut()
            .send_state(id.as_ref())
            .map_err(S::map_error)?
            .ok_or_else(inaccessible)?;
        if state.id != id.as_ref() || !state.is_accessible(context) {
            return Err(inaccessible());
        }
        if state.kind != 0 {
            return Err(ApiError::invalid("type", "Only text Sends are supported."));
        }
        // Do not precheck max here. Upstream's attempted CAS may advance owner revision
        // even when the current maximum rejects this access.
        if !self
            .storage_mut()
            .register_send_access(&ValidatedSendAccess {
                id: id.as_ref(),
                now: context.now_unix_nanos,
            })
            .map_err(S::map_error)?
        {
            return Err(inaccessible());
        }
        let record = self
            .storage_mut()
            .send(id.as_ref())
            .map_err(S::map_error)?
            .ok_or_else(inaccessible)?;
        if record.id != id.as_ref() {
            return Err(inaccessible());
        }
        Ok(SendRecipientResponse { record, kind: 0 })
    }
}

impl<S: FileSendStorage> VaultService<S> {
    /// Reserve metadata only. The adapter supplies/retains encrypted bytes separately.
    pub fn reserve_file_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        request: &FileSendRequest<'_, P>,
        context: &SendContext,
    ) -> Result<SendFileUploadResponse<'_, S::Payload<'_>, S::Url>, ApiError> {
        require_owner(owner)?;
        let policy = self
            .storage_mut()
            .send_policy(owner)
            .map_err(S::map_error)?;
        if !policy.can_modify {
            return Err(ApiError::invalid(
                "send",
                "Due to an Enterprise Policy, you are only able to delete an existing Send.",
            ));
        }
        let common = &request.common;
        if common.kind != 1 {
            return Err(ApiError::invalid("type", "Send content is not a file"));
        }
        if common.hide_email == Some(true) && !policy.can_hide_email {
            return Err(ApiError::invalid(
                "hideEmail",
                "Due to an Enterprise Policy, you are not allowed to hide your email address from recipients when creating or editing a Send.",
            ));
        }
        let length = request
            .file_length
            .ok_or_else(|| ApiError::invalid("fileLength", "Invalid send length"))?
            .into_i64()?;
        let length = u64::try_from(length)
            .map_err(|_| ApiError::invalid("fileLength", "Send size can't be negative"))?;
        let quota = self
            .storage_mut()
            .file_send_quota(owner)
            .map_err(S::map_error)?;
        if !quota.uploads_enabled {
            return Err(ApiError::invalid("fileLength", "File uploads are disabled"));
        }
        let available = quota
            .remaining_bytes
            .unwrap_or(MAX_SEND_FILE_BYTES)
            .min(MAX_SEND_FILE_BYTES);
        if quota.remaining_bytes == Some(0) {
            return Err(ApiError::invalid(
                "fileLength",
                "Send storage limit reached! Delete some sends to free up space",
            ));
        }
        if length > available {
            return Err(ApiError::invalid(
                "fileLength",
                "Send storage limit exceeded with this file",
            ));
        }
        if request.file.is_none() {
            return Err(ApiError::invalid("file", "Send data not provided"));
        }
        deletion_date(common.deletion_ns, context)?;
        if common.emails.is_some() {
            return Err(ApiError::invalid(
                "emails",
                "Sends with email verification is not supported",
            ));
        }
        let maximum = common
            .max_access_count
            .map(SendNumber::into_i32)
            .transpose()?;
        let id = self
            .storage_mut()
            .create_file_send(
                owner,
                &ValidatedFileSend {
                    request,
                    maximum,
                    length: Some(length),
                    creating: true,
                },
            )
            .map_err(S::map_error)?;
        let url = self
            .storage_mut()
            .send_file_upload_url(id.as_ref())
            .map_err(S::map_error)?;
        let response = self.get_send(owner, id.as_ref())?;
        Ok(SendFileUploadResponse { response, url })
    }

    /// Update only common fields. Incoming file metadata and file length have no authority.
    pub fn update_file_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        id: &str,
        request: &FileSendRequest<'_, P>,
        context: &SendContext,
    ) -> Result<SendOwnerResponse<'_, S::Payload<'_>>, ApiError> {
        require_owner(owner)?;
        let common = &request.common;
        self.send_write_policy(owner, common.hide_email)?;
        let kind = self.owned_send_kind(owner, id)?;
        if common.emails.is_some() {
            return Err(ApiError::invalid(
                "emails",
                "Sends with email verification is not supported",
            ));
        }
        if kind != common.kind {
            return Err(ApiError::invalid("type", "Sends can't change type"));
        }
        if kind != 1 {
            return Err(ApiError::invalid("type", "Send content is not a file"));
        }
        deletion_date(common.deletion_ns, context)?;
        let maximum = common
            .max_access_count
            .map(SendNumber::into_i32)
            .transpose()?;
        self.storage_mut()
            .update_file_send(
                owner,
                id,
                &ValidatedFileSend {
                    request,
                    maximum,
                    length: None,
                    creating: false,
                },
            )
            .map_err(S::map_error)?;
        self.get_send(owner, id)
    }

    /// Authorize and publish adapter-staged bytes without changing immutable file metadata.
    pub fn upload_send_file(
        &mut self,
        owner: &str,
        id: &str,
        file_id: &str,
        upload: &SendFileUpload<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        self.send_write_policy(owner, None)?;
        let state = self.storage_mut().send_state(id).map_err(S::map_error)?;
        let Some(state) = state.filter(|state| state.id == id && state.owner_id == owner) else {
            return Err(ApiError::invalid(
                "send",
                "Send not found. Unable to save the file.",
            ));
        };
        if state.kind != 1 {
            return Err(ApiError::invalid("file", "Send is not a file type send."));
        }
        let metadata = self
            .storage_mut()
            .send_file_metadata(id)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::invalid("file", "Unable to decode send data as json."))?;
        let file_name = upload.file_name.ok_or_else(|| {
            ApiError::invalid(
                "fileName",
                "Send file name does not match or is not provided.",
            )
        })?;
        if metadata.file_name != file_name
            && !(upload.allow_legacy_filename_suffix && metadata.file_name.ends_with(file_name))
        {
            return Err(ApiError::invalid(
                "fileName",
                "Send file name does not match.",
            ));
        }
        if metadata.file_id != file_id {
            return Err(ApiError::invalid(
                "fileId",
                "Send file does not match send data.",
            ));
        }
        if metadata.file_size != upload.file_size {
            return Err(ApiError::invalid(
                "fileSize",
                "Send file size does not match.",
            ));
        }
        if !self
            .storage_mut()
            .commit_send_file_upload(
                owner,
                &ValidatedSendFileUpload {
                    id,
                    file_id,
                    file_size: upload.file_size,
                },
            )
            .map_err(S::map_error)?
        {
            return Err(ApiError::invalid("file", "OpenDAL"));
        }
        Ok(())
    }

    /// Recipient metadata access. File views do not consume the file-download count.
    pub fn access_send(
        &mut self,
        token: &Secret<'_>,
        context: &SendContext,
    ) -> Result<SendRecipientResponse<'_, S::Payload<'_>>, ApiError> {
        let id = self
            .storage_mut()
            .verify_send_access_token(token)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::new(ErrorKind::Unauthorized, "Invalid Send access token"))?;
        let state = self
            .storage_mut()
            .send_state(id.as_ref())
            .map_err(S::map_error)?
            .ok_or_else(inaccessible)?;
        if state.id != id.as_ref() || !state.is_accessible(context) {
            return Err(inaccessible());
        }
        let kind = state.kind;
        let plan = ValidatedSendAccess {
            id: id.as_ref(),
            now: context.now_unix_nanos,
        };
        match kind {
            0 => {
                if !self
                    .storage_mut()
                    .register_send_access(&plan)
                    .map_err(S::map_error)?
                {
                    return Err(inaccessible());
                }
            }
            1 => self
                .storage_mut()
                .touch_file_send_access(&plan)
                .map_err(S::map_error)?,
            _ => return Err(inaccessible()),
        }
        let record = self
            .storage_mut()
            .send(id.as_ref())
            .map_err(S::map_error)?
            .ok_or_else(inaccessible)?;
        if record.id != id.as_ref() {
            return Err(inaccessible());
        }
        Ok(SendRecipientResponse { record, kind })
    }

    /// Reserve a file access before issuing its short-lived byte capability. Bytes may
    /// still be absent: the later binary transport, not this reservation, returns 404.
    pub fn access_send_file<'a>(
        &mut self,
        token: &Secret<'_>,
        file_id: &'a str,
        context: &SendContext,
    ) -> Result<SendFileDownloadResponse<'a, S::Url>, ApiError> {
        let id = self
            .storage_mut()
            .verify_send_access_token(token)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::new(ErrorKind::Unauthorized, "Invalid Send access token"))?;
        let state = self
            .storage_mut()
            .send_state(id.as_ref())
            .map_err(S::map_error)?
            .ok_or_else(inaccessible)?;
        if state.id != id.as_ref() || !state.is_accessible(context) {
            return Err(inaccessible());
        }
        if state.kind != 1 {
            return Err(ApiError::invalid("type", "Send content is not a file"));
        }
        let metadata = self
            .storage_mut()
            .send_file_metadata(id.as_ref())
            .map_err(S::map_error)?
            .ok_or_else(inaccessible)?;
        if metadata.file_id != file_id {
            return Err(inaccessible());
        }
        if !self
            .storage_mut()
            .register_send_access(&ValidatedSendAccess {
                id: id.as_ref(),
                now: context.now_unix_nanos,
            })
            .map_err(S::map_error)?
        {
            return Err(inaccessible());
        }
        let grant = AuthorizedSendFileDownload {
            id: id.as_ref(),
            file_id,
        };
        let url = self
            .storage_mut()
            .send_file_download_url(&grant)
            .map_err(S::map_error)?;
        Ok(SendFileDownloadResponse { file_id, url })
    }

    pub fn authorize_send_file_download<'a>(
        &mut self,
        id: &'a str,
        file_id: &'a str,
        proof: &Secret<'_>,
    ) -> Result<AuthorizedSendFileDownload<'a>, ApiError> {
        if !self
            .storage_mut()
            .verify_send_file_download(id, file_id, proof)
            .map_err(S::map_error)?
        {
            return Err(inaccessible());
        }
        Ok(AuthorizedSendFileDownload { id, file_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use serde_json::{Value, json};
    use std::{format, string::String, vec, vec::Vec};

    struct Id(String); // Owned handle intentionally has no Debug/Clone/Copy bound.
    impl AsRef<str> for Id {
        fn as_ref(&self) -> &str {
            &self.0
        }
    }
    #[derive(Clone, PartialEq)]
    struct Row {
        id: String,
        owner: String,
        name: String,
        key: String,
        notes: Option<String>,
        raw: Value,
        display: Value,
        password: Option<String>,
        maximum: Option<i32>,
        count: i32,
        disabled: bool,
        hide: Option<bool>,
        deletion: i128,
        expiration: Option<i128>,
        revision: usize,
        kind: i32,
    }
    impl Row {
        fn new(id: &str, owner: &str) -> Self {
            Self {
                id: id.into(),
                owner: owner.into(),
                name: "opaque-name".into(),
                key: "opaque-key".into(),
                notes: Some("opaque-notes".into()),
                raw: json!({"text":"opaque-text","hidden":false}),
                display: json!({"text":"opaque-text","hidden":false}),
                password: None,
                maximum: None,
                count: 0,
                disabled: false,
                hide: None,
                deletion: 100,
                expiration: None,
                revision: 0,
                kind: 0,
            }
        }
        fn state(&self) -> SendState<'_> {
            SendState {
                id: &self.id,
                owner_id: &self.owner,
                kind: self.kind,
                disabled: self.disabled,
                max_access_count: self.maximum,
                access_count: self.count,
                expiration_ns: self.expiration,
                deletion_ns: self.deletion,
                password_protected: self.password.is_some(),
            }
        }
        fn record(&self) -> SendRecord<'_, &Value> {
            SendRecord {
                id: &self.id,
                owner_id: &self.owner,
                access_id: "public-access-id",
                name: &self.name,
                notes: self.notes.as_deref(),
                text: &self.display,
                key: &self.key,
                max_access_count: self.maximum,
                access_count: self.count,
                password_hash: self.password.as_ref().map(|_| "encoded-owner-hash"),
                disabled: self.disabled,
                hide_email: self.hide,
                revision_date: "revision-date",
                expiration_date: self.expiration.map(|_| "expiration-date"),
                deletion_date: "deletion-date",
                creator_identifier: Some("creator@example.test"),
            }
        }
        fn apply<P: Serialize + ?Sized>(&mut self, plan: &ValidatedTextSend<'_, '_, P>) {
            let input = plan.request();
            self.name = input.name.into();
            self.key = input.key.into();
            self.notes = input.notes.map(String::from);
            self.raw = serde_json::to_value(input.text.unwrap()).unwrap();
            if let Some(object) = self.raw.as_object_mut() {
                object.remove("response");
            }
            self.display = if self.raw.is_object() {
                self.raw.clone()
            } else {
                Value::Null
            };
            self.maximum = plan.max_access_count();
            self.disabled = input.disabled;
            self.hide = input.hide_email;
            self.expiration = input.expiration_ns;
            self.deletion = input.deletion_ns;
            match plan.password_change() {
                SendPasswordChange::Clear => self.password = None,
                SendPasswordChange::Preserve => {}
                SendPasswordChange::Set(value) => {
                    self.password = Some(value.expose_secret().into())
                }
            }
            self.revision += 1;
        }
    }
    struct Records<'a> {
        rows: &'a [Row],
        indices: &'a [usize],
    }
    impl<'a> SendListData<'a> for Records<'a> {
        type Payload = &'a Value;
        fn len(&self) -> usize {
            self.indices.len()
        }
        fn get(&self, index: usize) -> Option<SendRecord<'a, Self::Payload>> {
            self.rows.get(*self.indices.get(index)?).map(Row::record)
        }
        fn kind(&self, index: usize) -> Option<i32> {
            self.rows.get(*self.indices.get(index)?).map(|row| row.kind)
        }
    }
    struct Mock {
        rows: Vec<Row>,
        indices: Vec<usize>,
        calls: Vec<&'static str>,
        policy: SendPolicy,
        fail: Option<&'static str>,
        failure: ErrorKind,
        owner_revision: usize,
        foreign_revision: usize,
        token_valid: bool,
        inject_foreign: bool,
        race_exhaust: bool,
        received_password: String,
        quota: SendFileQuota,
        uploaded: bool,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                rows: vec![Row::new("send", "alice"), Row::new("foreign", "bob")],
                indices: vec![],
                calls: vec![],
                policy: SendPolicy {
                    can_modify: true,
                    can_hide_email: true,
                },
                fail: None,
                failure: ErrorKind::Storage,
                owner_revision: 0,
                foreign_revision: 7,
                token_valid: true,
                inject_foreign: false,
                race_exhaust: false,
                received_password: String::new(),
                quota: SendFileQuota::default(),
                uploaded: false,
            }
        }
        fn call(&mut self, label: &'static str) -> Result<(), ErrorKind> {
            self.calls.push(label);
            if self.fail == Some(label) {
                Err(self.failure)
            } else {
                Ok(())
            }
        }
        fn index(&self, id: &str) -> Option<usize> {
            self.rows.iter().position(|row| row.id == id)
        }
    }
    impl Storage for Mock {
        type Error = ErrorKind;
        fn map_error(error: Self::Error) -> ApiError {
            ApiError::new(error, "Static provider error")
        }
        fn account_exists(&mut self, _: &str) -> Result<bool, Self::Error> {
            unreachable!()
        }
        fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), Self::Error> {
            unreachable!()
        }
        fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error> {
            unreachable!()
        }
        fn save_folder(
            &mut self,
            _: &str,
            _: &str,
            _: &FolderRequest<'_>,
        ) -> Result<(), Self::Error> {
            unreachable!()
        }
        fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), Self::Error> {
            unreachable!()
        }
        fn cipher_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error> {
            unreachable!()
        }
        fn save_cipher(
            &mut self,
            _: &str,
            _: &str,
            _: &CipherRequest<'_>,
        ) -> Result<(), Self::Error> {
            unreachable!()
        }
        fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), Self::Error> {
            unreachable!()
        }
        fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), Self::Error> {
            unreachable!()
        }
    }
    impl SendStorage for Mock {
        type SendId = Id;
        type Payload<'a> = &'a Value;
        type Sends<'a> = Records<'a>;
        fn send_policy(&mut self, _: &str) -> Result<SendPolicy, Self::Error> {
            self.call("policy")?;
            Ok(self.policy)
        }
        fn send_state(&mut self, id: &str) -> SendLookup<SendState<'_>, Self::Error> {
            self.call("state")?;
            Ok(self.index(id).map(|index| self.rows[index].state()))
        }
        fn send(&mut self, id: &str) -> SendLookup<SendRecord<'_, Self::Payload<'_>>, Self::Error> {
            self.call("read")?;
            Ok(self.index(id).map(|index| self.rows[index].record()))
        }
        fn sends(&mut self, owner: &str) -> Result<Self::Sends<'_>, Self::Error> {
            self.call("list")?;
            self.indices = self
                .rows
                .iter()
                .enumerate()
                .filter(|(_, row)| self.inject_foreign || row.owner == owner)
                .map(|(index, _)| index)
                .collect();
            Ok(Records {
                rows: &self.rows,
                indices: &self.indices,
            })
        }
        fn create_text_send<P: Serialize + ?Sized>(
            &mut self,
            owner: &str,
            plan: &ValidatedTextSend<'_, '_, P>,
        ) -> Result<Self::SendId, Self::Error> {
            self.call("create")?;
            let mut row = Row::new("created", owner);
            row.apply(plan);
            self.rows.push(row);
            self.owner_revision += 1;
            Ok(Id("created".into()))
        }
        fn update_text_send<P: Serialize + ?Sized>(
            &mut self,
            owner: &str,
            id: &str,
            plan: &ValidatedTextSend<'_, '_, P>,
        ) -> Result<(), Self::Error> {
            self.call("update")?;
            let index = self.index(id).unwrap();
            assert!(self.rows[index].owner == owner);
            let mut next = self.rows[index].clone();
            next.apply(plan);
            self.rows[index] = next;
            self.owner_revision += 1;
            Ok(())
        }
        fn delete_send(&mut self, owner: &str, id: &str) -> Result<(), Self::Error> {
            self.call("delete")?;
            let index = self.index(id).unwrap();
            assert!(self.rows[index].owner == owner);
            self.rows.remove(index);
            self.owner_revision += 1;
            Ok(())
        }
        fn remove_send_password(&mut self, owner: &str, id: &str) -> Result<(), Self::Error> {
            self.call("remove")?;
            let index = self.index(id).unwrap();
            assert!(self.rows[index].owner == owner);
            self.rows[index].password = None;
            self.rows[index].revision += 1;
            self.owner_revision += 1;
            Ok(())
        }
        fn resolve_send_access_id(
            &mut self,
            id: &str,
        ) -> Result<Option<Self::SendId>, Self::Error> {
            self.call("resolve")?;
            Ok((id == "public-access-id").then(|| Id("send".into())))
        }
        fn verify_send_password(
            &mut self,
            id: &str,
            password: &Secret<'_>,
        ) -> Result<bool, Self::Error> {
            self.call("password")?;
            self.received_password = password.expose_secret().into();
            Ok(self.rows[self.index(id).unwrap()].password.as_deref()
                == Some(password.expose_secret()))
        } // Test double only.
        fn verify_send_access_token(
            &mut self,
            token: &Secret<'_>,
        ) -> Result<Option<Self::SendId>, Self::Error> {
            self.call("token")?;
            Ok(
                (self.token_valid && token.expose_secret() == "recipient-proof")
                    .then(|| Id("send".into())),
            )
        } // Test double only.
        fn register_send_access(
            &mut self,
            plan: &ValidatedSendAccess<'_>,
        ) -> Result<bool, Self::Error> {
            self.call("register")?;
            assert_eq!(plan.now_unix_nanos(), 1);
            self.owner_revision += 1;
            let index = self.index(plan.id()).unwrap();
            let row = &mut self.rows[index];
            if self.race_exhaust {
                row.maximum = Some(row.count);
            }
            if row.maximum.is_some_and(|maximum| row.count >= maximum) {
                return Ok(false);
            }
            row.count += 1;
            row.revision += 1;
            self.owner_revision += 1;
            Ok(true)
        }
    }
    impl FileSendStorage for Mock {
        type Url = String;
        fn file_send_quota(&mut self, _: &str) -> Result<SendFileQuota, Self::Error> {
            self.call("quota")?;
            Ok(self.quota)
        }
        fn create_file_send<P: Serialize + ?Sized>(
            &mut self,
            owner: &str,
            plan: &ValidatedFileSend<'_, '_, P>,
        ) -> Result<Id, Self::Error> {
            self.call("create-file")?;
            let mut row = Row::new("created", owner);
            row.kind = 1;
            row.raw = serde_json::to_value(plan.request().file.unwrap()).unwrap();
            if let Some(object) = row.raw.as_object_mut() {
                object.remove("response");
                object.insert("id".into(), json!("file-id"));
                object.insert("size".into(), json!(plan.file_length().unwrap()));
                object.insert("sizeName".into(), json!("opaque-size-label"));
            }
            row.display = if row.raw.is_object() {
                row.raw.clone()
            } else {
                Value::Null
            };
            apply_file_common(&mut row, plan);
            self.rows.push(row);
            self.owner_revision += 1;
            Ok(Id("created".into()))
        }
        fn update_file_send<P: Serialize + ?Sized>(
            &mut self,
            owner: &str,
            id: &str,
            plan: &ValidatedFileSend<'_, '_, P>,
        ) -> Result<(), Self::Error> {
            self.call("update-file")?;
            let index = self.index(id).unwrap();
            assert_eq!(self.rows[index].owner, owner);
            assert!(plan.file_length().is_none());
            apply_file_common(&mut self.rows[index], plan);
            self.owner_revision += 1;
            Ok(())
        }
        fn send_file_metadata(
            &mut self,
            id: &str,
        ) -> SendLookup<SendFileMetadata<'_>, Self::Error> {
            self.call("metadata")?;
            let Some(index) = self.index(id) else {
                return Ok(None);
            };
            let value = &self.rows[index].raw;
            Ok(
                match (
                    value["id"].as_str(),
                    value["fileName"].as_str(),
                    value["size"].as_u64(),
                ) {
                    (Some(file_id), Some(file_name), Some(file_size)) => Some(SendFileMetadata {
                        file_id,
                        file_name,
                        file_size,
                    }),
                    _ => None,
                },
            )
        }
        fn commit_send_file_upload(
            &mut self,
            owner: &str,
            plan: &ValidatedSendFileUpload<'_>,
        ) -> Result<bool, Self::Error> {
            self.call("upload-file")?;
            assert_eq!(self.rows[self.index(plan.id()).unwrap()].owner, owner);
            assert_eq!(plan.file_id(), "file-id");
            assert_eq!(plan.file_size(), 4);
            if self.uploaded {
                return Ok(false);
            }
            self.uploaded = true;
            self.owner_revision += 1;
            Ok(true)
        }
        fn touch_file_send_access(
            &mut self,
            plan: &ValidatedSendAccess<'_>,
        ) -> Result<(), Self::Error> {
            self.call("touch-file")?;
            assert!(self.index(plan.id()).is_some());
            self.owner_revision += 1;
            Ok(())
        }
        fn send_file_upload_url(&mut self, _: &str) -> Result<String, Self::Error> {
            self.call("upload-url")?;
            Ok("/sends/created/file/file-id".into())
        }
        fn send_file_download_url(
            &mut self,
            grant: &AuthorizedSendFileDownload<'_>,
        ) -> Result<String, Self::Error> {
            self.call("download-url")?;
            assert_eq!(grant.expires_in(), 120);
            assert_eq!(grant.file_id(), "file-id");
            Ok("https://example.test/api/sends/send/file-id?t=private-proof".into())
        }
        fn verify_send_file_download(
            &mut self,
            id: &str,
            file_id: &str,
            proof: &Secret<'_>,
        ) -> Result<bool, Self::Error> {
            self.call("file-proof")?;
            Ok(self.token_valid
                && id == "send"
                && file_id == "file-id"
                && proof.expose_secret() == "file-proof")
        } // Test verifier only: real providers verify the scoped signature and deadline.
    }
    fn apply_file_common<P: ?Sized>(row: &mut Row, plan: &ValidatedFileSend<'_, '_, P>) {
        let common = plan.common();
        row.name = common.name.into();
        row.key = common.key.into();
        row.notes = common.notes.map(String::from);
        row.maximum = plan.max_access_count();
        row.disabled = common.disabled;
        row.hide = common.hide_email;
        row.expiration = common.expiration_ns;
        row.deletion = common.deletion_ns;
        match plan.password_change() {
            SendPasswordChange::Clear => row.password = None,
            SendPasswordChange::Preserve => {}
            SendPasswordChange::Set(proof) => row.password = Some(proof.expose_secret().into()),
        }
        row.revision += 1;
    }
    fn file_request(value: &Value) -> FileSendRequest<'_, Value> {
        let mut common = request(value);
        common.kind = 1;
        common.text = None;
        FileSendRequest {
            common,
            file: Some(value),
            file_length: Some(SendNumber::Integer(4)),
        }
    }
    fn file_mock() -> Mock {
        let mut mock = Mock::new();
        mock.rows[0].kind = 1;
        mock.rows[0].raw =
            json!({"id":"file-id","fileName":"prefix-encrypted-name","size":4,"sizeName":"4 B"});
        mock.rows[0].display = mock.rows[0].raw.clone();
        mock
    }
    fn upload() -> SendFileUpload<'static> {
        SendFileUpload {
            file_name: Some("prefix-encrypted-name"),
            file_size: 4,
            allow_legacy_filename_suffix: false,
        }
    }

    #[test]
    fn file_reservation_auth_policy_length_and_quota_precede_mutation() {
        let value = json!({"fileName":"opaque\0雪"});
        let mut input = file_request(&value);
        let mut mock = Mock::new();
        assert_eq!(
            VaultService::new(&mut mock)
                .reserve_file_send("", &input, &context())
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(mock.calls.is_empty());
        mock.policy.can_modify = false;
        input.common.kind = 0;
        assert!(
            VaultService::new(&mut mock)
                .reserve_file_send("alice", &input, &context())
                .unwrap_err()
                .message
                .contains("Enterprise Policy")
        );
        assert_eq!(mock.calls, ["policy"]);
        mock.policy.can_modify = true;
        mock.policy.can_hide_email = false;
        input.common.hide_email = Some(true);
        mock.calls.clear();
        assert_eq!(
            VaultService::new(&mut mock)
                .reserve_file_send("alice", &input, &context())
                .unwrap_err()
                .message,
            "Send content is not a file"
        );
        input.common.kind = 1;
        input.common.hide_email = None;
        for length in [
            None,
            Some(SendNumber::String(" 4")),
            Some(SendNumber::Integer(-1)),
        ] {
            input.file_length = length;
            mock.calls.clear();
            assert!(
                VaultService::new(&mut mock)
                    .reserve_file_send("alice", &input, &context())
                    .is_err()
            );
            assert_eq!(mock.calls, ["policy"]);
        }
        input.file_length = Some(SendNumber::Integer(0));
        mock.quota.remaining_bytes = Some(0);
        assert!(
            VaultService::new(&mut mock)
                .reserve_file_send("alice", &input, &context())
                .is_err()
        );
        mock.quota = SendFileQuota {
            uploads_enabled: false,
            remaining_bytes: None,
        };
        assert!(
            VaultService::new(&mut mock)
                .reserve_file_send("alice", &input, &context())
                .is_err()
        );
        assert_eq!(mock.rows.len(), 2);
        assert_eq!(mock.owner_revision, 0);
    }

    #[test]
    fn file_reservation_enforces_absolute_and_provider_capacity_boundaries() {
        let value = json!({"fileName":""});
        for (remaining, length, accepted) in [
            (None, 0, true),
            (Some(1), 1, true),
            (Some(1), 2, false),
            (None, MAX_SEND_FILE_BYTES, true),
            (None, MAX_SEND_FILE_BYTES + 1, false),
            (Some(u64::MAX), MAX_SEND_FILE_BYTES + 1, false),
        ] {
            let mut mock = Mock::new();
            mock.quota.remaining_bytes = remaining;
            let mut input = file_request(&value);
            input.file_length = Some(SendNumber::Integer(length as i64));
            assert_eq!(
                VaultService::new(&mut mock)
                    .reserve_file_send("alice", &input, &context())
                    .is_ok(),
                accepted
            );
            assert_eq!(mock.owner_revision, usize::from(accepted));
            assert_eq!(mock.foreign_revision, 7);
        }
    }

    #[test]
    fn file_reservation_owner_list_and_recipient_project_file_without_private_leaks() {
        let value = json!({"fileName":"opaque-file\0雪","response":"removed","future":[1,2]});
        let input = file_request(&value);
        let mut mock = Mock::new();
        let mut service = VaultService::new(&mut mock);
        let response = serde_json::to_value(
            service
                .reserve_file_send("alice", &input, &context())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.as_object().unwrap().len(), 4);
        assert_eq!(response["object"], "send-fileUpload");
        assert_eq!(response["fileUploadType"], 0);
        assert_eq!(response["sendResponse"]["type"], 1);
        assert!(response["sendResponse"]["text"].is_null());
        assert_eq!(
            response["sendResponse"]["file"]["fileName"],
            "opaque-file\0雪"
        );
        assert!(response["sendResponse"]["file"].get("response").is_none());
        let response = serde_json::to_value(service.list_sends("alice").unwrap()).unwrap();
        assert_eq!(response["data"][0]["type"], 0);
        assert_eq!(response["data"][1]["type"], 1);
        let mut mock = file_mock();
        mock.rows[0].hide = Some(true);
        let response = serde_json::to_value(
            VaultService::new(&mut mock)
                .access_send(&Secret::new("recipient-proof"), &context())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.as_object().unwrap().len(), 8);
        assert_eq!(response["type"], 1);
        assert!(response["text"].is_null() && response["creatorIdentifier"].is_null());
        for key in ["key", "notes", "password", "accessCount", "deletionDate"] {
            assert!(response.get(key).is_none());
        }
    }

    #[test]
    fn file_update_preserves_metadata_bytes_count_and_omitted_password() {
        let value = json!({"id":"forged","size":999});
        let mut input = file_request(&value);
        input.file = None;
        input.file_length = Some(SendNumber::String("invalid-but-ignored"));
        let mut mock = file_mock();
        mock.uploaded = true;
        mock.rows[0].count = 3;
        mock.rows[0].password = Some("old-proof".into());
        let raw = mock.rows[0].raw.clone();
        VaultService::new(&mut mock)
            .update_file_send("alice", "send", &input, &context())
            .unwrap();
        assert_eq!(mock.rows[0].raw, raw);
        assert_eq!(mock.rows[0].count, 3);
        assert_eq!(mock.rows[0].password.as_deref(), Some("old-proof"));
        assert!(mock.uploaded);
        input.common.password = Some(Secret::new(""));
        VaultService::new(&mut mock)
            .update_file_send("alice", "send", &input, &context())
            .unwrap();
        assert_eq!(mock.rows[0].password.as_deref(), Some(""));
        input.common.kind = 0;
        assert_eq!(
            VaultService::new(&mut mock)
                .update_file_send("alice", "send", &input, &context())
                .unwrap_err()
                .message,
            "Sends can't change type"
        );
    }

    #[test]
    fn file_upload_checks_name_then_id_then_exact_size_and_keeps_reservation() {
        let mut mock = file_mock();
        let revision = mock.rows[0].revision;
        let mut input = upload();
        input.file_name = None;
        input.file_size = 5;
        assert_eq!(
            VaultService::new(&mut mock)
                .upload_send_file("alice", "send", "wrong-id", &input)
                .unwrap_err()
                .field,
            Some("fileName")
        );
        input.file_name = Some("wrong-name");
        assert_eq!(
            VaultService::new(&mut mock)
                .upload_send_file("alice", "send", "wrong-id", &input)
                .unwrap_err()
                .field,
            Some("fileName")
        );
        input.file_name = upload().file_name;
        assert_eq!(
            VaultService::new(&mut mock)
                .upload_send_file("alice", "send", "wrong-id", &input)
                .unwrap_err()
                .field,
            Some("fileId")
        );
        assert_eq!(
            VaultService::new(&mut mock)
                .upload_send_file("alice", "send", "file-id", &input)
                .unwrap_err()
                .field,
            Some("fileSize")
        );
        assert!(!mock.uploaded && mock.owner_revision == 0);
        input.file_size = 4;
        mock.quota.uploads_enabled = false; // Upload does not repeat reservation quota checks.
        VaultService::new(&mut mock)
            .upload_send_file("alice", "send", "file-id", &input)
            .unwrap();
        assert!(mock.uploaded && mock.owner_revision == 1);
        assert_eq!(mock.rows[0].revision, revision);
        assert!(!mock.calls.contains(&"quota"));
    }

    #[test]
    fn file_upload_legacy_filename_rule_is_directional_and_trusted() {
        for (name, legacy, accepted) in [
            ("encrypted-name", false, false),
            ("encrypted-name", true, true),
            ("prefix-encrypted-name-extra", true, false),
            ("", true, true),
            ("", false, false),
        ] {
            let mut mock = file_mock();
            let input = SendFileUpload {
                file_name: Some(name),
                file_size: 4,
                allow_legacy_filename_suffix: legacy,
            };
            assert_eq!(
                VaultService::new(&mut mock)
                    .upload_send_file("alice", "send", "file-id", &input)
                    .is_ok(),
                accepted
            );
        }
        let mut mock = file_mock();
        mock.rows[0].raw["fileName"] = json!("");
        let input = SendFileUpload {
            file_name: Some(""),
            ..upload()
        };
        assert!(
            VaultService::new(&mut mock)
                .upload_send_file("alice", "send", "file-id", &input)
                .is_ok()
        );
    }

    #[test]
    fn file_metadata_view_does_not_consume_exhausted_download_count() {
        let mut mock = file_mock();
        mock.rows[0].count = 2;
        mock.rows[0].maximum = Some(2);
        let revision = mock.rows[0].revision;
        VaultService::new(&mut mock)
            .access_send(&Secret::new("recipient-proof"), &context())
            .unwrap();
        assert_eq!(mock.rows[0].count, 2);
        assert_eq!(mock.rows[0].revision, revision);
        assert_eq!(mock.owner_revision, 1);
        assert!(!mock.calls.contains(&"register"));
        assert!(matches!(
            VaultService::new(&mut mock).authenticate_send_access(&token_request(), &context()),
            Err(SendAccessError::InvalidSend)
        ));
        let error = VaultService::new(&mut mock)
            .access_send_file(&Secret::new("recipient-proof"), "file-id", &context())
            .unwrap_err();
        assert_eq!(error.status_code(), 404);
        assert_eq!(mock.owner_revision, 2); // Exhausted CAS still advances its owner.
    }

    #[test]
    fn file_url_access_reserves_count_without_requiring_uploaded_bytes() {
        let mut mock = file_mock();
        let response = serde_json::to_value(
            VaultService::new(&mut mock)
                .access_send_file(&Secret::new("recipient-proof"), "file-id", &context())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.as_object().unwrap().len(), 3);
        assert_eq!(response["object"], "send-fileDownload");
        assert_eq!(response["id"], "file-id");
        assert!(response["url"].as_str().unwrap().contains("private-proof"));
        assert_eq!(mock.rows[0].count, 1);
        assert!(!mock.uploaded);
        let revision = mock.owner_revision;
        assert_eq!(
            VaultService::new(&mut mock)
                .access_send_file(&Secret::new("recipient-proof"), "wrong-id", &context())
                .unwrap_err()
                .status_code(),
            404
        );
        assert_eq!(mock.owner_revision, revision);
    }

    #[test]
    fn file_capability_is_scoped_and_raw_download_does_not_recheck_rows() {
        let mut mock = file_mock();
        mock.rows.clear(); // File bytes may outlive metadata in a provider's cleanup window.
        let mut service = VaultService::new(&mut mock);
        let grant = service
            .authorize_send_file_download("send", "file-id", &Secret::new("file-proof"))
            .unwrap();
        assert_eq!(
            (grant.id(), grant.file_id(), grant.expires_in()),
            ("send", "file-id", 120)
        );
        for (id, file_id, token) in [
            ("foreign", "file-id", "file-proof"),
            ("send", "other-file", "file-proof"),
            ("send", "file-id", "recipient-proof"),
            ("send", "file-id", "owner-bearer"),
        ] {
            assert_eq!(
                service
                    .authorize_send_file_download(id, file_id, &Secret::new(token))
                    .unwrap_err()
                    .status_code(),
                404
            );
        }
        assert!(mock.calls.iter().all(|call| *call == "file-proof"));
        assert_eq!(mock.owner_revision, 0);
    }

    #[test]
    fn file_provider_errors_preserve_state_and_never_expose_private_inputs() {
        let value = json!({"fileName":"private encrypted filename"});
        let input = file_request(&value);
        let mut mock = file_mock();
        for fail in ["policy", "quota", "create-file"] {
            mock.fail = Some(fail);
            let error = VaultService::new(&mut mock)
                .reserve_file_send("alice", &input, &context())
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Storage);
            assert_eq!(mock.rows.len(), 2);
            assert_eq!(mock.owner_revision, 0);
            assert!(!format!("{error:?}").contains("private"));
        }
        mock.fail = Some("upload-file");
        assert!(
            VaultService::new(&mut mock)
                .upload_send_file("alice", "send", "file-id", &upload())
                .is_err()
        );
        assert!(!mock.uploaded && mock.owner_revision == 0);
        mock.fail = Some("metadata");
        assert_eq!(
            VaultService::new(&mut mock)
                .access_send_file(&Secret::new("recipient-proof"), "file-id", &context())
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
        mock.fail = Some("register");
        assert!(
            VaultService::new(&mut mock)
                .access_send_file(&Secret::new("recipient-proof"), "file-id", &context())
                .is_err()
        );
        assert_eq!(mock.rows[0].count, 0);
        mock.fail = Some("download-url");
        assert!(
            VaultService::new(&mut mock)
                .access_send_file(&Secret::new("recipient-proof"), "file-id", &context())
                .is_err()
        );
        assert_eq!(mock.rows[0].count, 1); // Issuance failure does not imply a reserved access rollback.
    }

    #[test]
    fn file_opaque_non_object_metadata_can_be_reserved_but_not_uploaded() {
        for value in [json!([]), json!("opaque"), json!(123), json!(true)] {
            let mut mock = Mock::new();
            let input = file_request(&value);
            VaultService::new(&mut mock)
                .reserve_file_send("alice", &input, &context())
                .unwrap();
            assert_eq!(
                VaultService::new(&mut mock)
                    .upload_send_file("alice", "created", "file-id", &upload())
                    .unwrap_err()
                    .status_code(),
                400
            );
        }
    }

    #[test]
    fn file_upload_is_create_only_and_foreign_or_unauthenticated_writes_do_not_commit() {
        let mut mock = file_mock();
        assert_eq!(
            VaultService::new(&mut mock)
                .upload_send_file("", "send", "file-id", &upload())
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(mock.calls.is_empty());
        assert_eq!(
            VaultService::new(&mut mock)
                .upload_send_file("bob", "send", "file-id", &upload())
                .unwrap_err()
                .status_code(),
            400
        );
        assert!(!mock.calls.contains(&"metadata") && !mock.uploaded);
        VaultService::new(&mut mock)
            .upload_send_file("alice", "send", "file-id", &upload())
            .unwrap();
        let revision = mock.owner_revision;
        let error = VaultService::new(&mut mock)
            .upload_send_file("alice", "send", "file-id", &upload())
            .unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(error.message, "OpenDAL");
        assert_eq!(mock.owner_revision, revision);
        assert!(mock.uploaded);
    }

    #[test]
    fn file_url_checks_current_availability_before_type_and_metadata_without_writes() {
        let mut mock = Mock::new(); // Existing text row.
        assert_eq!(
            VaultService::new(&mut mock)
                .access_send_file(&Secret::new("recipient-proof"), "file-id", &context())
                .unwrap_err()
                .status_code(),
            400
        );
        mock.rows[0].disabled = true;
        assert_eq!(
            VaultService::new(&mut mock)
                .access_send_file(&Secret::new("recipient-proof"), "file-id", &context())
                .unwrap_err()
                .status_code(),
            404
        );
        mock.rows[0].kind = 1;
        assert_eq!(
            VaultService::new(&mut mock)
                .access_send(&Secret::new("recipient-proof"), &context())
                .unwrap_err()
                .status_code(),
            404
        );
        mock.rows[0].disabled = false;
        assert_eq!(
            VaultService::new(&mut mock)
                .access_send_file(&Secret::new("recipient-proof"), "file-id", &context())
                .unwrap_err()
                .status_code(),
            404
        );
        assert_eq!(mock.owner_revision, 0);
        assert!(!mock.calls.contains(&"register") && !mock.calls.contains(&"touch-file"));
    }

    #[test]
    fn file_private_views_and_explicit_transport_responses_redact_debug() {
        let payload = json!({"fileName":"private-name"});
        let request = file_request(&payload);
        let mut mock = file_mock();
        let metadata = SendFileMetadata {
            file_id: "private-id",
            file_name: "private-name",
            file_size: 4,
        };
        let input = SendFileUpload {
            file_name: Some("private-name"),
            ..upload()
        };
        for rendered in [
            format!("{request:?}"),
            format!("{metadata:?}"),
            format!("{input:?}"),
        ] {
            assert!(!rendered.contains("private"));
        }
        let mut service = VaultService::new(&mut mock);
        assert!(
            !format!(
                "{:?}",
                service
                    .reserve_file_send("alice", &request, &context())
                    .unwrap()
            )
            .contains("private")
        );
        assert!(
            !format!(
                "{:?}",
                service
                    .access_send_file(&Secret::new("recipient-proof"), "file-id", &context())
                    .unwrap()
            )
            .contains("private")
        );
        let decoded: crate::wire::SendFileData<'_> =
            serde_json::from_str(r#"{"fileName":"opaque"}"#).unwrap();
        assert_eq!(decoded.file_name, "opaque");
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            json!({"fileName":"opaque"})
        );
    }

    fn context() -> SendContext {
        SendContext { now_unix_nanos: 1 }
    }
    fn request(payload: &Value) -> TextSendRequest<'_, Value> {
        TextSendRequest {
            kind: 0,
            key: " future-key\0雪 ",
            password: None,
            max_access_count: None,
            expiration_ns: None,
            deletion_ns: 100,
            disabled: false,
            hide_email: None,
            emails: None,
            name: "opaque-name\0雪",
            notes: Some("opaque-notes"),
            text: Some(payload),
        }
    }
    fn token_request() -> SendAccessTokenRequest<'static> {
        SendAccessTokenRequest {
            grant_type: Some("send_access"),
            client_id: Some(""),
            send_id: Some("public-access-id"),
            password_hash_b64: None,
        }
    }
    fn value<T: Serialize>(response: T) -> Value {
        serde_json::to_value(response).unwrap()
    }

    #[test]
    fn send_owner_authentication_precedes_all_provider_calls() {
        let mut mock = Mock::new();
        let payload = json!({"text":"opaque"});
        let input = request(&payload);
        assert_eq!(
            VaultService::new(&mut mock)
                .get_send("", "send")
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(
            VaultService::new(&mut mock)
                .list_sends("")
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(
            VaultService::new(&mut mock)
                .create_text_send("", &input, &context())
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(
            VaultService::new(&mut mock)
                .update_text_send("", "send", &input, &context())
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(
            VaultService::new(&mut mock)
                .remove_send_password("", "send")
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(
            VaultService::new(&mut mock)
                .delete_send("", "send")
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(mock.calls.is_empty());
    }
    #[test]
    fn send_write_policy_precedes_owner_lookup_and_delete_bypasses_policy() {
        let mut mock = Mock::new();
        mock.policy.can_modify = false;
        let payload = json!({});
        let input = request(&payload);
        let error = VaultService::new(&mut mock)
            .update_text_send("alice", "missing", &input, &context())
            .unwrap_err();
        assert!(error.message.contains("only able to delete"));
        assert_eq!(mock.calls, ["policy"]);
        mock.calls.clear();
        mock.rows[0].disabled = true;
        mock.rows[0].deletion = 0;
        VaultService::new(&mut mock)
            .delete_send("alice", "send")
            .unwrap();
        assert_eq!(mock.calls, ["state", "delete"]);
        assert_eq!(mock.foreign_revision, 7);
        assert_eq!(mock.rows[0].owner, "bob");
    }
    #[test]
    fn send_hide_email_policy_is_requested_option_not_existing_metadata() {
        let mut mock = Mock::new();
        mock.policy.can_hide_email = false;
        let payload = json!({});
        let mut input = request(&payload);
        input.hide_email = Some(true);
        assert_eq!(
            VaultService::new(&mut mock)
                .update_text_send("alice", "missing", &input, &context())
                .unwrap_err()
                .field,
            Some("hideEmail")
        );
        assert_eq!(mock.calls, ["policy"]);
        mock.rows[0].hide = Some(true);
        mock.rows[0].password = Some("proof".into());
        mock.calls.clear();
        let response = value(
            VaultService::new(&mut mock)
                .remove_send_password("alice", "send")
                .unwrap(),
        );
        assert_eq!(response["hideEmail"], true);
        assert_eq!(response["password"], Value::Null);
        assert_eq!(mock.calls, ["policy", "state", "remove", "state", "read"]);
    }
    #[test]
    fn send_create_validation_order_and_exact_thirty_one_day_boundary() {
        let mut mock = Mock::new();
        let payload = json!({"text":"opaque"});
        let mut input = request(&payload);
        input.kind = 1;
        input.text = None;
        input.deletion_ns = SEND_DELETION_WINDOW_NANOS + 2;
        input.emails = Some("");
        input.max_access_count = Some(SendNumber::String("bad"));
        assert_eq!(
            VaultService::new(&mut mock)
                .create_text_send("alice", &input, &context())
                .unwrap_err()
                .message,
            "File sends should use /api/sends/file/v2"
        );
        input.kind = 2;
        assert_eq!(
            VaultService::new(&mut mock)
                .create_text_send("alice", &input, &context())
                .unwrap_err()
                .message,
            "Invalid Send type"
        );
        input.kind = 0;
        assert_eq!(
            VaultService::new(&mut mock)
                .create_text_send("alice", &input, &context())
                .unwrap_err()
                .field,
            Some("text")
        );
        input.text = Some(&payload);
        assert_eq!(
            VaultService::new(&mut mock)
                .create_text_send("alice", &input, &context())
                .unwrap_err()
                .field,
            Some("deletionDate")
        );
        input.deletion_ns = SEND_DELETION_WINDOW_NANOS + 1;
        assert_eq!(
            VaultService::new(&mut mock)
                .create_text_send("alice", &input, &context())
                .unwrap_err()
                .field,
            Some("emails")
        );
        input.emails = None;
        assert_eq!(
            VaultService::new(&mut mock)
                .create_text_send("alice", &input, &context())
                .unwrap_err()
                .message,
            "Can't convert to number"
        );
        assert!(mock.calls.iter().all(|call| *call == "policy"));
        input.max_access_count = Some(SendNumber::Integer(-1));
        input.expiration_ns = Some(-100);
        input.disabled = true;
        let response = value(
            VaultService::new(&mut mock)
                .create_text_send("alice", &input, &context())
                .unwrap(),
        );
        assert_eq!(response["maxAccessCount"], -1);
        assert_eq!(response["disabled"], true);
        assert_eq!(mock.rows[2].expiration, Some(-100));
    }
    #[test]
    fn send_update_owner_emails_type_date_text_number_order_and_past_dates() {
        let mut mock = Mock::new();
        let payload = json!({});
        let mut input = request(&payload);
        input.emails = Some("");
        input.kind = 1;
        input.text = None;
        input.deletion_ns = SEND_DELETION_WINDOW_NANOS + 2;
        assert_eq!(
            VaultService::new(&mut mock)
                .update_text_send("alice", "foreign", &input, &context())
                .unwrap_err(),
            not_found()
        );
        assert_eq!(
            VaultService::new(&mut mock)
                .update_text_send("alice", "send", &input, &context())
                .unwrap_err()
                .field,
            Some("emails")
        );
        input.emails = None;
        assert_eq!(
            VaultService::new(&mut mock)
                .update_text_send("alice", "send", &input, &context())
                .unwrap_err()
                .message,
            "Sends can't change type"
        );
        input.kind = 0;
        assert_eq!(
            VaultService::new(&mut mock)
                .update_text_send("alice", "send", &input, &context())
                .unwrap_err()
                .field,
            Some("deletionDate")
        );
        input.deletion_ns = -100;
        assert_eq!(
            VaultService::new(&mut mock)
                .update_text_send("alice", "send", &input, &context())
                .unwrap_err()
                .field,
            Some("text")
        );
        input.text = Some(&payload);
        input.max_access_count = Some(SendNumber::Integer(i64::MAX));
        assert_eq!(
            VaultService::new(&mut mock)
                .update_text_send("alice", "send", &input, &context())
                .unwrap_err()
                .message,
            "Number does not fit in i32"
        );
        input.max_access_count = None;
        assert!(
            VaultService::new(&mut mock)
                .update_text_send("alice", "send", &input, &context())
                .is_ok()
        );
        assert_eq!(mock.rows[0].deletion, -100);
    }
    #[test]
    fn send_password_none_preserves_update_some_empty_protects_and_remove_is_repeatable() {
        let mut mock = Mock::new();
        let payload = json!({"text":"opaque"});
        let mut input = request(&payload);
        mock.rows[0].password = Some("old\0雪".into());
        mock.rows[0].count = 7;
        let response = value(
            VaultService::new(&mut mock)
                .update_text_send("alice", "send", &input, &context())
                .unwrap(),
        );
        assert_eq!(response["accessCount"], 7);
        assert_eq!(mock.rows[0].password.as_deref(), Some("old\0雪"));
        input.password = Some(Secret::new(""));
        let response = value(
            VaultService::new(&mut mock)
                .update_text_send("alice", "send", &input, &context())
                .unwrap(),
        );
        assert_eq!(response["authType"], 1);
        assert_eq!(mock.rows[0].password.as_deref(), Some(""));
        for _ in 0..2 {
            let response = value(
                VaultService::new(&mut mock)
                    .remove_send_password("alice", "send")
                    .unwrap(),
            );
            assert_eq!(response["authType"], 2);
            assert_eq!(response["accessCount"], 7);
        }
        assert_eq!(mock.owner_revision, 4);
        assert_eq!(mock.foreign_revision, 7);
    }
    #[test]
    fn send_arbitrary_payload_and_opaque_metadata_reach_provider_without_core_restrictions() {
        for payload in [
            json!({"text":"opaque","extra":{"response":"keep"},"response":"remove"}),
            json!([1, "opaque", false]),
            json!(7),
            json!(false),
            json!("opaque-root"),
        ] {
            let mut mock = Mock::new();
            let input = request(&payload);
            let response = value(
                VaultService::new(&mut mock)
                    .create_text_send("alice", &input, &context())
                    .unwrap(),
            );
            let mut expected = payload.clone();
            if let Some(object) = expected.as_object_mut() {
                object.remove("response");
            }
            assert!(mock.rows[2].raw == expected);
            assert_eq!(mock.rows[2].key, input.key);
            assert_eq!(mock.rows[2].name, input.name);
            if !payload.is_object() {
                assert_eq!(response["text"], Value::Null);
            }
        }
    }
    #[test]
    fn send_owner_and_recipient_projections_have_exact_fields_and_list_owner_isolation() {
        let mut mock = Mock::new();
        mock.rows[0].password = Some("private-proof".into());
        mock.rows[0].disabled = true;
        mock.rows[0].deletion = -1;
        let owner = value(
            VaultService::new(&mut mock)
                .get_send("alice", "send")
                .unwrap(),
        );
        assert_eq!(owner.as_object().unwrap().len(), 18);
        assert_eq!(owner["password"], "encoded-owner-hash");
        assert_eq!(owner["file"], Value::Null);
        let list = value(VaultService::new(&mut mock).list_sends("alice").unwrap());
        assert_eq!(list.as_object().unwrap().len(), 3);
        assert_eq!(list["data"], json!([owner]));
        mock.rows[0].disabled = false;
        mock.rows[0].deletion = 100;
        mock.rows[0].hide = Some(true);
        let recipient = value(
            VaultService::new(&mut mock)
                .access_text_send(&Secret::new("recipient-proof"), &context())
                .unwrap(),
        );
        assert_eq!(recipient.as_object().unwrap().len(), 8);
        assert_eq!(recipient["id"], "public-access-id");
        assert_eq!(recipient["creatorIdentifier"], Value::Null);
        for field in [
            "key",
            "password",
            "notes",
            "owner_id",
            "accessCount",
            "maxAccessCount",
            "deletionDate",
            "revisionDate",
        ] {
            assert!(recipient.get(field).is_none());
        }
        mock.inject_foreign = true;
        assert_eq!(
            VaultService::new(&mut mock)
                .list_sends("alice")
                .unwrap_err(),
            not_found()
        );
    }
    #[test]
    fn send_access_grant_presence_availability_and_password_order_never_increment_count() {
        let mut mock = Mock::new();
        let mut input = token_request();
        input.grant_type = None;
        input.client_id = None;
        input.send_id = None;
        assert!(matches!(
            VaultService::new(&mut mock).authenticate_send_access(&input, &context()),
            Err(SendAccessError::Api(ApiError {
                field: Some("grant_type"),
                ..
            }))
        ));
        input.grant_type = Some("send_access");
        assert!(matches!(
            VaultService::new(&mut mock).authenticate_send_access(&input, &context()),
            Err(SendAccessError::Api(ApiError {
                field: Some("client_id"),
                ..
            }))
        ));
        input.client_id = Some("");
        assert!(matches!(
            VaultService::new(&mut mock).authenticate_send_access(&input, &context()),
            Err(SendAccessError::Api(ApiError {
                field: Some("send_id"),
                ..
            }))
        ));
        assert!(mock.calls.is_empty());
        input.send_id = Some("");
        assert_eq!(
            VaultService::new(&mut mock)
                .authenticate_send_access(&input, &context())
                .unwrap_err(),
            SendAccessError::InvalidSend
        );
        input.send_id = Some("public-access-id");
        mock.rows[0].password = Some("".into());
        mock.rows[0].maximum = Some(0);
        assert_eq!(
            VaultService::new(&mut mock)
                .authenticate_send_access(&input, &context())
                .unwrap_err(),
            SendAccessError::InvalidSend
        );
        mock.rows[0].maximum = None;
        mock.rows[0].disabled = true;
        assert_eq!(
            VaultService::new(&mut mock)
                .authenticate_send_access(&input, &context())
                .unwrap_err(),
            SendAccessError::InvalidSend
        );
        mock.rows[0].disabled = false;
        assert_eq!(
            VaultService::new(&mut mock)
                .authenticate_send_access(&input, &context())
                .unwrap_err(),
            SendAccessError::PasswordRequired
        );
        input.password_hash_b64 = Some(Secret::new("wrong"));
        assert_eq!(
            VaultService::new(&mut mock)
                .authenticate_send_access(&input, &context())
                .unwrap_err(),
            SendAccessError::InvalidPassword
        );
        input.password_hash_b64 = Some(Secret::new(""));
        let grant = VaultService::new(&mut mock)
            .authenticate_send_access(&input, &context())
            .unwrap();
        assert_eq!(grant.id(), "send");
        assert_eq!(grant.scope(), "api.send.access");
        assert_eq!(grant.expires_in(), 120);
        assert!(!grant.allows_refresh());
        assert_eq!(mock.rows[0].count, 0);
        assert_eq!(mock.owner_revision, 0);
        assert_eq!(mock.received_password, "");
    }
    #[test]
    fn send_unprotected_token_ignores_supplied_password_and_issued_capability_ignores_password_edits()
     {
        let mut mock = Mock::new();
        let mut input = token_request();
        input.password_hash_b64 = Some(Secret::new("ignored\0雪"));
        assert!(
            VaultService::new(&mut mock)
                .authenticate_send_access(&input, &context())
                .is_ok()
        );
        assert_eq!(mock.calls, ["resolve", "state"]);
        let payload = json!({});
        let mut write = request(&payload);
        write.password = Some(Secret::new("new-password"));
        let _ = VaultService::new(&mut mock)
            .update_text_send("alice", "send", &write, &context())
            .unwrap();
        mock.calls.clear();
        assert!(
            VaultService::new(&mut mock)
                .access_text_send(&Secret::new("recipient-proof"), &context())
                .is_ok()
        );
        assert_eq!(mock.calls, ["token", "state", "register", "read"]);
        let _ = VaultService::new(&mut mock)
            .remove_send_password("alice", "send")
            .unwrap();
        assert!(
            VaultService::new(&mut mock)
                .access_text_send(&Secret::new("recipient-proof"), &context())
                .is_ok()
        );
    }
    #[test]
    fn send_recipient_scope_strict_deadlines_and_current_deletion_precede_counter_writes() {
        let mut mock = Mock::new();
        assert_eq!(
            VaultService::new(&mut mock)
                .access_text_send(&Secret::new("owner-token"), &context())
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(mock.calls, ["token"]);
        for invalid in 0..3 {
            let mut mock = Mock::new();
            match invalid {
                0 => mock.rows[0].disabled = true,
                1 => mock.rows[0].expiration = Some(1),
                _ => mock.rows[0].deletion = 1,
            };
            assert_eq!(
                VaultService::new(&mut mock)
                    .access_text_send(&Secret::new("recipient-proof"), &context())
                    .unwrap_err()
                    .status_code(),
                404
            );
            assert_eq!(mock.owner_revision, 0);
            assert_eq!(mock.calls, ["token", "state"]);
        }
        let mut mock = Mock::new();
        mock.rows[0].expiration = Some(2);
        mock.rows[0].deletion = 2;
        assert!(
            VaultService::new(&mut mock)
                .access_text_send(&Secret::new("recipient-proof"), &context())
                .is_ok()
        );
        mock.rows.remove(0);
        assert_eq!(
            VaultService::new(&mut mock)
                .access_text_send(&Secret::new("recipient-proof"), &context())
                .unwrap_err()
                .status_code(),
            404
        );
    }
    #[test]
    fn send_recipient_already_maxed_and_racing_counter_denials_still_call_provider_cas() {
        for race in [false, true] {
            let mut mock = Mock::new();
            mock.race_exhaust = race;
            if !race {
                mock.rows[0].maximum = Some(0);
            }
            assert_eq!(
                VaultService::new(&mut mock)
                    .access_text_send(&Secret::new("recipient-proof"), &context())
                    .unwrap_err()
                    .status_code(),
                404
            );
            assert_eq!(mock.calls, ["token", "state", "register"]);
            assert_eq!(mock.rows[0].count, 0);
            assert_eq!(mock.rows[0].revision, 0);
            assert_eq!(mock.owner_revision, 1);
            assert_eq!(mock.foreign_revision, 7);
        }
    }
    #[test]
    fn send_counter_limit_is_enforced_per_access_not_per_issued_capability() {
        let mut mock = Mock::new();
        mock.rows[0].maximum = Some(2);
        for _ in 0..3 {
            assert!(
                VaultService::new(&mut mock)
                    .authenticate_send_access(&token_request(), &context())
                    .is_ok()
            );
        }
        for count in 1..=2 {
            assert!(
                VaultService::new(&mut mock)
                    .access_text_send(&Secret::new("recipient-proof"), &context())
                    .is_ok()
            );
            assert_eq!(mock.rows[0].count, count);
        }
        assert_eq!(
            VaultService::new(&mut mock)
                .access_text_send(&Secret::new("recipient-proof"), &context())
                .unwrap_err()
                .status_code(),
            404
        );
        assert_eq!(mock.rows[0].count, 2);
        assert_eq!(
            VaultService::new(&mut mock)
                .authenticate_send_access(&token_request(), &context())
                .unwrap_err(),
            SendAccessError::InvalidSend
        );
    }
    #[test]
    fn send_signed_number_conversion_preserves_source_ranges_and_does_not_trim() {
        for (input, expected) in [
            (SendNumber::Integer(i32::MIN.into()), i32::MIN),
            (SendNumber::Integer(i32::MAX.into()), i32::MAX),
            (SendNumber::String("+2"), 2),
            (SendNumber::String("-1"), -1),
        ] {
            assert_eq!(input.into_i32().unwrap(), expected);
        }
        for input in [
            SendNumber::String(" 1"),
            SendNumber::String("1 "),
            SendNumber::String(""),
            SendNumber::Integer(i64::MAX),
        ] {
            assert_eq!(input.into_i32().unwrap_err().status_code(), 400);
        }
    }
    #[test]
    fn send_provider_errors_keep_typed_mapping_and_do_not_forge_successful_mutations() {
        let payload = json!({});
        let input = request(&payload);
        for fail in ["policy", "create", "update", "remove", "delete"] {
            let mut mock = Mock::new();
            let rows = mock.rows.clone();
            mock.fail = Some(fail);
            mock.failure = ErrorKind::Conflict;
            let error = match fail {
                "policy" | "create" => VaultService::new(&mut mock)
                    .create_text_send("alice", &input, &context())
                    .unwrap_err(),
                "update" => VaultService::new(&mut mock)
                    .update_text_send("alice", "send", &input, &context())
                    .unwrap_err(),
                "remove" => VaultService::new(&mut mock)
                    .remove_send_password("alice", "send")
                    .unwrap_err(),
                _ => VaultService::new(&mut mock)
                    .delete_send("alice", "send")
                    .unwrap_err(),
            };
            assert_eq!(error.kind, ErrorKind::Conflict);
            assert!(mock.rows == rows);
            assert_eq!(mock.owner_revision, 0);
        }
        for fail in ["resolve", "state", "password"] {
            let mut mock = Mock::new();
            mock.fail = Some(fail);
            mock.rows[0].password = Some("proof".into());
            let mut input = token_request();
            input.password_hash_b64 = Some(Secret::new("proof"));
            assert!(matches!(
                VaultService::new(&mut mock).authenticate_send_access(&input, &context()),
                Err(SendAccessError::Api(ApiError {
                    kind: ErrorKind::Storage,
                    ..
                }))
            ));
            assert_eq!(mock.owner_revision, 0);
        }
    }
    #[test]
    fn send_borrowed_provider_and_all_private_debug_are_redacted() {
        let mut mock = Mock::new();
        let payload = json!({"text":"private-data"});
        let mut input = request(&payload);
        input.password = Some(Secret::new("private-proof"));
        assert_eq!(format!("{input:?}"), "TextSendRequest { .. }");
        assert_eq!(format!("{:?}", mock.rows[0].state()), "SendState { .. }");
        assert_eq!(format!("{:?}", mock.rows[0].record()), "SendRecord { .. }");
        let mut borrowed = &mut mock;
        let mut service = VaultService::new(&mut borrowed);
        assert_eq!(
            format!(
                "{:?}",
                service
                    .create_text_send("alice", &input, &context())
                    .unwrap()
            ),
            "SendOwnerResponse { .. }"
        );
        let grant = service
            .authenticate_send_access(&token_request(), &context())
            .unwrap();
        assert_eq!(format!("{grant:?}"), "AuthorizedSendAccessGrant { .. }");
        let token:SendAccessTokenRequest<'_>=serde_json::from_str(r#"{"grant_type":"send_access","client_id":"","send_id":"id","password_hash_b64":"private-proof"}"#).unwrap();
        assert_eq!(format!("{token:?}"), "SendAccessTokenRequest { .. }");
    }
}
