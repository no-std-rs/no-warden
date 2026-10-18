//! Attachment authorization and metadata transitions over host-owned encrypted bytes.
//!
//! Multipart parsing, randomness, byte storage, quotas, transport limits, URL signing,
//! clocks, and notifications belong to the host. Hold the operation's lock/transaction
//! across authorization and commit. Ciphertext and encrypted filename/key strings remain
//! opaque; no encrypted-envelope format is imposed by these attachment operations.

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    bulk::CipherAccess,
    identity::Secret,
    service::require_owner,
    wire::{AttachmentRequest, LegacyAttachmentRequest},
};

pub const MAX_ATTACHMENT_BYTES: u64 = 525 * 1024 * 1024;
pub const ATTACHMENT_SIZE_LEEWAY_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentMetadata<'a> {
    pub cipher_id: &'a str,
    pub file_size: u64,
}

#[derive(Clone, Copy)]
pub struct AttachmentWrite<'a> {
    pub file_name: &'a str,
    pub key: Option<&'a str>,
    pub file_size: u64,
}

impl core::fmt::Debug for AttachmentWrite<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AttachmentWrite")
            .field("file_size", &self.file_size)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentAction {
    Reserve,
    Upload,
    Legacy,
    ReplaceLegacy,
    Delete,
    DiscardMismatch,
    UpdateMetadata,
}

/// A transition whose access, attachment association, and size were checked by the core.
#[derive(Clone, Copy, Debug)]
pub struct ValidatedAttachment<'a> {
    action: AttachmentAction,
    cipher_id: &'a str,
    attachment_id: &'a str,
    replaced_attachment_id: Option<&'a str>,
    write: Option<AttachmentWrite<'a>>,
}

impl<'a> ValidatedAttachment<'a> {
    pub const fn action(&self) -> AttachmentAction {
        self.action
    }
    pub const fn cipher_id(&self) -> &'a str {
        self.cipher_id
    }
    pub const fn attachment_id(&self) -> &'a str {
        self.attachment_id
    }
    pub const fn replaced_attachment_id(&self) -> Option<&'a str> {
        self.replaced_attachment_id
    }
    pub const fn write(&self) -> Option<AttachmentWrite<'a>> {
        self.write
    }
}

/// A host-verified download capability, scoped to both route identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedAttachmentDownload<'a> {
    cipher_id: &'a str,
    attachment_id: &'a str,
}

impl<'a> AuthorizedAttachmentDownload<'a> {
    pub const fn cipher_id(&self) -> &'a str {
        self.cipher_id
    }
    pub const fn attachment_id(&self) -> &'a str {
        self.attachment_id
    }
}

/// Opt-in persistence and capability verification for attachment services.
///
/// Reserve inserts metadata only, with no cipher/account revision change. Upload atomically
/// publishes host-staged encrypted bytes and records the plan's measured size, preserving
/// the reservation's filename/key. Legacy publishes a fresh metadata/byte record; ReplaceLegacy
/// atomically removes its old record/bytes/capabilities and creates the fresh record. This
/// atomic replacement is stronger than the reference server's delete-then-upload behavior.
/// Delete removes metadata, bytes, and outstanding capabilities. These successful byte/deletion
/// operations advance account revisions without changing the cipher revision/updated timestamp.
/// UpdateMetadata changes only filename/key; it has no byte or revision effects by itself.
///
/// Use insert-only writes for new IDs. Provider errors leave the prior state unchanged,
/// including revision and byte state, and notifications occur after commit. Publishing bytes
/// in a filesystem/object store may need staging and durable cleanup outside a DB transaction.
/// DiscardMismatch is an intentional mutation on an HTTP error path: remove the reservation,
/// any old bytes, and outstanding download capabilities, without revision changes. After that
/// commit the service returns an invalid-size error. Failed cleanup instead maps provider error.
///
/// A permanent cipher delete must remove all its attachments/bytes/capabilities; trash, restore,
/// and archive retain them. Quotas and host upload limits must be checked consistently with the
/// staged bytes. A plan's size never authorizes consuming a differently sized byte source.
/// Download verification must validate an opaque capability's expiry and both identifiers,
/// and require that its attachment still exists; bearer authentication is not substituted.
/// The host supplies scoped URLs (the pinned server uses a 60-second token, with JWT leeway).
pub trait AttachmentStorage: Storage {
    fn attachment_access(
        &mut self,
        owner: &str,
        cipher_id: &str,
    ) -> Result<Option<CipherAccess>, Self::Error> {
        Ok(self.cipher_metadata(cipher_id)?.map(|metadata| {
            let owned = metadata.owner_id == owner;
            CipherAccess {
                readable: owned,
                writable: owned,
            }
        }))
    }
    fn attachment_metadata(
        &mut self,
        attachment_id: &str,
    ) -> Result<Option<AttachmentMetadata<'_>>, Self::Error>;
    fn commit_attachment(
        &mut self,
        owner: &str,
        plan: &ValidatedAttachment<'_>,
    ) -> Result<(), Self::Error>;
    fn verify_attachment_download(
        &mut self,
        cipher_id: &str,
        attachment_id: &str,
        token: &Secret<'_>,
    ) -> Result<bool, Self::Error>;
}

impl<T: AttachmentStorage + ?Sized> AttachmentStorage for &mut T {
    fn attachment_access(
        &mut self,
        owner: &str,
        cipher_id: &str,
    ) -> Result<Option<CipherAccess>, Self::Error> {
        (**self).attachment_access(owner, cipher_id)
    }
    fn attachment_metadata(
        &mut self,
        attachment_id: &str,
    ) -> Result<Option<AttachmentMetadata<'_>>, Self::Error> {
        (**self).attachment_metadata(attachment_id)
    }
    fn commit_attachment(
        &mut self,
        owner: &str,
        plan: &ValidatedAttachment<'_>,
    ) -> Result<(), Self::Error> {
        (**self).commit_attachment(owner, plan)
    }
    fn verify_attachment_download(
        &mut self,
        cipher_id: &str,
        attachment_id: &str,
        token: &Secret<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).verify_attachment_download(cipher_id, attachment_id, token)
    }
}

fn unavailable() -> ApiError {
    ApiError::invalid(
        "attachmentId",
        "The attachment is unavailable for this operation.",
    )
}

fn validate_size(size: u64) -> Result<(), ApiError> {
    if size > MAX_ATTACHMENT_BYTES {
        return Err(ApiError::invalid(
            "fileSize",
            "The maximum attachment size is 525 MiB.",
        ));
    }
    Ok(())
}

fn legacy_write<'a>(
    request: &LegacyAttachmentRequest<'a>,
) -> Result<AttachmentWrite<'a>, ApiError> {
    validate_size(request.file_size)?;
    Ok(AttachmentWrite {
        file_name: request.file_name.ok_or(ApiError::invalid(
            "fileName",
            "An attachment filename is required.",
        ))?,
        key: Some(
            request
                .key
                .ok_or(ApiError::invalid("key", "An attachment key is required."))?,
        ),
        file_size: request.file_size,
    })
}

impl<S: AttachmentStorage> VaultService<S> {
    fn check_attachment_access(
        &mut self,
        owner: &str,
        cipher_id: &str,
        write: bool,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        if self
            .storage_mut()
            .attachment_access(owner, cipher_id)
            .map_err(S::map_error)?
            .is_some_and(|access| {
                if write {
                    access.writable
                } else {
                    access.readable
                }
            })
        {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    fn check_attachment(&mut self, cipher_id: &str, attachment_id: &str) -> Result<u64, ApiError> {
        match self
            .storage_mut()
            .attachment_metadata(attachment_id)
            .map_err(S::map_error)?
        {
            Some(metadata) if metadata.cipher_id == cipher_id => Ok(metadata.file_size),
            _ => Err(unavailable()),
        }
    }

    fn check_new_attachment(&mut self, attachment_id: &str) -> Result<(), ApiError> {
        if attachment_id.is_empty() {
            return Err(ApiError::invalid(
                "attachmentId",
                "A fresh attachment identifier is required.",
            ));
        }
        if self
            .storage_mut()
            .attachment_metadata(attachment_id)
            .map_err(S::map_error)?
            .is_some()
        {
            return Err(ApiError::new(
                ErrorKind::Conflict,
                "The attachment identifier already exists.",
            ));
        }
        Ok(())
    }

    pub fn reserve_attachment(
        &mut self,
        owner: &str,
        cipher_id: &str,
        attachment_id: &str,
        request: &AttachmentRequest<'_>,
    ) -> Result<(), ApiError> {
        self.check_attachment_access(owner, cipher_id, true)?;
        let size = u64::try_from(request.file_size)
            .map_err(|_| ApiError::invalid("fileSize", "Attachment size cannot be negative."))?;
        validate_size(size)?;
        self.check_new_attachment(attachment_id)?;
        self.storage_mut()
            .commit_attachment(
                owner,
                &ValidatedAttachment {
                    action: AttachmentAction::Reserve,
                    cipher_id,
                    attachment_id,
                    replaced_attachment_id: None,
                    write: Some(AttachmentWrite {
                        file_name: request.file_name,
                        key: Some(request.key),
                        file_size: size,
                    }),
                },
            )
            .map_err(S::map_error)
    }

    pub fn upload_attachment(
        &mut self,
        owner: &str,
        cipher_id: &str,
        attachment_id: &str,
        actual_size: u64,
    ) -> Result<(), ApiError> {
        self.check_attachment_access(owner, cipher_id, true)?;
        let declared = self.check_attachment(cipher_id, attachment_id)?;
        validate_size(actual_size)?;
        let mismatch = declared.abs_diff(actual_size) > ATTACHMENT_SIZE_LEEWAY_BYTES;
        self.storage_mut()
            .commit_attachment(
                owner,
                &ValidatedAttachment {
                    action: if mismatch {
                        AttachmentAction::DiscardMismatch
                    } else {
                        AttachmentAction::Upload
                    },
                    cipher_id,
                    attachment_id,
                    replaced_attachment_id: None,
                    // Upload keeps stored opaque metadata. Only its actual byte count changes.
                    write: (!mismatch).then_some(AttachmentWrite {
                        file_name: "",
                        key: None,
                        file_size: actual_size,
                    }),
                },
            )
            .map_err(S::map_error)?;
        if mismatch {
            return Err(ApiError::invalid(
                "fileSize",
                "Attachment size does not match its reservation.",
            ));
        }
        Ok(())
    }

    pub fn create_legacy_attachment(
        &mut self,
        owner: &str,
        cipher_id: &str,
        attachment_id: &str,
        request: &LegacyAttachmentRequest<'_>,
    ) -> Result<(), ApiError> {
        self.check_attachment_access(owner, cipher_id, true)?;
        let write = legacy_write(request)?;
        self.check_new_attachment(attachment_id)?;
        self.storage_mut()
            .commit_attachment(
                owner,
                &ValidatedAttachment {
                    action: AttachmentAction::Legacy,
                    cipher_id,
                    attachment_id,
                    replaced_attachment_id: None,
                    write: Some(write),
                },
            )
            .map_err(S::map_error)
    }

    pub fn replace_legacy_attachment(
        &mut self,
        owner: &str,
        cipher_id: &str,
        previous_id: &str,
        attachment_id: &str,
        request: &LegacyAttachmentRequest<'_>,
    ) -> Result<(), ApiError> {
        self.check_attachment_access(owner, cipher_id, true)?;
        self.check_attachment(cipher_id, previous_id)?;
        let write = legacy_write(request)?;
        self.check_new_attachment(attachment_id)?;
        self.storage_mut()
            .commit_attachment(
                owner,
                &ValidatedAttachment {
                    action: AttachmentAction::ReplaceLegacy,
                    cipher_id,
                    attachment_id,
                    replaced_attachment_id: Some(previous_id),
                    write: Some(write),
                },
            )
            .map_err(S::map_error)
    }

    pub fn delete_attachment(
        &mut self,
        owner: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<(), ApiError> {
        self.check_attachment_access(owner, cipher_id, true)?;
        self.check_attachment(cipher_id, attachment_id)?;
        self.storage_mut()
            .commit_attachment(
                owner,
                &ValidatedAttachment {
                    action: AttachmentAction::Delete,
                    cipher_id,
                    attachment_id,
                    replaced_attachment_id: None,
                    write: None,
                },
            )
            .map_err(S::map_error)
    }

    pub fn authorize_attachment_read(
        &mut self,
        owner: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<(), ApiError> {
        self.check_attachment_access(owner, cipher_id, false)?;
        self.check_attachment(cipher_id, attachment_id)?;
        Ok(())
    }

    /// Update a matching attachment's metadata only. For `attachments2` maps, the host
    /// implements missing-ID skip and foreign-cipher break before calling this method;
    /// the pinned source's map iteration order and partial-update behavior are unspecified.
    pub fn update_attachment_metadata(
        &mut self,
        owner: &str,
        cipher_id: &str,
        attachment_id: &str,
        file_name: &str,
        key: &str,
    ) -> Result<(), ApiError> {
        self.check_attachment_access(owner, cipher_id, true)?;
        let file_size = self.check_attachment(cipher_id, attachment_id)?;
        self.storage_mut()
            .commit_attachment(
                owner,
                &ValidatedAttachment {
                    action: AttachmentAction::UpdateMetadata,
                    cipher_id,
                    attachment_id,
                    replaced_attachment_id: None,
                    write: Some(AttachmentWrite {
                        file_name,
                        key: Some(key),
                        file_size,
                    }),
                },
            )
            .map_err(S::map_error)
    }

    pub fn authorize_attachment_download<'a>(
        &mut self,
        cipher_id: &'a str,
        attachment_id: &'a str,
        token: &Secret<'_>,
    ) -> Result<AuthorizedAttachmentDownload<'a>, ApiError> {
        if !self
            .storage_mut()
            .verify_attachment_download(cipher_id, attachment_id, token)
            .map_err(S::map_error)?
        {
            return Err(ApiError::new(
                ErrorKind::NotFound,
                "The attachment download is unavailable.",
            ));
        }
        Ok(AuthorizedAttachmentDownload {
            cipher_id,
            attachment_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use std::{
        collections::BTreeMap,
        string::{String, ToString},
        vec::Vec,
    };

    #[derive(Clone, Copy, Debug)]
    enum Failure {
        Backend,
        Conflict,
    }

    #[derive(Clone, Eq, PartialEq)]
    struct Record {
        cipher: String,
        name: String,
        key: Option<String>,
        size: u64,
        // A virtual opaque byte source lets boundary tests avoid allocating 525 MiB.
        bytes: Option<(&'static str, u64)>,
    }
    impl core::fmt::Debug for Record {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("Record")
                .field("cipher", &self.cipher)
                .field("size", &self.size)
                .field("uploaded", &self.bytes.is_some())
                .finish_non_exhaustive()
        }
    }

    #[derive(Clone)]
    struct Memory {
        ciphers: BTreeMap<String, &'static str>,
        attachments: BTreeMap<String, Record>,
        pending: (&'static str, u64),
        account_revision: usize,
        cipher_revision: usize,
        capability: Option<String>,
        capability_valid: bool,
        actions: Vec<AttachmentAction>,
        fail: Option<Failure>,
    }
    impl core::fmt::Debug for Memory {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("Memory")
                .field("actions", &self.actions)
                .finish_non_exhaustive()
        }
    }

    macro_rules! unused_storage_methods {
        () => {
            fn account_exists(&mut self, _: &str) -> Result<bool, Failure> {
                unreachable!()
            }
            fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), Failure> {
                unreachable!()
            }
            fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
                unreachable!()
            }
            fn save_folder(
                &mut self,
                _: &str,
                _: &str,
                _: &FolderRequest<'_>,
            ) -> Result<(), Failure> {
                unreachable!()
            }
            fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), Failure> {
                unreachable!()
            }
            fn save_cipher(
                &mut self,
                _: &str,
                _: &str,
                _: &CipherRequest<'_>,
            ) -> Result<(), Failure> {
                unreachable!()
            }
            fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), Failure> {
                unreachable!()
            }
            fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), Failure> {
                unreachable!()
            }
        };
    }

    impl Storage for Memory {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            match error {
                Failure::Backend => {
                    ApiError::new(ErrorKind::Storage, "Attachment provider failed.")
                }
                Failure::Conflict => {
                    ApiError::new(ErrorKind::Conflict, "Retry the attachment operation.")
                }
            }
        }
        fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
            Ok(self.ciphers.get(id).map(|owner| ItemMetadata {
                owner_id: owner,
                deleted: false,
            }))
        }
        unused_storage_methods!();
    }

    impl AttachmentStorage for Memory {
        fn attachment_metadata(
            &mut self,
            id: &str,
        ) -> Result<Option<AttachmentMetadata<'_>>, Failure> {
            Ok(self.attachments.get(id).map(|record| AttachmentMetadata {
                cipher_id: &record.cipher,
                file_size: record.size,
            }))
        }
        fn commit_attachment(
            &mut self,
            _: &str,
            plan: &ValidatedAttachment<'_>,
        ) -> Result<(), Failure> {
            self.actions.push(plan.action());
            let mut staged = self.clone();
            let record = |write: AttachmentWrite<'_>, bytes| Record {
                cipher: plan.cipher_id().to_string(),
                name: write.file_name.to_string(),
                key: write.key.map(ToString::to_string),
                size: write.file_size,
                bytes,
            };
            match plan.action() {
                AttachmentAction::Reserve => {
                    assert!(
                        staged
                            .attachments
                            .insert(
                                plan.attachment_id().to_string(),
                                record(plan.write().unwrap(), None)
                            )
                            .is_none()
                    );
                }
                AttachmentAction::Legacy | AttachmentAction::ReplaceLegacy => {
                    let write = plan.write().unwrap();
                    assert_eq!(write.file_size, staged.pending.1);
                    if let Some(old) = plan.replaced_attachment_id() {
                        staged.attachments.remove(old).unwrap();
                        if staged.capability.as_deref() == Some(old) {
                            staged.capability = None;
                        }
                    }
                    assert!(
                        staged
                            .attachments
                            .insert(
                                plan.attachment_id().to_string(),
                                record(write, Some(staged.pending))
                            )
                            .is_none()
                    );
                    staged.account_revision += 1;
                }
                AttachmentAction::Upload => {
                    let write = plan.write().unwrap();
                    assert_eq!(write.file_size, staged.pending.1);
                    let record = staged.attachments.get_mut(plan.attachment_id()).unwrap();
                    record.size = write.file_size;
                    record.bytes = Some(staged.pending);
                    staged.account_revision += 1;
                }
                AttachmentAction::Delete | AttachmentAction::DiscardMismatch => {
                    staged.attachments.remove(plan.attachment_id()).unwrap();
                    if staged.capability.as_deref() == Some(plan.attachment_id()) {
                        staged.capability = None;
                    }
                    if plan.action() == AttachmentAction::Delete {
                        staged.account_revision += 1;
                    }
                }
                AttachmentAction::UpdateMetadata => {
                    let write = plan.write().unwrap();
                    let record = staged.attachments.get_mut(plan.attachment_id()).unwrap();
                    record.name = write.file_name.to_string();
                    record.key = write.key.map(ToString::to_string);
                }
            }
            // Inject an error after all staged byte/metadata/revision changes.
            if let Some(error) = self.fail {
                return Err(error);
            }
            *self = staged;
            Ok(())
        }
        fn verify_attachment_download(
            &mut self,
            cipher: &str,
            attachment: &str,
            token: &Secret<'_>,
        ) -> Result<bool, Failure> {
            Ok(self.capability_valid
                && token.expose_secret() == "opaque-capability"
                && self.capability.as_deref() == Some(attachment)
                && self
                    .attachments
                    .get(attachment)
                    .is_some_and(|record| record.cipher == cipher))
        }
    }

    #[derive(Debug)]
    struct ReadOnly(Memory);
    impl Storage for ReadOnly {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            Memory::map_error(error)
        }
        fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
            self.0.cipher_metadata(id)
        }
        unused_storage_methods!();
    }
    impl AttachmentStorage for ReadOnly {
        fn attachment_access(
            &mut self,
            _: &str,
            cipher: &str,
        ) -> Result<Option<CipherAccess>, Failure> {
            Ok(self.0.ciphers.contains_key(cipher).then_some(CipherAccess {
                readable: true,
                writable: false,
            }))
        }
        fn attachment_metadata(
            &mut self,
            id: &str,
        ) -> Result<Option<AttachmentMetadata<'_>>, Failure> {
            self.0.attachment_metadata(id)
        }
        fn commit_attachment(
            &mut self,
            owner: &str,
            plan: &ValidatedAttachment<'_>,
        ) -> Result<(), Failure> {
            self.0.commit_attachment(owner, plan)
        }
        fn verify_attachment_download(
            &mut self,
            cipher: &str,
            attachment: &str,
            token: &Secret<'_>,
        ) -> Result<bool, Failure> {
            self.0.verify_attachment_download(cipher, attachment, token)
        }
    }

    fn memory() -> Memory {
        Memory {
            ciphers: [
                ("cipher".into(), "alice"),
                ("another".into(), "alice"),
                ("foreign".into(), "bob"),
            ]
            .into(),
            attachments: BTreeMap::new(),
            pending: ("opaque bytes", 17),
            account_revision: 0,
            cipher_revision: 7,
            capability: None,
            capability_valid: true,
            actions: Vec::new(),
            fail: None,
        }
    }
    fn request(size: i64) -> AttachmentRequest<'static> {
        AttachmentRequest {
            file_name: "opaque encrypted filename",
            key: "opaque wrapped key",
            file_size: size,
            admin_request: None,
        }
    }
    fn legacy(size: u64) -> LegacyAttachmentRequest<'static> {
        LegacyAttachmentRequest {
            file_name: Some("new opaque encrypted filename"),
            key: Some("new opaque wrapped key"),
            file_size: size,
        }
    }
    fn uploaded() -> Memory {
        let mut storage = memory();
        VaultService::new(&mut storage)
            .reserve_attachment("alice", "cipher", "file", &request(17))
            .unwrap();
        VaultService::new(&mut storage)
            .upload_attachment("alice", "cipher", "file", 17)
            .unwrap();
        storage.capability = Some("file".into());
        storage
    }
    fn snapshot(storage: &Memory) -> (BTreeMap<String, Record>, usize, usize, Option<String>) {
        (
            storage.attachments.clone(),
            storage.account_revision,
            storage.cipher_revision,
            storage.capability.clone(),
        )
    }

    #[test]
    fn reservations_validate_declared_sizes_without_changing_revisions_or_opaque_metadata() {
        let mut storage = memory();
        for size in [-1, MAX_ATTACHMENT_BYTES as i64 + 1] {
            assert_eq!(
                VaultService::new(&mut storage)
                    .reserve_attachment("alice", "cipher", "invalid", &request(size))
                    .unwrap_err()
                    .field,
                Some("fileSize")
            );
        }
        assert!(storage.actions.is_empty());
        for (id, size) in [("zero", 0), ("max", MAX_ATTACHMENT_BYTES as i64)] {
            VaultService::new(&mut storage)
                .reserve_attachment("alice", "cipher", id, &request(size))
                .unwrap();
            assert_eq!(storage.attachments[id].size, size as u64);
            assert!(storage.attachments[id].bytes.is_none());
            assert_eq!(storage.attachments[id].name, "opaque encrypted filename");
            assert_eq!(
                storage.attachments[id].key.as_deref(),
                Some("opaque wrapped key")
            );
        }
        assert_eq!(storage.account_revision, 0);
        assert_eq!(storage.cipher_revision, 7);
        assert_eq!(
            VaultService::new(&mut storage)
                .reserve_attachment("alice", "cipher", "max", &request(0))
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );
    }

    #[test]
    fn upload_tolerance_is_inclusive_and_keeps_reservation_metadata() {
        let declared = ATTACHMENT_SIZE_LEEWAY_BYTES * 2;
        for actual in [
            declared - ATTACHMENT_SIZE_LEEWAY_BYTES,
            declared,
            declared + ATTACHMENT_SIZE_LEEWAY_BYTES,
        ] {
            let mut storage = memory();
            VaultService::new(&mut storage)
                .reserve_attachment("alice", "cipher", "file", &request(declared as i64))
                .unwrap();
            storage.pending = ("replacement opaque bytes", actual);
            VaultService::new(&mut storage)
                .upload_attachment("alice", "cipher", "file", actual)
                .unwrap();
            let record = &storage.attachments["file"];
            assert_eq!(record.size, actual);
            assert_eq!(record.bytes, Some(storage.pending));
            assert_eq!(record.name, "opaque encrypted filename");
            assert_eq!(record.key.as_deref(), Some("opaque wrapped key"));
            assert_eq!(storage.account_revision, 1);
            assert_eq!(storage.cipher_revision, 7);
        }
    }

    #[test]
    fn mismatched_upload_intentionally_discards_metadata_bytes_and_capability_then_errors() {
        for actual in [0, ATTACHMENT_SIZE_LEEWAY_BYTES * 3 + 1] {
            let mut storage = uploaded();
            storage.attachments.get_mut("file").unwrap().size = ATTACHMENT_SIZE_LEEWAY_BYTES * 2;
            let revision = storage.account_revision;
            let error = VaultService::new(&mut storage)
                .upload_attachment("alice", "cipher", "file", actual)
                .unwrap_err();
            assert_eq!(error.status_code(), 400);
            assert_eq!(error.field, Some("fileSize"));
            assert!(!storage.attachments.contains_key("file"));
            assert!(storage.capability.is_none());
            assert_eq!(storage.account_revision, revision);
            assert_eq!(storage.cipher_revision, 7);
            assert_eq!(
                storage.actions.last(),
                Some(&AttachmentAction::DiscardMismatch)
            );
        }
    }

    #[test]
    fn read_only_access_does_not_authorize_any_attachment_mutation() {
        let mut storage = ReadOnly(uploaded());
        let before = snapshot(&storage.0);
        let attempts = storage.0.actions.len();
        VaultService::new(&mut storage)
            .authorize_attachment_read("reader", "cipher", "file")
            .unwrap();
        let mut service = VaultService::new(&mut storage);
        let errors = [
            service
                .reserve_attachment("reader", "cipher", "new", &request(17))
                .unwrap_err(),
            service
                .upload_attachment("reader", "cipher", "file", 17)
                .unwrap_err(),
            service
                .create_legacy_attachment("reader", "cipher", "new", &legacy(17))
                .unwrap_err(),
            service
                .replace_legacy_attachment("reader", "cipher", "file", "new", &legacy(17))
                .unwrap_err(),
            service
                .delete_attachment("reader", "cipher", "file")
                .unwrap_err(),
            service
                .update_attachment_metadata("reader", "cipher", "file", "name", "key")
                .unwrap_err(),
        ];
        assert!(errors.iter().all(|error| error.status_code() == 400));
        assert_eq!(snapshot(&storage.0), before);
        assert_eq!(storage.0.actions.len(), attempts);
    }

    #[test]
    fn foreign_missing_and_misassociated_attachments_cannot_mutate_or_discard_data() {
        let mut storage = uploaded();
        let before = snapshot(&storage);
        let attempts = storage.actions.len();
        for (owner, cipher, attachment) in [
            ("bob", "cipher", "file"),
            ("alice", "another", "file"),
            ("alice", "cipher", "absent"),
        ] {
            let mut service = VaultService::new(&mut storage);
            assert_eq!(
                service
                    .authorize_attachment_read(owner, cipher, attachment)
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(
                service
                    .upload_attachment(owner, cipher, attachment, MAX_ATTACHMENT_BYTES)
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(
                service
                    .delete_attachment(owner, cipher, attachment)
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(
                service
                    .update_attachment_metadata(owner, cipher, attachment, "name", "key")
                    .unwrap_err()
                    .status_code(),
                400
            );
        }
        assert_eq!(
            VaultService::new(&mut storage)
                .reserve_attachment("", "cipher", "new", &request(17))
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
        assert_eq!(snapshot(&storage), before);
        assert_eq!(storage.actions.len(), attempts);
    }

    #[test]
    fn legacy_replacement_and_metadata_updates_preserve_their_distinct_byte_and_revision_effects() {
        let mut storage = uploaded();
        let original_bytes = storage.attachments["file"].bytes;
        let revision = storage.account_revision;
        VaultService::new(&mut storage)
            .update_attachment_metadata(
                "alice",
                "cipher",
                "file",
                "changed opaque name",
                "changed opaque key",
            )
            .unwrap();
        assert_eq!(storage.attachments["file"].bytes, original_bytes);
        assert_eq!(storage.attachments["file"].size, 17);
        assert_eq!(storage.attachments["file"].name, "changed opaque name");
        assert_eq!(storage.account_revision, revision);
        let missing = LegacyAttachmentRequest {
            file_name: None,
            ..legacy(17)
        };
        assert!(
            VaultService::new(&mut storage)
                .replace_legacy_attachment("alice", "cipher", "file", "new", &missing)
                .is_err()
        );
        assert!(storage.attachments.contains_key("file"));
        let missing = LegacyAttachmentRequest {
            key: None,
            ..legacy(17)
        };
        assert!(
            VaultService::new(&mut storage)
                .create_legacy_attachment("alice", "cipher", "new", &missing)
                .is_err()
        );
        storage.pending = ("new opaque bytes", 5);
        VaultService::new(&mut storage)
            .replace_legacy_attachment("alice", "cipher", "file", "new", &legacy(5))
            .unwrap();
        assert!(!storage.attachments.contains_key("file"));
        assert!(storage.capability.is_none());
        assert_eq!(storage.attachments["new"].bytes, Some(storage.pending));
        assert_eq!(storage.account_revision, revision + 1);
        assert_eq!(storage.cipher_revision, 7);
    }

    #[test]
    fn provider_failures_roll_back_bytes_metadata_capabilities_and_revisions_for_every_action() {
        for action in [
            AttachmentAction::Reserve,
            AttachmentAction::Upload,
            AttachmentAction::Legacy,
            AttachmentAction::ReplaceLegacy,
            AttachmentAction::Delete,
            AttachmentAction::DiscardMismatch,
            AttachmentAction::UpdateMetadata,
        ] {
            for failure in [Failure::Backend, Failure::Conflict] {
                let mut storage = uploaded();
                let before = snapshot(&storage);
                storage.fail = Some(failure);
                let mut service = VaultService::new(&mut storage);
                let error = match action {
                    AttachmentAction::Reserve => {
                        service.reserve_attachment("alice", "cipher", "new", &request(17))
                    }
                    AttachmentAction::Upload => {
                        service.upload_attachment("alice", "cipher", "file", 17)
                    }
                    AttachmentAction::Legacy => {
                        service.create_legacy_attachment("alice", "cipher", "new", &legacy(17))
                    }
                    AttachmentAction::ReplaceLegacy => service.replace_legacy_attachment(
                        "alice",
                        "cipher",
                        "file",
                        "new",
                        &legacy(17),
                    ),
                    AttachmentAction::Delete => {
                        service.delete_attachment("alice", "cipher", "file")
                    }
                    AttachmentAction::DiscardMismatch => service.upload_attachment(
                        "alice",
                        "cipher",
                        "file",
                        ATTACHMENT_SIZE_LEEWAY_BYTES + 18,
                    ),
                    AttachmentAction::UpdateMetadata => service.update_attachment_metadata(
                        "alice", "cipher", "file", "changed", "changed",
                    ),
                }
                .unwrap_err();
                assert_eq!(
                    error.kind,
                    match failure {
                        Failure::Backend => ErrorKind::Storage,
                        Failure::Conflict => ErrorKind::Conflict,
                    }
                );
                assert_eq!(snapshot(&storage), before);
                assert_eq!(storage.actions.last(), Some(&action));
            }
        }
    }

    #[test]
    fn downloads_require_an_unexpired_capability_scoped_to_both_existing_identifiers() {
        let mut storage = uploaded();
        let token = Secret::new("opaque-capability");
        let grant = VaultService::new(&mut storage)
            .authorize_attachment_download("cipher", "file", &token)
            .unwrap();
        assert_eq!(grant.cipher_id(), "cipher");
        assert_eq!(grant.attachment_id(), "file");
        for (cipher, attachment, token) in [
            ("another", "file", Secret::new("opaque-capability")),
            ("cipher", "another", Secret::new("opaque-capability")),
            ("cipher", "file", Secret::new("wrong-capability")),
        ] {
            let error = VaultService::new(&mut storage)
                .authorize_attachment_download(cipher, attachment, &token)
                .unwrap_err();
            assert_eq!(error.status_code(), 404);
            assert!(!std::format!("{error:?}").contains("capability"));
        }
        storage.capability_valid = false;
        assert_eq!(
            VaultService::new(&mut storage)
                .authorize_attachment_download("cipher", "file", &token)
                .unwrap_err()
                .status_code(),
            404
        );
        storage.capability_valid = true;
        VaultService::new(&mut storage)
            .delete_attachment("alice", "cipher", "file")
            .unwrap();
        assert_eq!(
            VaultService::new(&mut storage)
                .authorize_attachment_download("cipher", "file", &token)
                .unwrap_err()
                .status_code(),
            404
        );
        assert_eq!(storage.cipher_revision, 7);
    }
}
