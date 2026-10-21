//! Opt-in single-cipher lifecycle decisions with current source WRITE authority.
//!
//! Backend admission differs from advertised GET permissions: an assigned manage
//! grant can authorize a readonly source. This module does not change GET flags.
//! Opaque documents, timestamps, revision fanout and deletion cleanup stay in the
//! adapter. Groups, historical/hidden-grant lifecycle variants, attachments and
//! native backend/concurrency parity remain unverified.

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    organization_cipher_bulk_sharing::resolve_bulk_cipher_source_write_access,
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherCollectionAccessRecord, CipherSharingMembership,
        CipherSharingSource,
    },
    service::require_owner,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherLifecycleOperation {
    Trash,
    Restore,
    PermanentDelete,
}

/// One sealed source mutation. No body, lifecycle date, clock or encrypted payload
/// is accepted as authority. Construction follows exact scope and current WRITE.
pub struct ValidatedCipherLifecycle<'a> {
    actor: &'a str,
    cipher: &'a str,
    owner: Option<&'a str>,
    organization: Option<&'a str>,
    revision: &'a str,
    operation: CipherLifecycleOperation,
}
impl<'a> ValidatedCipherLifecycle<'a> {
    pub const fn actor(&self) -> &'a str {
        self.actor
    }
    pub const fn cipher_id(&self) -> &'a str {
        self.cipher
    }
    pub const fn personal_owner_id(&self) -> Option<&'a str> {
        self.owner
    }
    pub const fn organization_id(&self) -> Option<&'a str> {
        self.organization
    }
    pub const fn source_revision(&self) -> &'a str {
        self.revision
    }
    pub const fn operation(&self) -> CipherLifecycleOperation {
        self.operation
    }
    /// Invoke under the provider's mutation transaction before any writes. Reload
    /// the exact source, canonical membership and linked viewer grant facts; IDs,
    /// canonical ownership and opaque revision remain bound to this operation.
    pub fn validate_live<I: AsRef<str>, A: CipherCollectionAccessData + ?Sized>(
        &self,
        source: &CipherSharingSource<I>,
        member: Option<CipherSharingMembership<&str>>,
        access: &A,
    ) -> Result<(), ApiError> {
        validate_source(source, self.cipher)?;
        if source.owner_id.as_ref().map(AsRef::as_ref) != self.owner
            || source.organization_id.as_ref().map(AsRef::as_ref) != self.organization
            || source.revision.as_ref() != self.revision
        {
            return Err(invalid_snapshot());
        }
        authorize(self.actor, source, member, access)
    }
}
impl core::fmt::Debug for ValidatedCipherLifecycle<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCipherLifecycle([REDACTED])")
    }
}

/// All observational snapshots own backing storage independently of subsequent
/// cache-reusing provider calls, without Clone/Debug/serde requirements. Hold a
/// consistent operation lock through service, commit and immediate projection.
///
/// Commit reloads CURRENT source/member/linked grants and invokes validate_live.
/// Determine current READ viewers before mutation, especially PermanentDelete,
/// using existing scoped READ resolution; ordinary readonly readers receive
/// account revisions despite lacking WRITE. Confirmed no-grant, accepted and
/// revoked canonical members do not receive revisions in the measured fixtures.
/// Atomically perform the operation and advance eligible account revisions:
///
/// * Trash sets a fresh deletion date and cipher revision, even if already trashed.
/// * Restore clears deletion and refreshes cipher revision even if already active.
/// * PermanentDelete removes the source and its associated link/private/archive
///   database state; preserve unrelated accounts, folders, ciphers and keys.
///
/// Trash/Restore must reload and patch CURRENT opaque document without a minimal
/// DTO roundtrip. Preserve every other common encrypted field/key/extension,
/// canonical ownership/collections/creation and ALL viewers' archive dates,
/// favorites and folders. Errors roll back all operation changes and revisions;
/// notifications follow successful commit. Clocks, SQL and file handling stay in
/// the adapter. Rollback/live checks and database cleanup are local guarantees,
/// not native failure/concurrency or attachment-file parity. No request date or
/// deleted-state gate is introduced in this service; no intrinsic ID/count cap.
pub trait CipherLifecycleStorage: Storage {
    type LifecycleId: AsRef<str>;
    type LifecycleAccess: CipherCollectionAccessData;
    fn cipher_lifecycle_source(
        &mut self,
        cipher: &str,
    ) -> Result<Option<CipherSharingSource<Self::LifecycleId>>, Self::Error>;
    fn cipher_lifecycle_membership(
        &mut self,
        actor: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::LifecycleId>>, Self::Error>;
    fn cipher_lifecycle_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<Self::LifecycleId>,
    ) -> Result<Self::LifecycleAccess, Self::Error>;
    fn commit_cipher_lifecycle(
        &mut self,
        plan: &ValidatedCipherLifecycle<'_>,
    ) -> Result<(), Self::Error>;
}
impl<T: CipherLifecycleStorage + ?Sized> CipherLifecycleStorage for &mut T {
    type LifecycleId = T::LifecycleId;
    type LifecycleAccess = T::LifecycleAccess;
    fn cipher_lifecycle_source(
        &mut self,
        cipher: &str,
    ) -> Result<Option<CipherSharingSource<Self::LifecycleId>>, Self::Error> {
        (**self).cipher_lifecycle_source(cipher)
    }
    fn cipher_lifecycle_membership(
        &mut self,
        actor: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::LifecycleId>>, Self::Error> {
        (**self).cipher_lifecycle_membership(actor, organization)
    }
    fn cipher_lifecycle_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<Self::LifecycleId>,
    ) -> Result<Self::LifecycleAccess, Self::Error> {
        (**self).cipher_lifecycle_collections(actor, source)
    }
    fn commit_cipher_lifecycle(
        &mut self,
        plan: &ValidatedCipherLifecycle<'_>,
    ) -> Result<(), Self::Error> {
        (**self).commit_cipher_lifecycle(plan)
    }
}

impl<S: CipherLifecycleStorage> VaultService<S> {
    /// Admit one personal or canonical organization source using current WRITE,
    /// independent of GET delete/restore flags and any opaque document contents.
    pub fn mutate_cipher_lifecycle(
        &mut self,
        actor: &str,
        cipher: &str,
        operation: CipherLifecycleOperation,
    ) -> Result<(), ApiError> {
        require_owner(actor)?;
        let source = self
            .storage_mut()
            .cipher_lifecycle_source(cipher)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::invalid("cipher", "Cipher doesn't exist"))?;
        validate_source(&source, cipher)?;
        match source.organization_id.as_ref() {
            Some(organization) => {
                let member = self
                    .storage_mut()
                    .cipher_lifecycle_membership(actor, organization.as_ref())
                    .map_err(S::map_error)?;
                let access = self
                    .storage_mut()
                    .cipher_lifecycle_collections(actor, &source)
                    .map_err(S::map_error)?;
                authorize(
                    actor,
                    &source,
                    member.as_ref().map(CipherSharingMembership::view),
                    &access,
                )?;
            }
            None => {
                let empty: &[CipherCollectionAccessRecord<'_>] = &[];
                authorize(actor, &source, None, empty)?;
            }
        }
        self.storage_mut()
            .commit_cipher_lifecycle(&ValidatedCipherLifecycle {
                actor,
                cipher,
                owner: source.owner_id.as_ref().map(AsRef::as_ref),
                organization: source.organization_id.as_ref().map(AsRef::as_ref),
                revision: source.revision.as_ref(),
                operation,
            })
            .map_err(S::map_error)
    }
}
fn validate_source<I: AsRef<str>>(
    source: &CipherSharingSource<I>,
    expected: &str,
) -> Result<(), ApiError> {
    if expected.is_empty() || source.id.as_ref() != expected || source.revision.as_ref().is_empty()
    {
        return Err(invalid_snapshot());
    }
    source.ownership()?;
    Ok(())
}
fn authorize<I: AsRef<str>, A: CipherCollectionAccessData + ?Sized>(
    actor: &str,
    source: &CipherSharingSource<I>,
    member: Option<CipherSharingMembership<&str>>,
    access: &A,
) -> Result<(), ApiError> {
    if !resolve_bulk_cipher_source_write_access(actor, source.ownership()?, member, access)? {
        return Err(ApiError::invalid(
            "cipher",
            "Cipher is not write accessible",
        ));
    }
    Ok(())
}
fn invalid_snapshot() -> ApiError {
    ApiError::new(ErrorKind::Storage, "Invalid cipher lifecycle snapshot")
}

#[cfg(test)]
mod tests;
