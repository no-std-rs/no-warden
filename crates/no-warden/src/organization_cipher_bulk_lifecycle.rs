//! Opt-in selected lifecycle orchestration with durable, independently admitted steps.
//!
//! Native selected Trash, Restore and PermanentDelete can retain successful items
//! and their current-reader revision fanout before a later error. Native order can
//! vary for identical selections; this module prescribes no request-order prefix
//! or permutation distribution. Storage owns that choice and each atomic step.

use crate::{
    ApiError, ErrorKind, VaultService,
    organization_cipher_lifecycle::{CipherLifecycleOperation, CipherLifecycleStorage},
    service::require_owner,
};

/// Separate opt-in selected behavior; existing globally atomic bulk providers and
/// the single lifecycle sealed plan remain unchanged. Hold the operation lock
/// across order selection, per-item admission, commit and response projection.
///
/// Each item reuses current WRITE admission and the existing sealed lifecycle
/// commit, including its live exact source/scope/revision checks and atomic CURRENT
/// READERS revision fanout. This is not selected archive's actor-only policy. Each
/// completed step is durable before the next lookup; a later lookup, admission or
/// commit error retains earlier steps. The failing step's local rollback contract
/// does not claim native injected-failure or concurrency parity. Store clocks,
/// opaque document mutation, reader enumeration and Restore rows in the adapter.
pub trait CipherLifecycleSelectionStorage: CipherLifecycleStorage {
    /// Own stable backing storage independent of caches reused by later calls.
    /// No Clone, Debug, serde, allocation or intrinsic count bound is required.
    type LifecycleOrder: AsRef<[usize]>;

    /// Observational permutation of the provided sorted UNIQUE exact IDs. Return
    /// every index once; the service checks the complete order BEFORE any target
    /// lookup or write. This call must not mutate source/annotation/account data.
    /// Body organization IDs never supply canonical source authority here.
    fn cipher_lifecycle_order(
        &mut self,
        actor: &str,
        operation: CipherLifecycleOperation,
        sorted_unique_ids: &[&str],
    ) -> Result<Self::LifecycleOrder, Self::Error>;
}
impl<T: CipherLifecycleSelectionStorage + ?Sized> CipherLifecycleSelectionStorage for &mut T {
    type LifecycleOrder = T::LifecycleOrder;
    fn cipher_lifecycle_order(
        &mut self,
        actor: &str,
        operation: CipherLifecycleOperation,
        sorted_unique_ids: &[&str],
    ) -> Result<Self::LifecycleOrder, Self::Error> {
        (**self).cipher_lifecycle_order(actor, operation, sorted_unique_ids)
    }
}

impl<S: CipherLifecycleSelectionStorage> VaultService<S> {
    /// Decode separately with the existing caller-bounded `CipherIdsRequest` if
    /// needed. Raw ID scratch includes duplicates; bool scratch covers UNIQUE
    /// IDs. Exact strings are copied without normalization. There is no intrinsic
    /// ID/count cap, clock, payload serializer or body organization field.
    ///
    /// Copy/sort/deduplicate and validate the complete provider-owned permutation
    /// before any source admission. Then freshly admit and commit each unique ID
    /// through `mutate_cipher_lifecycle`. A later failure retains completed steps;
    /// no globally cached authority or whole-selection transaction is introduced.
    /// Empty input makes no provider calls. On success the count's prefix of ID
    /// scratch contains sorted unique response-lookup IDs, not native row order.
    /// Scratch contents are unspecified on error; input/seen-capacity errors occur
    /// before the observational order call or any data mutation.
    pub fn mutate_selected_cipher_lifecycle<'ids>(
        &mut self,
        actor: &str,
        operation: CipherLifecycleOperation,
        ids: impl IntoIterator<Item = &'ids str>,
        id_scratch: &mut [&'ids str],
        seen_scratch: &mut [bool],
    ) -> Result<usize, ApiError> {
        require_owner(actor)?;
        let mut count = 0;
        for id in ids {
            *id_scratch.get_mut(count).ok_or_else(scratch_too_small)? = id;
            count += 1;
        }
        let selected = &mut id_scratch[..count];
        selected.sort_unstable();
        let mut unique = 0;
        for index in 0..selected.len() {
            if unique == 0 || selected[index] != selected[unique - 1] {
                selected[unique] = selected[index];
                unique += 1;
            }
        }
        if seen_scratch.len() < unique {
            return Err(scratch_too_small());
        }
        if unique == 0 {
            return Ok(0);
        }
        let selected = &selected[..unique];
        let order = self
            .storage_mut()
            .cipher_lifecycle_order(actor, operation, selected)
            .map_err(S::map_error)?;
        let order = order.as_ref();
        let seen = &mut seen_scratch[..unique];
        seen.fill(false);
        if order.len() != unique {
            return Err(invalid_order());
        }
        for &index in order {
            let slot = seen.get_mut(index).ok_or_else(invalid_order)?;
            if *slot {
                return Err(invalid_order());
            }
            *slot = true;
        }
        for &index in order {
            self.mutate_cipher_lifecycle(actor, selected[index], operation)?;
        }
        Ok(unique)
    }
}
fn scratch_too_small() -> ApiError {
    ApiError::invalid("ids", "Selection scratch capacity is too small")
}
fn invalid_order() -> ApiError {
    ApiError::new(ErrorKind::Storage, "Invalid lifecycle selection order")
}

#[cfg(test)]
mod tests;
