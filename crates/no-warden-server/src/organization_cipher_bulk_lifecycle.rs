//! Selected lifecycle operations commit independent, currently writable items.
//! An error retains earlier steps. Processing order/distribution is not part of
//! the protocol contract; source/reader checks remain in single-item commits.
use crate::{
    Failure, Store, organization_cipher_archive as archive,
    organization_cipher_lifecycle as lifecycle,
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    VaultService, organization_cipher_bulk_lifecycle::CipherLifecycleSelectionStorage,
    organization_cipher_lifecycle::CipherLifecycleOperation, route::Route,
};
use serde_json::json;

pub fn render_error(error: Failure) -> Response {
    if matches!(error.0, StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND) {
        lifecycle::render_error(error)
    } else {
        archive::render_error(error)
    }
}

pub fn dispatch(
    route: Route<'_>,
    actor: &str,
    body: &[u8],
    s: &mut Store,
) -> Result<Response, Failure> {
    let operation = match route {
        Route::CipherBulkTrash => CipherLifecycleOperation::Trash,
        Route::CipherBulkRestore => CipherLifecycleOperation::Restore,
        Route::CipherBulkDelete => CipherLifecycleOperation::PermanentDelete,
        _ => return Err(crate::missing()),
    };
    // The measured input has only lowercase `ids`; organizationId and other
    // unknown properties confer no authority. Reuse bounded owned decoding.
    let input = archive::selected_ids(body)?;
    let mut unique: Vec<&str> = input.iter().map(String::as_str).collect();
    unique.sort_unstable();
    unique.dedup();
    // Resource accounting only, not a whole-selection permission preflight.
    // These inherited 4096/8MiB policies are local, not measured native limits.
    archive::preflight(&s.db, actor, &unique)?;
    let mut ids = vec![""; input.len()];
    let mut seen = vec![false; input.len()];
    let count = VaultService::new(&mut *s).mutate_selected_cipher_lifecycle(
        actor,
        operation,
        input.iter().map(String::as_str),
        &mut ids,
        &mut seen,
    )?;
    if operation == CipherLifecycleOperation::Restore {
        let rows = ids[..count]
            .iter()
            .map(|id| archive::project(&s.db, actor, id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::json_response(
            json!({"object":"list","data":rows,"continuationToken":null}),
        ))
    } else {
        Ok(StatusCode::OK.into_response())
    }
}

impl CipherLifecycleSelectionStorage for Store {
    type LifecycleOrder = Vec<usize>;
    fn cipher_lifecycle_order(
        &mut self,
        _actor: &str,
        _operation: CipherLifecycleOperation,
        sorted_unique_ids: &[&str],
    ) -> rusqlite::Result<Self::LifecycleOrder> {
        // Owned, observational order. The core validates the entire permutation
        // before source lookups, then fresh WRITE admission precedes each step.
        Ok((0..sorted_unique_ids.len())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect())
    }
}

#[cfg(test)]
mod tests;
