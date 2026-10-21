//! Shared attachment reads reuse the allocation-free cipher access resolver.
//! Download capabilities remain bearer-independent and scoped by the provider.
use crate::{Failure, Store, attachments, cipher_reads, organization_cipher_archive as archive};
use axum::{
    body::{Body, HttpBody},
    http::{Method, header},
    response::Response,
};
use no_warden::{VaultService, bulk::CipherAccess, route};
use rusqlite::{Connection, OptionalExtension, params};

/// Only the two measured read routes receive HEAD's GET authorization semantics.
pub fn route(path: &str) -> Option<route::Route<'_>> {
    match route::classify(route::Method::Get, path) {
        Some(found @ (route::Route::AttachmentGet(..) | route::Route::AttachmentDownload(..))) => {
            Some(found)
        }
        _ => None,
    }
}

pub fn error_scope(method: &Method, path: &str) -> bool {
    match route(path) {
        Some(route::Route::AttachmentDownload(..)) => true,
        Some(route::Route::AttachmentGet(..)) => {
            matches!(*method, Method::GET | Method::HEAD | Method::PUT)
        }
        _ => false,
    }
}

pub fn render_error(error: Failure) -> Response {
    crate::organization_cipher_lifecycle::render_error(error)
}

pub fn metadata(
    store: &mut Store,
    actor: &str,
    cipher: &str,
    attachment: &str,
    base: &str,
) -> Result<Response, Failure> {
    // Authenticate before validating this UUID. Keep its spelling:
    // an uppercase source is not an alias, whereas attachment lookup folds case.
    let cipher = cipher_reads::path_id(cipher)?;
    VaultService::new(&mut *store).authorize_attachment_read(actor, &cipher, attachment)?;
    let record = attachments::load(&store.db, attachment)?.ok_or_else(crate::missing)?;
    Ok(crate::json_response(attachments::wire(
        &store.db, base, &record,
    )?))
}

pub fn access(
    db: &Connection,
    actor: &str,
    cipher: &str,
) -> rusqlite::Result<Option<CipherAccess>> {
    // Negative loading filter only. SQL cannot confer read authority. Avoid
    // loading foreign or unconfirmed opaque documents/collection facts at all.
    let candidate: Option<(bool, bool)> = db.query_row(
        "SELECT coalesce(i.organization_id IS NULL AND i.owner=?2,0), coalesce((i.organization_id IS NULL AND i.owner=?2) OR EXISTS(SELECT 1 FROM organization_memberships m WHERE m.organization_id=i.organization_id AND m.user_id=?2 AND m.status=2),0) FROM items i WHERE i.id=?1 AND i.kind='cipher'",
        params![cipher, actor],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let Some((personal, eligible)) = candidate else {
        return Ok(None);
    };
    if !eligible {
        return Ok(Some(CipherAccess {
            readable: false,
            writable: false,
        }));
    }
    archive::preflight(db, actor, &[cipher]).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(
        crate::organization_cipher_sharing::access(db, actor, cipher)?.map(|access| CipherAccess {
            readable: access.readable(),
            // Shared attachment writes have their own unimplemented provider path.
            // Preserve personal writes without admitting unverified shared writes.
            writable: personal && access.writable(),
        }),
    )
}

pub fn head(response: &mut Response) {
    // Preserve the GET representation length and media headers, send no body.
    if let Some(length) = response.body().size_hint().exact() {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, length.into());
    }
    *response.body_mut() = Body::empty();
}

#[cfg(test)]
mod tests;
