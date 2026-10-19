//! Personal-vault mutation; authentication and proof verification precede this call.
//! The upstream handler saves sequentially. This adapter supplies a stronger atomic
//! boundary for ciphertext, attachment bytes/capabilities, annotations and revision.

use rusqlite::Connection;

/// Rocket's `query_value::<OrganizationId>` uses a transparent form String,
/// not its UUID path guard. A matching root selects organization handling even
/// for an empty/invalid value. NameView compares the first dotted/bracketed key.
pub(crate) fn organization_requested(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(name, _)| {
            let root = if let Some(rest) = name.strip_prefix('[') {
                rest.split_once(']').map_or(rest, |(key, _)| key)
            } else {
                name.strip_prefix('.')
                    .unwrap_or(&name)
                    .split(['.', '['])
                    .next()
                    .unwrap_or("")
            };
            root == "organizationId"
        })
    })
}

pub(crate) fn personal(db: &mut Connection, owner: &str) -> rusqlite::Result<()> {
    let tx = db.savepoint()?;
    let revision = crate::store::next_revision(&tx, owner)?;
    // Scope by both owner and kind. Foreign vaults and future non-vault records
    // cannot be selected by an encrypted payload's document fields.
    // Foreign keys remove attachments, download grants and archive annotations.
    tx.execute(
        "DELETE FROM items WHERE owner=?1 AND kind='cipher'",
        [owner],
    )?;
    tx.execute(
        "DELETE FROM items WHERE owner=?1 AND kind='folder'",
        [owner],
    )?;
    // An empty purge is still a committed upstream account-revision mutation.
    crate::store::bump(&tx, owner, &revision)?;
    tx.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_query_preserves_rocket_root_selection_before_personal_mutation() {
        for query in [
            "organizationId",
            "organizationId=",
            "organizationId=invalid",
            "organizationId=00000000-0000-0000-0000-000000000000",
            "organizationId=invalid&organizationId=",
            "organizationId.x=ignored",
            "organizationId[x]=ignored",
            ".organizationId=ignored",
            "[organizationId]=ignored",
            "[organizationId=ignored",
            "%6FrganizationId=ignored",
            "organizationId%5Bx%5D=ignored",
            "unknown=x&organizationId=invalid",
        ] {
            assert!(organization_requested(Some(query)));
        }
        for query in [
            "",
            "unknown=organizationId",
            "OrganizationId=ignored",
            "organizationid=ignored",
            "organizationIdExtra=ignored",
            "organizationId]=ignored",
            "[organizationId.x]=ignored",
            "[organizationId.x=ignored",
            ".[organizationId]=ignored",
            "other.organizationId=ignored",
            "other[organizationId]=ignored",
        ] {
            assert!(!organization_requested(Some(query)));
        }
        assert!(!organization_requested(None));
    }
}
