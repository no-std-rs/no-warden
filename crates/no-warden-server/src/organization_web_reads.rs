//! Route-specific web reads; opaque cipher JSON stays in this adapter.
use crate::{Failure, Store, organization_cipher_sharing, organization_collections};
use no_warden::{
    VaultService,
    organization_web_reads::{
        OrganizationCipherReadData, OrganizationCipherReadRecord,
        OrganizationCollectionDetailsData, OrganizationGroupPresence, OrganizationWebReadsStorage,
    },
};
use serde_json::{Value, json};

pub struct Ciphers(Vec<(String, String)>);
impl OrganizationCipherReadData for Ciphers {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> Option<OrganizationCipherReadRecord<'_>> {
        self.0
            .get(index)
            .map(|(id, organization_id)| OrganizationCipherReadRecord {
                id,
                organization_id,
            })
    }
}
pub struct CollectionDetails(Vec<organization_collections::Detail>);
impl OrganizationCollectionDetailsData for CollectionDetails {
    type Details<'a> = &'a organization_collections::Detail;
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> Option<Self::Details<'_>> {
        self.0.get(index)
    }
}
impl OrganizationWebReadsStorage for Store {
    type CipherReads<'a> = Ciphers;
    type CollectionDetails<'a> = CollectionDetails;
    fn organization_cipher_reads(&mut self, org: &str) -> rusqlite::Result<Ciphers> {
        let mut statement=self.db.prepare("SELECT id,organization_id FROM items WHERE organization_id=?1 AND kind='cipher' ORDER BY rowid")?;
        Ok(Ciphers(
            statement
                .query_map([org], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?,
        ))
    }
    fn organization_collection_details(
        &mut self,
        owner: &str,
        org: &str,
    ) -> rusqlite::Result<CollectionDetails> {
        Ok(CollectionDetails(organization_collections::web_details(
            &self.db, owner, org,
        )?))
    }
    fn organization_group_presence(
        &mut self,
        _org: &str,
    ) -> rusqlite::Result<OrganizationGroupPresence> {
        // The default host has no group store or group administration. Refuse to
        // fabricate an empty list if a future/embedding schema introduces group data.
        let configured:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND lower(name) IN('organization_groups','organization_group_users','organization_collection_groups'))",[],|r|r.get(0))?;
        Ok(if configured {
            OrganizationGroupPresence::ConfiguredOrUnknown
        } else {
            OrganizationGroupPresence::NoCreatedGroups
        })
    }
}
/// Rocket query names use their first dotted/bracketed root and first value.
/// IDs remain exact decoded strings; uppercase and unknown IDs cannot acquire scope.
pub fn query_organization(query: Option<&str>) -> Result<String, Failure> {
    query
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(name, _)| organization_collections::query_root(name) == "organizationId")
                .map(|(_, value)| value.into_owned())
        })
        .ok_or_else(crate::unauthorized)
}
pub fn cipher_list(store: &mut Store, owner: &str, org: &str) -> Result<Value, Failure> {
    let mut service = VaultService::new(&mut *store);
    let grant = service.authorize_org_cipher_list(owner, org)?;
    let ids = (0..grant.len())
        .map(|index| {
            grant
                .get(index)
                .map(|r| r.id.to_owned())
                .ok_or(rusqlite::Error::InvalidQuery)
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut rows = Vec::new();
    for id in ids {
        let mut row = organization_cipher_sharing::project(&store.db, owner, &id, false)?
            .ok_or(rusqlite::Error::InvalidQuery)?;
        project_organization_cipher(&mut row)?;
        crate::attachments::enrich_cipher(&store.db, &store.download_base, &mut row)?;
        rows.push(row);
    }
    Ok(json!({"object":"list","data":rows,"continuationToken":null}))
}
fn project_organization_cipher(value: &mut Value) -> rusqlite::Result<()> {
    let row = value.as_object_mut().ok_or(rusqlite::Error::InvalidQuery)?;
    for field in [
        "archivedDate",
        "edit",
        "favorite",
        "folderId",
        "permissions",
        "viewPassword",
    ] {
        row.remove(field);
    }
    for field in ["fields", "passwordHistory"] {
        if row.get(field).is_none_or(Value::is_null) {
            row.insert(field.to_owned(), json!([]));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
