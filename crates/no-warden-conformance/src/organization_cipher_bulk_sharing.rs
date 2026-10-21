//! Independently authored native bulk-sharing contracts. MIT OR Apache-2.0.
//! Direct HTTP callers are separate from CLI observations and browser evidence.
use crate::{
    fixture,
    organization_collections::create_organization,
    organization_confirmations as confirmation, organization_invites,
    organization_member_removal as removal, organization_member_status as status,
    organization_owner::{self, Account, Http, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
};
use reqwest::Method;
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, io::Read, time::Duration};
use uuid::Uuid;
pub const CASE_COUNT: usize = 6;
pub const HTTP_REQUEST_COUNT: usize = 1001;
pub(crate) const NOTE: &str = "Independent bulk sharing Ω\0";
const MISSING_ID: &str = "Request missing ids field";
const MISSING: &str = "Cipher doesn't exist";
const SOURCE: &str = "Cipher is not write accessible";
const COLLECTION: &str = "Invalid collection ID provided";
const RIGHTS: &str = "No rights to modify the collection";
const MISMATCH: &str = "Organization mismatch. Please resync the client before updating the cipher";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_cipher_bulk_sharing_native_schema_and_global_id_preflight",
        schema,
    ),
    (
        "organization_cipher_bulk_sharing_reverse_items_forward_prefix_and_duplicates",
        ordering,
    ),
    (
        "organization_cipher_bulk_sharing_confirmed_membership_and_destination_permissions",
        admission,
    ),
    (
        "organization_cipher_bulk_sharing_source_manage_same_org_and_priority",
        source_acl,
    ),
    (
        "organization_cipher_bulk_sharing_opaque_payload_and_final_folder_failure",
        payloads,
    ),
    (
        "organization_cipher_bulk_sharing_preserved_controls_keys_context_and_authority",
        preservation,
    ),
];
struct Reply {
    status: u16,
    content_type: bool,
    bytes: Vec<u8>,
}
impl Reply {
    fn check(self, code: u16, message: Option<&str>) -> Result<(), Error> {
        if self.status != code {
            eprintln!(
                "Bulk sharing status: actual {}, expected {code}",
                self.status
            );
        }
        require(self.status == code, "Bulk sharing HTTP status differed")?;
        if code == 200 {
            return require(
                self.bytes.is_empty() && !self.content_type,
                "Bulk sharing success body or Content-Type differed",
            );
        }
        let v: Value = serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Bulk sharing error was not JSON"))?;
        if let Some(message) = message {
            let fields = BTreeSet::from([
                "error",
                "errorModel",
                "error_description",
                "exceptionMessage",
                "exceptionStackTrace",
                "innerExceptionMessage",
                "message",
                "object",
                "validationErrors",
            ]);
            require(
                v.as_object().is_some_and(|o| {
                    o.keys().map(String::as_str).collect::<BTreeSet<_>>() == fields
                }) && v["object"] == "error"
                    && v["message"] == message
                    && v["errorModel"]["message"] == message,
                "Bulk sharing business error differed",
            )
        } else {
            require(
                v.as_object()
                    .is_some_and(|o| o.len() == 1 && o.contains_key("error")),
                "Bulk sharing structural error envelope differed",
            )
        }
    }
}
pub(crate) fn put(http: &mut Http, token: &str, body: &Value, media: bool) -> Result<(), Error> {
    raw(http, token, body, media)?.check(200, None)
}
fn raw(http: &mut Http, token: &str, body: &Value, media: bool) -> Result<Reply, Error> {
    http.requests += 1;
    let mut request = http_client()?
        .put(format!("{}/api/ciphers/share", http.server))
        .bearer_auth(token)
        .header(reqwest::header::ACCEPT, "application/json")
        .body(body.to_string());
    if media {
        request = request.header(reqwest::header::CONTENT_TYPE, "application/json");
    }
    let response = request
        .send()
        .map_err(|_| Error("Bulk sharing request failed"))?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .contains_key(reqwest::header::CONTENT_TYPE);
    let mut bytes = Vec::new();
    response
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("Bulk sharing private capture failed"))?;
    require(
        bytes.len() <= 16 * 1024 * 1024,
        "Bulk sharing response bound exceeded",
    )?;
    Ok(Reply {
        status,
        content_type,
        bytes,
    })
}
pub(crate) fn wrapper(items: Value, collections: Value) -> Value {
    json!({"ciphers":items,"collectionIds":collections})
}
pub(crate) fn item(
    id: &str,
    account: &Account,
    org: Option<&Organization>,
    variant: &str,
) -> Result<Value, Error> {
    let bytes = format!("{NOTE}{variant}");
    let encrypted = if let Some(org) = org {
        fixture::encrypt(bytes.as_bytes(), &org.key)
    } else {
        fixture::encrypted_fixture_value(&account.fixture, &account.password, bytes.as_bytes())
    }
    .map_err(|_| Error("Bulk sharing opaque fixture encryption failed"))?;
    Ok(
        json!({"id":id,"type":2,"organizationId":org.map(|g|g.id.as_str()),"encryptedFor":account.user_id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"key":null,"favorite":false,"folderId":null}),
    )
}
pub(crate) fn invite(
    http: &mut Http,
    owner: &Account,
    recipient: &Account,
    org: &Organization,
    role: i64,
    grants: Value,
    confirmed: bool,
) -> Result<String, Error> {
    organization_invites::invite_owner(
        http,
        &org.id,
        &owner.token,
        &json!({"emails":[recipient.fixture["email"]],"type":role,"collections":grants,"groups":[],"permissions":{"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true}}),
    )?;
    let row = confirmation::member_row(
        http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    let member = text(&row["id"])?.to_owned();
    if confirmed {
        removal::confirm_fixture_member(http, org, &member, &owner.token, &recipient.fixture)?;
    }
    Ok(member)
}
#[derive(Clone)]
struct Source {
    id: String,
    owner: usize,
}
#[derive(Clone)]
enum Change {
    Unchanged,
    Prefix(Vec<String>),
    Applied(Value, Vec<String>),
}
struct Trial {
    actor: usize,
    body: Value,
    code: u16,
    message: Option<&'static str>,
    changes: Vec<Change>,
    revisions: [bool; 3],
    media: bool,
}
impl Trial {
    fn unchanged(
        actor: usize,
        body: Value,
        count: usize,
        code: u16,
        message: Option<&'static str>,
    ) -> Self {
        Self {
            actor,
            body,
            code,
            message,
            changes: vec![Change::Unchanged; count],
            revisions: [false; 3],
            media: true,
        }
    }
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    collections: Vec<String>,
    folders: Vec<String>,
    controls: Vec<Value>,
    keys: Vec<Value>,
    profiles: Vec<Value>,
    passed: Vec<&'static str>,
    receipt: Option<fs::File>,
    finished: bool,
}
impl Drop for Suite {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.receipt("failed");
        }
    }
}
impl Suite {
    fn receipt(&mut self, state: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":state,"cases":self.passed,"passedCases":self.passed.len(),"expectedCases":CASE_COUNT,"httpRequests":self.http.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.logins,"fixtureRegistrations":3,"fixtureRegistrationHttpRequests":6,"nativeBulkPutCaller":"directHTTP","cliBulkCallerClaimed":false,"capturedRouteTrace":false,"browserTraceClaimed":false,"configuredGroups":false,"configuredPolicies":false,"attachments":false,"otherItemTypes":false,"smtpEnabled":false,"concurrencyParity":false,"providerFailureParity":false,"fullParityClaimed":false,"successContentTypeAbsentAsserted":self.passed.contains(&CASES[0].0),"malformedTypeAndWrapperShapeDistinctAsserted":self.passed.contains(&CASES[0].0),"encryptedForRequiredOpaqueStringAndOptionalFieldBehaviorAsserted":self.passed.contains(&CASES[0].0),"missingAndNullFavoritePreservedAcrossOwnershipContextsAsserted":self.passed.contains(&CASES[0].0),"reverseItemsAndForwardSelectionPrefixAsserted":self.passed.contains(&CASES[1].0),"bulkManageDistinctFromNewSelectionAndGetAsserted":self.passed.contains(&CASES[3].0)}),
        )
    }
    fn get(&mut self, actor: usize, path: &str) -> Result<Value, Error> {
        self.http
            .json(Method::GET, path, &self.accounts[actor].token, None)
    }
    fn revisions(&mut self) -> Result<Vec<Value>, Error> {
        let mut out = Vec::new();
        for a in &self.accounts {
            out.push(self.http.revision(&a.token)?);
        }
        Ok(out)
    }
    fn source(&mut self, owner: usize) -> Result<Source, Error> {
        let a = &self.accounts[owner];
        let encrypted = fixture::encrypted_fixture_value(&a.fixture, &a.password, NOTE.as_bytes())
            .map_err(|_| Error("Bulk source encryption failed"))?;
        let v=self.http.json(Method::POST,"/api/ciphers",&a.token,Some(&json!({"type":2,"encryptedFor":a.user_id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"favorite":true,"folderId":self.folders[owner]})))?;
        Ok(Source {
            id: text(&v["id"])?.to_owned(),
            owner,
        })
    }
    fn sources(&mut self, count: usize, owner: usize) -> Result<Vec<Source>, Error> {
        (0..count).map(|_| self.source(owner)).collect()
    }
    fn items(&self, sources: &[Source], org: usize) -> Result<Vec<Value>, Error> {
        sources
            .iter()
            .enumerate()
            .map(|(i, s)| {
                item(
                    &s.id,
                    &self.accounts[s.owner],
                    Some(&self.orgs[org]),
                    &format!("variant{i}"),
                )
            })
            .collect()
    }
    fn trial(&mut self, sources: &[Source], trial: Trial) -> Result<(), Error> {
        require(
            sources.len() == trial.changes.len(),
            "Bulk trial authored shape invalid",
        )?;
        let mut before = Vec::new();
        for s in sources {
            before.push(self.get(s.owner, &format!("/api/ciphers/{}", s.id))?);
        }
        let rev = self.revisions()?;
        std::thread::sleep(Duration::from_millis(8));
        raw(
            &mut self.http,
            &self.accounts[trial.actor].token,
            &trial.body,
            trial.media,
        )?
        .check(trial.code, trial.message)?;
        for (i, s) in sources.iter().enumerate() {
            let after = self.get(s.owner, &format!("/api/ciphers/{}", s.id))?;
            check_change(
                &before[i],
                &after,
                &trial.changes[i],
                trial.actor == s.owner,
            )?;
        }
        for (i, (old, new)) in rev.iter().zip(self.revisions()?).enumerate() {
            require(
                (old != &new) == trial.revisions[i],
                "Bulk sharing account revision fanout differed",
            )?;
        }
        Ok(())
    }
    fn success(
        &mut self,
        sources: &[Source],
        actor: usize,
        items: Vec<Value>,
        ids: Vec<String>,
        revisions: [bool; 3],
    ) -> Result<(), Error> {
        let changes = items
            .iter()
            .map(|v| Change::Applied(v.clone(), ids.clone()))
            .collect();
        self.trial(
            sources,
            Trial {
                actor,
                body: wrapper(json!(items), json!(ids)),
                code: 200,
                message: None,
                changes,
                revisions,
                media: true,
            },
        )
    }
    fn shared(&mut self, collection: usize) -> Result<Source, Error> {
        let s = self.source(0)?;
        let v = item(&s.id, &self.accounts[0], Some(&self.orgs[0]), "initial")?;
        put(
            &mut self.http,
            &self.accounts[0].token,
            &wrapper(json!([v]), json!([self.collections[collection]])),
            true,
        )?;
        Ok(s)
    }
}
fn ids(value: &Value) -> Result<BTreeSet<&str>, Error> {
    value
        .as_array()
        .ok_or(Error("Bulk collection projection missing"))?
        .iter()
        .map(text)
        .collect()
}
fn check_change(
    before: &Value,
    after: &Value,
    change: &Change,
    own_annotations: bool,
) -> Result<(), Error> {
    match change {
        Change::Unchanged => require(before == after, "Rejected bulk sharing changed source")?,
        Change::Prefix(collections) => {
            let mut old = before.clone();
            let mut new = after.clone();
            old.as_object_mut()
                .ok_or(Error("Bulk source malformed"))?
                .remove("collectionIds");
            new.as_object_mut()
                .ok_or(Error("Bulk source malformed"))?
                .remove("collectionIds");
            require(
                old == new,
                "Bulk prefix changed payload/key/revision/private annotations",
            )?;
            let expected = collections
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            require(
                ids(&after["collectionIds"])? == expected,
                "Bulk association prefix differed",
            )?;
        }
        Change::Applied(payload, selected) => {
            require(
                after["organizationId"] == payload["organizationId"]
                    && after["name"] == payload["name"]
                    && after["notes"] == payload["notes"]
                    && after["key"] == payload["key"]
                    && after["id"] == before["id"]
                    && after["type"] == 2
                    && after["secureNote"] == json!({"type":0})
                    && after["creationDate"] == before["creationDate"]
                    && after["revisionDate"] != before["revisionDate"],
                "Bulk committed opaque payload/ownership differed",
            )?;
            let expected = if payload["organizationId"].is_null() {
                BTreeSet::new()
            } else {
                ids(&before["collectionIds"])?
                    .into_iter()
                    .chain(selected.iter().map(String::as_str))
                    .collect()
            };
            require(
                ids(&after["collectionIds"])? == expected,
                "Bulk committed associations differed",
            )?;
            let annotations = if own_annotations { payload } else { before };
            require(
                after["favorite"] == annotations["favorite"]
                    && after["folderId"] == annotations["folderId"],
                "Bulk sharing crossed private annotation context",
            )?;
        }
    }
    Ok(())
}
fn schema(s: &mut Suite) -> Result<(), Error> {
    let sources = s.sources(3, 0)?;
    let items = s.items(&sources, 0)?;
    let selections = json!([s.collections[0]]);
    for value in [
        json!({}),
        json!({"ciphers":null,"collectionIds":selections}),
        json!({"ciphers":"bad","collectionIds":selections}),
        json!({"ciphers":items}),
        json!({"ciphers":items,"collectionIds":null}),
        json!({"ciphers":items,"collectionIds":"bad"}),
        json!({"Ciphers":items,"CollectionIds":selections}),
        json!({"ciphers":items,"CollectionIds":selections}),
        json!([items]),
        json!([selections, items]),
    ] {
        s.trial(&sources, Trial::unchanged(0, value, 3, 422, None))?;
    }
    s.trial(
        &sources,
        Trial::unchanged(0, json!([items, selections, 0]), 3, 400, None),
    )?;
    for field in ["type", "name"] {
        for null in [false, true] {
            let mut changed = items.clone();
            if null {
                changed[2][field] = Value::Null;
            } else {
                changed[2].as_object_mut().unwrap().remove(field);
            }
            s.trial(
                &sources,
                Trial::unchanged(0, wrapper(json!(changed), selections.clone()), 3, 422, None),
            )?;
        }
    }
    // Error text is attacker-controlled input, never a wrapper-shape signal.
    // Both complete native item shapes fail before any source is mutated.
    for malformed_type in ["bad", "expected fewer elements"] {
        let mut changed = items.clone();
        changed[0]["lastKnownRevisionDate"] = Value::Null;
        changed[0]["type"] = json!(malformed_type);
        s.trial(
            &sources,
            Trial::unchanged(0, wrapper(json!(changed), selections.clone()), 3, 422, None),
        )?;
    }
    let mut missing_encrypted_for = items.clone();
    missing_encrypted_for[0]
        .as_object_mut()
        .unwrap()
        .remove("encryptedFor");
    s.trial(
        &sources,
        Trial::unchanged(
            0,
            wrapper(json!(missing_encrypted_for), selections.clone()),
            3,
            422,
            None,
        ),
    )?;
    for invalid_encrypted_for in [Value::Null, json!(7)] {
        let mut changed = items.clone();
        changed[0]["encryptedFor"] = invalid_encrypted_for;
        s.trial(
            &sources,
            Trial::unchanged(0, wrapper(json!(changed), selections.clone()), 3, 422, None),
        )?;
    }
    // The required string is opaque and does not select a caller or account.
    for encrypted_for in ["", "not-a-uuid"] {
        let source = s.source(0)?;
        let mut payload = item(&source.id, &s.accounts[0], None, "opaque-encrypted-for")?;
        payload["encryptedFor"] = json!(encrypted_for);
        payload["lastKnownRevisionDate"] = Value::Null;
        s.trial(
            &[source],
            Trial {
                actor: 0,
                body: wrapper(
                    json!([payload.clone()]),
                    json!([Uuid::new_v4().to_string()]),
                ),
                code: 200,
                message: None,
                changes: vec![Change::Applied(payload, vec![])],
                revisions: [true, false, false],
                media: true,
            },
        )?;
    }
    // These fields are optional in a complete native personal-item update.
    // A nonempty unknown selection is deliberately skipped for a personal item.
    for field in ["favorite", "folderId", "lastKnownRevisionDate"] {
        let source = s.source(0)?;
        let mut payload = item(&source.id, &s.accounts[0], None, "omitted-field")?;
        payload["lastKnownRevisionDate"] = Value::Null;
        payload.as_object_mut().unwrap().remove(field);
        let mut expected = payload.clone();
        if field == "favorite" {
            // The fresh source's private favorite survives an omitted field.
            expected["favorite"] = json!(true);
        } else if field == "folderId" {
            expected["folderId"] = Value::Null;
        }
        s.trial(
            &[source],
            Trial {
                actor: 0,
                body: wrapper(json!([payload]), json!([Uuid::new_v4().to_string()])),
                code: 200,
                message: None,
                changes: vec![Change::Applied(expected, vec![])],
                revisions: [true, false, false],
                media: true,
            },
        )?;
    }
    // Missing and null favorites preserve the caller's existing annotation in
    // personal updates, transfers, and subsequent same-organization updates.
    for context in 0..3 {
        for null in [false, true] {
            if context == 0 && !null {
                continue; // The optional-field control above covers this form.
            }
            let source = s.source(0)?;
            if context == 2 {
                let mut initial = item(
                    &source.id,
                    &s.accounts[0],
                    Some(&s.orgs[0]),
                    "favorite-before",
                )?;
                initial["favorite"] = json!(true);
                initial["folderId"] = json!(s.folders[0]);
                s.success(
                    std::slice::from_ref(&source),
                    0,
                    vec![initial],
                    vec![s.collections[0].clone()],
                    [true, true, false],
                )?;
            }
            let organization = (context != 0).then_some(&s.orgs[0]);
            let mut payload = item(
                &source.id,
                &s.accounts[0],
                organization,
                "favorite-preserved",
            )?;
            payload["lastKnownRevisionDate"] = Value::Null;
            if null {
                payload["favorite"] = Value::Null;
            } else {
                payload.as_object_mut().unwrap().remove("favorite");
            }
            let mut expected = payload.clone();
            expected["favorite"] = json!(true);
            let collections = if context == 0 {
                vec![]
            } else {
                vec![s.collections[0].clone()]
            };
            let selection = if context == 0 {
                vec![Uuid::new_v4().to_string()]
            } else {
                collections.clone()
            };
            s.trial(
                &[source],
                Trial {
                    actor: 0,
                    body: wrapper(json!([payload]), json!(selection)),
                    code: 200,
                    message: None,
                    changes: vec![Change::Applied(expected, collections)],
                    revisions: [true, context != 0, false],
                    media: true,
                },
            )?;
        }
    }
    let mut bad = items.clone();
    bad[2]["name"] = json!(4);
    s.trial(
        &sources,
        Trial::unchanged(0, wrapper(json!(bad), selections.clone()), 3, 422, None),
    )?;
    let mut opaque = items.clone();
    opaque[2]["id"] = json!("opaque-non-uuid-source");
    s.trial(
        &sources,
        Trial::unchanged(
            0,
            wrapper(json!(opaque), selections.clone()),
            3,
            400,
            Some(MISSING),
        ),
    )?;
    for index in [0, 2] {
        for null in [false, true] {
            let mut changed = items.clone();
            if null {
                changed[index]["id"] = Value::Null;
            } else {
                changed[index].as_object_mut().unwrap().remove("id");
            }
            s.trial(
                &sources,
                Trial::unchanged(
                    0,
                    wrapper(json!(changed), selections.clone()),
                    3,
                    400,
                    Some(MISSING_ID),
                ),
            )?;
        }
    }
    let mut pascal = items.clone();
    pascal[2]["Id"] = pascal[2]["id"].clone();
    pascal[2].as_object_mut().unwrap().remove("id");
    s.trial(
        &sources,
        Trial::unchanged(
            0,
            wrapper(json!(pascal), selections.clone()),
            3,
            400,
            Some(MISSING_ID),
        ),
    )?;
    let mut number = items.clone();
    number[2]["id"] = json!(2);
    s.trial(
        &sources,
        Trial::unchanged(0, wrapper(json!(number), selections.clone()), 3, 422, None),
    )?;
    s.trial(
        &sources,
        Trial::unchanged(
            0,
            wrapper(json!([]), selections.clone()),
            3,
            400,
            Some("You must select at least one cipher."),
        ),
    )?;
    s.trial(
        &sources,
        Trial::unchanged(
            0,
            wrapper(json!(items), json!([])),
            3,
            400,
            Some("You must select at least one collection."),
        ),
    )?;
    // Positional success and omitted media are independently measured native forms.
    for positional in [false, true] {
        let src = s.sources(1, 0)?;
        let p = s.items(&src, 0)?;
        let body = if positional {
            json!([p, [s.collections[0]]])
        } else {
            wrapper(json!(p), selections.clone())
        };
        s.trial(
            &src,
            Trial {
                actor: 0,
                body,
                code: 200,
                message: None,
                changes: vec![Change::Applied(
                    p[0].clone(),
                    vec![s.collections[0].clone()],
                )],
                revisions: [true, true, false],
                media: positional,
            },
        )?;
    }
    Ok(())
}
fn ordering(s: &mut Suite) -> Result<(), Error> {
    for missing in [0, 1, 2] {
        let src = s.sources(3, 0)?;
        let mut p = s.items(&src, 0)?;
        p[missing]["id"] = json!(Uuid::new_v4().to_string());
        let changes = p
            .iter()
            .enumerate()
            .map(|(i, v)| {
                if i > missing {
                    Change::Applied(v.clone(), vec![s.collections[0].clone()])
                } else {
                    Change::Unchanged
                }
            })
            .collect();
        s.trial(
            &src,
            Trial {
                actor: 0,
                body: wrapper(json!(p), json!([s.collections[0]])),
                code: 400,
                message: Some(MISSING),
                changes,
                revisions: [missing < 2, missing < 2, false],
                media: true,
            },
        )?;
    }
    for count in [2, 3] {
        let src = s.sources(1, 0)?;
        let p = (0..count)
            .map(|i| {
                item(
                    &src[0].id,
                    &s.accounts[0],
                    Some(&s.orgs[0]),
                    &format!("duplicate{i}"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        s.trial(
            &src,
            Trial {
                actor: 0,
                body: wrapper(json!(p), json!([s.collections[0]])),
                code: 200,
                message: None,
                changes: vec![Change::Applied(
                    p[0].clone(),
                    vec![s.collections[0].clone()],
                )],
                revisions: [true, true, false],
                media: true,
            },
        )?;
    }
    for (selected, prefix) in [
        (
            vec![s.collections[0].clone(), Uuid::new_v4().to_string()],
            true,
        ),
        (
            vec![s.collections[0].clone(), s.orgs[1].collection_id.clone()],
            true,
        ),
        (
            vec![Uuid::new_v4().to_string(), s.collections[0].clone()],
            false,
        ),
    ] {
        let src = s.sources(2, 0)?;
        let p = s.items(&src, 0)?;
        let changes = vec![
            Change::Unchanged,
            if prefix {
                Change::Prefix(vec![s.collections[0].clone()])
            } else {
                Change::Unchanged
            },
        ];
        s.trial(
            &src,
            Trial {
                actor: 0,
                body: wrapper(json!(p), json!(selected)),
                code: 400,
                message: Some(COLLECTION),
                changes,
                revisions: [prefix, prefix, false],
                media: true,
            },
        )?;
    }
    Ok(())
}
fn admission(s: &mut Suite) -> Result<(), Error> {
    for org in [2, 3, 5] {
        let src = s.sources(1, 1)?;
        let p = s.items(&src, org)?;
        s.trial(
            &src,
            Trial::unchanged(
                1,
                wrapper(json!(p), json!([s.orgs[org].collection_id])),
                1,
                400,
                Some(RIGHTS),
            ),
        )?;
    }
    for col in [1, 2, 3] {
        let src = s.sources(1, 1)?;
        let p = s.items(&src, 0)?;
        s.trial(
            &src,
            Trial::unchanged(
                1,
                wrapper(json!(p), json!([s.collections[col]])),
                1,
                400,
                Some(RIGHTS),
            ),
        )?;
    }
    for org in [0, 4] {
        let src = s.sources(1, 1)?;
        let p = s.items(&src, org)?;
        s.success(
            &src,
            1,
            p,
            vec![s.orgs[org].collection_id.clone()],
            [true, true, false],
        )?;
    }
    let src = s.sources(2, 0)?;
    let p = s.items(&src, 0)?;
    s.trial(
        &src,
        Trial::unchanged(
            1,
            wrapper(json!(p), json!([s.collections[0]])),
            2,
            400,
            Some(SOURCE),
        ),
    )?;
    Ok(())
}
fn source_acl(s: &mut Suite) -> Result<(), Error> {
    for (initial, new, allowed) in [(1, 0, false), (2, 0, true), (0, 2, false), (2, 2, false)] {
        let source = s.shared(initial)?;
        let p = item(&source.id, &s.accounts[1], Some(&s.orgs[0]), "recipient")?;
        if initial == 2 {
            let v = s.get(1, &format!("/api/ciphers/{}", source.id))?;
            require(
                v["edit"] == false
                    && v["permissions"] == json!({"delete":false,"restore":false})
                    && v["viewPassword"] == true
                    && v["collectionIds"] == json!([]),
                "Bulk manage source GET flags were conflated with bulk authority",
            )?;
        }
        if allowed {
            s.success(
                &[source],
                1,
                vec![p],
                vec![s.collections[new].clone()],
                [true, true, false],
            )?;
        } else {
            s.trial(
                &[source],
                Trial::unchanged(
                    1,
                    wrapper(json!([p]), json!([s.collections[new]])),
                    1,
                    400,
                    Some(if initial == 1 { SOURCE } else { RIGHTS }),
                ),
            )?;
        }
    }
    for actor in [0, 1] {
        for null in [false, true] {
            let source = s.shared(0)?;
            let mut p = item(
                &source.id,
                &s.accounts[actor],
                Some(&s.orgs[0]),
                "missingorg",
            )?;
            if null {
                p["organizationId"] = Value::Null;
            } else {
                p.as_object_mut().unwrap().remove("organizationId");
            }
            s.trial(
                &[source],
                Trial::unchanged(
                    actor,
                    wrapper(json!([p]), json!([s.collections[0]])),
                    1,
                    400,
                    Some(MISMATCH),
                ),
            )?;
        }
    }
    let source = s.shared(0)?;
    let p = item(&source.id, &s.accounts[0], Some(&s.orgs[1]), "foreign")?;
    s.trial(
        &[source],
        Trial::unchanged(
            0,
            wrapper(json!([p]), json!([s.orgs[1].collection_id])),
            1,
            400,
            Some(MISMATCH),
        ),
    )?;
    let source = s.shared(1)?;
    let p = item(&source.id, &s.accounts[1], None, "readonlynull")?;
    s.trial(
        &[source],
        Trial::unchanged(
            1,
            wrapper(json!([p]), json!([s.collections[0]])),
            1,
            400,
            Some(SOURCE),
        ),
    )?;
    let source = s.shared(0)?;
    let mut p = item(&source.id, &s.accounts[1], Some(&s.orgs[0]), "private")?;
    p["favorite"] = json!(true);
    p["folderId"] = json!(s.folders[1]);
    let id = source.id.clone();
    s.success(
        &[source],
        1,
        vec![p],
        vec![s.collections[0].clone()],
        [true, true, false],
    )?;
    let caller = s.get(1, &format!("/api/ciphers/{id}"))?;
    require(
        caller["favorite"] == true && caller["folderId"] == s.folders[1],
        "Bulk recipient private annotations were not caller scoped",
    )?;
    Ok(())
}
fn payloads(s: &mut Suite) -> Result<(), Error> {
    for mode in 0..6 {
        let src = s.sources(1, 0)?;
        let mut p = s.items(&src, 0)?;
        let mut body = wrapper(json!(p), json!([s.collections[0]]));
        match mode {
            0 => {
                p[0]["name"] = json!("");
                p[0]["notes"] = json!("native opaque non-envelope");
            }
            1 => {
                p[0]["name"] = json!("native non-envelope");
                p[0]["encryptedFor"] = json!(s.accounts[2].user_id);
                body["encryptedFor"] = json!(s.accounts[2].user_id);
            }
            2 => {
                p[0]["key"] = json!(
                    fixture::encrypt(b"opaque-key-contract", &s.orgs[0].key)
                        .map_err(|_| Error("Bulk key fixture encryption failed"))?
                );
            }
            3..=5 => {
                p[0] = item(&src[0].id, &s.accounts[0], None, "personal")?;
                if mode == 3 {
                    p[0].as_object_mut().unwrap().remove("organizationId");
                } else if mode == 4 {
                    p[0]["OrganizationId"] = json!(s.orgs[0].id);
                    p[0].as_object_mut().unwrap().remove("organizationId");
                }
                body["organizationId"] = json!(s.orgs[1].id);
                body["collectionIds"] = json!([Uuid::new_v4().to_string()]);
            }
            _ => unreachable!(),
        }
        body["ciphers"] = json!(p);
        let selected = if mode < 3 {
            vec![s.collections[0].clone()]
        } else {
            vec![]
        };
        s.trial(
            &src,
            Trial {
                actor: 0,
                body,
                code: 200,
                message: None,
                changes: vec![Change::Applied(p[0].clone(), selected)],
                revisions: [true, mode < 3, false],
                media: true,
            },
        )?;
    }
    for folder in [s.folders[1].clone(), Uuid::new_v4().to_string()] {
        let src = s.sources(2, 0)?;
        let mut p = s.items(&src, 0)?;
        p[1]["folderId"] = json!(folder);
        s.trial(
            &src,
            Trial {
                actor: 0,
                body: wrapper(json!(p), json!([s.collections[0]])),
                code: 400,
                message: Some("Invalid folder"),
                changes: vec![
                    Change::Unchanged,
                    Change::Prefix(vec![s.collections[0].clone()]),
                ],
                revisions: [true, true, false],
                media: true,
            },
        )?;
    }
    Ok(())
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for i in 0..3 {
        let control = s.get(i, &format!("/api/ciphers/{}", s.accounts[i].cipher_id))?;
        let keys = s.get(i, "/api/accounts/keys")?;
        let profile = s.get(i, "/api/accounts/profile")?;
        require(
            control == s.controls[i] && keys == s.keys[i] && profile == s.profiles[i],
            "Bulk sharing changed personal control/account keys/membership context",
        )?;
        let key = fixture::fixture_user_key(&s.accounts[i].fixture, &s.accounts[i].password)
            .map_err(|_| Error("Bulk personal key unwrap failed"))?;
        require(
            fixture::decrypt(text(&control["notes"])?, &key)
                .map_err(|_| Error("Bulk control decryption failed"))?
                == organization_owner::NOTE.as_bytes(),
            "Bulk sharing personal control failed decryption",
        )?;
    }
    Ok(())
}
fn seed(http: &mut Http) -> Result<Account, Error> {
    let mut single = Http::new()?;
    let account = organization_owner::seed(&mut single)?;
    http.requests += single.requests;
    http.logins += single.logins;
    Ok(account)
}
pub fn run() -> Result<(), Error> {
    let mut http = Http::new()?;
    let mut accounts = Vec::new();
    for _ in 0..3 {
        accounts.push(seed(&mut http)?);
    }
    let mut orgs = Vec::new();
    for owner in [0, 2, 0, 0, 0, 0] {
        orgs.push(create_organization(&mut http, &accounts[owner])?);
    }
    let mut collections = vec![orgs[0].collection_id.clone()];
    for _ in 0..3 {
        collections.push(
            text(&confirmation::hidden_collection(&mut http, &accounts[0], &orgs[0])?["id"])?
                .to_owned(),
        );
    }
    let grants = json!([{"id":collections[0],"readOnly":false,"hidePasswords":false,"manage":false},{"id":collections[1],"readOnly":true,"hidePasswords":false,"manage":false},{"id":collections[2],"readOnly":true,"hidePasswords":false,"manage":true}]);
    invite(
        &mut http,
        &accounts[0],
        &accounts[1],
        &orgs[0],
        2,
        grants,
        true,
    )?;
    for (index, role, confirmed) in [(2, 2, false), (3, 2, true), (4, 4, true), (5, 3, true)] {
        let grant = if index == 4 || index == 5 {
            json!([])
        } else {
            json!([{"id":orgs[index].collection_id,"readOnly":false,"hidePasswords":false,"manage":false}])
        };
        let member = invite(
            &mut http,
            &accounts[0],
            &accounts[1],
            &orgs[index],
            role,
            grant,
            confirmed,
        )?;
        if index == 3 {
            status::put_fixture_status(
                &mut http,
                &orgs[index].id,
                &member,
                "revoke",
                &accounts[0].token,
            )?;
        }
    }
    let mut folders = Vec::new();
    for account in &accounts {
        let name = fixture::encrypted_fixture_value(
            &account.fixture,
            &account.password,
            b"Bulk private folder",
        )
        .map_err(|_| Error("Bulk folder encryption failed"))?;
        let v = http.json(
            Method::POST,
            "/api/folders",
            &account.token,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&v["id"])?.to_owned());
    }
    let mut s = Suite {
        http,
        accounts,
        orgs,
        collections,
        folders,
        controls: vec![],
        keys: vec![],
        profiles: vec![],
        passed: vec![],
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_BULK_SHARING_RECEIPT")?,
        finished: false,
    };
    for i in 0..3 {
        let control = s.get(i, &format!("/api/ciphers/{}", s.accounts[i].cipher_id))?;
        let keys = s.get(i, "/api/accounts/keys")?;
        let profile = s.get(i, "/api/accounts/profile")?;
        s.controls.push(control);
        s.keys.push(keys);
        s.profiles.push(profile);
    }
    s.receipt("running")?;
    for (name, case) in CASES {
        eprintln!("Bulk sharing case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    if s.http.requests != HTTP_REQUEST_COUNT {
        eprintln!(
            "Bulk sharing HTTP count actual {}, expected {HTTP_REQUEST_COUNT}",
            s.http.requests
        );
    }
    require(
        s.http.requests == HTTP_REQUEST_COUNT && s.http.logins == 3,
        "Bulk sharing request/login budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!("PASS organization-cipher-bulk-sharing: {CASE_COUNT} cases/{HTTP_REQUEST_COUNT} HTTP");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bulk_success_rejects_nonempty_content_typed_and_wrong_status() {
        for (status, content_type, bytes) in [
            (200, false, b"null".to_vec()),
            (200, false, b"{\"data\":[]}".to_vec()),
            (200, true, vec![]),
            (204, false, vec![]),
        ] {
            assert!(
                Reply {
                    status,
                    content_type,
                    bytes
                }
                .check(200, None)
                .is_err()
            );
        }
        assert!(
            Reply {
                status: 200,
                content_type: false,
                bytes: vec![]
            }
            .check(200, None)
            .is_ok()
        );
    }
    #[test]
    fn prefix_contract_rejects_payload_revision_or_annotation_changes() {
        let v = json!({"collectionIds":[],"notes":"opaque","revisionDate":"old","folderId":"private","favorite":true});
        let mut prefix = v.clone();
        prefix["collectionIds"] = json!(["collection"]);
        assert!(
            check_change(
                &v,
                &prefix,
                &Change::Prefix(vec!["collection".into()]),
                true
            )
            .is_ok()
        );
        for field in ["notes", "revisionDate", "folderId", "favorite"] {
            let mut bad = prefix.clone();
            bad[field] = json!("changed");
            assert!(
                check_change(&v, &bad, &Change::Prefix(vec!["collection".into()]), true).is_err()
            );
        }
    }
}
