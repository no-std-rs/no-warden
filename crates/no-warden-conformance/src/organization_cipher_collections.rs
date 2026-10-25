//! Independently authored collections_v2 contracts. MIT OR Apache-2.0.
//! Native invalid-selection order is unstable; no prefix/distribution parity claim.
use crate::{
    fixture,
    organization_cipher_sharing::{CipherExpectation, check_cipher},
    organization_collections::create_organization,
    organization_owner::{self, Account, Http as OwnerHttp, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, io::Read};
use uuid::Uuid;

pub const CASE_COUNT: usize = 6;
// Fixed after the independently executed native development count, before proofs.
pub const HTTP_REQUEST_COUNT: usize = 522;
const NOTE: &str = "Collection reassignment preserves encrypted bytes Ω\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_cipher_collections_schema_path_and_personal_source_guards",
        guards,
    ),
    (
        "organization_cipher_collections_confirmed_source_authority_and_revocation",
        admission,
    ),
    (
        "organization_cipher_collections_replacement_duplicates_noop_and_lost_access",
        replacement,
    ),
    (
        "organization_cipher_collections_readonly_targets_and_protected_old_links",
        protected,
    ),
    (
        "organization_cipher_collections_unordered_invalid_subsets_and_revision_fanout",
        partial,
    ),
    (
        "organization_cipher_collections_opaque_private_annotations_keys_and_sessions",
        preservation,
    ),
];
struct Reply {
    status: u16,
    value: Value,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Value, Error> {
        if self.status != expected {
            eprintln!(
                "Collection reassignment status expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Collection reassignment status differed",
        )?;
        Ok(self.value)
    }
    fn rejected(self, expected: u16) -> Result<(), Error> {
        let value = self.status(expected)?;
        require(
            [
                "access_token",
                "refresh_token",
                "key",
                "privateKey",
                "publicKey",
            ]
            .iter()
            .all(|k| value.get(k).is_none()),
            "Collection rejection exposed authority",
        )?;
        if expected == 422 {
            return require(
                value
                    .as_object()
                    .is_some_and(|v| v.len() == 1 && v.contains_key("error")),
                "Collection schema envelope differed",
            );
        }
        if expected == 400 {
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
                value.as_object().is_some_and(|v| {
                    v.keys().map(String::as_str).collect::<BTreeSet<_>>() == fields
                }) && value["object"] == "error"
                    && value["message"].is_string()
                    && value["validationErrors"].is_object(),
                "Collection business envelope differed",
            )?;
        }
        Ok(())
    }
}
struct Http {
    owner: OwnerHttp,
    client: Client,
    refreshes: usize,
}
impl Http {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            owner: OwnerHttp::new()?,
            client: http_client()?,
            refreshes: 0,
        })
    }
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
        media: bool,
    ) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let mut req = self
            .client
            .request(method, format!("{}{path}", self.owner.server))
            .header("Accept", "application/json");
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.body(body.to_string());
            if media {
                req = req.header("Content-Type", "application/json");
            }
        }
        let response = req
            .send()
            .map_err(|_| Error("Collection HTTP request failed"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Collection private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Collection response exceeded capture bound",
        )?;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| Error("Collection response was not JSON"))?
        };
        Ok(Reply { status, value })
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        self.raw(method, path, token, body, true)?.status(200)
    }
}
struct Snapshot {
    owner: Value,
    actor: Option<Value>,
    revisions: [Value; 2],
}
struct Trial {
    id: String,
    before: Snapshot,
    after: Snapshot,
    reply: Reply,
}
impl Trial {
    fn unchanged(self, status: u16) -> Result<(), Error> {
        self.reply.rejected(status)?;
        require(
            self.before.owner == self.after.owner
                && self.before.actor == self.after.actor
                && self.before.revisions == self.after.revisions,
            "Rejected reassignment mutated source, annotations or revisions",
        )
    }
    fn success(self, expected: &[String], edit: bool, view: bool) -> Result<String, Error> {
        let value = self.reply.status(200)?;
        require(
            value.as_object().is_some_and(|v| {
                v.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    == BTreeSet::from(["cipher", "object", "unavailable"])
            }) && value["object"] == "optionalCipherDetails"
                && value["unavailable"] == false
                && value["cipher"].is_object(),
            "Collection v2 wrapper differed",
        )?;
        let returned = &value["cipher"];
        let mut normalized = returned.clone();
        normalized["collectionIds"] = json!(expected);
        require(
            id_set(&returned["collectionIds"])? == expected.iter().cloned().collect(),
            "Collection operation projection IDs differed",
        )?;
        check_cipher(
            &normalized,
            CipherExpectation {
                id: &self.id,
                organization: text(&self.before.owner["organizationId"]).ok(),
                collections: expected,
                edit,
                view_password: view,
                favorite: self
                    .before
                    .actor
                    .as_ref()
                    .and_then(|v| v["favorite"].as_bool())
                    .unwrap_or(false),
                folder: self
                    .before
                    .actor
                    .as_ref()
                    .and_then(|v| v["folderId"].as_str()),
            },
        )?;
        require(
            only_links_changed(&self.before.owner, &self.after.owner)
                && self.before.revisions[0] != self.after.revisions[0]
                && self.before.revisions[1] != self.after.revisions[1],
            "Successful reassignment changed ciphertext/cipher revision/private metadata or lost account fanout",
        )?;
        require(
            self.before
                .actor
                .as_ref()
                .is_some_and(|before| operation_payload_preserved(before, returned, edit, view)),
            "Collection immediate response changed opaque payload, cipher revision or private annotations",
        )?;
        if let Some(after) = &self.after.actor {
            require(
                after == returned,
                "Collection response and ordinary actor GET differed while readable",
            )?;
        }
        Ok(self.id)
    }
}
fn id_set(value: &Value) -> Result<BTreeSet<String>, Error> {
    let rows = value.as_array().ok_or(Error("Collection IDs missing"))?;
    let ids = rows
        .iter()
        .map(|v| text(v).map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    require(
        ids.len() == rows.len(),
        "Collection response repeated an ID",
    )?;
    Ok(ids)
}

fn operation_payload_preserved(before: &Value, returned: &Value, edit: bool, view: bool) -> bool {
    let mut expected = before.clone();
    expected["collectionIds"] = returned["collectionIds"].clone();
    expected["edit"] = json!(edit);
    expected["viewPassword"] = json!(view);
    expected["permissions"] = json!({"delete":edit,"restore":edit});
    expected == *returned
}
fn only_links_changed(before: &Value, after: &Value) -> bool {
    let mut copy = before.clone();
    copy["collectionIds"] = after["collectionIds"].clone();
    copy == *after
}
fn cipher<'a>(list: &'a Value, id: &str) -> Result<&'a Value, Error> {
    let rows = list.as_array().ok_or(Error("Cipher alias list absent"))?;
    let found = rows.iter().filter(|v| v["id"] == id).collect::<Vec<_>>();
    require(
        found.len() == 1,
        "Cipher alias identity missing or duplicated",
    )?;
    Ok(found[0])
}
fn absent(list: &Value, id: &str) -> Result<(), Error> {
    require(
        list.as_array()
            .is_some_and(|v| v.iter().all(|v| v["id"] != id)),
        "Inaccessible cipher appeared in alias",
    )
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    collections: [String; 4],
    folders: [String; 2],
    member: String,
    keys: [Value; 2],
    controls: [Value; 2],
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
    fn receipt(&mut self, status: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":status,"passedCases":self.passed.len(),"expectedCases":CASE_COUNT,"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"cipherRevisionAndOpaquePayloadPreservedAsserted":true,"privateAnnotationsPreservedAsserted":true,"noopAccountRevisionFanoutAsserted":true,"protectedOldLinksAsserted":true,"lostReadNonnullImmediateResponseAsserted":true,"unorderedInvalidCommittedSubsetAsserted":true,"requestPrefixOrDistributionClaimed":false,"cliCallerClaimed":false,"capturedRouteTrace":false,"browserTraceClaimed":false,"legacyAliasesClaimed":false,"adminRouteClaimed":false,"attachmentBearingTested":false,"groupsConfigured":false,"configuredPolicies":false,"smtpEnabled":false,"historicalGrantsClaimed":false,"businessErrorTextAsserted":false,"fullParityClaimed":false}),
        )
    }
    fn token(&self, actor: usize) -> String {
        self.accounts[actor].token.clone()
    }
    fn get(&mut self, actor: usize, path: &str) -> Result<Value, Error> {
        self.http.json(Method::GET, path, &self.token(actor), None)
    }
    fn revisions(&mut self) -> Result<[Value; 2], Error> {
        Ok([
            self.get(0, "/api/accounts/revision-date")?,
            self.get(1, "/api/accounts/revision-date")?,
        ])
    }
    fn snapshot(&mut self, owner: usize, actor: usize, id: &str) -> Result<Snapshot, Error> {
        let path = format!("/api/ciphers/{id}");
        let full = self.get(owner, &path)?;
        let reply = self
            .http
            .raw(Method::GET, &path, &self.token(actor), None, true)?;
        let actor = if reply.status == 200 {
            Some(reply.value)
        } else {
            reply.rejected(400)?;
            None
        };
        Ok(Snapshot {
            owner: full,
            actor,
            revisions: self.revisions()?,
        })
    }
    fn shared(&mut self, source: usize, org: usize, ids: &[String]) -> Result<String, Error> {
        let encrypted = fixture::encrypted_fixture_value(
            &self.accounts[source].fixture,
            &self.accounts[source].password,
            NOTE.as_bytes(),
        )
        .map_err(|_| Error("Collection personal encryption failed"))?;
        let value=self.http.json(Method::POST,"/api/ciphers",&self.token(source),Some(&json!({"type":2,"encryptedFor":self.accounts[source].user_id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"favorite":true,"folderId":self.folders[source]})))?;
        let id = text(&value["id"])?.to_owned();
        let encrypted = fixture::encrypt(NOTE.as_bytes(), &self.orgs[org].key)
            .map_err(|_| Error("Collection organization encryption failed"))?;
        self.http.json(Method::PUT,&format!("/api/ciphers/{id}/share"),&self.token(source),Some(&json!({"collectionIds":ids,"cipher":{"type":2,"organizationId":self.orgs[org].id,"encryptedFor":self.accounts[source].user_id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"favorite":true,"folderId":self.folders[source],"key":null,"lastKnownRevisionDate":value["revisionDate"]}})))?;
        Ok(id)
    }
    fn on(
        &mut self,
        id: &str,
        org: usize,
        actor: usize,
        body: Value,
        media: bool,
        path: Option<&str>,
    ) -> Result<Trial, Error> {
        let owner = usize::from(org == 1);
        let before = self.snapshot(owner, actor, id)?;
        let reply = self.http.raw(
            Method::PUT,
            &format!("/api/ciphers/{}/collections_v2", path.unwrap_or(id)),
            &self.token(actor),
            Some(&body),
            media,
        )?;
        let after = self.snapshot(owner, actor, id)?;
        Ok(Trial {
            id: id.into(),
            before,
            after,
            reply,
        })
    }
    fn trial(
        &mut self,
        org: usize,
        actor: usize,
        initial: &[String],
        selected: &[String],
    ) -> Result<Trial, Error> {
        let id = self.shared(usize::from(org == 1), org, initial)?;
        self.on(
            &id,
            org,
            actor,
            json!({"collectionIds":selected}),
            true,
            None,
        )
    }
    fn invite(
        &mut self,
        org: usize,
        role: i32,
        selections: Value,
        permissions: Value,
        confirm: bool,
    ) -> Result<String, Error> {
        let token = self.token(0);
        self.http.json(Method::POST,&format!("/api/organizations/{}/users/invite",self.orgs[org].id),&token,Some(&json!({"emails":[self.accounts[1].fixture["email"]],"type":role,"collections":selections,"groups":[],"permissions":permissions})))?;
        let rows = self.get(
            0,
            &format!(
                "/api/organizations/{}/users?includeCollections=true",
                self.orgs[org].id
            ),
        )?;
        let row = rows["data"]
            .as_array()
            .and_then(|v| {
                v.iter()
                    .find(|v| v["email"] == self.accounts[1].fixture["email"])
            })
            .ok_or(Error("Collection invitee missing"))?;
        require(row["status"] == 1, "Collection invitee was not accepted")?;
        let id = text(&row["id"])?.to_owned();
        if confirm {
            let key = fixture::organization_key_for_account(
                &self.accounts[1].fixture,
                &self.orgs[org].key,
            )
            .map_err(|_| Error("Collection RSA confirmation failed"))?;
            self.http.json(
                Method::POST,
                &format!(
                    "/api/organizations/{}/users/{id}/confirm",
                    self.orgs[org].id
                ),
                &token,
                Some(&json!({"key":key})),
            )?;
        }
        Ok(id)
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let first = s.orgs[0].collection_id.clone();
    let second = s.collections[0].clone();
    let id = s.shared(0, 0, std::slice::from_ref(&first))?;
    let before = s.snapshot(0, 0, &id)?;
    let reply = s.http.raw(
        Method::PUT,
        &format!("/api/ciphers/{id}/collections_v2"),
        "",
        Some(&json!({"collectionIds":[]})),
        true,
    )?;
    let after = s.snapshot(0, 0, &id)?;
    Trial {
        id: id.clone(),
        before,
        after,
        reply,
    }
    .unchanged(401)?;
    for body in [
        json!({}),
        json!({"collectionIds":null}),
        json!({"collectionIds":"bad"}),
        json!({"collectionIds":[second,1]}),
        json!({"collectionids":[second]}),
        Value::Null,
        json!([]),
    ] {
        s.on(&id, 0, 0, body, true, None)?.unchanged(422)?;
    }
    s.on(
        &id,
        0,
        0,
        json!({"collectionIds":[second]}),
        true,
        Some("not-a-uuid"),
    )?
    .unchanged(422)?;
    s.on(
        &id,
        0,
        0,
        json!({"collectionIds":[]}),
        true,
        Some(&Uuid::new_v4().to_string()),
    )?
    .unchanged(400)?;
    let personal = s.accounts[0].cipher_id.clone();
    s.on(
        &personal,
        0,
        0,
        json!({"collectionIds":[second]}),
        true,
        None,
    )?
    .unchanged(400)?;
    let foreign = s.orgs[1].collection_id.clone();
    s.trial(
        1,
        0,
        std::slice::from_ref(&foreign),
        std::slice::from_ref(&foreign),
    )?
    .unchanged(400)?;
    for body in [
        json!({"CollectionIds":[second]}),
        json!([[second]]),
        json!({"collectionIds":[second],"organizationId":s.orgs[1].id,"cipher":{"name":"ignored"}}),
    ] {
        s.on(&id, 0, 0, body, true, None)?
            .success(std::slice::from_ref(&second), true, true)?;
    }
    s.on(&id, 0, 0, json!({"collectionIds":[first]}), false, None)?
        .success(std::slice::from_ref(&first), true, true)?;
    Ok(())
}
fn admission(s: &mut Suite) -> Result<(), Error> {
    let initial = s.orgs[0].collection_id.clone();
    let second = s.collections[0].clone();
    s.trial(
        0,
        1,
        std::slice::from_ref(&initial),
        std::slice::from_ref(&second),
    )?
    .success(std::slice::from_ref(&second), true, true)?;
    for org in [2, 3] {
        let first = s.orgs[org].collection_id.clone();
        s.trial(
            org,
            1,
            std::slice::from_ref(&first),
            std::slice::from_ref(&first),
        )?
        .success(std::slice::from_ref(&first), true, true)?;
    }
    for org in [4, 5] {
        let first = s.orgs[org].collection_id.clone();
        s.trial(
            org,
            1,
            std::slice::from_ref(&first),
            std::slice::from_ref(&first),
        )?
        .unchanged(400)?;
    }
    let unassigned = s.collections[3].clone();
    s.trial(
        0,
        1,
        std::slice::from_ref(&unassigned),
        std::slice::from_ref(&second),
    )?
    .unchanged(400)?;
    let ro = s.collections[1].clone();
    let manage = s.collections[2].clone();
    s.trial(
        0,
        1,
        std::slice::from_ref(&ro),
        std::slice::from_ref(&second),
    )?
    .unchanged(400)?;
    s.trial(
        0,
        1,
        std::slice::from_ref(&manage),
        std::slice::from_ref(&second),
    )?
    .success(std::slice::from_ref(&second), true, true)?;
    let before = s.get(
        0,
        &format!(
            "/api/organizations/{}/users/{}?includeCollections=true",
            s.orgs[0].id, s.member
        ),
    )?;
    s.http.json(
        Method::PUT,
        &format!(
            "/api/organizations/{}/users/{}/revoke",
            s.orgs[0].id, s.member
        ),
        &s.token(0),
        None,
    )?;
    s.trial(
        0,
        1,
        std::slice::from_ref(&initial),
        std::slice::from_ref(&second),
    )?
    .unchanged(400)?;
    s.http.json(
        Method::PUT,
        &format!(
            "/api/organizations/{}/users/{}/restore",
            s.orgs[0].id, s.member
        ),
        &s.token(0),
        None,
    )?;
    require(
        before
            == s.get(
                0,
                &format!(
                    "/api/organizations/{}/users/{}?includeCollections=true",
                    s.orgs[0].id, s.member
                ),
            )?,
        "Collection reassignment changed restored membership",
    )?;
    Ok(())
}
fn replacement(s: &mut Suite) -> Result<(), Error> {
    let first = s.orgs[0].collection_id.clone();
    let second = s.collections[0].clone();
    for selected in [
        vec![second.clone()],
        vec![second.clone(), second.clone()],
        vec![first.clone()],
    ] {
        let expected = selected
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        s.trial(0, 0, std::slice::from_ref(&first), &selected)?
            .success(&expected, true, true)?;
    }
    s.trial(0, 0, std::slice::from_ref(&first), &[])?
        .success(&[], true, true)?;
    let id = s
        .trial(0, 1, std::slice::from_ref(&first), &[])?
        .success(&[], false, false)?;
    let sync = s.get(1, "/api/sync")?;
    let list = s.get(1, "/api/ciphers")?;
    absent(&sync["ciphers"], &id)?;
    absent(&list["data"], &id)?;
    Ok(())
}
fn protected(s: &mut Suite) -> Result<(), Error> {
    let first = s.orgs[0].collection_id.clone();
    let second = s.collections[0].clone();
    for target in [
        s.collections[1].clone(),
        s.collections[2].clone(),
        s.collections[3].clone(),
    ] {
        s.trial(
            0,
            1,
            std::slice::from_ref(&first),
            std::slice::from_ref(&target),
        )?
        .unchanged(400)?;
    }
    let manage = s.collections[2].clone();
    s.trial(
        0,
        1,
        std::slice::from_ref(&manage),
        std::slice::from_ref(&manage),
    )?
    .unchanged(400)?;
    let initial = vec![
        first,
        s.collections[1].clone(),
        manage,
        s.collections[3].clone(),
    ];
    let protected = initial[1..].iter().cloned().collect::<BTreeSet<_>>();
    for selected in [vec![second.clone()], vec![]] {
        let trial = s.trial(0, 1, &initial, &selected)?;
        let mut expected = protected.clone();
        expected.extend(selected.iter().cloned());
        require(
            id_set(&trial.after.owner["collectionIds"])? == expected,
            "Restricted reassignment removed protected old links",
        )?;
        trial.success(&selected, !selected.is_empty(), true)?;
    }
    s.trial(0, 0, &initial, &[])?.success(&[], true, true)?;
    Ok(())
}
fn check_partial_state(
    before: &Snapshot,
    after: &Snapshot,
    first: &str,
    valid: &str,
) -> Result<(), Error> {
    let ids = id_set(&after.owner["collectionIds"])?;
    let committed = ids.contains(valid);
    let expected = if committed {
        BTreeSet::from([first.to_owned(), valid.to_owned()])
    } else {
        BTreeSet::from([first.to_owned()])
    };
    require(
        ids == expected
            && only_links_changed(&before.owner, &after.owner)
            && before.actor
                == after.actor.as_ref().map(|v| {
                    let mut copy = v.clone();
                    copy["collectionIds"] = before.owner["collectionIds"].clone();
                    copy
                })
            && (before.revisions[0] != after.revisions[0]) == committed
            && (before.revisions[1] != after.revisions[1]) == committed,
        "Invalid selection lost old links, added forbidden IDs or rewrote source/revisions",
    )
}
fn partial(s: &mut Suite) -> Result<(), Error> {
    let first = s.orgs[0].collection_id.clone();
    let second = s.collections[0].clone();
    let foreign = s.orgs[1].collection_id.clone();
    let missing = Uuid::new_v4().to_string();
    for selected in [
        vec![second.clone(), missing.clone()],
        vec![missing, second.clone()],
        vec![second.clone(), foreign.clone()],
        vec![foreign, second.clone()],
        vec![second.clone(), second.clone(), Uuid::new_v4().to_string()],
    ] {
        let trial = s.trial(0, 0, std::slice::from_ref(&first), &selected)?;
        trial.reply.rejected(400)?;
        check_partial_state(&trial.before, &trial.after, &first, &second)?;
    }
    Ok(())
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    let first = s.orgs[0].collection_id.clone();
    let second = s.collections[0].clone();
    let id = s.shared(1, 0, std::slice::from_ref(&first))?;
    let before = s.get(1, &format!("/api/ciphers/{id}"))?;
    s.on(&id, 0, 0, json!({"collectionIds":[second]}), true, None)?
        .success(std::slice::from_ref(&second), true, true)?;
    s.on(&id, 0, 1, json!({"collectionIds":[first]}), true, None)?
        .success(std::slice::from_ref(&first), true, true)?;
    require(
        before == s.get(1, &format!("/api/ciphers/{id}"))?,
        "Reassignment changed source creator private annotations or opaque payload after roundtrip",
    )?;
    for actor in 0..2 {
        let direct = s.get(actor, &format!("/api/ciphers/{id}"))?;
        let sync = s.get(actor, "/api/sync")?;
        let list = s.get(actor, "/api/ciphers")?;
        require(
            cipher(&sync["ciphers"], &id)? == &direct && cipher(&list["data"], &id)? == &direct,
            "Reassignment read aliases differed",
        )?;
        let key = s.get(actor, "/api/accounts/keys")?;
        let control = s.get(
            actor,
            &format!("/api/ciphers/{}", s.accounts[actor].cipher_id),
        )?;
        require(
            key == s.keys[actor] && control == s.controls[actor],
            "Reassignment changed account keys or personal control",
        )?;
    }
    let revisions = s.revisions()?;
    for actor in 0..2 {
        s.http.owner.requests += 1;
        s.http.refreshes += 1;
        let response = s
            .http
            .client
            .post(format!("{}/identity/connect/token", s.http.owner.server))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", "cli"),
                ("refresh_token", s.accounts[actor].refresh.as_str()),
            ])
            .send()
            .map_err(|_| Error("Collection refresh failed"))?;
        require(
            response.status().as_u16() == 200,
            "Collection refresh rejected",
        )?;
        let value: Value = response
            .json()
            .map_err(|_| Error("Collection refresh response invalid"))?;
        let profile = s.http.json(
            Method::GET,
            "/api/accounts/profile",
            text(&value["access_token"])?,
            None,
        )?;
        require(
            profile["id"] == s.accounts[actor].user_id,
            "Collection session changed account",
        )?;
    }
    require(
        revisions == s.revisions()?,
        "Collection read/session controls changed account revisions",
    )?;
    Ok(())
}
fn setup() -> Result<Suite, Error> {
    let mut http = Http::new()?;
    let accounts = vec![
        organization_owner::seed(&mut http.owner)?,
        organization_owner::seed(&mut http.owner)?,
    ];
    let mut orgs = Vec::new();
    for owner in [0, 1, 0, 0, 0, 0] {
        orgs.push(create_organization(&mut http.owner, &accounts[owner])?);
    }
    let mut folders = Vec::new();
    for a in &accounts {
        let name =
            fixture::encrypted_fixture_value(&a.fixture, &a.password, b"Private collection folder")
                .map_err(|_| Error("Collection folder encryption failed"))?;
        let value = http.json(
            Method::POST,
            "/api/folders",
            &a.token,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&value["id"])?.to_owned());
    }
    let mut collections = Vec::new();
    for name in [
        "Second writable",
        "Readonly",
        "Readonly manage",
        "Unassigned",
    ] {
        let encrypted = fixture::encrypt(name.as_bytes(), &orgs[0].key)
            .map_err(|_| Error("Collection name encryption failed"))?;
        let row = http.json(
            Method::POST,
            &format!("/api/organizations/{}/collections", orgs[0].id),
            &accounts[0].token,
            Some(&json!({"name":encrypted,"users":[],"groups":[]})),
        )?;
        collections.push(text(&row["id"])?.to_owned());
    }
    let mut s = Suite {
        http,
        accounts,
        orgs,
        collections: collections
            .try_into()
            .map_err(|_| Error("Collection fixtures incomplete"))?,
        folders: folders
            .try_into()
            .map_err(|_| Error("Folder fixtures incomplete"))?,
        member: String::new(),
        keys: [Value::Null, Value::Null],
        controls: [Value::Null, Value::Null],
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_COLLECTIONS_RECEIPT")?,
        finished: false,
    };
    s.member=s.invite(0,2,json!([{"id":s.orgs[0].collection_id,"readOnly":false,"hidePasswords":false,"manage":false},{"id":s.collections[0],"readOnly":false,"hidePasswords":false,"manage":false},{"id":s.collections[1],"readOnly":true,"hidePasswords":false,"manage":false},{"id":s.collections[2],"readOnly":true,"hidePasswords":false,"manage":true}]),json!({}),true)?;
    s.invite(2, 1, json!([]), json!({}), true)?;
    s.invite(
        3,
        4,
        json!([]),
        json!({"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true}),
        true,
    )?;
    s.invite(4, 3, json!([]), json!({}), true)?;
    s.invite(5,2,json!([{"id":s.orgs[5].collection_id,"readOnly":false,"hidePasswords":false,"manage":false}]),json!({}),false)?;
    for actor in 0..2 {
        s.keys[actor] = s.get(actor, "/api/accounts/keys")?;
        s.controls[actor] = s.get(
            actor,
            &format!("/api/ciphers/{}", s.accounts[actor].cipher_id),
        )?;
    }
    Ok(s)
}
pub fn run() -> Result<(), Error> {
    let mut s = setup()?;
    s.receipt("running")?;
    for (name, case) in CASES {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    if s.http.owner.requests != HTTP_REQUEST_COUNT {
        eprintln!(
            "Collection HTTP budget expected {HTTP_REQUEST_COUNT}, actual {}",
            s.http.owner.requests
        );
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 2,
        "Collection fixture budget differed",
    )?;
    s.finished = true;
    s.receipt("passed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(ids: Value, revision: i32) -> Snapshot {
        let value = json!({"id":"cipher","organizationId":"org","collectionIds":ids,"revisionDate":"fixed","name":"opaque","notes":"opaque","key":null,"favorite":true,"folderId":"private"});
        Snapshot {
            owner: value.clone(),
            actor: Some(value),
            revisions: [json!(revision), json!(revision)],
        }
    }
    #[test]
    fn lost_read_operation_response_preserves_prior_ciphertext_revision_and_annotations() {
        let before = json!({"id":"cipher","organizationId":"org","name":"opaque","notes":"opaque","key":null,"creationDate":"created","revisionDate":"fixed","favorite":true,"folderId":"private","collectionIds":["old"],"edit":true,"viewPassword":true,"permissions":{"delete":true,"restore":true}});
        let mut returned = before.clone();
        returned["collectionIds"] = json!([]);
        returned["edit"] = json!(false);
        returned["viewPassword"] = json!(false);
        returned["permissions"] = json!({"delete":false,"restore":false});
        assert!(operation_payload_preserved(
            &before, &returned, false, false
        ));
        for field in [
            "id",
            "organizationId",
            "name",
            "notes",
            "key",
            "creationDate",
            "revisionDate",
            "favorite",
            "folderId",
        ] {
            let mut changed = returned.clone();
            changed[field] = json!("changed");
            assert!(!operation_payload_preserved(
                &before, &changed, false, false
            ));
        }
    }
    #[test]
    fn unordered_partial_validator_accepts_both_observed_subsets_and_rejects_authority_or_payload_drift()
     {
        let before = snapshot(json!(["old"]), 1);
        assert!(check_partial_state(&before, &snapshot(json!(["old"]), 1), "old", "valid").is_ok());
        assert!(
            check_partial_state(
                &before,
                &snapshot(json!(["old", "valid"]), 2),
                "old",
                "valid"
            )
            .is_ok()
        );
        for ids in [
            json!([]),
            json!(["valid"]),
            json!(["old", "foreign"]),
            json!(["old", "valid", "valid"]),
        ] {
            assert!(check_partial_state(&before, &snapshot(ids, 2), "old", "valid").is_err());
        }
        for field in [
            "name",
            "notes",
            "key",
            "revisionDate",
            "favorite",
            "folderId",
        ] {
            let mut after = snapshot(json!(["old", "valid"]), 2);
            after.owner[field] = json!("changed");
            assert!(check_partial_state(&before, &after, "old", "valid").is_err());
        }
        assert!(
            check_partial_state(
                &before,
                &snapshot(json!(["old", "valid"]), 1),
                "old",
                "valid"
            )
            .is_err()
        );
        assert!(
            check_partial_state(&before, &snapshot(json!(["old"]), 2), "old", "valid").is_err()
        );
    }
}
