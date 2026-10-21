//! Independently authored actor-private annotation contracts. MIT OR Apache-2.0.
//! Manual HTTP mutations; actual client observation is a separate suite.
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
// Development count; fixed from actual native execution before final proofs.
pub const HTTP_REQUEST_COUNT: usize = 0;
const NOTE: &str = "Archive retains encrypted note Ω\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_cipher_archive_path_personal_and_method_guards",
        guards,
    ),
    (
        "organization_cipher_archive_confirmed_read_admission_and_states",
        admission,
    ),
    (
        "organization_cipher_archive_single_private_dates_and_reader_revision_fanout",
        single,
    ),
    (
        "organization_cipher_archive_selected_actor_revision_duplicates_empty_and_durable_authorized_steps",
        selected,
    ),
    (
        "organization_cipher_archive_selected_wire_schema_and_ignored_single_body",
        schema,
    ),
    (
        "organization_cipher_archive_opaque_private_aliases_keys_and_sessions",
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
            eprintln!("Archive status expected {expected}, actual {}", self.status);
        }
        require(self.status == expected, "Archive status differed")?;
        Ok(self.value)
    }
    fn schema(self, expected: u16) -> Result<(), Error> {
        let value = self.status(expected)?;
        require(
            value
                .as_object()
                .is_some_and(|o| o.len() == 1 && o.contains_key("error")),
            "Archive schema envelope differed",
        )
    }
    fn rejected(self, expected: u16) -> Result<(), Error> {
        let v = self.status(expected)?;
        require(
            [
                "access_token",
                "refresh_token",
                "key",
                "privateKey",
                "publicKey",
            ]
            .iter()
            .all(|k| v.get(k).is_none()),
            "Archive rejection exposed authority",
        )?;
        if expected == 422 {
            return require(
                v.as_object()
                    .is_some_and(|o| o.len() == 1 && o.contains_key("error")),
                "Archive schema envelope differed",
            );
        }
        if expected == 400 {
            let keys = BTreeSet::from([
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
                v.as_object()
                    .is_some_and(|o| o.keys().map(String::as_str).collect::<BTreeSet<_>>() == keys)
                    && v["object"] == "error"
                    && v["message"].is_string()
                    && v["validationErrors"].is_object(),
                "Archive business envelope differed",
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
    ) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let mut q = self
            .client
            .request(method, format!("{}{path}", self.owner.server))
            .header("Accept", "application/json");
        if !token.is_empty() {
            q = q.bearer_auth(token);
        }
        if let Some(v) = body {
            q = q.json(v);
        }
        let r = q.send().map_err(|_| Error("Archive HTTP request failed"))?;
        let status = r.status().as_u16();
        let mut bytes = Vec::new();
        r.take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Archive private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Archive capture bound exceeded",
        )?;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| Error("Archive response was not JSON"))?
        };
        Ok(Reply { status, value })
    }
    fn raw_text(&mut self, path: &str, token: &str, body: &str) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let r = self
            .client
            .put(format!("{}{path}", self.owner.server))
            .bearer_auth(token)
            .header("Content-Type", "application/json")
            .body(body.to_owned())
            .send()
            .map_err(|_| Error("Archive raw request failed"))?;
        let status = r.status().as_u16();
        let mut bytes = Vec::new();
        r.take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Archive raw capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Archive raw capture bound exceeded",
        )?;
        let value =
            serde_json::from_slice(&bytes).map_err(|_| Error("Archive raw response not JSON"))?;
        Ok(Reply { status, value })
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        self.raw(method, path, token, body)?.status(200)
    }
}
#[derive(Clone)]
struct Snapshot {
    documents: [Option<Value>; 2],
    revisions: [Value; 2],
}
struct Trial {
    id: String,
    actor: usize,
    before: Snapshot,
    after: Snapshot,
    reply: Reply,
}
fn archive_only(before: &Value, after: &Value) -> bool {
    let mut expected = before.clone();
    expected["archivedDate"] = after["archivedDate"].clone();
    expected == *after
}
impl Trial {
    fn unchanged(self, status: u16, schema: bool) -> Result<(), Error> {
        if schema {
            self.reply.schema(status)?;
        } else {
            self.reply.rejected(status)?;
        }
        require(
            self.before.documents == self.after.documents
                && self.before.revisions == self.after.revisions,
            "Rejected archive changed source/annotations/account revisions",
        )
    }
    fn success(self, archived: bool, selected: bool) -> Result<(), Error> {
        let reply = self.reply.status(200)?;
        let prior = self.before.documents[self.actor]
            .as_ref()
            .ok_or(Error("Archive actor lacked prior read"))?;
        let after = self.after.documents[self.actor]
            .as_ref()
            .ok_or(Error("Archive lost actor read"))?;
        require(
            archive_only(prior, after)
                && if archived {
                    after["archivedDate"].is_string()
                        && after["archivedDate"] != prior["archivedDate"]
                } else {
                    after["archivedDate"].is_null()
                },
            "Archive modified common/private state or wrong archive date",
        )?;
        require(
            self.before.revisions[self.actor] != self.after.revisions[self.actor],
            "Archive did not advance acting account revision",
        )?;
        let other = 1 - self.actor;
        require(
            self.before.documents[other] == self.after.documents[other],
            "Archive crossed viewer private boundary",
        )?;
        let notify_other = !selected && self.before.documents[other].is_some();
        require(
            (self.before.revisions[other] != self.after.revisions[other]) == notify_other,
            "Archive single/selected reader revision effect differed",
        )?;
        let returned = if selected {
            require(
                reply.as_object().is_some_and(|o| o.len() == 3)
                    && reply["object"] == "list"
                    && reply["continuationToken"].is_null()
                    && reply["data"].as_array().is_some_and(|a| a.len() == 1),
                "Archive selected envelope or deduplication differed",
            )?;
            &reply["data"][0]
        } else {
            &reply
        };
        require(
            returned == after && returned.as_object().is_some_and(|o| o.len() == 30),
            "Archive reply differed from 30-field actor GET",
        )?;
        let ids = after["collectionIds"]
            .as_array()
            .ok_or(Error("Archive collection IDs missing"))?
            .iter()
            .map(|v| text(v).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        let mut normalized = after.clone();
        normalized["key"] = Value::Null;
        normalized["archivedDate"] = Value::Null;
        check_cipher(
            &normalized,
            CipherExpectation {
                id: &self.id,
                organization: after["organizationId"].as_str(),
                collections: &ids,
                edit: after["edit"]
                    .as_bool()
                    .ok_or(Error("Archive edit missing"))?,
                view_password: after["viewPassword"]
                    .as_bool()
                    .ok_or(Error("Archive view missing"))?,
                favorite: after["favorite"]
                    .as_bool()
                    .ok_or(Error("Archive favorite missing"))?,
                folder: after["folderId"].as_str(),
            },
        )
    }
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    collections: [String; 3],
    folders: [String; 2],
    members: [String; 2],
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
            &json!({"schemaVersion":1,"status":status,"passedCases":self.passed.len(),"expectedCases":CASE_COUNT,"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"passwordCredentialAttempts":self.http.owner.logins,"singleCurrentReaderRevisionFanoutAsserted":true,"selectedActorOnlyRevisionAsserted":true,"duplicateAndEmptySelectionsAsserted":true,"singleSchemaAndAllInvalidFailuresPreserveStateAsserted":true,"mixedSelectionFailureEligibleActorOnlyDurableSubsetAsserted":true,"selectedInputOrderClaimed":false,"readonlyReadAdmissionAsserted":true,"opaquePayloadCipherRevisionPrivateAnnotationsKeysAndSessionsAsserted":true,"replyEqualsActorGetWith30FieldsAsserted":true,"cliCallerClaimed":false,"capturedRouteTrace":false,"browserTraceClaimed":false,"attachmentBearingTested":false,"groupsConfigured":false,"configuredPolicies":false,"smtpEnabled":false,"fullParityClaimed":false}),
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
    fn snapshot(&mut self, id: &str) -> Result<Snapshot, Error> {
        let mut docs = [None, None];
        for (actor, slot) in docs.iter_mut().enumerate() {
            let r = self.http.raw(
                Method::GET,
                &format!("/api/ciphers/{id}"),
                &self.token(actor),
                None,
            )?;
            if r.status == 200 {
                *slot = Some(r.value);
            } else {
                r.rejected(400)?;
            }
        }
        Ok(Snapshot {
            documents: docs,
            revisions: self.revisions()?,
        })
    }
    fn on(
        &mut self,
        id: &str,
        actor: usize,
        op: &str,
        selected: bool,
        body: Value,
    ) -> Result<Trial, Error> {
        let path = if selected {
            format!("/api/ciphers/{op}")
        } else {
            format!("/api/ciphers/{id}/{op}")
        };
        self.at(id, actor, Method::PUT, &path, Some(body), false)
    }
    fn at(
        &mut self,
        id: &str,
        actor: usize,
        method: Method,
        path: &str,
        body: Option<Value>,
        anonymous: bool,
    ) -> Result<Trial, Error> {
        let before = self.snapshot(id)?;
        let token = if anonymous {
            String::new()
        } else {
            self.token(actor)
        };
        let reply = self.http.raw(method, path, &token, body.as_ref())?;
        let after = self.snapshot(id)?;
        Ok(Trial {
            id: id.into(),
            actor,
            before,
            after,
            reply,
        })
    }
    fn apply(
        &mut self,
        id: &str,
        actor: usize,
        archived: bool,
        selected: bool,
    ) -> Result<(), Error> {
        self.on(
            id,
            actor,
            if archived { "archive" } else { "unarchive" },
            selected,
            json!({"ids":[id]}),
        )?
        .success(archived, selected)
    }
    fn selected_failure(
        &mut self,
        observed: &[String],
        eligible: &[String],
        actor: usize,
        archived: bool,
        ids: Value,
    ) -> Result<(), Error> {
        let before = observed
            .iter()
            .map(|id| self.snapshot(id))
            .collect::<Result<Vec<_>, _>>()?;
        self.http
            .raw(
                Method::PUT,
                if archived {
                    "/api/ciphers/archive"
                } else {
                    "/api/ciphers/unarchive"
                },
                &self.token(actor),
                Some(&json!({"ids":ids})),
            )?
            .rejected(400)?;
        let after = observed
            .iter()
            .map(|id| self.snapshot(id))
            .collect::<Result<Vec<_>, _>>()?;
        let revisions_before = &before
            .first()
            .ok_or(Error("Archive failure observation empty"))?
            .revisions;
        let revisions_after = &after
            .first()
            .ok_or(Error("Archive failure observation empty"))?
            .revisions;
        let advanced = revisions_before[actor] != revisions_after[actor];
        let mut date_changed = false;
        let mut eligible_prior_null = false;
        require(
            revisions_before[1 - actor] == revisions_after[1 - actor],
            "Failed selected archive advanced peer account revision",
        )?;
        for ((id, b), a) in observed.iter().zip(&before).zip(&after) {
            require(
                &b.revisions == revisions_before && &a.revisions == revisions_after,
                "Archive failure snapshots lost coherent account state",
            )?;
            require(
                b.documents[1 - actor] == a.documents[1 - actor],
                "Failed selected archive changed peer document",
            )?;
            if eligible.contains(id) {
                let prior = b.documents[actor]
                    .as_ref()
                    .ok_or(Error("Archive eligible actor prior missing"))?;
                eligible_prior_null |= prior["archivedDate"].is_null();
                let next = a.documents[actor]
                    .as_ref()
                    .ok_or(Error("Archive eligible actor read removed"))?;
                require(
                    archive_only(prior, next),
                    "Failed selected archive changed common payload/cipher revision/private annotations",
                )?;
                if prior["archivedDate"] != next["archivedDate"] {
                    date_changed = true;
                    require(
                        if archived {
                            next["archivedDate"].is_string()
                        } else {
                            next["archivedDate"].is_null()
                        },
                        "Failed selected archive applied wrong operation",
                    )?;
                }
            } else {
                require(
                    b.documents[actor] == a.documents[actor],
                    "Failed selected archive changed ineligible/unselected actor source",
                )?;
            }
        }
        require(
            !date_changed || advanced,
            "Failed selected archive changed date without actor revision",
        )?;
        require(
            !advanced || date_changed || (!archived && eligible_prior_null),
            "Failed selected archive advanced actor without a fresh date or eligible unarchive noop",
        )?;
        require(
            !eligible.is_empty() || !advanced,
            "All-invalid selected archive advanced actor revision",
        )
    }
    fn raw_trial(
        &mut self,
        id: &str,
        actor: usize,
        path: &str,
        body: &str,
    ) -> Result<Trial, Error> {
        let before = self.snapshot(id)?;
        let reply = self.http.raw_text(path, &self.token(actor), body)?;
        let after = self.snapshot(id)?;
        Ok(Trial {
            id: id.into(),
            actor,
            before,
            after,
            reply,
        })
    }
    fn personal(&mut self, source: usize) -> Result<String, Error> {
        let sealed = fixture::encrypted_fixture_value(
            &self.accounts[source].fixture,
            &self.accounts[source].password,
            NOTE.as_bytes(),
        )
        .map_err(|_| Error("Archive personal encryption failed"))?;
        let v=self.http.json(Method::POST,"/api/ciphers",&self.token(source),Some(&json!({"type":2,"encryptedFor":self.accounts[source].user_id,"name":sealed,"notes":sealed,"secureNote":{"type":0},"favorite":true,"folderId":self.folders[source]})))?;
        Ok(text(&v["id"])?.to_owned())
    }
    fn share(
        &mut self,
        id: &str,
        source: usize,
        org: usize,
        selected: &[String],
        wrapped: bool,
    ) -> Result<(), Error> {
        let cipher_key = [91u8; 64];
        let key = if wrapped {
            &cipher_key
        } else {
            &self.orgs[org].key
        };
        let sealed = fixture::encrypt(NOTE.as_bytes(), key)
            .map_err(|_| Error("Archive shared encryption failed"))?;
        let wrapped = if wrapped {
            Some(
                fixture::encrypt(&cipher_key, &self.orgs[org].key)
                    .map_err(|_| Error("Archive cipher key encryption failed"))?,
            )
        } else {
            None
        };
        self.http.json(Method::PUT,&format!("/api/ciphers/{id}/share"),&self.token(source),Some(&json!({"collectionIds":selected,"cipher":{"type":2,"organizationId":self.orgs[org].id,"encryptedFor":self.accounts[source].user_id,"name":sealed,"notes":sealed,"secureNote":{"type":0},"fields":[{"name":sealed,"value":sealed,"type":0,"linkedId":null}],"passwordHistory":[{"password":sealed,"lastUsedDate":"2024-01-01T00:00:00.000000Z"}],"favorite":true,"folderId":self.folders[source],"key":wrapped}})))?;
        Ok(())
    }
    fn shared(&mut self, org: usize, collection: &str, wrapped: bool) -> Result<String, Error> {
        let source = usize::from(org == 1);
        let id = self.personal(source)?;
        self.share(&id, source, org, &[collection.into()], wrapped)?;
        Ok(id)
    }
    fn invite(
        &mut self,
        org: usize,
        role: i32,
        collections: Value,
        permissions: Value,
        confirm: bool,
    ) -> Result<String, Error> {
        self.http.json(Method::POST,&format!("/api/organizations/{}/users/invite",self.orgs[org].id),&self.token(0),Some(&json!({"emails":[self.accounts[1].fixture["email"]],"type":role,"groups":[],"collections":collections,"permissions":permissions})))?;
        let v = self.get(
            0,
            &format!(
                "/api/organizations/{}/users?includeCollections=true",
                self.orgs[org].id
            ),
        )?;
        let r = v["data"]
            .as_array()
            .and_then(|rows| {
                rows.iter()
                    .find(|r| r["email"] == self.accounts[1].fixture["email"])
            })
            .ok_or(Error("Archive fixture member missing"))?;
        require(
            r["status"] == 1,
            "Archive fixture invitation state differed",
        )?;
        let id = text(&r["id"])?.to_owned();
        if confirm {
            let key = fixture::organization_key_for_account(
                &self.accounts[1].fixture,
                &self.orgs[org].key,
            )
            .map_err(|_| Error("Archive RSA fixture failed"))?;
            self.http.json(
                Method::POST,
                &format!(
                    "/api/organizations/{}/users/{id}/confirm",
                    self.orgs[org].id
                ),
                &self.token(0),
                Some(&json!({"key":key})),
            )?;
        }
        Ok(id)
    }
    fn status(&mut self, org: usize, member: &str, op: &str) -> Result<(), Error> {
        self.http.json(
            Method::PUT,
            &format!(
                "/api/organizations/{}/users/{member}/{op}",
                self.orgs[org].id
            ),
            &self.token(0),
            Some(&json!({})),
        )?;
        Ok(())
    }
    fn aliases(&mut self, id: &str, actor: usize) -> Result<(), Error> {
        let direct = self.get(actor, &format!("/api/ciphers/{id}"))?;
        for path in ["/api/ciphers", "/api/sync"] {
            let v = self.get(actor, path)?;
            let rows = if path == "/api/sync" {
                &v["ciphers"]
            } else {
                &v["data"]
            };
            let row = rows
                .as_array()
                .and_then(|a| a.iter().find(|v| v["id"] == id))
                .ok_or(Error("Archive cipher absent from readable alias"))?;
            let mut normalized = row.clone();
            normalized["collectionIds"] = direct["collectionIds"].clone();
            require(
                normalized == direct,
                "Archive read alias changed annotations/common fields",
            )?;
        }
        Ok(())
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let id = s.personal(0)?;
    s.at(
        &id,
        0,
        Method::PUT,
        &format!("/api/ciphers/{id}/archive"),
        None,
        true,
    )?
    .unchanged(401, false)?;
    s.at(
        &id,
        0,
        Method::PUT,
        "/api/ciphers/not-a-uuid/archive",
        None,
        false,
    )?
    .unchanged(422, true)?;
    s.at(
        &id,
        0,
        Method::PUT,
        &format!("/api/ciphers/{}/archive", Uuid::new_v4()),
        None,
        false,
    )?
    .unchanged(400, false)?;
    for op in ["archive", "unarchive"] {
        s.at(
            &id,
            0,
            Method::POST,
            &format!("/api/ciphers/{id}/{op}"),
            None,
            false,
        )?
        .unchanged(404, false)?;
    }
    s.on(&id, 1, "archive", false, json!({}))?
        .unchanged(400, false)?;
    s.apply(&id, 0, true, false)?;
    s.apply(&id, 0, false, false)
}
fn admission(s: &mut Suite) -> Result<(), Error> {
    for (org, collection, actor, allowed) in [
        (0, s.orgs[0].collection_id.clone(), 0, true),
        (0, s.orgs[0].collection_id.clone(), 1, true),
        (0, s.collections[0].clone(), 1, true),
        (0, s.collections[1].clone(), 1, true),
        (0, s.collections[2].clone(), 1, false),
        (2, s.orgs[2].collection_id.clone(), 1, true),
        (3, s.orgs[3].collection_id.clone(), 1, true),
        (4, s.orgs[4].collection_id.clone(), 1, false),
    ] {
        let id = s.shared(org, &collection, false)?;
        for selected in [false, true] {
            for archived in [true, false] {
                if allowed {
                    s.apply(&id, actor, archived, selected)?;
                } else {
                    s.on(
                        &id,
                        actor,
                        if archived { "archive" } else { "unarchive" },
                        selected,
                        json!({"ids":[id]}),
                    )?
                    .unchanged(400, false)?;
                }
            }
        }
    }
    let id = s.shared(0, &s.orgs[0].collection_id.clone(), false)?;
    let member = s.members[0].clone();
    s.status(0, &member, "revoke")?;
    for selected in [false, true] {
        s.on(&id, 1, "archive", selected, json!({"ids":[id]}))?
            .unchanged(400, false)?;
    }
    s.status(0, &member, "restore")?;
    s.apply(&id, 1, true, false)?;
    s.apply(&id, 1, false, true)
}
fn single(s: &mut Suite) -> Result<(), Error> {
    let id = s.shared(0, &s.orgs[0].collection_id.clone(), true)?;
    // Give the peer a distinct legitimate private baseline through the proven route.
    s.http.json(
        Method::PUT,
        &format!("/api/ciphers/{id}/partial"),
        &s.token(1),
        Some(&json!({"favorite":false,"folderId":s.folders[1]})),
    )?;
    for (actor, archived) in [
        (0, true),
        (0, true),
        (1, false),
        (1, true),
        (0, false),
        (0, false),
        (1, false),
    ] {
        s.apply(&id, actor, archived, false)?;
    }
    s.aliases(&id, 0)?;
    s.aliases(&id, 1)
}
fn selected(s: &mut Suite) -> Result<(), Error> {
    let id = s.shared(0, &s.orgs[0].collection_id.clone(), false)?;
    for (actor, archived) in [
        (0, true),
        (0, true),
        (1, false),
        (1, true),
        (0, false),
        (1, false),
    ] {
        s.apply(&id, actor, archived, true)?;
    }
    s.on(&id, 1, "archive", true, json!({"ids":[id,id]}))?
        .success(true, true)?;
    let t = s.on(&id, 1, "unarchive", true, json!({"ids":[]}))?;
    let v = t.reply.status(200)?;
    require(
        v == json!({"object":"list","data":[],"continuationToken":null})
            && t.before.documents == t.after.documents
            && t.before.revisions == t.after.revisions,
        "Empty archive selection mutated state",
    )?;
    let foreign = s.personal(1)?;
    let second = s.shared(0, &s.orgs[0].collection_id.clone(), true)?;
    let absent = Uuid::new_v4().to_string();
    let observed = [id.clone(), second.clone(), foreign.clone()];
    // Native uses an unstable per-request processing order: eligible completed
    // steps can survive400. Constrain the changed set; do not assume input order.
    for archived in [true, false] {
        for ids in [
            json!([id, absent]),
            json!([absent, id]),
            json!([id, foreign]),
        ] {
            s.selected_failure(&observed, std::slice::from_ref(&id), 0, archived, ids)?;
        }
        for ids in [json!([id, second, absent]), json!([absent, second, id])] {
            s.selected_failure(&observed, &[id.clone(), second.clone()], 0, archived, ids)?;
        }
        for ids in [json!([absent]), json!([foreign])] {
            s.selected_failure(&observed, &[], 0, archived, ids)?;
        }
    }
    Ok(())
}
fn schema(s: &mut Suite) -> Result<(), Error> {
    let id = s.shared(0, &s.orgs[0].collection_id.clone(), false)?;
    for body in [
        json!({}),
        json!({"ids":null}),
        json!({"Ids":[id]}),
        json!({"ids":[3]}),
        json!({"ids":[null]}),
        Value::Null,
    ] {
        s.on(&id, 0, "archive", true, body)?.unchanged(422, true)?;
    }
    s.on(&id, 0, "archive", true, json!({"ids":["not-a-uuid"]}))?
        .unchanged(400, false)?;
    s.on(&id, 0, "archive", true, json!([[id]]))?
        .success(true, true)?;
    s.on(&id, 0, "unarchive", true, json!([[id], "extra"]))?
        .unchanged(400, true)?;
    s.on(
        &id,
        0,
        "unarchive",
        true,
        json!({"ids":[id],"ignored":true}),
    )?
    .success(false, true)?;
    s.raw_trial(
        &id,
        0,
        "/api/ciphers/archive",
        &format!("{{\"ids\":[\"{id}\"],\"ids\":[\"{id}\"]}}"),
    )?
    .unchanged(422, true)?;
    s.raw_trial(&id, 0, "/api/ciphers/archive", "{")?
        .unchanged(400, true)?;
    s.raw_trial(&id, 0, &format!("/api/ciphers/{id}/archive"), "{")?
        .success(true, false)
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    let id = s.shared(0, &s.orgs[0].collection_id.clone(), true)?;
    s.http.json(
        Method::PUT,
        &format!("/api/ciphers/{id}/partial"),
        &s.token(1),
        Some(&json!({"favorite":false,"folderId":s.folders[1]})),
    )?;
    let before = s.snapshot(&id)?;
    s.apply(&id, 1, true, true)?;
    s.aliases(&id, 0)?;
    s.aliases(&id, 1)?;
    s.apply(&id, 1, false, true)?;
    let after = s.snapshot(&id)?;
    require(
        before.documents == after.documents,
        "Archive cycle lost opaque/private/source revision state",
    )?;
    for actor in 0..2 {
        require(
            s.get(actor, "/api/accounts/keys")? == s.keys[actor],
            "Archive changed account keys",
        )?;
        let control = s.accounts[actor].cipher_id.clone();
        require(
            s.get(actor, &format!("/api/ciphers/{control}"))? == s.controls[actor],
            "Archive changed personal control",
        )?;
    }
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
            fixture::encrypted_fixture_value(&a.fixture, &a.password, b"Private archive folder")
                .map_err(|_| Error("Archive folder encryption failed"))?;
        let v = http.json(
            Method::POST,
            "/api/folders",
            &a.token,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&v["id"])?.to_owned());
    }
    let mut collections = Vec::new();
    for name in [
        "Writable archive",
        "Readonly manage archive",
        "Unassigned archive",
    ] {
        let sealed = fixture::encrypt(name.as_bytes(), &orgs[0].key)
            .map_err(|_| Error("Archive collection encryption failed"))?;
        let v = http.json(
            Method::POST,
            &format!("/api/organizations/{}/collections", orgs[0].id),
            &accounts[0].token,
            Some(&json!({"name":sealed,"users":[],"groups":[]})),
        )?;
        collections.push(text(&v["id"])?.to_owned());
    }
    let mut s = Suite {
        http,
        accounts,
        orgs,
        collections: collections
            .try_into()
            .map_err(|_| Error("Archive collections incomplete"))?,
        folders: folders
            .try_into()
            .map_err(|_| Error("Archive folders incomplete"))?,
        members: [String::new(), String::new()],
        keys: [Value::Null, Value::Null],
        controls: [Value::Null, Value::Null],
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_ARCHIVE_RECEIPT")?,
        finished: false,
    };
    s.members[0]=s.invite(0,2,json!([{"id":s.orgs[0].collection_id,"readOnly":true,"manage":false,"hidePasswords":false},{"id":s.collections[0],"readOnly":false,"manage":false,"hidePasswords":false},{"id":s.collections[1],"readOnly":true,"manage":true,"hidePasswords":false}]),json!({}),true)?;
    s.invite(2, 1, json!([]), json!({}), true)?;
    s.invite(
        3,
        4,
        json!([]),
        json!({"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true}),
        true,
    )?;
    s.invite(4,2,json!([{"id":s.orgs[4].collection_id,"readOnly":true,"manage":false,"hidePasswords":false}]),json!({}),false)?;
    s.members[1] = s.invite(5, 2, json!([]), json!({}), true)?;
    for actor in 0..2 {
        s.keys[actor] = s.get(actor, "/api/accounts/keys")?;
        let id = s.accounts[actor].cipher_id.clone();
        s.controls[actor] = s.get(actor, &format!("/api/ciphers/{id}"))?;
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
            "Archive HTTP budget expected {HTTP_REQUEST_COUNT}, actual {}",
            s.http.owner.requests
        );
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 0,
        "Archive fixture budget differed",
    )?;
    s.finished = true;
    s.receipt("passed")?;
    Ok(())
}
