//! Independently authored shared single-item lifecycle contracts. MIT OR Apache-2.0.
//! Manual HTTP mutations; actual client observation is a separate suite.
use crate::{
    fixture,
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
// Intentionally zero until all six native development cases complete.
pub const HTTP_REQUEST_COUNT: usize = 0;
const NOTE: &str = "Lifecycle retains encrypted note Ω\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_cipher_lifecycle_method_auth_uuid_personal_guards",
        guards,
    ),
    (
        "organization_cipher_lifecycle_confirmed_write_roles_and_states",
        admission,
    ),
    (
        "organization_cipher_lifecycle_trash_repeat_restore_private_archives_reader_revisions",
        surviving,
    ),
    (
        "organization_cipher_lifecycle_permanent_active_trashed_aliases_absence",
        permanent,
    ),
    (
        "organization_cipher_lifecycle_denied_operations_preserve_full_state",
        denied,
    ),
    (
        "organization_cipher_lifecycle_ignored_body_restore_projection_keys_sessions",
        preservation,
    ),
];
struct Reply {
    status: u16,
    value: Value,
    empty: bool,
    content_type: Option<String>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Value, Error> {
        if self.status != expected {
            eprintln!(
                "Lifecycle status expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Lifecycle status differed")?;
        Ok(self.value)
    }
    fn empty_success(self) -> Result<(), Error> {
        require(
            self.status == 200 && self.empty && self.content_type.is_none(),
            "Lifecycle mutation did not return empty200 without Content-Type",
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
            "Lifecycle rejection exposed authority",
        )?;
        if expected == 422 {
            return require(
                v.as_object()
                    .is_some_and(|o| o.len() == 1 && o.contains_key("error")),
                "Lifecycle schema envelope differed",
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
                "Lifecycle business envelope differed",
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
        let r = q
            .send()
            .map_err(|_| Error("Lifecycle HTTP request failed"))?;
        let status = r.status().as_u16();
        let content_type = r
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        r.take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Lifecycle private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Lifecycle capture bound exceeded",
        )?;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| Error("Lifecycle response was not JSON"))?
        };
        Ok(Reply {
            status,
            value,
            empty: bytes.is_empty(),
            content_type,
        })
    }
    fn raw_text(&mut self, path: &str, token: &str, body: &str) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let r = self
            .client
            .put(format!("{}{path}", self.owner.server))
            .bearer_auth(token)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(body.to_owned())
            .send()
            .map_err(|_| Error("Lifecycle raw request failed"))?;
        let status = r.status().as_u16();
        let content_type = r
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        r.take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Lifecycle raw capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Lifecycle raw capture bound exceeded",
        )?;
        let value =
            serde_json::from_slice(&bytes).map_err(|_| Error("Lifecycle raw response not JSON"))?;
        Ok(Reply {
            status,
            value,
            empty: bytes.is_empty(),
            content_type,
        })
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
    actor: usize,
    before: Snapshot,
    after: Snapshot,
    reply: Reply,
}
fn lifecycle_only(before: &Value, after: &Value) -> bool {
    let mut expected = before.clone();
    expected["deletedDate"] = after["deletedDate"].clone();
    expected["revisionDate"] = after["revisionDate"].clone();
    expected == *after
}
impl Trial {
    fn unchanged(self, status: u16) -> Result<(), Error> {
        self.reply.rejected(status)?;
        require(
            self.before.documents == self.after.documents
                && self.before.revisions == self.after.revisions,
            "Rejected lifecycle changed document/private state/account revisions",
        )
    }
    fn success(self, op: Op) -> Result<(), Error> {
        for actor in 0..2 {
            let prior = &self.before.documents[actor];
            let after = &self.after.documents[actor];
            require(
                (self.before.revisions[actor] != self.after.revisions[actor]) == prior.is_some(),
                "Lifecycle did not notify exactly observed current readers",
            )?;
            match (prior, after) {
                (Some(prior), Some(after)) if op != Op::Permanent => {
                    require(
                        lifecycle_only(prior, after)
                            && prior["revisionDate"] != after["revisionDate"],
                        "Lifecycle lost common/opaque/private/archive state or source revision",
                    )?;
                    require(
                        if op == Op::Trash {
                            after["deletedDate"].is_string()
                                && prior["deletedDate"] != after["deletedDate"]
                        } else {
                            after["deletedDate"].is_null()
                        },
                        "Lifecycle deletion date differed",
                    )?;
                }
                (Some(_), None) if op == Op::Permanent => {}
                (None, None) => {}
                _ => return Err(Error("Lifecycle changed read scope unexpectedly")),
            }
        }
        require(
            self.before.documents[self.actor].is_some(),
            "Lifecycle actor lacked prior read",
        )?;
        if op == Op::Restore {
            require(
                self.reply.status == 200
                    && self
                        .reply
                        .content_type
                        .as_deref()
                        .is_some_and(|v| v.starts_with("application/json"))
                    && self.reply.value.as_object().is_some_and(|o| o.len() == 30)
                    && self.after.documents[self.actor].as_ref() == Some(&self.reply.value),
                "Lifecycle restore response not JSON30 equal actor GET",
            )
        } else {
            self.reply.empty_success()
        }
    }
}
#[derive(Clone, Copy, PartialEq)]
enum Op {
    Trash,
    Restore,
    Permanent,
}
impl Op {
    fn path(self, id: &str) -> String {
        match self {
            Self::Trash => format!("/api/ciphers/{id}/delete"),
            Self::Restore => format!("/api/ciphers/{id}/restore"),
            Self::Permanent => format!("/api/ciphers/{id}"),
        }
    }
    fn method(self) -> Method {
        if self == Self::Permanent {
            Method::DELETE
        } else {
            Method::PUT
        }
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
            &json!({"schemaVersion":1,"status":status,"passedCases":self.passed.len(),"expectedCases":CASE_COUNT,"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"passwordCredentialAttempts":self.http.owner.logins,"currentWriteRoleAndStatusAdmissionAsserted":true,"readonlyManageAdmissionIndependentOfGetFlagsAsserted":true,"currentObservedReadersRevisionFanoutAsserted":true,"trashRepeatActiveRestoreAndPermanentBothStatesAsserted":true,"opaquePayloadPrivateAnnotationsArchivesKeysAndSessionsAsserted":true,"empty200WithoutContentTypeAsserted":true,"restoreJson30EqualsActorGetAsserted":true,"postRestore404BeforeServiceAsserted":true,"allRejectedOperationsPreserveStateAsserted":true,"cliCallerClaimed":false,"capturedRouteTrace":false,"browserTraceClaimed":false,"attachmentBearingTested":false,"selectedBulkLifecycleTested":false,"groupsConfigured":false,"configuredPolicies":false,"smtpEnabled":false,"fullParityClaimed":false}),
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
            actor,
            before,
            after,
            reply,
        })
    }
    fn apply(&mut self, id: &str, actor: usize, op: Op) -> Result<(), Error> {
        self.at(id, actor, op.method(), &op.path(id), None, false)?
            .success(op)
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
            actor,
            before,
            after,
            reply,
        })
    }
    fn private(&mut self, id: &str) -> Result<(), Error> {
        self.http.json(
            Method::PUT,
            &format!("/api/ciphers/{id}/partial"),
            &self.token(1),
            Some(&json!({"favorite":false,"folderId":self.folders[1]})),
        )?;
        let docs = self.snapshot(id)?.documents;
        for actor in 0..2 {
            let d = docs[actor]
                .as_ref()
                .ok_or(Error("Lifecycle private fixture lacks reader"))?;
            require(
                d["favorite"] == (actor == 0)
                    && d["folderId"] == self.folders[actor]
                    && d["key"].is_string(),
                "Lifecycle private/wrapped-key fixture differed",
            )?;
        }
        Ok(())
    }
    fn archives(&mut self, id: &str) -> Result<(), Error> {
        for actor in 0..2 {
            self.http.json(
                Method::PUT,
                &format!("/api/ciphers/{id}/archive"),
                &self.token(actor),
                None,
            )?;
            if actor == 0 {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
        let docs = self.snapshot(id)?.documents;
        require(
            docs[0]
                .as_ref()
                .is_some_and(|v| v["archivedDate"].is_string())
                && docs[1]
                    .as_ref()
                    .is_some_and(|v| v["archivedDate"].is_string())
                && docs[0].as_ref().map(|v| &v["archivedDate"])
                    != docs[1].as_ref().map(|v| &v["archivedDate"]),
            "Lifecycle distinct private archive baselines missing",
        )
    }
    fn absent(&mut self, id: &str) -> Result<(), Error> {
        for actor in 0..2 {
            self.http
                .raw(
                    Method::GET,
                    &format!("/api/ciphers/{id}"),
                    &self.token(actor),
                    None,
                )?
                .rejected(400)?;
            for path in ["/api/ciphers", "/api/sync"] {
                let v = self.get(actor, path)?;
                let rows = if path == "/api/sync" {
                    &v["ciphers"]
                } else {
                    &v["data"]
                };
                require(
                    rows.as_array()
                        .is_some_and(|a| a.iter().all(|v| v["id"] != id)),
                    "Permanently deleted lifecycle source remained in read alias",
                )?;
            }
        }
        Ok(())
    }
    fn personal(&mut self, source: usize) -> Result<String, Error> {
        let sealed = fixture::encrypted_fixture_value(
            &self.accounts[source].fixture,
            &self.accounts[source].password,
            NOTE.as_bytes(),
        )
        .map_err(|_| Error("Lifecycle personal encryption failed"))?;
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
            .map_err(|_| Error("Lifecycle shared encryption failed"))?;
        let wrapped = if wrapped {
            Some(
                fixture::encrypt(&cipher_key, &self.orgs[org].key)
                    .map_err(|_| Error("Lifecycle cipher key encryption failed"))?,
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
            .ok_or(Error("Lifecycle fixture member missing"))?;
        require(
            r["status"] == 1,
            "Lifecycle fixture invitation state differed",
        )?;
        let id = text(&r["id"])?.to_owned();
        if confirm {
            let key = fixture::organization_key_for_account(
                &self.accounts[1].fixture,
                &self.orgs[org].key,
            )
            .map_err(|_| Error("Lifecycle RSA fixture failed"))?;
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
                .ok_or(Error("Lifecycle cipher absent from readable alias"))?;
            let mut normalized = row.clone();
            normalized["collectionIds"] = direct["collectionIds"].clone();
            require(
                normalized == direct,
                "Lifecycle read alias changed annotations/common fields",
            )?;
        }
        Ok(())
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let id = s.personal(0)?;
    for op in [Op::Trash, Op::Restore, Op::Permanent] {
        s.at(&id, 0, op.method(), &op.path(&id), None, true)?
            .unchanged(401)?;
    }
    s.at(
        &id,
        0,
        Method::PUT,
        "/api/ciphers/not-a-uuid/delete",
        None,
        true,
    )?
    .unchanged(401)?;
    s.at(
        &id,
        0,
        Method::PUT,
        "/api/ciphers/not-a-uuid/delete",
        None,
        false,
    )?
    .unchanged(422)?;
    s.at(
        &id,
        0,
        Method::PUT,
        &Op::Trash.path(&Uuid::new_v4().to_string()),
        None,
        false,
    )?
    .unchanged(400)?;
    s.apply(&id, 0, Op::Trash)?;
    s.apply(&id, 0, Op::Restore)?;
    s.apply(&id, 0, Op::Permanent)?;
    s.absent(&id)
}
fn admission(s: &mut Suite) -> Result<(), Error> {
    // Native lifecycle WRITE differs from ordinary GET edit/delete/restore flags.
    for (org, collection, actor) in [
        (0, s.orgs[0].collection_id.clone(), 0),
        (0, s.collections[0].clone(), 1),
        (0, s.collections[1].clone(), 1),
        (2, s.orgs[2].collection_id.clone(), 1),
    ] {
        let id = s.shared(org, &collection, true)?;
        if org == 0 && collection == s.collections[1] {
            let d = s.get(1, &format!("/api/ciphers/{id}"))?;
            require(
                d["edit"] == false
                    && d["permissions"]["delete"] == false
                    && d["permissions"]["restore"] == false,
                "Lifecycle readonly-manage GET flags changed",
            )?;
        }
        s.apply(&id, actor, Op::Trash)?;
        s.aliases(&id, actor)?;
        s.apply(&id, actor, Op::Restore)?;
        s.apply(&id, actor, Op::Permanent)?;
        s.absent(&id)?;
    }
    Ok(())
}
fn surviving(s: &mut Suite) -> Result<(), Error> {
    let id = s.shared(0, &s.collections[1].clone(), true)?;
    s.private(&id)?;
    s.archives(&id)?;
    for (actor, op) in [
        (0, Op::Trash),
        (1, Op::Trash),
        (1, Op::Restore),
        (0, Op::Restore),
        (1, Op::Restore),
    ] {
        s.apply(&id, actor, op)?;
        s.aliases(&id, 0)?;
        s.aliases(&id, 1)?;
    }
    Ok(())
}
fn permanent(s: &mut Suite) -> Result<(), Error> {
    for (trashed, post, actor) in [
        (false, false, 0),
        (true, false, 1),
        (false, true, 0),
        (true, true, 1),
    ] {
        let id = s.shared(0, &s.collections[1].clone(), true)?;
        s.private(&id)?;
        s.archives(&id)?;
        if trashed {
            s.apply(&id, 0, Op::Trash)?;
        }
        let (method, path) = if post {
            (Method::POST, format!("/api/ciphers/{id}/delete"))
        } else {
            (Method::DELETE, Op::Permanent.path(&id))
        };
        s.at(&id, actor, method, &path, None, false)?
            .success(Op::Permanent)?;
        s.absent(&id)?;
    }
    Ok(())
}
fn denied(s: &mut Suite) -> Result<(), Error> {
    for (org, collection) in [
        (0, s.orgs[0].collection_id.clone()),
        (0, s.collections[2].clone()),
        (4, s.orgs[4].collection_id.clone()),
        (5, s.orgs[5].collection_id.clone()),
    ] {
        let id = s.shared(org, &collection, true)?;
        if org == 5 {
            s.status(5, &s.members[1].clone(), "revoke")?;
        }
        for op in [Op::Trash, Op::Restore, Op::Permanent] {
            s.at(&id, 1, op.method(), &op.path(&id), None, false)?
                .unchanged(400)?;
        }
        s.at(
            &id,
            1,
            Method::POST,
            &format!("/api/ciphers/{id}/delete"),
            None,
            false,
        )?
        .unchanged(400)?;
        // A trashed source must remain equally protected.
        s.apply(&id, 0, Op::Trash)?;
        s.at(&id, 1, Method::PUT, &Op::Restore.path(&id), None, false)?
            .unchanged(400)?;
        if org == 5 {
            s.status(5, &s.members[1].clone(), "restore")?;
        }
    }
    let foreign = s.personal(1)?;
    for op in [Op::Trash, Op::Restore, Op::Permanent] {
        s.at(&foreign, 0, op.method(), &op.path(&foreign), None, false)?
            .unchanged(400)?;
    }
    Ok(())
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    let id = s.shared(0, &s.collections[0].clone(), true)?;
    s.private(&id)?;
    s.archives(&id)?;
    s.at(&id, 1, Method::POST, &Op::Restore.path(&id), None, false)?
        .unchanged(404)?;
    s.at(
        &id,
        1,
        Method::PUT,
        &Op::Trash.path(&id),
        Some(json!({"ignored":true,"ids":["ignored"]})),
        false,
    )?
    .success(Op::Trash)?;
    s.raw_trial(&id, 1, &Op::Restore.path(&id), "{")?
        .success(Op::Restore)?;
    s.at(&id, 0, Method::POST, &Op::Restore.path(&id), None, false)?
        .unchanged(404)?;
    for actor in 0..2 {
        s.aliases(&id, actor)?;
        require(
            s.get(actor, "/api/accounts/keys")? == s.keys[actor],
            "Lifecycle changed account keys",
        )?;
        let control = s.accounts[actor].cipher_id.clone();
        require(
            s.get(actor, &format!("/api/ciphers/{control}"))? == s.controls[actor],
            "Lifecycle changed unrelated personal source",
        )?;
        let folder = s.get(actor, &format!("/api/folders/{}", s.folders[actor]))?;
        require(
            folder["id"] == s.folders[actor],
            "Lifecycle private folder disappeared",
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
            fixture::encrypted_fixture_value(&a.fixture, &a.password, b"Private lifecycle folder")
                .map_err(|_| Error("Lifecycle folder encryption failed"))?;
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
        "Writable lifecycle",
        "Readonly manage lifecycle",
        "Unassigned lifecycle",
    ] {
        let sealed = fixture::encrypt(name.as_bytes(), &orgs[0].key)
            .map_err(|_| Error("Lifecycle collection encryption failed"))?;
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
            .map_err(|_| Error("Lifecycle collections incomplete"))?,
        folders: folders
            .try_into()
            .map_err(|_| Error("Lifecycle folders incomplete"))?,
        members: [String::new(), String::new()],
        keys: [Value::Null, Value::Null],
        controls: [Value::Null, Value::Null],
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_LIFECYCLE_RECEIPT")?,
        finished: false,
    };
    s.members[0]=s.invite(0,2,json!([{"id":s.orgs[0].collection_id,"readOnly":true,"manage":false,"hidePasswords":false},{"id":s.collections[0],"readOnly":false,"manage":false,"hidePasswords":false},{"id":s.collections[1],"readOnly":true,"manage":true,"hidePasswords":false}]),json!({}),true)?;
    s.invite(2, 1, json!([]), json!({}), true)?;

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
            "Lifecycle HTTP budget expected {HTTP_REQUEST_COUNT}, actual {}",
            s.http.owner.requests
        );
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 0,
        "Lifecycle fixture budget differed",
    )?;
    s.finished = true;
    s.receipt("passed")?;
    Ok(())
}
