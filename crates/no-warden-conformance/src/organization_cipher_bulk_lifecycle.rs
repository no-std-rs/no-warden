//! Independently authored selected-cipher lifecycle contracts. MIT OR Apache-2.0.
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
// Set from complete successful native development, registration HTTP is separate.
pub const HTTP_REQUEST_COUNT: usize = 0;
const NOTE: &str = "Selected lifecycle retains opaque note Ω\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_cipher_bulk_lifecycle_guards_personal_and_native_nonalias",
        guards,
    ),
    (
        "organization_cipher_bulk_lifecycle_current_write_roles_states_and_admin_aliases",
        admission,
    ),
    (
        "organization_cipher_bulk_lifecycle_unique_empty_repeat_and_current_readers",
        selections,
    ),
    (
        "organization_cipher_bulk_lifecycle_durable_authorized_subset_failures",
        durable,
    ),
    (
        "organization_cipher_bulk_lifecycle_required_ids_tuple_ignored_scope_and_errors",
        schema,
    ),
    (
        "organization_cipher_bulk_lifecycle_opaque_private_archives_keys_sessions_and_aliases",
        preservation,
    ),
];
#[derive(Clone, Copy, PartialEq)]
enum Op {
    Trash,
    Restore,
    Permanent,
}
impl Op {
    fn method(self) -> Method {
        if self == Self::Permanent {
            Method::DELETE
        } else {
            Method::PUT
        }
    }
    fn path(self) -> &'static str {
        match self {
            Self::Trash => "/api/ciphers/delete",
            Self::Restore => "/api/ciphers/restore",
            Self::Permanent => "/api/ciphers",
        }
    }
}
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
                "Selected lifecycle status expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Selected lifecycle status differed",
        )?;
        Ok(self.value)
    }
    fn empty_success(self) -> Result<(), Error> {
        require(
            self.status == 200 && self.empty && self.content_type.is_none(),
            "Selected lifecycle mutation did not return empty200 without Content-Type",
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
            "Selected lifecycle rejection exposed authority",
        )?;
        if expected == 422 {
            return require(
                v.as_object()
                    .is_some_and(|o| o.len() == 1 && o.contains_key("error")),
                "Selected lifecycle schema envelope differed",
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
                "Selected lifecycle business envelope differed",
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
            .map_err(|_| Error("Selected lifecycle HTTP request failed"))?;
        let status = r.status().as_u16();
        let content_type = r
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        r.take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Selected lifecycle private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Selected lifecycle capture bound exceeded",
        )?;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|_| Error("Selected lifecycle response was not JSON"))?
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
            .map_err(|_| Error("Selected lifecycle raw request failed"))?;
        let status = r.status().as_u16();
        let content_type = r
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        r.take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Selected lifecycle raw capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Selected lifecycle raw capture bound exceeded",
        )?;
        let value = serde_json::from_slice(&bytes)
            .map_err(|_| Error("Selected lifecycle raw response not JSON"))?;
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
    documents: Vec<Option<Value>>,
    revisions: Vec<Value>,
}
struct Trial {
    actor: usize,
    before: Vec<(String, Snapshot)>,
    after: Vec<(String, Snapshot)>,
    reply: Reply,
}
fn common(before: &Value, after: &Value) -> bool {
    let mut expected = before.clone();
    expected["deletedDate"] = after["deletedDate"].clone();
    expected["revisionDate"] = after["revisionDate"].clone();
    expected == *after
}
impl Trial {
    fn unchanged(self, status: u16) -> Result<(), Error> {
        self.reply.rejected(status)?;
        require(
            self.before
                .iter()
                .zip(&self.after)
                .all(|((id, a), (other, b))| {
                    id == other && a.documents == b.documents && a.revisions == b.revisions
                }),
            "Rejected selected lifecycle changed state",
        )
    }
    fn check_effects(
        &self,
        op: Op,
        eligible: &BTreeSet<&str>,
        required: bool,
    ) -> Result<(), Error> {
        let mut readers = [false; 6];
        for ((id, a), (other, b)) in self.before.iter().zip(&self.after) {
            require(
                id == other,
                "Selected lifecycle observation identity changed",
            )?;
            let progressed = a.documents.iter().zip(&b.documents).any(|(a, b)| a != b);
            require(
                !progressed || eligible.contains(id.as_str()),
                "Selected lifecycle changed unauthorized/unselected source",
            )?;
            require(
                !required || !eligible.contains(id.as_str()) || progressed,
                "Selected lifecycle skipped successful target",
            )?;
            for (actor, (prior, after)) in a.documents.iter().zip(&b.documents).enumerate() {
                if !progressed {
                    require(
                        prior == after,
                        "Selected lifecycle partially changed a source",
                    )?;
                    continue;
                }
                match (prior, after) {
                    (Some(prior), Some(after)) if op != Op::Permanent => {
                        require(
                            common(prior, after) && prior["revisionDate"] != after["revisionDate"],
                            "Selected lifecycle lost opaque/private/archive state or cipher revision",
                        )?;
                        require(
                            if op == Op::Trash {
                                after["deletedDate"].is_string()
                                    && prior["deletedDate"] != after["deletedDate"]
                            } else {
                                after["deletedDate"].is_null()
                            },
                            "Selected lifecycle date differed",
                        )?;
                    }
                    (Some(_), None) if op == Op::Permanent => {}
                    (None, None) => {}
                    _ => return Err(Error("Selected lifecycle changed read scope")),
                }
                if prior.is_some() {
                    readers[actor] = true;
                }
            }
        }
        let a = &self
            .before
            .first()
            .ok_or(Error("Selected lifecycle needs an observed control"))?
            .1
            .revisions;
        let b = &self
            .after
            .first()
            .ok_or(Error("Selected lifecycle needs an observed control"))?
            .1
            .revisions;
        for (actor, notify) in readers.iter().enumerate() {
            require(
                (a[actor] != b[actor]) == *notify,
                "Selected lifecycle current-reader notification scope differed",
            )?;
        }
        Ok(())
    }
    fn success(self, op: Op, selected: &[String]) -> Result<(), Error> {
        let unique = selected.iter().map(String::as_str).collect::<BTreeSet<_>>();
        self.check_effects(op, &unique, true)?;
        if op != Op::Restore {
            return self.reply.empty_success();
        }
        require(
            self.reply.status == 200
                && self
                    .reply
                    .content_type
                    .as_deref()
                    .is_some_and(|v| v.starts_with("application/json")),
            "Selected Restore did not return JSON200",
        )?;
        let v = self.reply.value;
        require(
            v.as_object().is_some_and(|o| o.len() == 3)
                && v["object"] == "list"
                && v["continuationToken"].is_null(),
            "Selected Restore list envelope differed",
        )?;
        let rows = v["data"]
            .as_array()
            .ok_or(Error("Selected Restore rows absent"))?;
        require(
            rows.len() == unique.len()
                && rows
                    .iter()
                    .map(|r| r["id"].as_str().unwrap_or(""))
                    .collect::<BTreeSet<_>>()
                    == unique,
            "Selected Restore unique result set differed",
        )?;
        for row in rows {
            let after = self
                .after
                .iter()
                .find(|(id, _)| row["id"] == *id)
                .and_then(|(_, s)| s.documents[self.actor].as_ref())
                .ok_or(Error("Selected Restore returned foreign row"))?;
            require(
                row == after && row.as_object().is_some_and(|o| o.len() == 30),
                "Selected Restore row not literal30 actor GET",
            )?;
        }
        Ok(())
    }
    fn durable(self, op: Op, eligible: &[String]) -> Result<(), Error> {
        self.check_effects(op, &eligible.iter().map(String::as_str).collect(), false)?;
        self.reply.rejected(400)
    }
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    folders: Vec<String>,
    revoked: String,
    keys: Vec<Value>,
    controls: Vec<Value>,
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
            &json!({"schemaVersion":1,"status":status,"passedCases":self.passed.len(),"expectedCases":CASE_COUNT,"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"fixtureRegistrations":6,"fixtureRegistrationHttpRequests":12,"passwordCredentialAttempts":self.http.owner.logins,"currentWriteRolesStatesAndAdminAliasesAsserted":true,"currentReaderFanoutIncludingReadonlyAndExcludingNonreadersAsserted":true,"duplicateEmptyAndUnorderedRestoreRowsAsserted":true,"durableAuthorizedSubsetWithoutInputOrderClaimAsserted":true,"requiredIdsIgnoredBodyScopeAndSchemaPreservationAsserted":true,"opaquePrivateArchivesKeysSessionsAndAbsenceAsserted":true,"cliCallerClaimed":false,"capturedRouteTrace":false,"browserTraceClaimed":false,"nativeOrderOrDistributionClaimed":false,"attachmentBearingTested":false,"groupsConfigured":false,"configuredPolicies":false,"smtpEnabled":false,"fullParityClaimed":false}),
        )
    }
    fn token(&self, actor: usize) -> String {
        self.accounts[actor].token.clone()
    }
    fn get(&mut self, actor: usize, path: &str) -> Result<Value, Error> {
        self.http.json(Method::GET, path, &self.token(actor), None)
    }
    fn snapshot(&mut self, id: &str) -> Result<Snapshot, Error> {
        let mut documents = Vec::new();
        let mut revisions = Vec::new();
        for actor in 0..self.accounts.len() {
            let r = self.http.raw(
                Method::GET,
                &format!("/api/ciphers/{id}"),
                &self.token(actor),
                None,
            )?;
            if r.status == 200 {
                documents.push(Some(r.value));
            } else {
                r.rejected(400)?;
                documents.push(None);
            }
            revisions.push(self.get(actor, "/api/accounts/revision-date")?);
        }
        Ok(Snapshot {
            documents,
            revisions,
        })
    }
    fn at(
        &mut self,
        observed: &[String],
        actor: usize,
        method: Method,
        path: &str,
        body: Value,
        anonymous: bool,
    ) -> Result<Trial, Error> {
        let before = observed
            .iter()
            .map(|id| Ok((id.clone(), self.snapshot(id)?)))
            .collect::<Result<Vec<_>, Error>>()?;
        let token = if anonymous {
            String::new()
        } else {
            self.token(actor)
        };
        let reply = self.http.raw(method, path, &token, Some(&body))?;
        let after = observed
            .iter()
            .map(|id| Ok((id.clone(), self.snapshot(id)?)))
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Trial {
            actor,
            before,
            after,
            reply,
        })
    }
    fn apply(
        &mut self,
        observed: &[String],
        actor: usize,
        op: Op,
        ids: &[String],
    ) -> Result<(), Error> {
        self.at(
            observed,
            actor,
            op.method(),
            op.path(),
            json!({"ids":ids}),
            false,
        )?
        .success(op, ids)
    }
    fn raw(&mut self, id: &str, body: &str) -> Result<Trial, Error> {
        let before = vec![(id.into(), self.snapshot(id)?)];
        let reply = self.http.raw_text(Op::Trash.path(), &self.token(1), body)?;
        let after = vec![(id.into(), self.snapshot(id)?)];
        Ok(Trial {
            actor: 1,
            before,
            after,
            reply,
        })
    }
    fn personal(&mut self, actor: usize) -> Result<String, Error> {
        let sealed = fixture::encrypted_fixture_value(
            &self.accounts[actor].fixture,
            &self.accounts[actor].password,
            NOTE.as_bytes(),
        )
        .map_err(|_| Error("Selected personal encryption failed"))?;
        let v=self.http.json(Method::POST,"/api/ciphers",&self.token(actor),Some(&json!({"type":2,"encryptedFor":self.accounts[actor].user_id,"name":sealed,"notes":sealed,"secureNote":{"type":0},"favorite":true,"folderId":self.folders[actor]})))?;
        Ok(text(&v["id"])?.into())
    }
    fn shared(&mut self, org: usize) -> Result<String, Error> {
        let id = self.personal(0)?;
        let key = [81u8; 64];
        let sealed = fixture::encrypt(NOTE.as_bytes(), &key)
            .map_err(|_| Error("Selected shared encryption failed"))?;
        let wrapped = fixture::encrypt(&key, &self.orgs[org].key)
            .map_err(|_| Error("Selected wrapped key failed"))?;
        self.http.json(Method::PUT,&format!("/api/ciphers/{id}/share"),&self.token(0),Some(&json!({"collectionIds":[self.orgs[org].collection_id],"cipher":{"type":2,"organizationId":self.orgs[org].id,"encryptedFor":self.accounts[0].user_id,"name":sealed,"notes":sealed,"secureNote":{"type":0},"fields":[{"name":sealed,"value":sealed,"type":0,"linkedId":null}],"passwordHistory":[{"password":sealed,"lastUsedDate":"2024-01-01T00:00:00.000000Z"}],"key":wrapped,"favorite":true,"folderId":self.folders[0]}})))?;
        for actor in 0..3 {
            self.http.json(
                Method::PUT,
                &format!("/api/ciphers/{id}/partial"),
                &self.token(actor),
                Some(&json!({"favorite":actor!=1,"folderId":self.folders[actor]})),
            )?;
            self.http.json(
                Method::PUT,
                &format!("/api/ciphers/{id}/archive"),
                &self.token(actor),
                None,
            )?;
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let snapshot = self.snapshot(&id)?;
        let mut dates = BTreeSet::new();
        for (actor, doc) in snapshot.documents.iter().enumerate() {
            if actor < 3 {
                let d = doc
                    .as_ref()
                    .ok_or(Error("Selected current reader missing"))?;
                require(
                    d["folderId"] == self.folders[actor]
                        && d["favorite"] == (actor != 1)
                        && d["key"].is_string()
                        && d["archivedDate"].is_string(),
                    "Selected strong private/key fixture differed",
                )?;
                dates.insert(d["archivedDate"].as_str().unwrap_or(""));
            } else {
                require(doc.is_none(), "Selected nonreader fixture admitted read")?;
            }
        }
        require(
            dates.len() == 3,
            "Selected private archive dates were not distinct",
        )?;
        Ok(id)
    }
    fn aliases(&mut self, id: &str, present: bool) -> Result<(), Error> {
        for actor in 0..self.accounts.len() {
            let reply = self.http.raw(
                Method::GET,
                &format!("/api/ciphers/{id}"),
                &self.token(actor),
                None,
            )?;
            let direct = if reply.status == 200 {
                Some(reply.value)
            } else {
                reply.rejected(400)?;
                None
            };
            for path in ["/api/ciphers", "/api/sync"] {
                let v = self.get(actor, path)?;
                let rows = if path == "/api/sync" {
                    &v["ciphers"]
                } else {
                    &v["data"]
                };
                let row = rows
                    .as_array()
                    .and_then(|a| a.iter().find(|v| v["id"] == id));
                if let Some(direct) = direct.as_ref().filter(|_| present) {
                    let mut row = row
                        .ok_or(Error("Selected source missing from read alias"))?
                        .clone();
                    row["collectionIds"] = direct["collectionIds"].clone();
                    require(
                        row == *direct,
                        "Selected read alias changed private/common fields",
                    )?;
                } else {
                    require(
                        row.is_none(),
                        "Selected unreadable/deleted source remained in alias",
                    )?;
                }
            }
        }
        Ok(())
    }
    fn invite(
        &mut self,
        org: usize,
        actor: usize,
        role: i32,
        grants: Value,
        permissions: Value,
        confirm: bool,
    ) -> Result<String, Error> {
        self.http.json(Method::POST,&format!("/api/organizations/{}/users/invite",self.orgs[org].id),&self.token(0),Some(&json!({"emails":[self.accounts[actor].fixture["email"]],"type":role,"groups":[],"collections":grants,"permissions":permissions})))?;
        let v = self.get(
            0,
            &format!("/api/organizations/{}/users", self.orgs[org].id),
        )?;
        let row = v["data"]
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|r| r["email"] == self.accounts[actor].fixture["email"])
            })
            .ok_or(Error("Selected member fixture absent"))?;
        require(row["status"] == 1, "Selected invitation state differed")?;
        let id = text(&row["id"])?.to_owned();
        if confirm {
            let key = fixture::organization_key_for_account(
                &self.accounts[actor].fixture,
                &self.orgs[org].key,
            )
            .map_err(|_| Error("Selected RSA fixture failed"))?;
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
}

fn ids(id: &str) -> Vec<String> {
    vec![id.into()]
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let id = s.personal(0)?;
    let observed = ids(&id);
    for op in [Op::Trash, Op::Restore, Op::Permanent] {
        s.at(
            &observed,
            0,
            op.method(),
            op.path(),
            json!({"ids":[id]}),
            true,
        )?
        .unchanged(401)?;
    }
    s.at(
        &observed,
        0,
        Method::POST,
        "/api/ciphers/restore",
        json!({"ids":[id]}),
        false,
    )?
    .unchanged(422)?;
    s.apply(&observed, 0, Op::Trash, &observed)?;
    s.apply(&observed, 0, Op::Restore, &observed)?;
    s.at(
        &observed,
        0,
        Method::POST,
        "/api/ciphers/delete",
        json!({"ids":[id]}),
        false,
    )?
    .success(Op::Permanent, &observed)?;
    s.aliases(&id, false)
}
fn admission(s: &mut Suite) -> Result<(), Error> {
    for (org, actor) in [(0, 0), (0, 1), (1, 1), (2, 1), (3, 1)] {
        let id = s.shared(org)?;
        let selected = ids(&id);
        if org == 0 && actor == 1 {
            let v = s.get(1, &format!("/api/ciphers/{id}"))?;
            require(
                v["edit"] == false
                    && v["permissions"]["delete"] == false
                    && v["permissions"]["restore"] == false,
                "Selected readonlyManage GETflags changed",
            )?;
        }
        for op in [Op::Trash, Op::Restore, Op::Permanent] {
            s.apply(&selected, actor, op, &selected)?;
        }
    }
    let id = s.shared(0)?;
    let observed = ids(&id);
    for actor in [2, 3, 4, 5] {
        for op in [Op::Trash, Op::Restore, Op::Permanent] {
            s.at(
                &observed,
                actor,
                op.method(),
                op.path(),
                json!({"ids":[id]}),
                false,
            )?
            .unchanged(400)?;
        }
    }
    // Each alias has native role evidence separate from its ordinary route.
    for (org, actor) in [(0, 0), (0, 1), (1, 1), (3, 1)] {
        for (op, method, path) in [
            (Op::Trash, Method::PUT, "/api/ciphers/delete-admin"),
            (Op::Restore, Method::PUT, "/api/ciphers/restore-admin"),
            (Op::Permanent, Method::DELETE, "/api/ciphers/admin"),
            (Op::Permanent, Method::POST, "/api/ciphers/delete-admin"),
        ] {
            let id = s.shared(org)?;
            let selected = ids(&id);
            if op == Op::Restore {
                s.apply(&selected, 0, Op::Trash, &selected)?;
            }
            s.at(&selected, actor, method, path, json!({"ids":[id]}), false)?
                .success(op, &selected)?;
        }
    }
    for (method, path) in [
        (Method::PUT, "/api/ciphers/delete-admin"),
        (Method::PUT, "/api/ciphers/restore-admin"),
        (Method::DELETE, "/api/ciphers/admin"),
        (Method::POST, "/api/ciphers/delete-admin"),
    ] {
        s.at(&observed, 2, method, path, json!({"ids":[id]}), false)?
            .unchanged(400)?;
    }
    Ok(())
}
fn selections(s: &mut Suite) -> Result<(), Error> {
    let first = s.shared(0)?;
    let second = s.shared(0)?;
    require(first != second, "Selected two-source fixture reused an ID")?;
    let observed = vec![first.clone(), second.clone()];
    for op in [Op::Trash, Op::Restore] {
        for _ in 0..2 {
            s.apply(&observed, 1, op, &observed)?;
        }
    }
    for op in [Op::Trash, Op::Restore] {
        s.apply(&observed, 1, op, &[first.clone(), first.clone()])?;
        s.apply(&observed, 1, op, &[])?;
    }
    s.apply(&observed, 1, Op::Permanent, &[first.clone(), first.clone()])?;
    s.aliases(&first, false)?;
    s.aliases(&second, true)
}
fn durable(s: &mut Suite) -> Result<(), Error> {
    let foreign = s.personal(3)?;
    let absent = Uuid::new_v4().to_string();
    for op in [Op::Trash, Op::Restore, Op::Permanent] {
        // Each permanent trial has its own surviving eligible baseline; no fabricated
        // successful second deletion or deterministic order assertion.
        for reverse in [false, true] {
            let first = s.shared(0)?;
            let second = s.shared(0)?;
            let observed = vec![first.clone(), second.clone(), foreign.clone()];
            if op == Op::Restore {
                s.apply(&observed, 0, Op::Trash, &[first.clone(), second.clone()])?;
            }
            let selected = if reverse {
                json!([absent, second, first])
            } else {
                json!([first, second, absent])
            };
            s.at(
                &observed,
                1,
                op.method(),
                op.path(),
                json!({"ids":selected}),
                false,
            )?
            .durable(op, &[first, second])?;
        }
        let id = s.shared(0)?;
        let observed = vec![id.clone(), foreign.clone()];
        if op == Op::Restore {
            s.apply(&observed, 0, Op::Trash, &ids(&id))?;
        }
        s.at(
            &observed,
            1,
            op.method(),
            op.path(),
            json!({"ids":[id,foreign]}),
            false,
        )?
        .durable(op, &ids(&id))?;
        s.at(
            &observed,
            1,
            op.method(),
            op.path(),
            json!({"ids":[absent,foreign]}),
            false,
        )?
        .unchanged(400)?;
    }
    Ok(())
}
fn schema(s: &mut Suite) -> Result<(), Error> {
    for op in [Op::Trash, Op::Restore, Op::Permanent] {
        let id = s.shared(0)?;
        let observed = ids(&id);
        for body in [
            json!({}),
            json!({"ids":null}),
            json!({"Ids":[id]}),
            json!({"ids":[17]}),
        ] {
            s.at(&observed, 1, op.method(), op.path(), body, false)?
                .unchanged(422)?;
        }
        if op == Op::Restore {
            s.apply(&observed, 0, Op::Trash, &observed)?;
        }
        s.at(&observed, 1, op.method(), op.path(), json!([[id]]), false)?
            .success(op, &observed)?;
    }
    let id = s.shared(0)?;
    let observed = ids(&id);
    s.raw(&id, &format!("{{\"ids\":[\"{id}\"],\"ids\":[\"{id}\"]}}"))?
        .unchanged(422)?;
    // Genuine struct sequence overflow is a syntax-length400, not user-text matching.
    let t = s.at(
        &observed,
        1,
        Method::PUT,
        Op::Trash.path(),
        json!([[id], null]),
        false,
    )?;
    require(
        t.reply.status == 400
            && t.reply
                .value
                .as_object()
                .is_some_and(|o| o.len() == 1 && o.contains_key("error"))
            && t.before
                .iter()
                .zip(&t.after)
                .all(|((_, a), (_, b))| a.documents == b.documents && a.revisions == b.revisions),
        "Selected extra tuple schema/state differed",
    )?;
    s.at(
        &observed,
        1,
        Method::PUT,
        Op::Trash.path(),
        json!({"ids":["not-a-uuid"]}),
        false,
    )?
    .unchanged(400)?;
    for scope in [
        Value::Null,
        json!(s.orgs[0].id),
        json!(Uuid::new_v4().to_string()),
        json!("not-an-organization"),
        json!(17),
    ] {
        s.at(
            &observed,
            1,
            Method::PUT,
            Op::Trash.path(),
            json!({"ids":[id],"organizationId":scope,"ignored":{"future":[true,null]}}),
            false,
        )?
        .success(Op::Trash, &observed)?;
    }
    s.raw(
        &id,
        &format!("{{\"ids\":[\"{id}\"],\"future\":null,\"future\":{{}}}}"),
    )?
    .success(Op::Trash, &observed)
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    let id = s.shared(0)?;
    let selected = ids(&id);
    for op in [Op::Trash, Op::Restore] {
        s.apply(&selected, 1, op, &selected)?;
        s.aliases(&id, true)?;
    }
    s.at(
        &selected,
        0,
        Method::PUT,
        "/api/ciphers/delete-admin",
        json!({"ids":[id],"organizationId":Uuid::new_v4().to_string()}),
        false,
    )?
    .success(Op::Trash, &selected)?;
    s.at(
        &selected,
        0,
        Method::PUT,
        "/api/ciphers/restore-admin",
        json!({"ids":[id],"organizationId":Uuid::new_v4().to_string()}),
        false,
    )?
    .success(Op::Restore, &selected)?;
    s.at(
        &selected,
        0,
        Method::POST,
        "/api/ciphers/delete-admin",
        json!({"ids":[id],"organizationId":Uuid::new_v4().to_string()}),
        false,
    )?
    .success(Op::Permanent, &selected)?;
    s.aliases(&id, false)?;
    for actor in 0..6 {
        require(
            s.get(actor, "/api/accounts/keys")? == s.keys[actor],
            "Selected lifecycle changed account keys",
        )?;
        let control = s.accounts[actor].cipher_id.clone();
        require(
            s.get(actor, &format!("/api/ciphers/{control}"))? == s.controls[actor],
            "Selected lifecycle changed unrelated personal source",
        )?;
    }
    Ok(())
}
fn setup() -> Result<Suite, Error> {
    let mut http = Http::new()?;
    let mut accounts = Vec::new();
    for _ in 0..6 {
        accounts.push(organization_owner::seed(&mut http.owner)?);
    }
    let mut orgs = Vec::new();
    for _ in 0..4 {
        orgs.push(create_organization(&mut http.owner, &accounts[0])?);
    }
    let mut folders = Vec::new();
    for a in &accounts {
        let name =
            fixture::encrypted_fixture_value(&a.fixture, &a.password, b"Selected private folder")
                .map_err(|_| Error("Selected folder encryption failed"))?;
        let v = http.json(
            Method::POST,
            "/api/folders",
            &a.token,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&v["id"])?.into());
    }
    let mut s = Suite {
        http,
        accounts,
        orgs,
        folders,
        revoked: String::new(),
        keys: Vec::new(),
        controls: Vec::new(),
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_BULK_LIFECYCLE_RECEIPT")?,
        finished: false,
    };
    let grant = |id: &str, readonly: bool, manage: bool| json!([{"id":id,"readOnly":readonly,"manage":manage,"hidePasswords":false}]);
    s.invite(
        0,
        1,
        2,
        grant(&s.orgs[0].collection_id, true, true),
        json!({}),
        true,
    )?;
    for org in 0..4 {
        s.invite(
            org,
            2,
            2,
            grant(&s.orgs[org].collection_id, true, false),
            json!({}),
            true,
        )?;
    }
    s.invite(0, 3, 2, json!([]), json!({}), true)?;
    s.invite(0, 4, 1, json!([]), json!({}), false)?;
    s.revoked = s.invite(0, 5, 1, json!([]), json!({}), true)?;
    s.http.json(
        Method::PUT,
        &format!(
            "/api/organizations/{}/users/{}/revoke",
            s.orgs[0].id, s.revoked
        ),
        &s.token(0),
        None,
    )?;
    s.invite(1, 1, 1, json!([]), json!({}), true)?;
    s.invite(
        2,
        1,
        4,
        json!([]),
        json!({"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true}),
        true,
    )?;
    s.invite(
        3,
        1,
        2,
        grant(&s.orgs[3].collection_id, false, false),
        json!({}),
        true,
    )?;
    for actor in 0..6 {
        let key = s.get(actor, "/api/accounts/keys")?;
        s.keys.push(key);
        let id = s.accounts[actor].cipher_id.clone();
        let control = s.get(actor, &format!("/api/ciphers/{id}"))?;
        s.controls.push(control);
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
            "Selected lifecycle HTTP budget expected {HTTP_REQUEST_COUNT}, actual {}",
            s.http.owner.requests
        );
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 6
            && s.http.refreshes == 0,
        "Selected lifecycle fixture budget differed",
    )?;
    s.finished = true;
    s.receipt("passed")
}
