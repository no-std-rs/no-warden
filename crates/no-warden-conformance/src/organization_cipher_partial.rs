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
// Fixed after an independently executed native six-case count, before proofs.
pub const HTTP_REQUEST_COUNT: usize = 605;
const NOTE: &str = "Partial annotations preserve opaque note Ω\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_cipher_partial_schema_path_and_personal_owner_guards",
        guards,
    ),
    (
        "organization_cipher_partial_confirmed_read_authority_and_foreign_sources",
        admission,
    ),
    (
        "organization_cipher_partial_folders_aliases_tuples_and_ignored_payload",
        folders,
    ),
    (
        "organization_cipher_partial_readonly_noop_actor_revision_and_read_aliases",
        readonly,
    ),
    (
        "organization_cipher_partial_historical_grants_and_membership_states",
        historical,
    ),
    (
        "organization_cipher_partial_opaque_keys_private_state_and_existing_sessions",
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
            eprintln!("Partial status expected {expected}, actual {}", self.status);
        }
        require(self.status == expected, "Partial status differed")?;
        Ok(self.value)
    }
    fn schema(self, expected: u16) -> Result<(), Error> {
        let value = self.status(expected)?;
        require(
            value
                .as_object()
                .is_some_and(|o| o.len() == 1 && o.contains_key("error")),
            "Partial schema envelope differed",
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
            "Partial rejection exposed authority",
        )?;
        if expected == 422 {
            return require(
                v.as_object()
                    .is_some_and(|o| o.len() == 1 && o.contains_key("error")),
                "Partial schema envelope differed",
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
                "Partial business envelope differed",
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
        let r = q.send().map_err(|_| Error("Partial HTTP request failed"))?;
        let status = r.status().as_u16();
        let mut bytes = Vec::new();
        r.take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Partial private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Partial capture bound exceeded",
        )?;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| Error("Partial response was not JSON"))?
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
fn annotation_document(
    before: &Value,
    after: &Value,
    favorite: bool,
    folder: Option<&str>,
) -> bool {
    let mut expected = before.clone();
    expected["favorite"] = json!(favorite);
    expected["folderId"] = json!(folder);
    expected == *after
}
impl Trial {
    fn unchanged(self, status: u16) -> Result<(), Error> {
        self.reply.rejected(status)?;
        require(
            self.before.documents == self.after.documents
                && self.before.revisions == self.after.revisions,
            "Rejected partial changed source/private annotations/account revisions",
        )
    }
    fn unchanged_schema(self, status: u16) -> Result<(), Error> {
        self.reply.schema(status)?;
        require(
            self.before.documents == self.after.documents
                && self.before.revisions == self.after.revisions,
            "Rejected partial schema mutated source/private annotations/account revisions",
        )
    }
    fn success(self, favorite: bool, folder: Option<&str>) -> Result<(), Error> {
        let returned = self.reply.status(200)?;
        let prior = self.before.documents[self.actor]
            .as_ref()
            .ok_or(Error("Successful partial actor had no prior read"))?;
        let after = self.after.documents[self.actor]
            .as_ref()
            .ok_or(Error("Partial removed actor read access"))?;
        require(
            returned == *after && annotation_document(prior, after, favorite, folder),
            "Partial changed common data/revision/ACL or returned different actor document",
        )?;
        let other = 1 - self.actor;
        require(
            self.before.documents[other] == self.after.documents[other]
                && self.before.revisions[other] == self.after.revisions[other]
                && self.before.revisions[self.actor] != self.after.revisions[self.actor],
            "Partial actor-only revision/private-state boundary differed",
        )?;
        let ids = prior["collectionIds"]
            .as_array()
            .ok_or(Error("Partial collection list missing"))?
            .iter()
            .map(|x| text(x).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        let mut normalized = returned.clone();
        normalized["key"] = Value::Null;
        check_cipher(
            &normalized,
            CipherExpectation {
                id: &self.id,
                organization: prior["organizationId"].as_str(),
                collections: &ids,
                edit: prior["edit"]
                    .as_bool()
                    .ok_or(Error("Partial edit flag missing"))?,
                view_password: prior["viewPassword"]
                    .as_bool()
                    .ok_or(Error("Partial view flag missing"))?,
                favorite,
                folder,
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
            &json!({"schemaVersion":1,"status":status,"passedCases":self.passed.len(),"expectedCases":CASE_COUNT,"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"bothPutPostAsserted":true,"requiredFavoriteBooleanAsserted":true,"folderAliasTupleAndEmptyClearAsserted":true,"readonlyReadAdmissionAsserted":true,"historicalCanonicalMembershipAsserted":true,"identicalAnnotationActorRevisionAsserted":true,"actorOnlyAnnotationsAndAccountRevisionAsserted":true,"opaquePayloadKeysCollectionsAndCipherRevisionPreservedAsserted":true,"accountKeysAndExistingSessionsPreservedAsserted":true,"replyEqualsActorGetWith30FieldsAsserted":true,"cliCallerClaimed":false,"capturedRouteTrace":false,"browserTraceClaimed":false,"attachmentBearingTested":false,"hiddenPasswordPartialTested":false,"groupsConfigured":false,"configuredPolicies":false,"smtpEnabled":false,"businessErrorTextAsserted":false,"fullParityClaimed":false}),
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
        method: Method,
        body: Value,
        path: Option<&str>,
        anonymous: bool,
    ) -> Result<Trial, Error> {
        let before = self.snapshot(id)?;
        let token = if anonymous {
            String::new()
        } else {
            self.token(actor)
        };
        let route = match path {
            Some(value) if value.starts_with('/') => value.to_owned(),
            _ => format!("/api/ciphers/{}/partial", path.unwrap_or(id)),
        };
        let reply = self.http.raw(method, &route, &token, Some(&body))?;
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
        method: Method,
        body: Value,
        favorite: bool,
        folder: Option<&str>,
    ) -> Result<(), Error> {
        self.on(id, actor, method, body, None, false)?
            .success(favorite, folder)
    }
    fn personal(&mut self, source: usize) -> Result<String, Error> {
        let sealed = fixture::encrypted_fixture_value(
            &self.accounts[source].fixture,
            &self.accounts[source].password,
            NOTE.as_bytes(),
        )
        .map_err(|_| Error("Partial personal encryption failed"))?;
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
            .map_err(|_| Error("Partial shared encryption failed"))?;
        let wrapped = if wrapped {
            Some(
                fixture::encrypt(&cipher_key, &self.orgs[org].key)
                    .map_err(|_| Error("Partial cipher key encryption failed"))?,
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
            .ok_or(Error("Partial fixture member missing"))?;
        require(
            r["status"] == 1,
            "Partial fixture invitation state differed",
        )?;
        let id = text(&r["id"])?.to_owned();
        if confirm {
            let key = fixture::organization_key_for_account(
                &self.accounts[1].fixture,
                &self.orgs[org].key,
            )
            .map_err(|_| Error("Partial RSA fixture failed"))?;
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
                .ok_or(Error("Partial cipher absent from readable alias"))?;
            let mut normalized = row.clone();
            normalized["collectionIds"] = direct["collectionIds"].clone();
            require(
                normalized == direct,
                "Partial read alias changed annotations/common fields",
            )?;
        }
        Ok(())
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let id = s.personal(0)?;
    for (method, path, body) in [
        (Method::PUT, None, json!({"favorite":"wrong"})),
        (Method::POST, Some("not-a-uuid"), json!({})),
    ] {
        s.on(&id, 0, method, body, path, true)?.unchanged(401)?;
    }
    s.on(
        &id,
        0,
        Method::PUT,
        json!({"favorite":false}),
        Some("not-a-uuid"),
        false,
    )?
    .unchanged(422)?;
    s.on(
        &id,
        0,
        Method::PUT,
        json!({"favorite":false}),
        Some(&Uuid::new_v4().to_string()),
        false,
    )?
    .unchanged(400)?;
    for body in [
        json!({}),
        json!({"favorite":null}),
        json!({"favorite":"false"}),
        json!({"favorite":0}),
        json!({"folderId":2,"favorite":false}),
        json!({"Favorite":false,"FolderId":null}),
        Value::Null,
        json!("body"),
    ] {
        s.on(&id, 0, Method::PUT, body, None, false)?
            .unchanged(422)?;
    }
    s.on(
        &id,
        0,
        Method::PUT,
        json!({"favorite":null}),
        Some(&Uuid::new_v4().to_string()),
        false,
    )?
    .unchanged(422)?;
    s.on(&id, 1, Method::PUT, json!({"favorite":null}), None, false)?
        .unchanged(422)?;
    s.on(
        &id,
        1,
        Method::PUT,
        json!({"favorite":false,"folderId":s.folders[0]}),
        None,
        false,
    )?
    .unchanged(400)?;
    s.apply(&id, 0, Method::PUT, json!({"favorite":false}), false, None)?;
    let folder = s.folders[0].clone();
    s.apply(
        &id,
        0,
        Method::POST,
        json!({"favorite":true,"folderId":folder}),
        true,
        Some(&folder),
    )?;
    s.on(&id, 0, Method::POST, json!({"favorite":null}), None, false)?
        .unchanged(422)?;
    let route = format!("/api/ciphers/{id}/partial?ignored=1");
    s.on(
        &id,
        0,
        Method::PUT,
        json!({"favorite":false}),
        Some(&route),
        false,
    )?
    .success(false, None)
}
fn admission(s: &mut Suite) -> Result<(), Error> {
    let ro = s.orgs[0].collection_id.clone();
    let write = s.collections[0].clone();
    let manage = s.collections[1].clone();
    for (org, col, actor) in [
        (0, ro, 0),
        (0, write, 1),
        (0, manage, 1),
        (2, s.orgs[2].collection_id.clone(), 1),
        (3, s.orgs[3].collection_id.clone(), 1),
    ] {
        let id = s.shared(org, &col, false)?;
        let folder = s.folders[actor].clone();
        s.apply(
            &id,
            actor,
            Method::PUT,
            json!({"favorite":false,"folderId":folder}),
            false,
            Some(&folder),
        )?;
    }
    for (org, col, actor) in [
        (0, s.collections[2].clone(), 1),
        (1, s.orgs[1].collection_id.clone(), 0),
        (4, s.orgs[4].collection_id.clone(), 1),
    ] {
        let id = s.shared(org, &col, false)?;
        s.on(
            &id,
            actor,
            Method::PUT,
            json!({"favorite":false,"folderId":s.folders[1-actor]}),
            None,
            false,
        )?
        .unchanged(400)?;
    }
    Ok(())
}
fn folders(s: &mut Suite) -> Result<(), Error> {
    let col = s.orgs[0].collection_id.clone();
    let id = s.shared(0, &col, false)?;
    let folder = s.folders[1].clone();
    for body in [
        json!({"favorite":true,"folderId":s.folders[0]}),
        json!({"favorite":true,"folderId":Uuid::new_v4().to_string()}),
        json!({"favorite":true,"folderId":"not-a-folder"}),
    ] {
        s.on(&id, 1, Method::PUT, body, None, false)?
            .unchanged(400)?;
    }
    for body in [
        json!({"favorite":false}),
        json!({"favorite":false,"folderId":null}),
        json!({"favorite":false,"folderId":""}),
        json!({"favorite":false,"folder_id":folder}),
        json!({"favorite":false,"FolderId":folder}),
        json!([null, false]),
    ] {
        s.apply(&id, 1, Method::PUT, body, false, None)?;
    }
    s.apply(
        &id,
        1,
        Method::PUT,
        json!([folder, false]),
        false,
        Some(&folder),
    )?;
    s.on(&id, 1, Method::PUT, json!([false, folder]), None, false)?
        .unchanged(422)?;
    s.on(&id, 1, Method::PUT, json!([folder, false, 0]), None, false)?
        .unchanged_schema(400)?;
    s.apply(&id,1,Method::POST,json!({"favorite":true,"folderId":folder,"organizationId":s.orgs[1].id,"name":"ignored","notes":null,"key":"ignored","collectionIds":[],"secureNote":{"type":17},"encryptedFor":"ignored","outerExtension":{"opaque":"ignored"}}),true,Some(&folder))
}
fn readonly(s: &mut Suite) -> Result<(), Error> {
    for col in [s.orgs[0].collection_id.clone(), s.collections[1].clone()] {
        let id = s.shared(0, &col, false)?;
        let before = s.get(1, &format!("/api/ciphers/{id}"))?;
        require(
            before["edit"] == false && before["collectionIds"] == json!([]),
            "Partial readonly fixture had write/GET collection flags",
        )?;
        let folder = s.folders[1].clone();
        for method in [Method::PUT, Method::POST, Method::PUT] {
            s.apply(
                &id,
                1,
                method,
                json!({"folderId":folder,"favorite":true}),
                true,
                Some(&folder),
            )?;
        }
        s.aliases(&id, 0)?;
        s.aliases(&id, 1)?;
    }
    Ok(())
}
fn historical(s: &mut Suite) -> Result<(), Error> {
    let id = s.personal(0)?;
    let historical = s.orgs[0].collection_id.clone();
    let sealed = fixture::encrypt(NOTE.as_bytes(), &s.orgs[0].key)
        .map_err(|_| Error("Partial historical fixture encryption failed"))?;
    s.http.raw(Method::PUT,&format!("/api/ciphers/{id}/share"),&s.token(0),Some(&json!({"collectionIds":[historical,Uuid::new_v4().to_string()],"cipher":{"type":2,"organizationId":s.orgs[0].id,"encryptedFor":s.accounts[0].user_id,"name":sealed,"notes":sealed,"secureNote":{"type":0}}})))?.rejected(400)?;
    let target = s.orgs[5].collection_id.clone();
    s.share(&id, 0, 5, std::slice::from_ref(&target), false)?;
    let full = s.get(0, &format!("/api/ciphers/{id}"))?;
    require(
        full["collectionIds"].as_array().is_some_and(|a| {
            a.len() == 2 && a.contains(&json!(historical)) && a.contains(&json!(target))
        }),
        "Partial historical fixture lost retained or canonical association",
    )?;
    let before = s.get(1, &format!("/api/ciphers/{id}"))?;
    require(
        before["edit"] == false && before["organizationId"] == s.orgs[5].id,
        "Partial historical readonly fixture differed",
    )?;
    let folder = s.folders[1].clone();
    for method in [Method::PUT, Method::POST] {
        s.apply(
            &id,
            1,
            method,
            json!({"favorite":true,"folderId":folder}),
            true,
            Some(&folder),
        )?;
    }
    let canonical = s.members[1].clone();
    s.status(5, &canonical, "revoke")?;
    s.on(&id, 1, Method::PUT, json!({"favorite":false}), None, false)?
        .unchanged(400)?;
    s.status(5, &canonical, "restore")?;
    s.apply(&id, 1, Method::PUT, json!({"favorite":false}), false, None)?;
    let old = s.members[0].clone();
    s.status(0, &old, "revoke")?;
    s.apply(
        &id,
        1,
        Method::POST,
        json!({"favorite":true,"folderId":folder}),
        true,
        Some(&folder),
    )?;
    s.status(0, &old, "restore")?;
    let no_grant = s.shared(5, &s.orgs[5].collection_id.clone(), false)?;
    s.on(
        &no_grant,
        1,
        Method::PUT,
        json!({"favorite":false}),
        None,
        false,
    )?
    .unchanged(400)?;
    Ok(())
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    let col = s.orgs[0].collection_id.clone();
    let id = s.shared(0, &col, true)?;
    let initial = s.get(0, &format!("/api/ciphers/{id}"))?;
    require(
        initial["key"].is_string()
            && initial["fields"].is_array()
            && initial["passwordHistory"].is_array(),
        "Partial opaque-key fixture incomplete",
    )?;
    let folder = s.folders[1].clone();
    s.apply(
        &id,
        1,
        Method::PUT,
        json!({"favorite":true,"folderId":folder}),
        true,
        Some(&folder),
    )?;
    s.apply(
        &id,
        1,
        Method::POST,
        json!({"favorite":false,"folderId":null}),
        false,
        None,
    )?;
    let folder = s.folders[0].clone();
    s.apply(
        &id,
        0,
        Method::POST,
        json!({"favorite":false,"folderId":folder}),
        false,
        Some(&folder),
    )?;
    for actor in 0..2 {
        s.aliases(&id, actor)?;
        require(
            s.get(actor, "/api/accounts/keys")? == s.keys[actor],
            "Partial changed account key material",
        )?;
        let control = s.accounts[actor].cipher_id.clone();
        require(
            s.get(actor, &format!("/api/ciphers/{control}"))? == s.controls[actor],
            "Partial changed independent personal control",
        )?;
    }
    let before = s.revisions()?;
    for actor in 0..2 {
        s.http.owner.requests += 1;
        s.http.refreshes += 1;
        let r = s
            .http
            .client
            .post(format!("{}/identity/connect/token", s.http.owner.server))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", "cli"),
                ("refresh_token", s.accounts[actor].refresh.as_str()),
            ])
            .send()
            .map_err(|_| Error("Partial refresh failed"))?;
        require(r.status().as_u16() == 200, "Partial refresh rejected")?;
        let v: Value = r
            .json()
            .map_err(|_| Error("Partial refresh JSON malformed"))?;
        let profile = s.http.json(
            Method::GET,
            "/api/accounts/profile",
            text(&v["access_token"])?,
            None,
        )?;
        require(
            profile["id"] == s.accounts[actor].user_id,
            "Partial refresh changed account identity",
        )?;
    }
    require(
        s.revisions()? == before,
        "Partial observational/session checks changed account revisions",
    )
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
            fixture::encrypted_fixture_value(&a.fixture, &a.password, b"Private partial folder")
                .map_err(|_| Error("Partial folder encryption failed"))?;
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
        "Writable partial",
        "Readonly manage partial",
        "Unassigned partial",
    ] {
        let sealed = fixture::encrypt(name.as_bytes(), &orgs[0].key)
            .map_err(|_| Error("Partial collection encryption failed"))?;
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
            .map_err(|_| Error("Partial collections incomplete"))?,
        folders: folders
            .try_into()
            .map_err(|_| Error("Partial folders incomplete"))?,
        members: [String::new(), String::new()],
        keys: [Value::Null, Value::Null],
        controls: [Value::Null, Value::Null],
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_PARTIAL_RECEIPT")?,
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
            "Partial HTTP budget expected {HTTP_REQUEST_COUNT}, actual {}",
            s.http.owner.requests
        );
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 2,
        "Partial fixture budget differed",
    )?;
    s.finished = true;
    s.receipt("passed")?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tuple_extra_schema_400_stays_distinct_from_business_400() {
        assert!(
            Reply {
                status: 400,
                value: json!({"error":"schema"})
            }
            .schema(400)
            .is_ok()
        );
        assert!(
            Reply {
                status: 400,
                value: json!({"object":"error","message":"business"})
            }
            .schema(400)
            .is_err()
        );
        assert!(
            Reply {
                status: 400,
                value: json!({"error":"schema"})
            }
            .rejected(400)
            .is_err()
        );
    }
    #[test]
    fn annotation_only_comparison_rejects_payload_revision_key_and_permission_drift() {
        let before = json!({"id":"cipher","favorite":false,"folderId":null,"name":"opaque","notes":"opaque","key":"wrapped","revisionDate":"fixed","collectionIds":["collection"],"permissions":{"delete":false,"restore":false}});
        let mut after = before.clone();
        after["favorite"] = json!(true);
        after["folderId"] = json!("actor-folder");
        assert!(annotation_document(
            &before,
            &after,
            true,
            Some("actor-folder")
        ));
        for field in [
            "id",
            "name",
            "notes",
            "key",
            "revisionDate",
            "collectionIds",
            "permissions",
        ] {
            let mut changed = after.clone();
            changed[field] = json!("changed");
            assert!(!annotation_document(
                &before,
                &changed,
                true,
                Some("actor-folder")
            ));
        }
    }
}
