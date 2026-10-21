//! Independently authored ordinary shared secure-note update comparisons.
use crate::{
    fixture, organization_cipher_bulk_sharing as bulk,
    organization_collections::create_organization,
    organization_member_status as status,
    organization_owner::{self, Account, Http, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
};
use reqwest::Method;
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, io::Read};
use uuid::Uuid;
pub const CASE_COUNT: usize = 6;
pub const HTTP_REQUEST_COUNT: usize = 505;
pub(crate) const NOTE: &str = "Independent ordinary shared note Ω\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_cipher_update_schema_note_presence_and_opaque_names",
        schema,
    ),
    (
        "organization_cipher_update_confirmed_roles_writable_and_manage_authority",
        admission,
    ),
    (
        "organization_cipher_update_canonical_scope_path_and_post_alias",
        scope,
    ),
    (
        "organization_cipher_update_older_revision_and_guard_order",
        revisions,
    ),
    (
        "organization_cipher_update_actor_private_favorite_and_folder",
        annotations,
    ),
    (
        "organization_cipher_update_opaque_key_fields_fanout_and_preserved_controls",
        preservation,
    ),
];
const FIELDS: [&str; 30] = [
    "archivedDate",
    "attachments",
    "bankAccount",
    "card",
    "collectionIds",
    "creationDate",
    "deletedDate",
    "driversLicense",
    "edit",
    "favorite",
    "fields",
    "folderId",
    "id",
    "identity",
    "key",
    "login",
    "name",
    "notes",
    "object",
    "organizationId",
    "organizationUseTotp",
    "passport",
    "passwordHistory",
    "permissions",
    "reprompt",
    "revisionDate",
    "secureNote",
    "sshKey",
    "type",
    "viewPassword",
];
struct Reply {
    code: u16,
    value: Value,
}
fn raw(
    http: &mut Http,
    actor: &Account,
    id: &str,
    method: Method,
    body: &Value,
) -> Result<Reply, Error> {
    http.requests += 1;
    let response = http_client()?
        .request(method, format!("{}/api/ciphers/{id}", http.server))
        .bearer_auth(&actor.token)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(body)
        .send()
        .map_err(|_| Error("Shared update HTTP failed"))?;
    let code = response.status().as_u16();
    let mut bytes = Vec::new();
    response
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("Shared update private capture failed"))?;
    require(
        bytes.len() <= 16 * 1024 * 1024,
        "Shared update response bound exceeded",
    )?;
    let value =
        serde_json::from_slice(&bytes).map_err(|_| Error("Shared update response was not JSON"))?;
    Ok(Reply { code, value })
}
fn error(reply: &Reply, expected: u16) -> Result<(), Error> {
    if reply.code != expected {
        eprintln!(
            "Shared update status: actual {}, expected {expected}",
            reply.code
        );
    }
    require(reply.code == expected, "Shared update status differed")?;
    let fields: BTreeSet<&str> = reply
        .value
        .as_object()
        .ok_or(Error("Shared update error object missing"))?
        .keys()
        .map(String::as_str)
        .collect();
    if expected == 422 {
        require(
            fields == BTreeSet::from(["error"]),
            "Shared update schema error envelope differed",
        )
    } else {
        require(
            fields
                == BTreeSet::from([
                    "error",
                    "errorModel",
                    "error_description",
                    "exceptionMessage",
                    "exceptionStackTrace",
                    "innerExceptionMessage",
                    "message",
                    "object",
                    "validationErrors",
                ])
                && reply.value["object"] == "error"
                && reply.value["message"].is_string()
                && reply.value["errorModel"]["message"] == reply.value["message"],
            "Shared update business envelope differed",
        )
    }
}
pub(crate) fn payload(
    account: &Account,
    org: &Organization,
    variant: &str,
) -> Result<Value, Error> {
    let encrypted = fixture::encrypt(format!("{NOTE}{variant}").as_bytes(), &org.key)
        .map_err(|_| Error("Shared update fixture encryption failed"))?;
    Ok(
        json!({"type":2,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"organizationId":org.id,"encryptedFor":account.user_id,"key":null,"favorite":false,"folderId":null}),
    )
}
pub(crate) fn seed_shared(
    http: &mut Http,
    account: &Account,
    org: &Organization,
    folder: Option<&str>,
) -> Result<Value, Error> {
    let encrypted =
        fixture::encrypted_fixture_value(&account.fixture, &account.password, NOTE.as_bytes())
            .map_err(|_| Error("Shared update personal fixture encryption failed"))?;
    let source=http.json(Method::POST,"/api/ciphers",&account.token,Some(&json!({"type":2,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"encryptedFor":account.user_id,"favorite":true,"folderId":folder})))?;
    let mut body = payload(account, org, "")?;
    body["favorite"] = json!(true);
    body["folderId"] = json!(folder);
    http.json(
        Method::PUT,
        &format!("/api/ciphers/{}/share", text(&source["id"])?),
        &account.token,
        Some(&json!({"cipher":body,"collectionIds":[org.collection_id]})),
    )
}
struct Trial {
    reply: Reply,
    before: Value,
    after: Value,
    actor_before: Value,
    actor_after: Value,
    body: Value,
    before_revisions: [Value; 2],
    after_revisions: [Value; 2],
}
impl Trial {
    fn rejected(self, code: u16) -> Result<Value, Error> {
        error(&self.reply, code)?;
        require(
            self.before == self.after && self.before_revisions == self.after_revisions,
            "Rejected shared edit mutated source or account revisions",
        )?;
        Ok(self.reply.value["message"].clone())
    }
    fn applied(self) -> Result<Value, Error> {
        require(self.reply.code == 200, "Authorized shared edit failed")?;
        let fields: BTreeSet<_> = self
            .reply
            .value
            .as_object()
            .ok_or(Error("Shared update projection missing"))?
            .keys()
            .map(String::as_str)
            .collect();
        require(
            fields == BTreeSet::from(FIELDS) && self.reply.value["object"] == "cipherDetails",
            "Shared update thirty-field projection differed",
        )?;
        require(
            self.after["id"] == self.before["id"]
                && self.after["organizationId"] == self.before["organizationId"]
                && self.after["collectionIds"] == self.before["collectionIds"]
                && self.after["creationDate"] == self.before["creationDate"]
                && self.after["deletedDate"] == self.before["deletedDate"],
            "Shared update changed canonical identity or associations",
        )?;
        require(
            self.after["name"] == self.body["name"]
                && self.after["notes"] == self.body["notes"]
                && self.after["key"] == self.body["key"]
                && self.after["revisionDate"] != self.before["revisionDate"],
            "Shared update lost opaque payload or revision",
        )?;
        require(
            self.before_revisions[0] != self.after_revisions[0]
                && self.before_revisions[1] != self.after_revisions[1],
            "Shared update account revision fanout differed",
        )?;
        require(
            self.reply.value == self.actor_after,
            "Shared update return and actor GET differed",
        )?;
        Ok(self.after)
    }
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    folders: Vec<String>,
    collections: Vec<String>,
    member: String,
    controls: [Value; 2],
    keys: [Value; 2],
    profiles: [Value; 2],
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
            &json!({"schemaVersion":1,"status":status,"passedCases":self.passed.len(),"expectedCases":CASE_COUNT,"cases":self.passed,"httpRequests":self.http.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.logins,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"capturedRouteTrace":false,"cliCallerClaimed":false,"browserTraceClaimed":false,"businessErrorTextAsserted":false,"guardOrderAsserted":true,"olderOnlyRevisionAsserted":true,"perActorAnnotationsAsserted":true,"canonicalAssociationsRetainedAsserted":true,"readonlyManageWriteSeparateFromGetAsserted":true,"opaqueEncryptedKeyAndFieldsAsserted":true,"configuredGroups":false,"configuredPolicies":false,"smtpEnabled":false,"attachments":false,"otherItemTypes":false,"fullParityClaimed":false}),
        )
    }
    fn get(&mut self, actor: usize, path: &str) -> Result<Value, Error> {
        self.http
            .json(Method::GET, path, &self.accounts[actor].token, None)
    }
    fn revision_pair(&mut self) -> Result<[Value; 2], Error> {
        Ok([
            self.http.revision(&self.accounts[0].token)?,
            self.http.revision(&self.accounts[1].token)?,
        ])
    }
    fn trial<F: FnOnce(&mut Value)>(
        &mut self,
        (owner, actor): (usize, usize),
        org: usize,
        collection: Option<usize>,
        prepare: bool,
        method: Method,
        change: F,
    ) -> Result<Trial, Error> {
        let collection_id = collection
            .map(|i| self.collections[i].clone())
            .unwrap_or_else(|| self.orgs[org].collection_id.clone());
        let mut body = payload(&self.accounts[owner], &self.orgs[org], "initial")?;
        let encrypted = fixture::encrypted_fixture_value(
            &self.accounts[owner].fixture,
            &self.accounts[owner].password,
            NOTE.as_bytes(),
        )
        .map_err(|_| Error("Shared update personal encryption failed"))?;
        let source=self.http.json(Method::POST,"/api/ciphers",&self.accounts[owner].token,Some(&json!({"type":2,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"encryptedFor":self.accounts[owner].user_id,"favorite":true,"folderId":self.folders[owner]})))?;
        let id = text(&source["id"])?.to_owned();
        body["favorite"] = json!(true);
        body["folderId"] = json!(self.folders[owner]);
        self.http.json(
            Method::PUT,
            &format!("/api/ciphers/{id}/share"),
            &self.accounts[owner].token,
            Some(&json!({"cipher":body,"collectionIds":[collection_id]})),
        )?;
        if prepare {
            let mut body = payload(&self.accounts[actor], &self.orgs[org], "baseline")?;
            body["favorite"] = json!(true);
            body["folderId"] = json!(self.folders[actor]);
            let r = raw(
                &mut self.http,
                &self.accounts[actor],
                &id,
                Method::PUT,
                &body,
            )?;
            require(
                r.code == 200,
                "Shared update actor annotation fixture failed",
            )?;
        }
        let path = format!("/api/ciphers/{id}");
        let before = self.get(owner, &path)?;
        // Do not require an actor read for denied/no-grant/status fixtures.
        let actor_before = if actor == owner {
            before.clone()
        } else {
            Value::Null
        };
        let before_revisions = self.revision_pair()?;
        let mut body = payload(&self.accounts[actor], &self.orgs[org], "updated")?;
        body["id"] = json!(id);
        body["lastKnownRevisionDate"] = before["revisionDate"].clone();
        change(&mut body);
        let reply = raw(&mut self.http, &self.accounts[actor], &id, method, &body)?;
        let after = self.get(owner, &path)?;
        let after_revisions = self.revision_pair()?;
        let actor_after = if reply.code == 200 {
            if actor == owner {
                after.clone()
            } else {
                self.get(actor, &path)?
            }
        } else {
            Value::Null
        };
        Ok(Trial {
            reply,
            before,
            after,
            actor_before,
            actor_after,
            body,
            before_revisions,
            after_revisions,
        })
    }
}
fn schema(s: &mut Suite) -> Result<(), Error> {
    for field in ["type", "name", "encryptedFor"] {
        s.trial((0, 0), 0, None, false, Method::PUT, |v| {
            v.as_object_mut().unwrap().remove(field);
        })?
        .rejected(422)?;
    }
    for (field, value) in [
        ("encryptedFor", Value::Null),
        ("encryptedFor", json!(7)),
        ("type", json!("expected fewer elements")),
    ] {
        s.trial((0, 0), 0, None, false, Method::PUT, |v| v[field] = value)?
            .rejected(422)?;
    }
    for value in [json!("plain name"), json!("")] {
        s.trial((0, 0), 0, None, false, Method::PUT, |v| v["name"] = value)?
            .applied()?;
    }
    for value in [Value::Null, json!("omit")] {
        s.trial((0, 0), 0, None, false, Method::PUT, |v| {
            if value == "omit" {
                v.as_object_mut().unwrap().remove("secureNote");
            } else {
                v["secureNote"] = value;
            }
        })?
        .rejected(400)?;
    }
    for value in [json!("opaque non-null data"), json!({}), json!({"type":17})] {
        let expected = if value.get("type") == Some(&json!(17)) {
            json!({"type":17})
        } else {
            json!({"type":0})
        };
        let after = s
            .trial((0, 0), 0, None, false, Method::PUT, |v| {
                v["secureNote"] = value
            })?
            .applied()?;
        require(
            after["secureNote"] == expected,
            "Native secure-note subtype normalization differed",
        )?;
    }
    s.trial((0, 0), 0, None, false, Method::PUT, |v| {
        v["encryptedFor"] = json!("")
    })?
    .applied()?;
    Ok(())
}
fn admission(s: &mut Suite) -> Result<(), Error> {
    for (actor, org, col, code) in [
        (0, 0, None, 200),
        (1, 2, None, 200),
        (1, 3, None, 200),
        (1, 0, None, 200),
        (1, 0, Some(0), 400),
        (1, 0, Some(1), 200),
        (1, 0, Some(2), 400),
        (1, 4, None, 400),
    ] {
        let t = s.trial((0, actor), org, col, false, Method::PUT, |_| {})?;
        if code == 200 {
            if col == Some(1) {
                require(
                    t.actor_after["edit"] == false,
                    "Manage-only GET edit projection changed",
                )?;
            }
            t.applied()?;
        } else {
            t.rejected(code)?;
        }
    }
    let org = s.orgs[0].id.clone();
    let member = s.member.clone();
    let token = s.accounts[0].token.clone();
    status::put_fixture_status(&mut s.http, &org, &member, "revoke", &token)?;
    s.trial((0, 1), 0, None, false, Method::PUT, |_| {})?
        .rejected(400)?;
    status::put_fixture_status(&mut s.http, &org, &member, "restore", &token)?;
    Ok(())
}
fn scope(s: &mut Suite) -> Result<(), Error> {
    let foreign = s.orgs[1].id.clone();
    for value in [None, Some(Value::Null), Some(json!(foreign))] {
        s.trial((0, 0), 0, None, false, Method::PUT, |v| {
            if let Some(x) = value {
                v["organizationId"] = x;
            } else {
                v.as_object_mut().unwrap().remove("organizationId");
            }
        })?
        .rejected(400)?;
    }
    s.trial((0, 0), 0, None, false, Method::POST, |_| {})?
        .applied()?;
    s.trial((0, 0), 0, None, false, Method::PUT, |v| {
        v["id"] = json!(Uuid::new_v4().to_string())
    })?
    .applied()?;
    let foreign = s.orgs[1].collection_id.clone();
    s.trial((0, 0), 0, None, false, Method::PUT, |v| {
        v["collectionIds"] = json!([foreign])
    })?
    .applied()?;
    s.trial((1, 0), 1, None, false, Method::PUT, |_| {})?
        .rejected(400)?;
    Ok(())
}
fn revisions(s: &mut Suite) -> Result<(), Error> {
    let stale = s
        .trial((0, 0), 0, None, false, Method::PUT, |v| {
            v["lastKnownRevisionDate"] = json!("2000-01-01T00:00:00.000Z")
        })?
        .rejected(400)?;
    for value in [
        None,
        Some(Value::Null),
        Some(json!("not-a-date")),
        Some(json!("2999-01-01T00:00:00.000Z")),
    ] {
        s.trial((0, 0), 0, None, false, Method::PUT, |v| {
            if let Some(value) = value {
                v["lastKnownRevisionDate"] = value;
            } else {
                v.as_object_mut().unwrap().remove("lastKnownRevisionDate");
            }
        })?
        .applied()?;
    }
    let denied = s
        .trial((0, 1), 0, Some(0), false, Method::PUT, |_| {})?
        .rejected(400)?;
    let joint = s
        .trial((0, 1), 0, Some(0), false, Method::PUT, |v| {
            v["lastKnownRevisionDate"] = json!("2000-01-01T00:00:00.000Z")
        })?
        .rejected(400)?;
    require(
        denied == joint && denied != stale,
        "Shared update authority/revision order differed",
    )?;
    let foreign = s.orgs[1].id.clone();
    let folder = s.folders[1].clone();
    let joint = s
        .trial((0, 0), 0, None, false, Method::PUT, |v| {
            v["lastKnownRevisionDate"] = json!("2000-01-01T00:00:00.000Z");
            v["organizationId"] = json!(foreign);
            v["folderId"] = json!(folder);
        })?
        .rejected(400)?;
    require(
        joint == stale,
        "Shared update revision/scope priority differed",
    )?;
    let foreign = s.orgs[1].id.clone();
    let org = s
        .trial((0, 0), 0, None, false, Method::PUT, |v| {
            v["organizationId"] = json!(foreign)
        })?
        .rejected(400)?;
    let foreign = s.orgs[1].id.clone();
    let folder = s.folders[1].clone();
    let joint = s
        .trial((0, 0), 0, None, false, Method::PUT, |v| {
            v["organizationId"] = json!(foreign);
            v["folderId"] = json!(folder);
            v["secureNote"] = Value::Null;
        })?
        .rejected(400)?;
    require(
        org == joint,
        "Shared update scope/folder/note priority differed",
    )?;
    Ok(())
}
fn annotations(s: &mut Suite) -> Result<(), Error> {
    for actor in 0..2 {
        for variant in 0..3 {
            let t = s.trial(
                (0, actor),
                0,
                None,
                actor == 1,
                Method::PUT,
                |v| match variant {
                    0 => {
                        v.as_object_mut().unwrap().remove("favorite");
                    }
                    1 => v["favorite"] = Value::Null,
                    _ => v["favorite"] = json!(false),
                },
            )?;
            require(
                t.actor_after["favorite"] == json!(variant != 2)
                    && t.actor_after["folderId"].is_null(),
                "Shared update actor annotations differed",
            )?;
            if actor == 1 {
                require(
                    t.after["favorite"] == t.before["favorite"]
                        && t.after["folderId"] == t.before["folderId"],
                    "Shared update changed another viewer's annotations",
                )?;
            } else {
                require(
                    t.actor_before["favorite"] == true,
                    "Shared update Owner annotation baseline differed",
                )?;
            }
            t.applied()?;
        }
    }
    let t = s.trial((0, 1), 0, None, true, Method::PUT, |v| {
        v.as_object_mut().unwrap().remove("folderId");
    })?;
    require(
        t.actor_after["folderId"].is_null(),
        "Missing shared edit folder did not clear actor state",
    )?;
    t.applied()?;
    let folder = s.folders[0].clone();
    s.trial((0, 1), 0, None, true, Method::PUT, |v| {
        v["folderId"] = json!(folder)
    })?
    .rejected(400)?;
    Ok(())
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    let mut key = [0u8; 64];
    key[..32].fill(37);
    key[32..].fill(94);
    let wrapped = fixture::encrypt(&key, &s.orgs[0].key)
        .map_err(|_| Error("Shared update wrapped key fixture failed"))?;
    let encrypted = fixture::encrypt(NOTE.as_bytes(), &key)
        .map_err(|_| Error("Shared update per-cipher encryption failed"))?;
    let t = s.trial((0, 1), 0, None, false, Method::PUT, |v| {
        v["key"] = json!(wrapped);
        v["name"] = json!(encrypted);
        v["notes"] = json!(encrypted);
        v["fields"] = json!([{"name":encrypted,"value":encrypted,"type":0}]);
        v["opaqueExtension"] = json!({"ciphertext":encrypted});
        v["secureNote"] = json!({"type":17,"opaqueNested":encrypted});
        v["attachments"] = json!({});
        v["attachments2"] = json!({});
    })?;
    require(
        t.after["fields"] == t.body["fields"]
            && t.after["secureNote"] == t.body["secureNote"]
            && t.after["attachments"].is_null(),
        "Shared update encrypted fields did not round-trip",
    )?;
    let after = t.applied()?;
    let id = text(&after["id"])?;
    for actor in 0..2 {
        let sync = s.get(actor, "/api/sync")?;
        let list = s.get(actor, "/api/ciphers")?;
        for rows in [&sync["ciphers"], &list["data"]] {
            let rows = rows
                .as_array()
                .ok_or(Error("Shared update read list missing"))?;
            let found = rows.iter().filter(|v| v["id"] == id).collect::<Vec<_>>();
            require(
                found.len() == 1
                    && found[0]["organizationId"] == after["organizationId"]
                    && found[0]["key"] == after["key"]
                    && found[0]["secureNote"] == after["secureNote"]
                    && found[0]["collectionIds"] == after["collectionIds"],
                "Shared update list/sync lost canonical encrypted data",
            )?;
        }
    }
    for actor in 0..2 {
        let control = s.get(
            actor,
            &format!("/api/ciphers/{}", s.accounts[actor].cipher_id),
        )?;
        require(
            control == s.controls[actor],
            "Shared update changed personal control",
        )?;
        let keys = s.get(actor, "/api/accounts/keys")?;
        let profile = s.get(actor, "/api/accounts/profile")?;
        require(
            keys == s.keys[actor] && profile == s.profiles[actor],
            "Shared update changed account authority",
        )?;
    }
    Ok(())
}
fn setup() -> Result<Suite, Error> {
    let mut http = Http::new()?;
    let accounts = vec![
        organization_owner::seed(&mut http)?,
        organization_owner::seed(&mut http)?,
    ];
    let mut orgs = Vec::new();
    for owner in [0, 1, 0, 0, 0] {
        orgs.push(create_organization(&mut http, &accounts[owner])?);
    }
    let mut folders = Vec::new();
    for a in &accounts {
        let name = fixture::encrypted_fixture_value(
            &a.fixture,
            &a.password,
            b"Private ordinary edit folder",
        )
        .map_err(|_| Error("Shared update folder fixture failed"))?;
        let v = http.json(
            Method::POST,
            "/api/folders",
            &a.token,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&v["id"])?.to_owned());
    }
    let mut collections = Vec::new();
    for label in ["Readonly", "Readonly manage", "Unassigned"] {
        let name = fixture::encrypt(label.as_bytes(), &orgs[0].key)
            .map_err(|_| Error("Shared update collection fixture failed"))?;
        let v = http.json(
            Method::POST,
            &format!("/api/organizations/{}/collections", orgs[0].id),
            &accounts[0].token,
            Some(&json!({"name":name,"groups":[],"users":[]})),
        )?;
        collections.push(text(&v["id"])?.to_owned());
    }
    let grants = json!([{"id":orgs[0].collection_id,"readOnly":false,"hidePasswords":false,"manage":false},{"id":collections[0],"readOnly":true,"hidePasswords":false,"manage":false},{"id":collections[1],"readOnly":true,"hidePasswords":false,"manage":true}]);
    let member = bulk::invite(
        &mut http,
        &accounts[0],
        &accounts[1],
        &orgs[0],
        2,
        grants,
        true,
    )?;
    for (org, role, confirmed) in [(2, 1, true), (3, 4, true), (4, 2, false)] {
        bulk::invite(
            &mut http,
            &accounts[0],
            &accounts[1],
            &orgs[org],
            role,
            json!([]),
            confirmed,
        )?;
    }
    let mut s = Suite {
        http,
        accounts,
        orgs,
        folders,
        collections,
        member,
        controls: [Value::Null, Value::Null],
        keys: [Value::Null, Value::Null],
        profiles: [Value::Null, Value::Null],
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_UPDATE_RECEIPT")?,
        finished: false,
    };
    for i in 0..2 {
        s.controls[i] = s.get(i, &format!("/api/ciphers/{}", s.accounts[i].cipher_id))?;
        s.keys[i] = s.get(i, "/api/accounts/keys")?;
        s.profiles[i] = s.get(i, "/api/accounts/profile")?;
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
    }
    eprintln!("Shared update counted HTTP: {}", s.http.requests);
    require(
        s.http.requests == HTTP_REQUEST_COUNT,
        "Shared update request budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    Ok(())
}
