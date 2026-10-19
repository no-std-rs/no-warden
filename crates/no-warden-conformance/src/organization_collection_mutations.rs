//! Independently authored MIT/Apache-2.0 organization-owner collection contracts.
//! Only owner collection update/deletion is covered, without general sharing.
use crate::{
    fixture,
    organization_collections::{collection_shape, create_organization, details_path, path},
    organization_owner::{self, Account, Http as OwnerHttp, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{fs, io::Read};
use uuid::Uuid;

pub const CASE_COUNT: usize = 6;
pub const HTTP_REQUEST_COUNT: usize = 229;
pub(crate) const NAME: &str = "Renamed collection Ω雪\0authenticated";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "collection_mutations_authentication_and_path_guards",
        guards,
    ),
    (
        "collection_mutations_update_json_and_reference_validation",
        schema,
    ),
    ("collection_mutations_encrypted_update_and_sync", encrypted),
    ("collection_mutations_external_id_and_replacement", opaque),
    (
        "collection_mutations_delete_empty_response_and_isolation",
        deletion,
    ),
    (
        "collection_mutations_preserved_vault_keys_and_sessions",
        preservation,
    ),
];
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, Error> {
        if self.status != expected {
            eprintln!(
                "Organization collections status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Organization collection HTTP status differed",
        )?;
        Ok(self)
    }
    fn empty(self) -> Result<(), Error> {
        let response = self.status(200)?;
        require(
            response.bytes.is_empty(),
            "Collection deletion response was not empty",
        )
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Organization collection response was not JSON"))
    }
    fn rejected(self, expected: u16) -> Result<(), Error> {
        let response = self.status(expected)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&response.bytes) {
            require(
                ["access_token", "refresh_token", "key", "privateKey"]
                    .iter()
                    .all(|k| value.get(k).is_none()),
                "Rejected collection request exposed authority",
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
    fn read(response: reqwest::blocking::Response) -> Result<Reply, Error> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Collection private response capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Collection response exceeded private bound",
        )?;
        Ok(Reply { status, bytes })
    }
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
        media: Option<&str>,
    ) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.owner.server));
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.body(body.to_vec());
        }
        if let Some(media) = media {
            request = request.header("Content-Type", media);
        }
        Self::read(
            request
                .send()
                .map_err(|_| Error("Organization collection request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        self.raw(
            method,
            path,
            Some(token),
            body.map(Value::to_string).as_deref().map(str::as_bytes),
            Some("application/json"),
        )?
        .status(200)?
        .json()
    }
    fn refresh(&mut self, proof: &str) -> Result<Value, Error> {
        self.owner.requests += 1;
        self.refreshes += 1;
        Self::read(
            self.client
                .post(format!("{}/identity/connect/token", self.owner.server))
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", proof),
                    ("client_id", "cli"),
                ])
                .send()
                .map_err(|_| Error("Collection refresh failed"))?,
        )?
        .status(200)?
        .json()
    }
}
pub(crate) fn mutation_path(org: &str, collection: &str) -> String {
    format!("{}/{collection}", path(org))
}
fn items(value: &Value) -> Result<&[Value], Error> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(Error("Collection mutation array missing"))
}
fn list(value: &Value) -> Result<&[Value], Error> {
    require(
        value.as_object().is_some_and(|o| o.len() == 3)
            && value["object"] == "list"
            && value.get("continuationToken").is_some_and(Value::is_null),
        "Collection mutation list envelope differed",
    )?;
    items(&value["data"])
}
fn access_details(value: &Value) -> Value {
    let mut value = value.clone();
    value["assigned"] = json!(true);
    value["users"] = json!([]);
    value["groups"] = json!([]);
    value["object"] = json!("collectionAccessDetails");
    value
}
fn percent_first(id: &str) -> Result<String, Error> {
    let (first, tail) = id
        .split_at_checked(1)
        .ok_or(Error("Mutation fixture UUID empty"))?;
    require(first.is_ascii(), "Mutation fixture UUID not ASCII")?;
    Ok(format!("%{:02X}{tail}", first.as_bytes()[0]))
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    organizations: Vec<Organization>,
    personal: Vec<Value>,
    revisions: Vec<Value>,
    other_authority: Value,
    current: Value,
    updates: usize,
    deleted: bool,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":self.accounts.len(),"fixtureRegistrationHttpRequests":self.accounts.len()*2,"setupOrganizationCreates":self.organizations.len(),"setupSiblingCreates":usize::from(!self.current.is_null()),"collectionUpdates":self.updates,"collectionDeleted":self.deleted}),
        )
    }
    fn other_authority_snapshot(&mut self) -> Result<Value, Error> {
        let mut memberships = Vec::new();
        for account in &self.accounts {
            let profile =
                self.http
                    .json(Method::GET, "/api/accounts/profile", &account.token, None)?;
            require(
                profile["organizations"].is_array() && profile["organizationsNew"].is_array(),
                "Mutation membership snapshot malformed",
            )?;
            memberships.push(json!({"organizations":profile["organizations"],"organizationsNew":profile["organizationsNew"]}));
        }
        let foreign = self.http.json(
            Method::GET,
            &path(&self.organizations[1].id),
            &self.accounts[1].token,
            None,
        )?;
        let other = self.http.json(
            Method::GET,
            &path(&self.organizations[2].id),
            &self.accounts[0].token,
            None,
        )?;
        list(&foreign)?;
        list(&other)?;
        let own = self.http.json(
            Method::GET,
            &path(&self.organizations[0].id),
            &self.accounts[0].token,
            None,
        )?;
        let siblings = list(&own)?
            .iter()
            .filter(|v| v["id"] != self.organizations[0].collection_id)
            .cloned()
            .collect::<Vec<_>>();
        require(
            siblings.len() == 1,
            "Mutation sibling snapshot omitted collection",
        )?;
        Ok(
            json!({"memberships":memberships,"foreignCollections":foreign,"otherOwnedCollections":other,"siblings":siblings}),
        )
    }
    fn readonly(&mut self) -> Result<(), Error> {
        for i in 0..self.accounts.len() {
            require(
                self.http.owner.personal(&self.accounts[i].token)? == self.personal[i]
                    && self.http.owner.revision(&self.accounts[i].token)? == self.revisions[i],
                "Collection mutation changed personal vault, keys, devices, settings or wrong revision",
            )?;
        }
        require(
            self.other_authority_snapshot()? == self.other_authority,
            "Collection mutation changed membership, sibling or another organization's collection",
        )?;
        let response = self.http.raw(
            Method::GET,
            &details_path(
                &self.organizations[0].id,
                &self.organizations[0].collection_id,
            ),
            Some(&self.accounts[0].token),
            None,
            None,
        )?;
        if self.deleted {
            response.rejected(401)?;
        } else {
            require(
                response.status(200)?.json()? == self.current,
                "Rejected or committed mutation left unexpected collection details",
            )?;
        }
        Ok(())
    }
    fn revised(&mut self) -> Result<(), Error> {
        require(
            self.http.owner.revision(&self.accounts[0].token)? != self.revisions[0]
                && self.http.owner.revision(&self.accounts[1].token)? == self.revisions[1],
            "Collection mutation did not advance only owner revision",
        )?;
        self.revisions[0] = self.http.owner.revision(&self.accounts[0].token)?;
        Ok(())
    }
    fn update(&mut self, body: &Value, media: Option<&str>, encoded: bool) -> Result<Value, Error> {
        let org = &self.organizations[0].id;
        let id = &self.organizations[0].collection_id;
        let request_path = if encoded {
            mutation_path(&percent_first(org)?, &percent_first(id)?)
        } else {
            mutation_path(org, id)
        };
        let value = self
            .http
            .raw(
                Method::PUT,
                &request_path,
                Some(&self.accounts[0].token),
                Some(body.to_string().as_bytes()),
                media,
            )?
            .status(200)?
            .json()?;
        let name = if body.is_array() {
            &body[0]
        } else {
            &body["name"]
        };
        let external = if body.is_array() {
            &body[3]
        } else {
            &body["externalId"]
        };
        let external = external
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .map_or(Value::Null, |s| json!(s));
        collection_shape(&value, org, name, &external, 1)?;
        require(
            value["id"] == *id,
            "Collection update changed generated identity",
        )?;
        self.current = access_details(&value);
        self.updates += 1;
        self.revised()?;
        Ok(value)
    }
    fn views(&mut self, present: bool) -> Result<(), Error> {
        let token = &self.accounts[0].token;
        let org = &self.organizations[0].id;
        let id = &self.organizations[0].collection_id;
        for p in [path(org), "/api/collections".into(), "/api/sync".into()] {
            let value = self.http.json(Method::GET, &p, token, None)?;
            let rows = if p == "/api/sync" {
                items(&value["collections"])?
            } else {
                list(&value)?
            };
            let row = rows.iter().find(|v| v["id"] == *id);
            require(
                row.is_some() == present,
                "Collection mutation did not reach every read view",
            )?;
            if let Some(row) = row {
                collection_shape(
                    row,
                    org,
                    &self.current["name"],
                    &self.current["externalId"],
                    u8::from(p == "/api/sync"),
                )?;
            }
        }
        Ok(())
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.organizations[0].id.clone();
    let id = s.organizations[0].collection_id.clone();
    let own = s.accounts[0].token.clone();
    let valid = json!({"name":s.current["name"],"groups":[],"users":[]}).to_string();
    for bearer in [None, Some("invalid-mutation-bearer")] {
        for method in [Method::PUT, Method::DELETE] {
            s.http
                .raw(method, &mutation_path(&org, &id), bearer, Some(b"{"), None)?
                .rejected(401)?;
        }
    }
    for method in [Method::PUT, Method::DELETE] {
        for (p, status) in [
            (mutation_path("bad.id", &id), 401),
            (
                format!("{}?organizationId={org}", mutation_path("bad.id", &id)),
                422,
            ),
            (mutation_path(&org, "bad.id"), 401),
            (
                format!("{}?collectionId={id}", mutation_path(&org, "bad.id")),
                422,
            ),
            (
                format!(
                    "{}?organizationId={org}&collectionId={id}",
                    mutation_path("bad.id", "bad.id")
                ),
                422,
            ),
            (
                format!(
                    "{}?collectionId={id}",
                    mutation_path(&org, &Uuid::new_v4().to_string())
                ),
                401,
            ),
            (mutation_path(&Uuid::new_v4().to_string(), &id), 401),
        ] {
            s.http
                .raw(method.clone(), &p, Some(&own), Some(b"{"), None)?
                .rejected(status)?;
        }
        s.http
            .raw(
                method.clone(),
                &mutation_path(&org, &id),
                Some(&s.accounts[1].token),
                Some(b"{"),
                None,
            )?
            .rejected(401)?;
        let error = s
            .http
            .raw(
                method,
                &mutation_path(&org, &s.organizations[2].collection_id),
                Some(&own),
                Some(valid.as_bytes()),
                Some("application/json"),
            )?
            .status(400)?
            .json()?;
        require(
            error["message"] == "Collection not found",
            "Same-owner cross-organization mutation error differed",
        )?;
    }
    for method in [Method::GET, Method::POST, Method::PATCH] {
        s.http
            .raw(method, &mutation_path(&org, &id), Some(&own), None, None)?
            .rejected(404)?;
    }
    s.readonly()
}
fn schema(s: &mut Suite) -> Result<(), Error> {
    let p = mutation_path(&s.organizations[0].id, &s.organizations[0].collection_id);
    let own = s.accounts[0].token.clone();
    let valid = json!({"name":"opaque","groups":[],"users":[]});
    let mut invalids = vec![
        (b"{".to_vec(), 400),
        (b"[]".to_vec(), 422),
        (b"[\"x\",[],[]]".to_vec(), 422),
        (b"[\"x\",[],[],null,0]".to_vec(), 400),
        (
            b"{\"name\":\"x\",\"groups\":[],\"users\":[],\"ignored\":\"\xff\"}".to_vec(),
            400,
        ),
        (
            b"{\"name\":\"x\",\"name\":\"y\",\"groups\":[],\"users\":[]}".to_vec(),
            422,
        ),
    ];
    for field in ["name", "groups", "users"] {
        let mut v = valid.clone();
        v.as_object_mut()
            .ok_or(Error("Mutation fixture malformed"))?
            .remove(field);
        invalids.push((v.to_string().into_bytes(), 422));
    }
    for (field, v) in [
        ("name", Value::Null),
        ("groups", Value::Null),
        ("users", json!({})),
        ("externalId", json!(3)),
        ("users", json!([{"id":"opaque"}])),
    ] {
        let mut b = valid.clone();
        b[field] = v;
        invalids.push((b.to_string().into_bytes(), 422));
    }
    invalids.push((br#"{"Name":"opaque","Groups":[],"Users":[]}"#.to_vec(), 422));
    for (body, status) in invalids {
        s.http
            .raw(
                Method::PUT,
                &p,
                Some(&own),
                Some(&body),
                Some("application/json"),
            )?
            .rejected(status)?;
    }
    for (groups, users, message) in [
        (
            json!([{"hidePasswords":false,"id":"missing-group","readOnly":false,"manage":true}]),
            json!([{"hidePasswords":false,"id":"missing-member","readOnly":false,"manage":true}]),
            "Invalid group",
        ),
        (
            json!([]),
            json!([{"hidePasswords":false,"id":s.accounts[0].user_id,"readOnly":false,"manage":true}]),
            "Invalid member",
        ),
    ] {
        let body = json!({"name":"opaque","groups":groups,"users":users});
        let error = s
            .http
            .raw(
                Method::PUT,
                &p,
                Some(&own),
                Some(body.to_string().as_bytes()),
                None,
            )?
            .status(400)?
            .json()?;
        require(
            error["message"] == message,
            "Collection mutation reference validation order differed",
        )?;
    }
    s.readonly()
}
fn encrypted(s: &mut Suite) -> Result<(), Error> {
    let profile = s.http.json(
        Method::GET,
        "/api/accounts/profile",
        &s.accounts[0].token,
        None,
    )?;
    let membership = items(&profile["organizations"])?
        .iter()
        .find(|v| v["id"] == s.organizations[0].id)
        .ok_or(Error("Mutation owner membership missing"))?;
    let ciphertext = fixture::encrypt(NAME.as_bytes(), &s.organizations[0].key)
        .map_err(|_| Error("Collection rename encryption failed"))?;
    let response=s.update(&json!({"name":ciphertext,"groups":[],"users":[{"hidePasswords":true,"id":membership["organizationUserId"],"readOnly":true,"manage":false}],"externalId":"renamed 雪\0"}),Some("application/problem+json"),false)?;
    let details = s.http.json(
        Method::GET,
        &details_path(&s.organizations[0].id, &s.organizations[0].collection_id),
        &s.accounts[0].token,
        None,
    )?;
    require(
        details == s.current
            && fixture::decrypt(text(&response["name"])?, &s.organizations[0].key)
                .is_ok_and(|p| p == NAME.as_bytes()),
        "Renamed collection failed independent authenticated decryption",
    )?;
    s.views(true)?;
    s.readonly()
}
fn opaque(s: &mut Suite) -> Result<(), Error> {
    for (name, external, media) in [
        (String::new(), None, None),
        ("future 雪\0".into(), Some(Value::Null), Some("text/plain")),
        (
            "empty-external".into(),
            Some(json!("")),
            Some("application/json"),
        ),
        (
            "x".repeat(4097),
            Some(json!("\u{2003}\u{00a0}\t\n")),
            Some("application/json"),
        ),
        (
            "nonblank".into(),
            Some(json!(" \u{2003}nonblank \t")),
            Some("application/json"),
        ),
    ] {
        let mut body = json!({"name":name,"groups":[],"users":[],"organizationId":s.organizations[1].id,"id":s.accounts[1].user_id,"ownerId":s.accounts[1].user_id});
        if let Some(external) = external {
            body["externalId"] = external;
        }
        s.update(&body, media, false)?;
        let details = s.http.json(
            Method::GET,
            &details_path(&s.organizations[0].id, &s.organizations[0].collection_id),
            &s.accounts[0].token,
            None,
        )?;
        require(
            details == s.current,
            "Opaque collection update was not persisted exactly",
        )?;
    }
    let positional = json!(["positional 雪\0", [], [], ""]);
    for encoded in [false, true] {
        s.update(&positional, Some("application/json"), encoded)?;
        let details = s.http.json(
            Method::GET,
            &details_path(&s.organizations[0].id, &s.organizations[0].collection_id),
            &s.accounts[0].token,
            None,
        )?;
        require(
            details == s.current,
            "Repeated or encoded collection update differed",
        )?;
    }
    s.readonly()
}
fn deletion(s: &mut Suite) -> Result<(), Error> {
    let org = s.organizations[0].id.clone();
    let id = s.organizations[0].collection_id.clone();
    let own = s.accounts[0].token.clone();
    s.http
        .raw(
            Method::DELETE,
            &format!(
                "{}?organizationId={}&collectionId=ignored",
                mutation_path(&org, &id),
                s.organizations[1].id
            ),
            Some(&own),
            Some(b"not-json"),
            Some("application/json"),
        )?
        .empty()?;
    s.deleted = true;
    s.revised()?;
    s.views(false)?;
    for method in [Method::DELETE, Method::PUT] {
        s.http
            .raw(
                method,
                &mutation_path(&org, &id),
                Some(&own),
                Some(b"{"),
                None,
            )?
            .rejected(401)?;
    }
    s.readonly()
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for account in &s.accounts {
        let refreshed = s.http.refresh(&account.refresh)?;
        let profile = s.http.json(
            Method::GET,
            "/api/accounts/profile",
            text(&refreshed["access_token"])?,
            None,
        )?;
        require(
            profile["id"] == account.user_id,
            "Collection mutation rebound refresh authority",
        )?;
        let cipher = s.http.json(
            Method::GET,
            &format!("/api/ciphers/{}", account.cipher_id),
            &account.token,
            None,
        )?;
        let key = fixture::fixture_user_key(&account.fixture, &account.password)
            .map_err(|_| Error("Mutation fixture key unwrap failed"))?;
        require(
            fixture::decrypt(text(&cipher["notes"])?, &key)
                .is_ok_and(|p| p == organization_owner::NOTE.as_bytes()),
            "Collection mutation changed personal authenticated note",
        )?;
    }
    s.views(false)?;
    s.readonly()
}
pub fn run() -> Result<(), Error> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        organizations: Vec::new(),
        personal: Vec::new(),
        revisions: Vec::new(),
        other_authority: Value::Null,
        current: Value::Null,
        updates: 0,
        deleted: false,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_COLLECTION_MUTATIONS_RECEIPT")?,
        finished: false,
    };
    s.receipt("running")?;
    for _ in 0..2 {
        let account = organization_owner::seed(&mut s.http.owner)?;
        s.organizations
            .push(create_organization(&mut s.http.owner, &account)?);
        s.accounts.push(account);
    }
    s.organizations
        .push(create_organization(&mut s.http.owner, &s.accounts[0])?);
    let sibling = fixture::encrypt(b"Unchanged sibling collection", &s.organizations[0].key)
        .map_err(|_| Error("Mutation sibling encryption failed"))?;
    s.http.json(
        Method::POST,
        &path(&s.organizations[0].id),
        &s.accounts[0].token,
        Some(&json!({"name":sibling,"groups":[],"users":[],"externalId":"unchanged-sibling"})),
    )?;
    s.current = s.http.json(
        Method::GET,
        &details_path(&s.organizations[0].id, &s.organizations[0].collection_id),
        &s.accounts[0].token,
        None,
    )?;
    for account in &s.accounts {
        s.personal.push(s.http.owner.personal(&account.token)?);
        s.revisions.push(s.http.owner.revision(&account.token)?);
    }
    s.other_authority = s.other_authority_snapshot()?;
    for (name, case) in CASES {
        eprintln!("Collection mutation case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.logins == 2
            && s.http.refreshes == 2
            && s.updates == 8
            && s.deleted
            && s.passed.len() == CASE_COUNT
            && s.http.owner.requests == HTTP_REQUEST_COUNT,
        "Collection mutation fixture budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-collection-mutations: {CASE_COUNT} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deletion_validator_rejects_json_null_or_nonempty_success_and_failure_status() {
        assert!(
            Reply {
                status: 200,
                bytes: Vec::new()
            }
            .empty()
            .is_ok()
        );
        for bytes in [b"null".to_vec(), b"\n".to_vec(), b"{}".to_vec()] {
            assert!(Reply { status: 200, bytes }.empty().is_err());
        }
        assert!(
            Reply {
                status: 500,
                bytes: Vec::new()
            }
            .empty()
            .is_err()
        );
    }
}
