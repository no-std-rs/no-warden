//! Independently authored MIT/Apache-2.0 organization-owner collection contracts.
//! Only owner creation/list/single details are covered, without general sharing.
use crate::{
    fixture,
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
pub const HTTP_REQUEST_COUNT: usize = 194;
pub(crate) const NAME: &str = "Created collection 雪\0authenticated";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_collections_authentication_and_path_guards",
        guards,
    ),
    (
        "organization_collections_json_and_reference_validation",
        schema,
    ),
    (
        "organization_collections_encrypted_create_and_projections",
        encrypted,
    ),
    (
        "organization_collections_opaque_name_and_external_id",
        opaque,
    ),
    (
        "organization_collections_owner_isolation_and_readonly_views",
        isolation,
    ),
    (
        "organization_collections_preserved_vault_keys_and_sessions",
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
pub(crate) fn path(org: &str) -> String {
    format!("/api/organizations/{org}/collections")
}
pub(crate) fn details_path(org: &str, collection: &str) -> String {
    format!("{}/{collection}/details", path(org))
}
fn items(value: &Value) -> Result<&[Value], Error> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(Error("Collection array missing"))
}
pub(crate) fn collection_shape(
    value: &Value,
    org: &str,
    name: &Value,
    external: &Value,
    mode: u8,
) -> Result<(), Error> {
    let (count, object) = match mode {
        0 => (7, "collection"),
        1 => (10, "collectionDetails"),
        2 => (13, "collectionAccessDetails"),
        _ => return Err(Error("Invalid collection fixture projection")),
    };
    require(
        value.as_object().is_some_and(|o| o.len() == count)
            && value["organizationId"] == org
            && value["name"] == *name
            && value["externalId"] == *external
            && value["type"] == 0
            && value
                .get("defaultUserCollectionEmail")
                .is_some_and(Value::is_null)
            && value["object"] == object
            && value["id"]
                .as_str()
                .is_some_and(|id| Uuid::parse_str(id).is_ok()),
        "Collection projection differed",
    )?;
    if mode > 0 {
        require(
            value["readOnly"] == false
                && value["hidePasswords"] == false
                && value["manage"] == true,
            "Owner collection permission projection differed",
        )?;
    }
    if mode == 2 {
        require(
            value["assigned"] == true
                && value["users"] == json!([])
                && value["groups"] == json!([]),
            "Owner access-all collection assignment projection differed",
        )?;
    }
    Ok(())
}
fn list(value: &Value) -> Result<&[Value], Error> {
    require(
        value.as_object().is_some_and(|o| o.len() == 3)
            && value["object"] == "list"
            && value.get("continuationToken").is_some_and(Value::is_null),
        "Organization collection list envelope differed",
    )?;
    items(&value["data"])
}
fn percent_first(id: &str) -> Result<String, Error> {
    let (first, tail) = id
        .split_at_checked(1)
        .ok_or(Error("Collection UUID fixture was empty"))?;
    require(first.is_ascii(), "Collection UUID fixture was not ASCII")?;
    Ok(format!("%{:02X}{tail}", first.as_bytes()[0]))
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    organizations: Vec<Organization>,
    personal: Vec<Value>,
    revisions: Vec<Value>,
    other_authority: Value,
    created: Vec<Value>,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":self.accounts.len(),"fixtureRegistrationHttpRequests":self.accounts.len()*2,"setupOrganizationCreates":self.organizations.len(),"collectionCreates":self.created.len()}),
        )
    }
    fn readonly(&mut self) -> Result<(), Error> {
        for i in 0..self.accounts.len() {
            require(
                self.http.owner.personal(&self.accounts[i].token)? == self.personal[i]
                    && self.http.owner.revision(&self.accounts[i].token)? == self.revisions[i],
                "Collection read or rejected mutation changed vault, keys, device, settings or revision",
            )?;
        }
        require(
            self.other_authority_snapshot()? == self.other_authority,
            "Collection lifecycle changed membership arrays or another organization's collections",
        )?;
        Ok(())
    }
    fn other_authority_snapshot(&mut self) -> Result<Value, Error> {
        let mut memberships = Vec::new();
        for account in &self.accounts {
            let profile =
                self.http
                    .json(Method::GET, "/api/accounts/profile", &account.token, None)?;
            require(
                profile["organizations"].is_array() && profile["organizationsNew"].is_array(),
                "Collection membership snapshot was malformed",
            )?;
            memberships.push(json!({"organizations":profile["organizations"],"organizationsNew":profile["organizationsNew"]}));
        }
        let foreign = self.http.json(
            Method::GET,
            &path(&self.organizations[1].id),
            &self.accounts[1].token,
            None,
        )?;
        let other_owned = self.http.json(
            Method::GET,
            &path(&self.organizations[2].id),
            &self.accounts[0].token,
            None,
        )?;
        list(&foreign)?;
        list(&other_owned)?;
        Ok(
            json!({"memberships":memberships,"foreignCollections":foreign,"otherOwnedCollections":other_owned}),
        )
    }
    fn create(&mut self, body: Value, media: Option<&str>) -> Result<Value, Error> {
        let token = self.accounts[0].token.clone();
        let org = self.organizations[0].id.clone();
        let value = self
            .http
            .raw(
                Method::POST,
                &path(&org),
                Some(&token),
                Some(body.to_string().as_bytes()),
                media,
            )?
            .status(200)?
            .json()?;
        let external = match body.get("externalId") {
            Some(Value::String(s)) if !s.is_empty() => json!(s),
            _ => Value::Null,
        };
        let name = if body.is_array() {
            &body[0]
        } else {
            &body["name"]
        };
        let external = if body.is_array() {
            body[3].clone()
        } else {
            external
        };
        collection_shape(&value, &org, name, &external, 1)?;
        require(
            self.http.owner.revision(&token)? != self.revisions[0]
                && self.http.owner.revision(&self.accounts[1].token)? == self.revisions[1],
            "Collection creation did not update only its owner's revision",
        )?;
        self.revisions[0] = self.http.owner.revision(&token)?;
        self.created.push(value.clone());
        Ok(value)
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.organizations[0].id.clone();
    let col = s.organizations[0].collection_id.clone();
    let token = s.accounts[0].token.clone();
    for bearer in [None, Some("invalid-collection-bearer")] {
        for (method, request_path) in [
            (Method::GET, path(&org)),
            (Method::POST, path(&org)),
            (Method::GET, details_path(&org, &col)),
        ] {
            s.http
                .raw(method, &request_path, bearer, Some(b"{"), None)?
                .rejected(401)?;
        }
    }
    for (request_path, expected) in [
        (path("bad.id"), 401),
        (format!("{}?organizationId={org}", path("bad.id")), 422),
        (details_path(&org, "bad.id"), 401),
        (
            format!("{}?collectionId={col}", details_path(&org, "bad.id")),
            422,
        ),
        (
            format!(
                "{}?organizationId={org}&collectionId={col}",
                details_path("bad.id", "bad.id")
            ),
            422,
        ),
        (
            format!("{}?organizationId={org}", path(&Uuid::new_v4().to_string())),
            401,
        ),
        (
            format!(
                "{}?collectionId={col}",
                details_path(&org, &Uuid::new_v4().to_string())
            ),
            401,
        ),
    ] {
        s.http
            .raw(Method::GET, &request_path, Some(&token), None, None)?
            .rejected(expected)?;
    }
    let ordinary = s
        .http
        .json(Method::GET, &details_path(&org, &col), &token, None)?;
    let encoded = s.http.json(
        Method::GET,
        &details_path(&percent_first(&org)?, &percent_first(&col)?),
        &token,
        None,
    )?;
    require(
        ordinary == encoded,
        "Percent-decoded collection lookup differed",
    )?;
    for (method, request_path) in [
        (Method::PATCH, path(&org)),
        (Method::PUT, path(&org)),
        (Method::POST, details_path(&org, &col)),
        (Method::DELETE, details_path(&org, &col)),
    ] {
        s.http
            .raw(method, &request_path, Some(&token), None, None)?
            .rejected(404)?;
    }
    s.readonly()
}
fn schema(s: &mut Suite) -> Result<(), Error> {
    let token = s.accounts[0].token.clone();
    let p = path(&s.organizations[0].id);
    let valid = json!({"name":"opaque", "groups":[], "users":[]});
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
            b"{\"name\":\"a\",\"name\":\"b\",\"groups\":[],\"users\":[]}".to_vec(),
            422,
        ),
    ];
    for field in ["name", "groups", "users"] {
        let mut v = valid.clone();
        v.as_object_mut()
            .ok_or(Error("Collection fixture invalid"))?
            .remove(field);
        invalids.push((v.to_string().into_bytes(), 422));
    }
    for (field, value) in [
        ("name", Value::Null),
        ("groups", Value::Null),
        ("users", json!({})),
        ("externalId", json!(7)),
        ("users", json!([{"id":"opaque"}])),
    ] {
        let mut v = valid.clone();
        v[field] = value;
        invalids.push((v.to_string().into_bytes(), 422));
    }
    for (body, status) in invalids {
        s.http
            .raw(
                Method::POST,
                &p,
                Some(&token),
                Some(&body),
                Some("application/json"),
            )?
            .rejected(status)?;
    }
    for (groups, users, message) in [
        (
            json!([{"hidePasswords":false,"id":"not-a-group","readOnly":false,"manage":true}]),
            json!([{"hidePasswords":false,"id":"not-a-member","readOnly":false,"manage":true}]),
            "Invalid group",
        ),
        (
            json!([]),
            json!([{"hidePasswords":false,"id":s.accounts[0].user_id,"readOnly":false,"manage":true}]),
            "Invalid member",
        ),
    ] {
        let v = json!({"name":"opaque","groups":groups,"users":users});
        let response = s
            .http
            .raw(
                Method::POST,
                &p,
                Some(&token),
                Some(v.to_string().as_bytes()),
                None,
            )?
            .status(400)?
            .json()?;
        require(
            response["message"] == message,
            "Collection reference validation order differed",
        )?;
    }
    s.readonly()
}
fn encrypted(s: &mut Suite) -> Result<(), Error> {
    let org = s.organizations[0].id.clone();
    let token = s.accounts[0].token.clone();
    let profile = s
        .http
        .json(Method::GET, "/api/accounts/profile", &token, None)?;
    let owner = items(&profile["organizations"])?
        .iter()
        .find(|v| v["id"] == org)
        .ok_or(Error("Owner membership missing"))?;
    let encrypted = fixture::encrypt(NAME.as_bytes(), &s.organizations[0].key)
        .map_err(|_| Error("Collection name encryption failed"))?;
    let response=s.create(json!({"name":encrypted,"groups":[],"users":[{"hidePasswords":false,"id":owner["organizationUserId"],"readOnly":true,"manage":false}],"externalId":"external 雪\0"}),Some("application/problem+json"))?;
    let id = text(&response["id"])?;
    let access = s
        .http
        .json(Method::GET, &details_path(&org, id), &token, None)?;
    collection_shape(&access, &org, &response["name"], &response["externalId"], 2)?;
    require(
        fixture::decrypt(text(&access["name"])?, &s.organizations[0].key)
            .is_ok_and(|p| p == NAME.as_bytes()),
        "Created collection name failed authenticated decryption",
    )?;
    let value = s.http.json(Method::GET, &path(&org), &token, None)?;
    let entry = list(&value)?
        .iter()
        .find(|v| v["id"] == response["id"])
        .ok_or(Error("Created collection missing from organization list"))?;
    collection_shape(entry, &org, &response["name"], &response["externalId"], 0)?;
    s.readonly()
}
fn opaque(s: &mut Suite) -> Result<(), Error> {
    for (name, external, media) in [
        (String::new(), Value::Null, None),
        ("future 雪\0".to_owned(), json!(""), Some("text/plain")),
        ("x".repeat(4097), json!(" \t\n"), Some("application/json")),
    ] {
        let mut body = json!({"name":name,"groups":[],"users":[],"externalId":external,"id":s.accounts[1].user_id,"organizationId":s.organizations[1].id,"ownerId":s.accounts[1].user_id,"manage":false});
        if body["externalId"].is_null() {
            body.as_object_mut()
                .ok_or(Error("Collection opaque fixture invalid"))?
                .remove("externalId");
        }
        let created = s.create(body, media)?;
        require(
            created["id"] != s.accounts[1].user_id,
            "Collection trusted ignored body authority",
        )?;
        let value = s.http.json(
            Method::GET,
            &details_path(&s.organizations[0].id, text(&created["id"])?),
            &s.accounts[0].token,
            None,
        )?;
        collection_shape(
            &value,
            &s.organizations[0].id,
            &created["name"],
            &created["externalId"],
            2,
        )?;
    }
    let created = s.create(
        json!(["positional 雪\0", [], [], "external-positional"]),
        Some("application/json"),
    )?;
    let value = s.http.json(
        Method::GET,
        &details_path(&s.organizations[0].id, text(&created["id"])?),
        &s.accounts[0].token,
        None,
    )?;
    collection_shape(
        &value,
        &s.organizations[0].id,
        &created["name"],
        &created["externalId"],
        2,
    )?;
    s.readonly()
}
fn isolation(s: &mut Suite) -> Result<(), Error> {
    let org = s.organizations[0].id.clone();
    let col = s.organizations[0].collection_id.clone();
    let token = s.accounts[0].token.clone();
    for request_path in [path(&org), details_path(&org, &col)] {
        s.http
            .raw(
                Method::GET,
                &request_path,
                Some(&s.accounts[1].token),
                None,
                None,
            )?
            .rejected(401)?;
    }
    s.http
        .raw(
            Method::POST,
            &path(&org),
            Some(&s.accounts[1].token),
            Some(b"{"),
            None,
        )?
        .rejected(401)?;
    s.http
        .raw(
            Method::GET,
            &details_path(&org, &Uuid::new_v4().to_string()),
            Some(&token),
            None,
            None,
        )?
        .rejected(401)?;
    let cross = s
        .http
        .raw(
            Method::GET,
            &details_path(&org, &s.organizations[2].collection_id),
            Some(&token),
            None,
            None,
        )?
        .status(400)?
        .json()?;
    require(
        cross["message"] == "Collection is not owned by organization",
        "Cross-organization collection error differed",
    )?;
    let first = s.http.json(Method::GET, &path(&org), &token, None)?;
    let ignored = s
        .http
        .raw(
            Method::GET,
            &format!(
                "{}?organizationId=foreign&collectionId=foreign&ignored=true",
                path(&org)
            ),
            Some(&token),
            Some(b"not-json"),
            None,
        )?
        .status(200)?
        .json()?;
    require(
        first == ignored,
        "Collection list query/body changed selection",
    )?;
    require(
        list(&first)?.len() == 1 + s.created.len(),
        "Organization list omitted or leaked a collection",
    )?;
    for row in list(&first)? {
        let detail = s.http.json(
            Method::GET,
            &details_path(&org, text(&row["id"])?),
            &token,
            None,
        )?;
        collection_shape(&detail, &org, &row["name"], &row["externalId"], 2)?;
    }
    let foreign = s.http.json(
        Method::GET,
        &path(&s.organizations[1].id),
        &s.accounts[1].token,
        None,
    )?;
    require(
        list(&foreign)?.len() == 1,
        "Foreign organization collection list changed",
    )?;
    s.readonly()
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for i in 0..s.accounts.len() {
        let account = &s.accounts[i];
        let refreshed = s.http.refresh(&account.refresh)?;
        let profile = s.http.json(
            Method::GET,
            "/api/accounts/profile",
            text(&refreshed["access_token"])?,
            None,
        )?;
        require(
            profile["id"] == account.user_id,
            "Collection lifecycle rebound refresh authority",
        )?;
        let cipher = s.http.json(
            Method::GET,
            &format!("/api/ciphers/{}", account.cipher_id),
            &account.token,
            None,
        )?;
        let key = fixture::fixture_user_key(&account.fixture, &account.password)
            .map_err(|_| Error("Collection fixture key unwrap failed"))?;
        require(
            fixture::decrypt(text(&cipher["notes"])?, &key)
                .is_ok_and(|p| p == organization_owner::NOTE.as_bytes()),
            "Collection lifecycle changed authenticated personal note",
        )?;
    }
    let sync = s
        .http
        .json(Method::GET, "/api/sync", &s.accounts[0].token, None)?;
    let user = s
        .http
        .json(Method::GET, "/api/collections", &s.accounts[0].token, None)?;
    for created in &s.created {
        let basic = list(&user)?
            .iter()
            .find(|v| v["id"] == created["id"])
            .ok_or(Error("Created collection absent from user collection list"))?;
        collection_shape(
            basic,
            &s.organizations[0].id,
            &created["name"],
            &created["externalId"],
            0,
        )?;
        let detail = items(&sync["collections"])?
            .iter()
            .find(|v| v["id"] == created["id"])
            .ok_or(Error("Created collection absent from sync"))?;
        require(
            detail == created,
            "Synced owner collection differed from create projection",
        )?;
    }
    s.readonly()
}
pub(crate) fn create_organization(
    http: &mut OwnerHttp,
    account: &Account,
) -> Result<Organization, Error> {
    let mut organization = Organization::encrypted(account)?;
    let created = http.json(
        Method::POST,
        "/api/organizations",
        &account.token,
        Some(&organization.body),
    )?;
    organization_owner::organization_shape(&created, &organization.body, false)?;
    organization.id = text(&created["id"])?.into();
    organization_owner::inspect_collection(http, account, &mut organization)?;
    Ok(organization)
}
pub fn run() -> Result<(), Error> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        organizations: Vec::new(),
        personal: Vec::new(),
        revisions: Vec::new(),
        other_authority: Value::Null,
        created: Vec::new(),
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_COLLECTIONS_RECEIPT")?,
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
    for account in &s.accounts {
        s.personal.push(s.http.owner.personal(&account.token)?);
        s.revisions.push(s.http.owner.revision(&account.token)?);
    }
    s.other_authority = s.other_authority_snapshot()?;
    for (name, case) in CASES {
        eprintln!("Organization collection case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.logins == 2
            && s.http.refreshes == 2
            && s.passed.len() == CASE_COUNT
            && s.http.owner.requests == HTTP_REQUEST_COUNT,
        "Collection fixture identity/case budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-collections: {CASE_COUNT} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_validator_rejects_missing_fields_and_assignment_authority() {
        let org = Uuid::nil().to_string();
        let mut value = json!({"id":Uuid::new_v4().to_string(),"organizationId":org,"name":"opaque","externalId":null,"type":0,"defaultUserCollectionEmail":null,"object":"collectionAccessDetails","readOnly":false,"hidePasswords":false,"manage":true,"assigned":true,"users":[],"groups":[]});
        assert!(collection_shape(&value, &org, &json!("opaque"), &Value::Null, 2).is_ok());
        value["users"] = json!([{"id":"unexpected"}]);
        assert!(collection_shape(&value, &org, &json!("opaque"), &Value::Null, 2).is_err());
        value["users"] = json!([]);
        value.as_object_mut().unwrap().remove("externalId");
        assert!(collection_shape(&value, &org, &json!("opaque"), &Value::Null, 2).is_err());
    }
}
