//! Independently authored actual-server contracts for three web organization reads.
//! Default no-created-groups only; no new CLI/browser caller claim is made here.
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
pub const HTTP_REQUEST_COUNT: usize = 156;
pub(crate) const NOTE: &str = "Independently authored web organization note Ω\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_web_reads_authentication_and_accepted_admin_guards",
        guards,
    ),
    (
        "organization_web_reads_exact_cipher_projection_and_canonical_scope",
        ciphers,
    ),
    (
        "organization_web_reads_aggregate_collection_projection_and_nested_grants",
        collections,
    ),
    (
        "organization_web_reads_confirmed_roles_and_revoked_restored_admission",
        actors,
    ),
    (
        "organization_web_reads_query_roots_duplicates_and_raw_path_scope",
        transport,
    ),
    (
        "organization_web_reads_retained_ciphertext_keys_revisions_and_sessions",
        preservation,
    ),
];
const CIPHER_FIELDS: [&str; 24] = [
    "attachments",
    "bankAccount",
    "card",
    "collectionIds",
    "creationDate",
    "deletedDate",
    "driversLicense",
    "fields",
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
    "reprompt",
    "revisionDate",
    "secureNote",
    "sshKey",
    "type",
];
const COLLECTION_FIELDS: [&str; 14] = [
    "assigned",
    "defaultUserCollectionEmail",
    "externalId",
    "groups",
    "hidePasswords",
    "id",
    "manage",
    "name",
    "object",
    "organizationId",
    "readOnly",
    "type",
    "unmanaged",
    "users",
];
pub(crate) fn cipher_path(org: &str) -> String {
    format!("/api/ciphers/organization-details?organizationId={org}")
}
pub(crate) fn collections_path(org: &str) -> String {
    format!("/api/organizations/{org}/collections/details")
}
pub(crate) fn groups_path(org: &str) -> String {
    format!("/api/organizations/{org}/groups")
}
fn rows(value: &Value) -> Result<&Vec<Value>, Error> {
    require(
        value.as_object().is_some_and(|v| v.len() == 3)
            && value["object"] == "list"
            && value["continuationToken"].is_null(),
        "Organization web list envelope differed",
    )?;
    value["data"]
        .as_array()
        .ok_or(Error("Organization web data was not an array"))
}
fn fields(value: &Value, expected: &[&str]) -> Result<(), Error> {
    require(
        value.as_object().is_some_and(|v| {
            v.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == expected.iter().copied().collect()
        }),
        "Organization web exact field set differed",
    )
}
pub(crate) fn check_empty_groups(value: &Value) -> Result<(), Error> {
    require(
        rows(value)?.is_empty(),
        "Default group response was not empty",
    )
}
pub(crate) fn check_cipher(value: &Value, shared: &Value) -> Result<(), Error> {
    fields(value, &CIPHER_FIELDS)?;
    let mut expected = shared.clone();
    for key in [
        "archivedDate",
        "edit",
        "favorite",
        "folderId",
        "permissions",
        "viewPassword",
    ] {
        expected
            .as_object_mut()
            .ok_or(Error("Cipher fixture was not an object"))?
            .remove(key);
    }
    for field in ["fields", "passwordHistory"] {
        if expected[field].is_null() {
            expected[field] = json!([]);
        }
    }
    require(
        *value == expected,
        "Organization cipher projection changed opaque payload or metadata",
    )
}
pub(crate) fn share_fixture(
    http: &mut OwnerHttp,
    account: &Account,
    org: &Organization,
) -> Result<Value, Error> {
    share_fixture_metadata(http, account, org, Metadata::Absent)
}
#[derive(Clone, Copy)]
enum Metadata {
    Absent,
    Null,
    Nonempty,
}
fn share_fixture_metadata(
    http: &mut OwnerHttp,
    account: &Account,
    org: &Organization,
    metadata: Metadata,
) -> Result<Value, Error> {
    let personal =
        fixture::encrypted_fixture_value(&account.fixture, &account.password, NOTE.as_bytes())
            .map_err(|_| Error("Web read personal encryption failed"))?;
    let item=http.json(Method::POST,"/api/ciphers",&account.token,Some(&json!({"type":2,"encryptedFor":account.user_id,"name":personal,"notes":personal,"secureNote":{"type":0}})))?;
    let id = text(&item["id"])?;
    let encrypted = fixture::encrypt(NOTE.as_bytes(), &org.key)
        .map_err(|_| Error("Web read organization encryption failed"))?;
    let mut body = json!({"collectionIds":[org.collection_id],"cipher":{"type":2,"organizationId":org.id,"encryptedFor":account.user_id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"key":null,"favorite":false}});
    match metadata {
        Metadata::Absent => (),
        Metadata::Null => {
            body["cipher"]["fields"] = Value::Null;
            body["cipher"]["passwordHistory"] = Value::Null;
        }
        Metadata::Nonempty => {
            body["cipher"]["fields"] = json!([{"name":encrypted,"value":encrypted,"type":0}]);
            body["cipher"]["passwordHistory"] =
                json!([{"password":encrypted,"lastUsedDate":"2026-10-21T00:00:00.000000Z"}]);
        }
    }
    let value = http.json(
        Method::PUT,
        &format!("/api/ciphers/{id}/share"),
        &account.token,
        Some(&body),
    )?;
    for field in ["fields", "passwordHistory"] {
        if matches!(metadata, Metadata::Nonempty) {
            require(
                value[field] == body["cipher"][field],
                "Share fixture nonempty opaque list metadata changed",
            )?;
        } else {
            require(
                value[field].is_null() || value[field] == json!([]),
                "Share fixture empty metadata type differed",
            )?;
        }
    }
    require(
        value["id"] == id && value["organizationId"] == org.id && value["notes"] == encrypted,
        "Web read sharing fixture differed",
    )?;
    Ok(value)
}
/// Direct observation beside real CLI collection/cache commands. These GETs
/// are explicit harness requests; the CLI is not claimed to call these routes.
pub(crate) fn observe_owner(
    http: &mut OwnerHttp,
    account: &Account,
    org: &Organization,
    shared: &Value,
    created: Option<&str>,
) -> Result<(), Error> {
    let value = http.json(Method::GET, &cipher_path(&org.id), &account.token, None)?;
    let values = rows(&value)?;
    require(
        values.len() == 1,
        "CLI observer organization cipher count differed",
    )?;
    check_cipher(&values[0], shared)?;
    let value = http.json(
        Method::GET,
        &collections_path(&org.id),
        &account.token,
        None,
    )?;
    let values = rows(&value)?;
    require(
        values.len() == 1 + usize::from(created.is_some()),
        "CLI observer collection count differed",
    )?;
    for row in values {
        fields(row, &COLLECTION_FIELDS)?;
        require(
            row["unmanaged"] == false
                && row["assigned"] == true
                && row["manage"] == true
                && row["readOnly"] == false
                && row["hidePasswords"] == false
                && row["groups"] == json!([]),
            "CLI observer collection flags differed",
        )?;
        let is_created = created.is_some_and(|id| row["id"] == id);
        require(
            is_created || row["id"] == org.collection_id,
            "CLI observer collection scope differed",
        )?;
        let expected = if is_created {
            crate::organization_collections::NAME
        } else {
            organization_owner::COLLECTION_NAME
        };
        require(
            fixture::decrypt(text(&row["name"])?, &org.key)
                .is_ok_and(|bytes| bytes == expected.as_bytes()),
            "CLI observer collection name failed authenticated decryption",
        )?;
        let users = row["users"]
            .as_array()
            .ok_or(Error("CLI observer aggregate user list differed"))?;
        require(
            users.len() == 1,
            "CLI observer implicit owner selection missing",
        )?;
        fields(&users[0], &["id", "readOnly", "hidePasswords", "manage"])?;
        require(
            users[0]["manage"] == true
                && users[0]["readOnly"] == false
                && users[0]["hidePasswords"] == false,
            "CLI observer implicit owner flags differed",
        )?;
    }
    check_empty_groups(&http.json(Method::GET, &groups_path(&org.id), &account.token, None)?)
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, Error> {
        if self.status != expected {
            eprintln!(
                "Organization web read HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Organization web read HTTP status differed",
        )?;
        Ok(self)
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Organization web read response was not JSON"))
    }
    fn rejected(self, expected: u16) -> Result<(), Error> {
        self.status(expected).map(|_| ())
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
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.owner.server))
            .header("Accept", "application/json");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .map_err(|_| Error("Organization web read HTTP request failed"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Organization web read private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Organization web read response exceeded capture bound",
        )?;
        Ok(Reply { status, bytes })
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        self.raw(method, path, token, body)?.status(200)?.json()
    }
    fn refresh(&mut self, proof: &str) -> Result<Value, Error> {
        self.owner.requests += 1;
        self.refreshes += 1;
        let response = self
            .client
            .post(format!("{}/identity/connect/token", self.owner.server))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", "cli"),
                ("refresh_token", proof),
            ])
            .send()
            .map_err(|_| Error("Organization web read refresh failed"))?;
        require(
            response.status().as_u16() == 200,
            "Organization web read refresh rejected",
        )?;
        response
            .json()
            .map_err(|_| Error("Organization web read refresh response malformed"))
    }
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    members: Vec<String>,
    owners: Vec<String>,
    extra_collection: String,
    invited_members: Vec<String>,
    shared: Vec<Value>,
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
            &json!({"schemaVersion":1,"status":status,"passedCases":self.passed.len(),"expectedCases":CASE_COUNT,"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"defaultNoCreatedGroupsAsserted":true,"groupsConfigured":false,"configuredPolicies":false,"smtpEnabled":false,"attachmentBearingTested":false,"cliCallerClaimed":false,"browserTraceClaimed":false,"capturedRouteTrace":false,"fullParityClaimed":false,"invitedRevokedCollectionUsersTested":status=="passed","cipherAbsentNullNonemptyMetadataTested":status=="passed"}),
        )
    }
    fn token(&self, actor: usize) -> String {
        self.accounts[actor].token.clone()
    }
    fn get(&mut self, actor: usize, path: &str) -> Result<Value, Error> {
        let token = self.token(actor);
        self.http.json(Method::GET, path, Some(&token), None)
    }
    fn statuses(&mut self, actor: usize, org: usize, statuses: [u16; 3]) -> Result<(), Error> {
        let token = self.token(actor);
        let id = self.orgs[org].id.clone();
        for (path, status) in [cipher_path(&id), collections_path(&id), groups_path(&id)]
            .iter()
            .zip(statuses)
        {
            let reply = self
                .http
                .raw(Method::GET, path, Some(&token), None)?
                .status(status)?;
            if status == 200 {
                rows(&reply.json()?)?;
            }
        }
        Ok(())
    }
    fn confirm(&mut self, org: usize) -> Result<(), Error> {
        let key =
            fixture::organization_key_for_account(&self.accounts[1].fixture, &self.orgs[org].key)
                .map_err(|_| Error("Web read confirmation encryption failed"))?;
        let token = self.token(0);
        self.http
            .raw(
                Method::POST,
                &format!(
                    "/api/organizations/{}/users/{}/confirm",
                    self.orgs[org].id, self.members[org]
                ),
                Some(&token),
                Some(&json!({"key":key})),
            )?
            .status(200)?;
        Ok(())
    }
    fn change_status(&mut self, org: usize, action: &str) -> Result<(), Error> {
        let token = self.token(0);
        self.http
            .raw(
                Method::PUT,
                &format!(
                    "/api/organizations/{}/users/{}/{action}",
                    self.orgs[org].id, self.members[org]
                ),
                Some(&token),
                None,
            )?
            .status(200)?;
        Ok(())
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    for path in [cipher_path(&org), collections_path(&org), groups_path(&org)] {
        s.http.raw(Method::GET, &path, None, None)?.rejected(401)?;
    }
    s.statuses(0, 1, [401; 3])?;
    s.statuses(1, 0, [401; 3])?;
    s.statuses(1, 2, [401; 3])?;
    admin_collection_users(s, false)?;
    s.confirm(0)?;
    s.confirm(2)?;
    Ok(())
}
fn ciphers(s: &mut Suite) -> Result<(), Error> {
    let a = share_fixture_metadata(
        &mut s.http.owner,
        &s.accounts[0],
        &s.orgs[0],
        Metadata::Null,
    )?;
    let b = share_fixture_metadata(
        &mut s.http.owner,
        &s.accounts[0],
        &s.orgs[6],
        Metadata::Nonempty,
    )?;
    let c = share_fixture(&mut s.http.owner, &s.accounts[0], &s.orgs[6])?;
    s.shared = vec![a, b, c];
    for org in [0, 6] {
        let path = cipher_path(&s.orgs[org].id);
        let value = s.get(0, &path)?;
        let values = rows(&value)?;
        require(
            values.len() == if org == 0 { 1 } else { 2 },
            "Organization cipher scope included unrelated vault items",
        )?;
        let expected = if org == 0 {
            &s.shared[..1]
        } else {
            &s.shared[1..]
        };
        for shared in expected {
            let matching = values
                .iter()
                .filter(|v| v["id"] == shared["id"])
                .collect::<Vec<_>>();
            require(
                matching.len() == 1,
                "Organization cipher projection omitted or duplicated metadata fixture",
            )?;
            check_cipher(matching[0], shared)?;
        }
        require(
            values.iter().all(|v| v["id"] != s.accounts[0].cipher_id),
            "Personal cipher leaked into organization list",
        )?;
    }
    let value = s.get(0, &cipher_path(&s.orgs[2].id))?;
    require(
        rows(&value)?.is_empty(),
        "Empty organization cipher list was not empty",
    )?;
    Ok(())
}
fn selection(id: &str, ro: bool, manage: bool) -> Value {
    json!({"id":id,"readOnly":ro,"hidePasswords":false,"manage":manage})
}
fn check_collections(
    value: &Value,
    org: &str,
    expected: &[(String, Vec<Value>, bool, bool)],
) -> Result<(), Error> {
    let data = rows(value)?;
    require(
        data.len() == expected.len(),
        "Aggregate collection count differed",
    )?;
    for (id, users, ro, manage) in expected {
        let matches = data.iter().filter(|v| v["id"] == *id).collect::<Vec<_>>();
        require(
            matches.len() == 1,
            "Aggregate collection ID omitted or duplicated",
        )?;
        let row = matches[0];
        fields(row, &COLLECTION_FIELDS)?;
        require(
            row["organizationId"] == org
                && row["object"] == "collectionAccessDetails"
                && row["type"] == 0
                && row["unmanaged"] == false
                && row["assigned"] == true
                && row["readOnly"] == *ro
                && row["hidePasswords"] == false
                && row["manage"] == *manage
                && row["externalId"].is_null()
                && row["defaultUserCollectionEmail"].is_null()
                && row["groups"] == json!([])
                && row["name"].is_string(),
            "Aggregate collection metadata differed",
        )?;
        let actual = row["users"]
            .as_array()
            .ok_or(Error("Aggregate collection users were not an array"))?;
        require(
            actual.len() == users.len(),
            "Implicit or direct collection user count differed",
        )?;
        for user in actual {
            fields(user, &["id", "readOnly", "hidePasswords", "manage"])?;
        }
        require(
            users.iter().all(|user| actual.contains(user)),
            "Aggregate collection user flags or identities differed",
        )?;
    }
    Ok(())
}
fn main_collection_users(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let expected = vec![
        (
            s.orgs[0].collection_id.clone(),
            vec![
                selection(&s.owners[0], false, true),
                selection(&s.members[0], false, false),
            ],
            false,
            true,
        ),
        (
            s.extra_collection.clone(),
            vec![selection(&s.owners[0], false, true)],
            false,
            true,
        ),
    ];
    check_collections(&s.get(0, &collections_path(&org))?, &org, &expected)?;
    Ok(())
}
fn collections(s: &mut Suite) -> Result<(), Error> {
    main_collection_users(s)?;
    let org = s.orgs[3].id.clone();
    let expected = vec![(
        s.orgs[3].collection_id.clone(),
        vec![
            selection(&s.owners[3], false, true),
            selection(&s.members[3], true, false),
        ],
        true,
        false,
    )];
    check_collections(&s.get(1, &collections_path(&org))?, &org, &expected)?;
    admin_collection_users(s, true)?;
    let value = s.get(1, &collections_path(&s.orgs[4].id))?;
    require(
        rows(&value)?.is_empty(),
        "Restricted custom actor saw unassigned collections",
    )?;
    Ok(())
}
fn admin_collection_users(s: &mut Suite, confirmed: bool) -> Result<(), Error> {
    let org = s.orgs[2].id.clone();
    let mut users = vec![
        selection(&s.owners[2], false, true),
        selection(&s.invited_members[1], true, false),
    ];
    if confirmed {
        users.push(selection(&s.members[2], false, true));
    }
    // Implicit full access requires Confirmed; a direct invited grant remains.
    // The invited Admin deliberately stays absent without a direct selection.
    let expected = vec![(s.orgs[2].collection_id.clone(), users, false, true)];
    check_collections(&s.get(0, &collections_path(&org))?, &org, &expected)
}
fn actors(s: &mut Suite) -> Result<(), Error> {
    s.statuses(0, 0, [200; 3])?;
    s.statuses(1, 0, [401; 3])?;
    s.statuses(1, 2, [200; 3])?;
    s.statuses(1, 3, [404, 200, 404])?;
    s.statuses(1, 4, [404, 200, 404])?;
    s.statuses(1, 5, [200; 3])?;
    for org in [0, 2, 5] {
        let v = s.get(0, &groups_path(&s.orgs[org].id))?;
        check_empty_groups(&v)?;
    }
    s.change_status(2, "revoke")?;
    s.statuses(1, 2, [401; 3])?;
    admin_collection_users(s, false)?;
    s.change_status(2, "restore")?;
    s.statuses(1, 2, [200; 3])?;
    admin_collection_users(s, true)?;
    s.change_status(0, "revoke")?;
    main_collection_users(s)?;
    s.change_status(0, "restore")?;
    main_collection_users(s)?;
    Ok(())
}
fn transport(s: &mut Suite) -> Result<(), Error> {
    let id = s.orgs[0].id.clone();
    let foreign = s.orgs[1].id.clone();
    let token = s.token(0);
    for query in [
        String::new(),
        "?organizationId=".into(),
        "?organizationId=not-a-uuid".into(),
        format!("?organizationId={}", Uuid::new_v4()),
        format!("?organizationId={foreign}"),
        format!("?organizationId={}", id.to_uppercase()),
        format!("?organizationId={foreign}&organizationId={id}"),
    ] {
        s.http
            .raw(
                Method::GET,
                &format!("/api/ciphers/organization-details{query}"),
                Some(&token),
                None,
            )?
            .rejected(401)?;
    }
    for query in [
        format!("?organizationId={id}&organizationId={foreign}"),
        format!("?%6FrganizationId={id}"),
        format!("?organizationId=%{:02x}{}", id.as_bytes()[0], &id[1..]),
        format!("?.organizationId={id}"),
        format!("?organizationId[value]={id}"),
        format!("?organizationId={id}&ignored=true"),
    ] {
        let value = s.http.json(
            Method::GET,
            &format!("/api/ciphers/organization-details{query}"),
            Some(&token),
            None,
        )?;
        require(
            rows(&value)?.len() == 1,
            "Organization query selection differed",
        )?;
    }
    for suffix in ["collections/details", "groups"] {
        for org in [
            "not-a-uuid".to_owned(),
            Uuid::new_v4().to_string(),
            foreign.clone(),
            id.to_uppercase(),
        ] {
            s.http
                .raw(
                    Method::GET,
                    &format!("/api/organizations/{org}/{suffix}"),
                    Some(&token),
                    None,
                )?
                .rejected(401)?;
        }
        let before = s.http.json(
            Method::GET,
            &format!("/api/organizations/{id}/{suffix}"),
            Some(&token),
            None,
        )?;
        for query in [
            "?includeAccessDetails=true",
            "?includeAccessDetails=false",
            "?includeAccessDetails=invalid",
            "?ignored=true",
        ] {
            require(
                s.http.json(
                    Method::GET,
                    &format!("/api/organizations/{id}/{suffix}{query}"),
                    Some(&token),
                    None,
                )? == before,
                "Ignored organization read query changed projection",
            )?;
        }
    }
    Ok(())
}
fn preserved(s: &mut Suite) -> Result<Vec<Value>, Error> {
    let mut out = Vec::new();
    for actor in 0..2 {
        let id = s.accounts[actor].cipher_id.clone();
        out.push(s.get(actor, &format!("/api/ciphers/{id}"))?);
        out.push(s.get(actor, "/api/accounts/keys")?);
        out.push(s.get(actor, "/api/accounts/revision-date")?);
    }
    Ok(out)
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    let before = preserved(s)?;
    s.statuses(0, 0, [200; 3])?;
    s.statuses(1, 5, [200; 3])?;
    s.statuses(1, 3, [404, 200, 404])?;
    require(
        preserved(s)? == before,
        "Organization reads changed ciphertext keys or revisions",
    )?;
    for actor in 0..2 {
        let proof = s.accounts[actor].refresh.clone();
        let value = s.http.refresh(&proof)?;
        let profile = s.http.json(
            Method::GET,
            "/api/accounts/profile",
            Some(text(&value["access_token"])?),
            None,
        )?;
        require(
            profile["id"] == s.accounts[actor].user_id,
            "Organization reads changed retained session owner",
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
    for actor in [0, 1, 0, 0, 0, 0, 0] {
        orgs.push(create_organization(&mut http.owner, &accounts[actor])?);
    }
    let name = fixture::encrypt(b"Unassigned collection", &orgs[0].key)
        .map_err(|_| Error("Web read collection encryption failed"))?;
    let extra = http.owner.json(
        Method::POST,
        &format!("/api/organizations/{}/collections", orgs[0].id),
        &accounts[0].token,
        Some(&json!({"name":name,"groups":[],"users":[]})),
    )?;
    let mut s = Suite {
        http,
        accounts,
        orgs,
        members: vec![String::new(); 7],
        owners: vec![String::new(); 7],
        extra_collection: text(&extra["id"])?.to_owned(),
        invited_members: Vec::new(),
        shared: Vec::new(),
        passed: Vec::new(),
        receipt: receipt_file("BW_WEB_ORGANIZATION_READS_RECEIPT")?,
        finished: false,
    };
    for (org, role, ro, full) in [
        (0, 2, false, false),
        (2, 1, false, false),
        (3, 3, true, false),
        (4, 4, false, false),
        (5, 4, false, true),
    ] {
        let grant = if org == 0 || org == 3 {
            json!([{"id":s.orgs[org].collection_id,"readOnly":ro,"hidePasswords":false,"manage":false}])
        } else {
            json!([])
        };
        let permissions = if full {
            json!({"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true})
        } else {
            json!({})
        };
        let token = s.token(0);
        s.http.raw(Method::POST,&format!("/api/organizations/{}/users/invite",s.orgs[org].id),Some(&token),Some(&json!({"emails":[s.accounts[1].fixture["email"]],"type":role,"collections":grant,"groups":[],"permissions":permissions})))?.status(200)?;
        let rows = s.get(
            0,
            &format!(
                "/api/organizations/{}/users?includeCollections=true&includeGroups=true",
                s.orgs[org].id
            ),
        )?;
        let rows = rows["data"]
            .as_array()
            .ok_or(Error("Web read member fixture missing"))?;
        for row in rows {
            if row["userId"] == s.accounts[0].user_id {
                s.owners[org] = text(&row["id"])?.to_owned();
            }
            if row["userId"] == s.accounts[1].user_id {
                s.members[org] = text(&row["id"])?.to_owned();
                require(
                    row["status"] == 1,
                    "Registered web read fixture was not accepted",
                )?;
            }
        }
        require(
            !s.owners[org].is_empty() && !s.members[org].is_empty(),
            "Web read membership fixture incomplete",
        )?;
        if org != 0 && org != 2 {
            s.confirm(org)?;
        }
    }
    // Ordinary no-SMTP invitations create legitimate passwordless placeholders.
    // No registration or direct storage mutation is used for these target states.
    let emails = [
        format!("invited-admin-{}@example.test", Uuid::new_v4()),
        format!("invited-user-{}@example.test", Uuid::new_v4()),
    ];
    for (index, email) in emails.iter().enumerate() {
        let grants = if index == 0 {
            json!([])
        } else {
            json!([{"id":s.orgs[2].collection_id,"readOnly":true,"hidePasswords":false,"manage":false}])
        };
        let token = s.token(0);
        s.http.raw(Method::POST, &format!("/api/organizations/{}/users/invite",s.orgs[2].id), Some(&token), Some(&json!({"emails":[email],"type":if index==0 {1} else {2},"collections":grants,"groups":[],"permissions":{}})))?.status(200)?;
    }
    let members = s.get(
        0,
        &format!(
            "/api/organizations/{}/users?includeCollections=true",
            s.orgs[2].id
        ),
    )?;
    for (index, email) in emails.iter().enumerate() {
        let rows = members["data"]
            .as_array()
            .ok_or(Error("Invited target list missing"))?;
        let row = rows
            .iter()
            .find(|r| r["email"] == *email)
            .ok_or(Error("Invited target omitted"))?;
        require(
            row["status"] == 0 && row["type"] == if index == 0 { 1 } else { 2 },
            "Invited target status/role differed",
        )?;
        s.invited_members.push(text(&row["id"])?.to_owned());
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
    require(
        s.http.owner.logins == 2 && s.http.refreshes == 2 && s.passed.len() == CASE_COUNT,
        "Web read authentication budget differed",
    )?;
    if s.http.owner.requests != HTTP_REQUEST_COUNT {
        eprintln!(
            "Web organization read HTTP budget expected {HTTP_REQUEST_COUNT}, actual {}",
            s.http.owner.requests
        );
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT,
        "Web organization read HTTP budget differed",
    )?;
    s.finished = true;
    s.receipt("passed")?;
    Ok(())
}
