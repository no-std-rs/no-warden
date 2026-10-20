//! Independently authored MIT/Apache-2.0 single-member confirmation contracts.
//! No SMTP, bulk confirmation, shared-cipher writes or transport trace is implied.
use crate::{
    fixture,
    organization_collections::{self, create_organization},
    organization_invites,
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
// Setup38 + guards37 + validation30 + confirmation26 + scope26 + roles32 + preservation24.
pub const HTTP_REQUEST_COUNT: usize = 213;
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_confirmation_authentication_and_json_guards",
        guards,
    ),
    (
        "organization_confirmation_key_scope_and_state_order",
        validation,
    ),
    (
        "organization_confirmation_rsa_delivery_and_selective_collections",
        confirm,
    ),
    (
        "organization_confirmation_recipient_scope_and_read_preservation",
        recipient_guards,
    ),
    (
        "organization_confirmation_admin_role_and_opaque_key_boundaries",
        roles,
    ),
    (
        "organization_confirmation_preserved_personal_keys_and_sessions",
        preservation,
    ),
];
const EMPTY_KEY: &str = "Key or UserId is not set, unable to process request";
const MISSING: &str = "The specified user isn't a member of the organization";
const STATE: &str = "User in invalid state";
const OWNER_ONLY: &str = "Only Owners can confirm Managers, Admins or Owners";
const OPAQUE_KEY: &str = " \0future organization key 雪 ";
pub(crate) const HIDDEN_NAME: &str = "Unassigned collection Ω\0";

struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, Error> {
        if self.status != expected {
            eprintln!(
                "Confirmation status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Confirmation HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Confirmation private response was not JSON"))
    }
    fn empty(self) -> Result<(), Error> {
        require(
            self.status(200)?.bytes.is_empty(),
            "Confirmation success was not empty",
        )
    }
    fn rejected(self, status: u16) -> Result<(), Error> {
        let reply = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.bytes) {
            require(
                ["access_token", "refresh_token", "key", "privateKey"]
                    .iter()
                    .all(|f| value.get(f).is_none()),
                "Rejected confirmation exposed authority",
            )?;
        }
        Ok(())
    }
    fn error(self, expected: &str) -> Result<(), Error> {
        let value = self.status(400)?.json()?;
        require(
            value["message"] == expected,
            "Confirmation rejection message differed",
        )
    }
}
struct Http {
    owner: OwnerHttp,
    client: Client,
    refreshes: usize,
}
impl Http {
    fn read(response: reqwest::blocking::Response) -> Result<Reply, Error> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Confirmation private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Confirmation private capture exceeded bound",
        )?;
        Ok(Reply { status, bytes })
    }
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
        media: Option<&str>,
    ) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.owner.server));
        if let Some(token) = token {
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
                .map_err(|_| Error("Confirmation HTTP request failed"))?,
        )
    }
    fn json(&mut self, path: &str, token: &str) -> Result<Value, Error> {
        self.raw(Method::GET, path, Some(token), None, None)?
            .status(200)?
            .json()
    }
    fn post(&mut self, path: &str, token: &str, body: &Value) -> Result<Reply, Error> {
        self.raw(
            Method::POST,
            path,
            Some(token),
            Some(body.to_string().as_bytes()),
            Some("application/json"),
        )
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
                .map_err(|_| Error("Confirmation refresh failed"))?,
        )?
        .status(200)?
        .json()
    }
}
pub(crate) fn path(org: &str, member: &str) -> String {
    format!("/api/organizations/{org}/users/{member}/confirm")
}
pub(crate) fn invitation(email: &str, role: i64, collection: Option<&str>) -> Value {
    let collections = collection.map_or_else(
        || json!([]),
        |id| json!([{"id":id,"readOnly":true,"hidePasswords":true,"manage":true}]),
    );
    json!({"emails":[email],"groups":[],"type":role,"collections":collections})
}
pub(crate) fn hidden_collection(
    http: &mut OwnerHttp,
    account: &Account,
    org: &Organization,
) -> Result<Value, Error> {
    let encrypted = fixture::encrypt(HIDDEN_NAME.as_bytes(), &org.key)
        .map_err(|_| Error("Hidden collection encryption failed"))?;
    http.json(
        Method::POST,
        &organization_collections::path(&org.id),
        &account.token,
        Some(&json!({"name":encrypted,"groups":[],"users":[]})),
    )
}
pub(crate) fn member_row(
    http: &mut OwnerHttp,
    org: &str,
    token: &str,
    email: &str,
) -> Result<Value, Error> {
    let value = http.json(
        Method::GET,
        &organization_invites::member_path(org),
        token,
        None,
    )?;
    Ok(organization_invites::member(&value, email)?.clone())
}
pub(crate) fn member_after(before: &Value, after: &Value, status: i64) -> Result<(), Error> {
    let mut expected = before.clone();
    expected["status"] = json!(status);
    require(
        *after == expected,
        "Confirmation changed membership identity, role or grants",
    )
}
fn array(value: &Value) -> Result<&[Value], Error> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(Error("Confirmation array missing"))
}
pub(crate) fn org_in<'a>(
    profile: &'a Value,
    field: &str,
    id: &str,
) -> Result<Option<&'a Value>, Error> {
    let rows = array(&profile[field])?;
    let matches = rows.iter().filter(|r| r["id"] == id).collect::<Vec<_>>();
    require(
        matches.len() <= 1,
        "Confirmation profile duplicated organization",
    )?;
    Ok(matches.first().copied())
}
pub(crate) fn selective(
    value: &Value,
    org: &Organization,
    hidden: &str,
    sync: bool,
) -> Result<(), Error> {
    let rows = if sync {
        array(&value["collections"])?
    } else {
        require(
            value["object"] == "list" && value["continuationToken"].is_null(),
            "Recipient collection list envelope differed",
        )?;
        array(&value["data"])?
    };
    let selected = rows
        .iter()
        .filter(|v| v["organizationId"] == org.id)
        .collect::<Vec<_>>();
    require(
        selected.len() == 1
            && selected[0]["id"] == org.collection_id
            && !rows.iter().any(|r| r["id"] == hidden),
        "Recipient gained unassigned collection or lost grant",
    )?;
    let row = selected[0];
    require(
        row.as_object()
            .is_some_and(|o| o.len() == if sync { 10 } else { 7 })
            && row["name"] == org.body["collectionName"]
            && row["externalId"].is_null()
            && row["type"] == 0
            && row["defaultUserCollectionEmail"].is_null()
            && row["object"]
                == if sync {
                    "collectionDetails"
                } else {
                    "collection"
                },
        "Recipient collection projection differed",
    )?;
    if sync {
        require(
            row["readOnly"] == true && row["hidePasswords"] == true && row["manage"] == false,
            "Ordinary recipient permission flags differed",
        )?;
    }
    let plain = fixture::decrypt(text(&row["name"])?, &org.key)
        .map_err(|_| Error("Recipient collection MAC/decryption failed"))?;
    require(
        plain == organization_owner::COLLECTION_NAME.as_bytes(),
        "Recipient collection plaintext differed",
    )
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    hidden: String,
    rows: Vec<Value>,
    target_email: String,
    manager_email: String,
    stub_email: String,
    personal: Vec<Value>,
    revisions: Vec<Value>,
    stable: Value,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":4,"registrationHttpRequests":8,"successfulConfirmationClaimed":true,"smtpEnabled":false,"capturedRouteTrace":false}),
        )
    }
    fn stable_snapshot(&mut self) -> Result<Value, Error> {
        let profile = self
            .http
            .json("/api/accounts/profile", &self.accounts[0].token)?;
        let mut orgs = Vec::new();
        let mut collections = Vec::new();
        for i in 0..3 {
            let token = &self.accounts[usize::from(i == 2)].token;
            orgs.push(
                self.http
                    .json(&format!("/api/organizations/{}", self.orgs[i].id), token)?,
            );
            collections.push(
                self.http
                    .json(&organization_collections::path(&self.orgs[i].id), token)?,
            );
        }
        let foreign = self.http.json(
            &organization_invites::member_path(&self.orgs[2].id),
            &self.accounts[1].token,
        )?;
        Ok(
            json!({"ownerOrganizations":profile["organizations"],"ownerOrganizationsNew":profile["organizationsNew"],"orgs":orgs,"collections":collections,"foreignMembers":foreign}),
        )
    }
    fn readonly(&mut self) -> Result<(), Error> {
        for i in 0..2 {
            require(
                self.http.owner.personal(&self.accounts[i].token)? == self.personal[i]
                    && self.http.owner.revision(&self.accounts[i].token)? == self.revisions[i],
                "Confirmation changed personal vault, credentials, settings or unexpected revision",
            )?;
        }
        require(
            self.stable_snapshot()? == self.stable,
            "Confirmation changed owner/foreign organizations or collection definitions",
        )
    }
    fn row(&mut self, org: usize, email: &str) -> Result<Value, Error> {
        member_row(
            &mut self.http.owner,
            &self.orgs[org].id,
            &self.accounts[0].token,
            email,
        )
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let member = text(&s.rows[0]["id"])?.to_owned();
    let p = path(&org, &member);
    let owner = s.accounts[0].token.clone();
    let recipient = s.accounts[1].token.clone();
    for token in [
        None,
        Some("invalid-confirmation-bearer"),
        Some(recipient.as_str()),
    ] {
        s.http
            .raw(Method::POST, &p, token, Some(b"{"), None)?
            .rejected(401)?;
    }
    for (p, status) in [
        (path("bad.id", &member), 401),
        (
            format!("{}?organizationId={org}", path("bad.id", &member)),
            422,
        ),
        (path(&org, "bad.id"), 422),
        (format!("{}?memberId={member}", path(&org, "bad.id")), 422),
    ] {
        s.http
            .raw(Method::POST, &p, Some(&owner), Some(b"{"), None)?
            .rejected(status)?;
    }
    let invalids: Vec<(Vec<u8>, u16)> = vec![
        (b"{".to_vec(), 400),
        (b"[]".to_vec(), 422),
        (b"[null]".to_vec(), 422),
        (b"[null,null,0]".to_vec(), 400),
        (br#"{"id":1,"key":"key"}"#.to_vec(), 422),
        (br#"{"key":false}"#.to_vec(), 422),
        (br#"{"key":"a","key":"b"}"#.to_vec(), 422),
        (b"{\"key\":\"a\",\"ignored\":\"\xff\"}".to_vec(), 400),
    ];
    for (body, status) in invalids {
        s.http
            .raw(
                Method::POST,
                &p,
                Some(&owner),
                Some(&body),
                Some("application/json"),
            )?
            .rejected(status)?;
    }
    for method in [Method::GET, Method::PUT, Method::DELETE, Method::PATCH] {
        s.http
            .raw(method, &p, Some(&owner), None, None)?
            .rejected(404)?;
    }
    s.readonly()
}
fn validation(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let member = text(&s.rows[0]["id"])?.to_owned();
    let token = s.accounts[0].token.clone();
    for body in [
        json!({}),
        json!({"key":null}),
        json!({"key":""}),
        json!({"Key":"ignored"}),
        json!([null, null]),
    ] {
        s.http
            .post(&path(&org, &member), &token, &body)?
            .error(EMPTY_KEY)?;
    }
    let absent = Uuid::new_v4().to_string();
    s.http
        .post(&path(&org, &absent), &token, &json!({}))?
        .error(EMPTY_KEY)?;
    s.http
        .post(&path(&org, &absent), &token, &json!({"key":"opaque"}))?
        .error(MISSING)?;
    s.http
        .post(
            &path(&org, text(&s.rows[1]["id"])?),
            &token,
            &json!({"key":"opaque"}),
        )?
        .error(MISSING)?;
    let owner = member_row(
        &mut s.http.owner,
        &org,
        &token,
        text(&s.accounts[0].fixture["email"])?,
    )?;
    s.http
        .post(
            &path(&org, text(&owner["id"])?),
            &token,
            &json!({"key":"opaque"}),
        )?
        .error(STATE)?;
    let stub = s.row(0, &s.stub_email.clone())?;
    s.http
        .post(
            &path(&org, text(&stub["id"])?),
            &token,
            &json!({"key":"opaque"}),
        )?
        .error(STATE)?;
    s.readonly()
}
fn confirm(s: &mut Suite) -> Result<(), Error> {
    let org = &s.orgs[0];
    let recipient = &s.accounts[1];
    let before = s.http.json("/api/accounts/profile", &recipient.token)?;
    require(
        org_in(&before, "organizations", &org.id)?.is_none()
            && org_in(&before, "organizationsNew", &org.id)?.is_some_and(|o| o["key"] == ""),
        "Accepted recipient already received confirmed key",
    )?;
    let before_collections = s.http.json("/api/collections", &recipient.token)?;
    require(
        !array(&before_collections["data"])?
            .iter()
            .any(|c| c["organizationId"] == org.id),
        "Accepted recipient saw collection before confirmation",
    )?;
    let wrapped = fixture::organization_key_for_account(&recipient.fixture, &org.key)
        .map_err(|_| Error("Recipient RSA delivery fixture failed"))?;
    s.http
        .post(
            &path(&org.id, text(&s.rows[0]["id"])?),
            &s.accounts[0].token,
            &json!({"id":"ignored-not-a-UUID","key":wrapped,"defaultUserCollectionName":"ignored","type":0,"accessAll":true,"userId":"ignored-owner"}),
        )?
        .empty()?;
    let after = s.row(
        0,
        text(&s.accounts[1].fixture["email"])?.to_owned().as_str(),
    )?;
    member_after(&s.rows[0], &after, 2)?;
    let revision = s.http.owner.revision(&s.accounts[1].token)?;
    require(
        revision != s.revisions[1],
        "Confirmation did not advance recipient revision",
    )?;
    s.revisions[1] = revision;
    let profile = s.http.json("/api/accounts/profile", &s.accounts[1].token)?;
    require(
        org_in(&profile, "organizations", &s.orgs[0].id)?.is_some_and(|o| o["key"] == wrapped)
            && org_in(&profile, "organizations", &s.orgs[1].id)?.is_none()
            && org_in(&profile, "organizationsNew", &s.orgs[1].id)?.is_some_and(|o| o["key"] == ""),
        "Confirmation delivered wrong organization key or confirmed sibling",
    )?;
    let collections = s.http.json("/api/collections", &s.accounts[1].token)?;
    selective(&collections, &s.orgs[0], &s.hidden, false)?;
    let sync = s.http.json("/api/sync", &s.accounts[1].token)?;
    selective(&sync, &s.orgs[0], &s.hidden, true)?;
    s.readonly()
}
fn recipient_guards(s: &mut Suite) -> Result<(), Error> {
    let token = s.accounts[1].token.clone();
    let org = &s.orgs[0];
    for p in [
        format!("/api/organizations/{}", org.id),
        organization_collections::path(&org.id),
        organization_collections::details_path(&org.id, &org.collection_id),
        organization_invites::member_path(&org.id),
        format!(
            "/api/organizations/{}/users/{}",
            org.id,
            text(&s.rows[0]["id"])?
        ),
    ] {
        s.http
            .raw(Method::GET, &p, Some(&token), Some(b"ignored"), None)?
            .rejected(401)?;
    }
    s.http
        .post(
            &path(&org.id, text(&s.rows[0]["id"])?),
            &token,
            &json!({"key":"opaque"}),
        )?
        .rejected(401)?;
    s.http
        .post(
            &path(&s.orgs[2].id, text(&s.rows[0]["id"])?),
            &s.accounts[0].token,
            &json!({"key":"opaque"}),
        )?
        .rejected(401)?;
    let p = format!(
        "{}?organizationId={}&memberId={}",
        path(&org.id, text(&s.rows[0]["id"])?),
        s.orgs[2].id,
        text(&s.rows[1]["id"])?
    );
    s.http
        .post(&p, &s.accounts[0].token, &json!({"key":"opaque"}))?
        .error(STATE)?;
    s.readonly()
}
fn roles(s: &mut Suite) -> Result<(), Error> {
    let token = s.accounts[0].token.clone();
    let email = text(&s.accounts[1].fixture["email"])?.to_owned();
    let p = path(&s.orgs[1].id, text(&s.rows[1]["id"])?);
    s.http
        .raw(
            Method::POST,
            &format!("{p}?ignored=true"),
            Some(&token),
            Some(
                json!({"id":"ignored","key":OPAQUE_KEY})
                    .to_string()
                    .as_bytes(),
            ),
            Some("text/plain"),
        )?
        .empty()?;
    let after = s.row(1, &email)?;
    member_after(&s.rows[1], &after, 2)?;
    let revision = s.http.owner.revision(&s.accounts[1].token)?;
    require(
        revision != s.revisions[1],
        "Opaque confirmation did not advance recipient revision",
    )?;
    s.revisions[1] = revision;
    let profile = s.http.json("/api/accounts/profile", &s.accounts[1].token)?;
    require(
        org_in(&profile, "organizations", &s.orgs[1].id)?.is_some_and(|o| o["key"] == OPAQUE_KEY),
        "Opaque confirmation key was normalized or discarded",
    )?;
    let user = s.row(1, &s.target_email.clone())?;
    let manager = s.row(1, &s.manager_email.clone())?;
    let owner = s.row(
        1,
        text(&s.accounts[0].fixture["email"])?.to_owned().as_str(),
    )?;
    for row in [&manager, &owner, &s.rows[1]] {
        s.http
            .post(
                &path(&s.orgs[1].id, text(&row["id"])?),
                &s.accounts[1].token,
                &json!({"key":"admin-attempt"}),
            )?
            .error(OWNER_ONLY)?;
    }
    s.http
        .raw(
            Method::POST,
            &path(&s.orgs[1].id, text(&user["id"])?),
            Some(&s.accounts[1].token),
            Some(
                json!([null, "admin-delivered-opaque-user-key"])
                    .to_string()
                    .as_bytes(),
            ),
            None,
        )?
        .empty()?;
    let after = s.row(1, &s.target_email.clone())?;
    member_after(&user, &after, 2)?;
    let after = s.row(1, &s.manager_email.clone())?;
    require(after == manager, "Denied Admin changed Manager membership")?;
    s.http
        .post(&p, &token, &json!({"key":"repeat"}))?
        .error(STATE)?;
    s.readonly()
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for i in 0..2 {
        let refreshed = s.http.refresh(&s.accounts[i].refresh)?;
        let token = text(&refreshed["access_token"])?;
        let profile = s.http.json("/api/accounts/profile", token)?;
        require(
            profile["id"] == s.accounts[i].user_id,
            "Confirmation refresh changed owner",
        )?;
        let cipher = s
            .http
            .json(&format!("/api/ciphers/{}", s.accounts[i].cipher_id), token)?;
        let key = fixture::fixture_user_key(&s.accounts[i].fixture, &s.accounts[i].password)
            .map_err(|_| Error("Confirmation personal key unwrap failed"))?;
        let plain = fixture::decrypt(text(&cipher["notes"])?, &key)
            .map_err(|_| Error("Confirmation personal note MAC failed"))?;
        require(
            plain == organization_owner::NOTE.as_bytes(),
            "Confirmation changed personal plaintext",
        )?;
    }
    s.readonly()
}
pub fn run() -> Result<(), Error> {
    let mut http = Http {
        owner: OwnerHttp::new()?,
        client: http_client()?,
        refreshes: 0,
    };
    let a = organization_owner::seed(&mut http.owner)?;
    let b = organization_owner::seed(&mut http.owner)?;
    let org = create_organization(&mut http.owner, &a)?;
    let sibling = create_organization(&mut http.owner, &a)?;
    let foreign = create_organization(&mut http.owner, &b)?;
    let hidden = hidden_collection(&mut http.owner, &a, &org)?;
    organization_invites::invite_owner(
        &mut http.owner,
        &org.id,
        &a.token,
        &invitation(text(&b.fixture["email"])?, 2, Some(&org.collection_id)),
    )?;
    organization_invites::invite_owner(
        &mut http.owner,
        &sibling.id,
        &a.token,
        &invitation(text(&b.fixture["email"])?, 1, None),
    )?;
    let mut emails = Vec::new();
    for role in [2, 3] {
        let email = format!("confirmation-role-{}@example.test", Uuid::new_v4());
        let fixture = fixture::registration(&email, &Uuid::new_v4().to_string(), 600000)
            .map_err(|_| Error("Confirmation role fixture failed"))?;
        fixture::register_modern_fixture(&http.owner.server, &fixture)
            .map_err(|_| Error("Confirmation role registration failed"))?;
        organization_invites::invite_owner(
            &mut http.owner,
            &sibling.id,
            &a.token,
            &invitation(&email, role, None),
        )?;
        emails.push(email);
    }
    let stub_email = format!("confirmation-invited-{}@example.test", Uuid::new_v4());
    organization_invites::invite_owner(
        &mut http.owner,
        &org.id,
        &a.token,
        &invitation(&stub_email, 2, None),
    )?;
    let rows = vec![
        member_row(
            &mut http.owner,
            &org.id,
            &a.token,
            text(&b.fixture["email"])?,
        )?,
        member_row(
            &mut http.owner,
            &sibling.id,
            &a.token,
            text(&b.fixture["email"])?,
        )?,
    ];
    require(
        rows[0]["status"] == 1 && rows[1]["status"] == 1,
        "Confirmation setup was not accepted",
    )?;
    let mut s = Suite {
        http,
        accounts: vec![a, b],
        orgs: vec![org, sibling, foreign],
        hidden: text(&hidden["id"])?.to_owned(),
        rows,
        target_email: emails[0].clone(),
        manager_email: emails[1].clone(),
        stub_email,
        personal: Vec::new(),
        revisions: Vec::new(),
        stable: Value::Null,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_CONFIRMATION_RECEIPT")?,
        finished: false,
    };
    for account in &s.accounts {
        s.personal.push(s.http.owner.personal(&account.token)?);
        s.revisions.push(s.http.owner.revision(&account.token)?);
    }
    s.stable = s.stable_snapshot()?;
    s.receipt("running")?;
    for (name, case) in CASES {
        eprintln!("Organization confirmation case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 2
            && s.passed.len() == CASE_COUNT,
        "Confirmation fixture budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-confirmation: {CASE_COUNT} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recipient_projection_rejects_unassigned_collection_and_manager_escalation() {
        let key = [7; 64];
        let encrypted =
            fixture::encrypt(organization_owner::COLLECTION_NAME.as_bytes(), &key).unwrap();
        let org = Organization {
            body: json!({"collectionName":encrypted}),
            key,
            id: Uuid::new_v4().to_string(),
            collection_id: Uuid::new_v4().to_string(),
        };
        let row = json!({"id":org.collection_id,"organizationId":org.id,"name":encrypted,"externalId":null,"type":0,"defaultUserCollectionEmail":null,"object":"collectionDetails","readOnly":true,"hidePasswords":true,"manage":false});
        let mut value = json!({"collections":[row]});
        assert!(selective(&value, &org, "hidden", true).is_ok());
        value["collections"][0]["manage"] = json!(true);
        assert!(selective(&value, &org, "hidden", true).is_err());
        value["collections"][0]["manage"] = json!(false);
        let mut hidden = value["collections"][0].clone();
        hidden["id"] = json!("hidden");
        value["collections"].as_array_mut().unwrap().push(hidden);
        assert!(selective(&value, &org, "hidden", true).is_err());
    }
}
