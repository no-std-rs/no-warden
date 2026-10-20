//! Independently authored MIT/Apache-2.0 bulk-member confirmation contracts.
//! Direct HTTP setup is distinct from actual recipient CLI decryption.
use crate::{
    fixture,
    organization_collections::{self, create_organization},
    organization_confirmations as single, organization_invites,
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
// Setup48 + guards40 + empty27 + ordered25 + prefix21 + roles26 + preservation24.
pub const HTTP_REQUEST_COUNT: usize = 211;
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_bulk_confirmation_authentication_and_whole_batch_json_guards",
        guards,
    ),
    (
        "organization_bulk_confirmation_empty_batches_and_exact_list_projection",
        empty,
    ),
    (
        "organization_bulk_confirmation_ordered_errors_and_rsa_delivery",
        ordered,
    ),
    (
        "organization_bulk_confirmation_missing_id_preserves_committed_prefix",
        prefix,
    ),
    (
        "organization_bulk_confirmation_admin_hierarchy_and_sibling_isolation",
        roles,
    ),
    (
        "organization_bulk_confirmation_preserved_personal_keys_and_sessions",
        preservation,
    ),
];
const EMPTY_KEY: &str = "Key or UserId is not set, unable to process request";
const MISSING: &str = "The specified user isn't a member of the organization";
const STATE: &str = "User in invalid state";
const OWNER_ONLY: &str = "Only Owners can confirm Managers, Admins or Owners";
const OPAQUE_KEY: &str = " \0bulk sibling key 雪 ";
pub(crate) fn path(org: &str) -> String {
    format!("/api/organizations/{org}/users/confirm")
}
pub(crate) fn result(value: &Value, expected: &[(&str, &str)]) -> Result<(), Error> {
    let rows=expected.iter().map(|(id,error)|json!({"object":"OrganizationBulkConfirmResponseModel","id":id,"error":error})).collect::<Vec<_>>();
    require(
        *value == json!({"object":"list","data":rows,"continuationToken":null}),
        "Bulk confirmation ordered result projection differed",
    )
}
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

struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    hidden: String,
    rows: Vec<Value>,
    emails: Vec<String>,
    personal: Vec<Value>,
    revisions: Vec<Value>,
    stable: Value,
    primary_key: String,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":5,"registrationHttpRequests":10,"bulkSetupViaDirectHttp":true,"cliBulkCallerClaimed":false,"capturedRouteTrace":false,"smtpEnabled":false}),
        )
    }
    fn row(&mut self, org: usize, email: &str) -> Result<Value, Error> {
        single::member_row(
            &mut self.http.owner,
            &self.orgs[org].id,
            &self.accounts[0].token,
            email,
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
            json!({"ownerOrganizations":profile["organizations"],"ownerOrganizationsNew":profile["organizationsNew"],"organizations":orgs,"collections":collections,"foreignMembers":foreign}),
        )
    }
    fn readonly(&mut self) -> Result<(), Error> {
        for i in 0..2 {
            require(
                self.http.owner.personal(&self.accounts[i].token)? == self.personal[i]
                    && self.http.owner.revision(&self.accounts[i].token)? == self.revisions[i],
                "Bulk confirmation changed personal authority, payloads or unexpected revision",
            )?;
        }
        require(
            self.stable_snapshot()? == self.stable,
            "Bulk confirmation changed owner/foreign organizations or collection definitions",
        )
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let owner = s.accounts[0].token.clone();
    let recipient = s.accounts[1].token.clone();
    let p = path(&org);
    for token in [None, Some("invalid-bulk-bearer"), Some(recipient.as_str())] {
        s.http
            .raw(Method::POST, &p, token, Some(b"{"), None)?
            .rejected(401)?;
    }
    for (p, status) in [
        (path("bad.id"), 401),
        (format!("{}?organizationId={org}", path("bad.id")), 422),
    ] {
        s.http
            .raw(Method::POST, &p, Some(&owner), Some(b"{"), None)?
            .rejected(status)?;
    }
    let first = json!({"id":s.rows[0]["id"],"key":"must-not-commit"});
    let invalids: Vec<(Vec<u8>, u16)> = vec![
        (b"{".to_vec(), 400),
        (b"[]".to_vec(), 422),
        (b"[null,0]".to_vec(), 400),
        (br#"{"keys":false}"#.to_vec(), 422),
        (br#"{"keys":[null]}"#.to_vec(), 422),
        (br#"{"keys":[[]]}"#.to_vec(), 422),
        (br#"{"keys":[[null]]}"#.to_vec(), 422),
        (br#"{"keys":[[null,null,0]]}"#.to_vec(), 400),
        (br#"{"keys":[{"id":1,"key":"k"}]}"#.to_vec(), 422),
        (br#"{"keys":[{"id":"raw","key":false}]}"#.to_vec(), 422),
        (br#"{"keys":[],"keys":[]}"#.to_vec(), 422),
        (br#"{"keys":[{"id":"a","id":"b","key":"k"}]}"#.to_vec(), 422),
        (b"{\"keys\":[],\"ignored\":\"\xff\"}".to_vec(), 400),
        (
            json!({"keys":[first,{"id":"later","key":false}]})
                .to_string()
                .into_bytes(),
            422,
        ),
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
    // GET binds the existing generic member-details route; the literal is not a UUID.
    s.http
        .raw(Method::GET, &p, None, None, None)?
        .rejected(401)?;
    s.http
        .raw(Method::GET, &p, Some(&owner), None, None)?
        .rejected(422)?;
    s.http
        .raw(Method::PATCH, &p, Some(&owner), None, None)?
        .rejected(404)?;
    s.readonly()
}
fn empty(s: &mut Suite) -> Result<(), Error> {
    let p = path(&s.orgs[0].id);
    let token = s.accounts[0].token.clone();
    for body in [
        json!({}),
        json!({"keys":null}),
        json!({"keys":[]}),
        json!({"Keys":[{"id":"ignored"}]}),
        json!([null]),
        json!([[]]),
    ] {
        let v = s.http.post(&p, &token, &body)?.status(200)?.json()?;
        result(&v, &[])?;
    }
    for body in [json!({"keys":[{}]}), json!({"keys":[[null,"opaque"]]})] {
        s.http
            .post(&p, &token, &body)?
            .error("Member id is required")?;
    }
    let absent = Uuid::new_v4().to_string();
    let raw = "raw 雪\0";
    let body = json!({"keys":[{"id":"","key":"opaque"},{"id":raw,"key":"opaque"},{"id":absent,"key":null}]});
    let v = s.http.post(&p, &token, &body)?.status(200)?.json()?;
    result(&v, &[("", EMPTY_KEY), (raw, MISSING), (&absent, EMPTY_KEY)])?;
    s.readonly()
}
fn ordered(s: &mut Suite) -> Result<(), Error> {
    let org = &s.orgs[0];
    let b = &s.accounts[1];
    let wrapped = fixture::organization_key_for_account(&b.fixture, &org.key)
        .map_err(|_| Error("Bulk recipient RSA wrapping failed"))?;
    let id = text(&s.rows[0]["id"])?.to_owned();
    let foreign = text(&s.rows[8]["id"])?.to_owned();
    let stub = text(&s.rows[7]["id"])?.to_owned();
    let later = text(&s.rows[2]["id"])?.to_owned();
    let body = json!({"keys":[{"id":id,"key":wrapped,"ignored":true},{"id":id,"key":"repeat"},{"id":foreign,"key":"foreign"},{"id":"bad.id","key":"opaque"},{"id":"","key":"opaque"},{"id":stub,"key":"opaque"},{"id":later,"key":"later-success"}]});
    let v = s
        .http
        .post(&path(&org.id), &s.accounts[0].token, &body)?
        .status(200)?
        .json()?;
    result(
        &v,
        &[
            (&id, ""),
            (&id, STATE),
            (&foreign, MISSING),
            ("bad.id", MISSING),
            ("", EMPTY_KEY),
            (&stub, STATE),
            (&later, ""),
        ],
    )?;
    let row = s.row(
        0,
        text(&s.accounts[1].fixture["email"])?.to_owned().as_str(),
    )?;
    single::member_after(&s.rows[0], &row, 2)?;
    let row = s.row(0, &s.emails[0].clone())?;
    single::member_after(&s.rows[2], &row, 2)?;
    let revision = s.http.owner.revision(&s.accounts[1].token)?;
    require(
        revision != s.revisions[1],
        "Bulk RSA confirmation did not advance recipient revision",
    )?;
    s.revisions[1] = revision;
    let profile = s.http.json("/api/accounts/profile", &s.accounts[1].token)?;
    require(
        single::org_in(&profile, "organizations", &s.orgs[0].id)?
            .is_some_and(|o| o["key"] == wrapped)
            && single::org_in(&profile, "organizations", &s.orgs[1].id)?.is_none()
            && single::org_in(&profile, "organizationsNew", &s.orgs[1].id)?
                .is_some_and(|o| o["key"] == ""),
        "Bulk confirmation lost primary key or prematurely confirmed sibling",
    )?;
    s.primary_key = wrapped;
    let value = s.http.json("/api/collections", &s.accounts[1].token)?;
    single::selective(&value, &s.orgs[0], &s.hidden, false)?;
    let value = s.http.json("/api/sync", &s.accounts[1].token)?;
    single::selective(&value, &s.orgs[0], &s.hidden, true)?;
    s.readonly()
}
fn prefix(s: &mut Suite) -> Result<(), Error> {
    let first = text(&s.rows[3]["id"])?.to_owned();
    let later = text(&s.rows[4]["id"])?.to_owned();
    let body = json!({"keys":[{"id":first,"key":"committed-prefix"},{"id":null,"key":"abort"},{"id":later,"key":"skipped-suffix"}]});
    s.http
        .post(&path(&s.orgs[0].id), &s.accounts[0].token, &body)?
        .error("Member id is required")?;
    let row = s.row(0, &s.emails[1].clone())?;
    single::member_after(&s.rows[3], &row, 2)?;
    let row = s.row(0, &s.emails[2].clone())?;
    require(
        row == s.rows[4],
        "Bulk missing-ID abort did not skip suffix",
    )?;
    s.readonly()
}
fn roles(s: &mut Suite) -> Result<(), Error> {
    let b = text(&s.rows[1]["id"])?.to_owned();
    let p = path(&s.orgs[1].id);
    let value = s
        .http
        .raw(
            Method::POST,
            &format!("{p}?ignored=true"),
            Some(&s.accounts[0].token),
            Some(
                json!({"keys":[{"id":b,"key":OPAQUE_KEY}]})
                    .to_string()
                    .as_bytes(),
            ),
            Some("text/plain"),
        )?
        .status(200)?
        .json()?;
    result(&value, &[(&b, "")])?;
    let row = s.row(
        1,
        text(&s.accounts[1].fixture["email"])?.to_owned().as_str(),
    )?;
    single::member_after(&s.rows[1], &row, 2)?;
    let revision = s.http.owner.revision(&s.accounts[1].token)?;
    require(
        revision != s.revisions[1],
        "Bulk Admin confirmation did not advance recipient revision",
    )?;
    s.revisions[1] = revision;
    let profile = s.http.json("/api/accounts/profile", &s.accounts[1].token)?;
    require(
        single::org_in(&profile, "organizations", &s.orgs[1].id)?
            .is_some_and(|o| o["key"] == OPAQUE_KEY)
            && single::org_in(&profile, "organizations", &s.orgs[0].id)?
                .is_some_and(|o| o["key"] == s.primary_key),
        "Bulk sibling confirmation altered delivered keys",
    )?;
    let owner = s.row(
        1,
        text(&s.accounts[0].fixture["email"])?.to_owned().as_str(),
    )?;
    let manager = text(&s.rows[6]["id"])?.to_owned();
    let owner = text(&owner["id"])?.to_owned();
    let user = text(&s.rows[5]["id"])?.to_owned();
    let v=s.http.post(&p,&s.accounts[1].token,&json!({"keys":[{"id":manager,"key":"denied"},{"id":owner,"key":"denied"},{"id":b,"key":"denied"},{"id":user,"key":"admin-user-success"}]}))?.status(200)?.json()?;
    result(
        &v,
        &[
            (&manager, OWNER_ONLY),
            (&owner, OWNER_ONLY),
            (&b, OWNER_ONLY),
            (&user, ""),
        ],
    )?;
    let row = s.row(1, &s.emails[0].clone())?;
    single::member_after(&s.rows[5], &row, 2)?;
    let row = s.row(1, &s.emails[2].clone())?;
    require(row == s.rows[6], "Bulk hierarchy rejection changed Manager")?;
    s.readonly()
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for i in 0..2 {
        let value = s.http.refresh(&s.accounts[i].refresh)?;
        let token = text(&value["access_token"])?;
        let profile = s.http.json("/api/accounts/profile", token)?;
        require(
            profile["id"] == s.accounts[i].user_id,
            "Bulk confirmation refresh changed identity",
        )?;
        let cipher = s
            .http
            .json(&format!("/api/ciphers/{}", s.accounts[i].cipher_id), token)?;
        let key = fixture::fixture_user_key(&s.accounts[i].fixture, &s.accounts[i].password)
            .map_err(|_| Error("Bulk personal key unwrap failed"))?;
        let plain = fixture::decrypt(text(&cipher["notes"])?, &key)
            .map_err(|_| Error("Bulk personal note MAC failed"))?;
        require(
            plain == organization_owner::NOTE.as_bytes(),
            "Bulk confirmation changed personal plaintext",
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
    let hidden = single::hidden_collection(&mut http.owner, &a, &org)?;
    organization_invites::invite_owner(
        &mut http.owner,
        &org.id,
        &a.token,
        &single::invitation(text(&b.fixture["email"])?, 2, Some(&org.collection_id)),
    )?;
    organization_invites::invite_owner(
        &mut http.owner,
        &sibling.id,
        &a.token,
        &single::invitation(text(&b.fixture["email"])?, 1, None),
    )?;
    let mut emails = Vec::new();
    for _ in 0..3 {
        let email = format!("bulk-confirmation-{}@example.test", Uuid::new_v4());
        let document = fixture::registration(&email, &Uuid::new_v4().to_string(), 600000)
            .map_err(|_| Error("Bulk role fixture creation failed"))?;
        fixture::register_modern_fixture(&http.owner.server, &document)
            .map_err(|_| Error("Bulk role registration failed"))?;
        organization_invites::invite_owner(
            &mut http.owner,
            &org.id,
            &a.token,
            &single::invitation(&email, 2, None),
        )?;
        emails.push(email);
    }
    for (index, role) in [(0, 2), (2, 3)] {
        organization_invites::invite_owner(
            &mut http.owner,
            &sibling.id,
            &a.token,
            &single::invitation(&emails[index], role, None),
        )?;
    }
    let stub = format!("bulk-invited-{}@example.test", Uuid::new_v4());
    organization_invites::invite_owner(
        &mut http.owner,
        &org.id,
        &a.token,
        &single::invitation(&stub, 2, None),
    )?;
    let mut rows = vec![
        single::member_row(
            &mut http.owner,
            &org.id,
            &a.token,
            text(&b.fixture["email"])?,
        )?,
        single::member_row(
            &mut http.owner,
            &sibling.id,
            &a.token,
            text(&b.fixture["email"])?,
        )?,
    ];
    for email in &emails {
        rows.push(single::member_row(
            &mut http.owner,
            &org.id,
            &a.token,
            email,
        )?);
    }
    rows.push(single::member_row(
        &mut http.owner,
        &sibling.id,
        &a.token,
        &emails[0],
    )?);
    rows.push(single::member_row(
        &mut http.owner,
        &sibling.id,
        &a.token,
        &emails[2],
    )?);
    rows.push(single::member_row(
        &mut http.owner,
        &org.id,
        &a.token,
        &stub,
    )?);
    rows.push(single::member_row(
        &mut http.owner,
        &foreign.id,
        &b.token,
        text(&b.fixture["email"])?,
    )?);
    let mut s = Suite {
        http,
        accounts: vec![a, b],
        orgs: vec![org, sibling, foreign],
        hidden: text(&hidden["id"])?.to_owned(),
        rows,
        emails,
        personal: Vec::new(),
        revisions: Vec::new(),
        stable: Value::Null,
        primary_key: String::new(),
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_BULK_CONFIRMATION_RECEIPT")?,
        finished: false,
    };
    for account in &s.accounts {
        s.personal.push(s.http.owner.personal(&account.token)?);
        s.revisions.push(s.http.owner.revision(&account.token)?);
    }
    s.stable = s.stable_snapshot()?;
    s.receipt("running")?;
    for (name, case) in CASES {
        eprintln!("Organization bulk confirmation case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 2
            && s.passed.len() == CASE_COUNT,
        "Bulk confirmation request budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-bulk-confirmation: {CASE_COUNT} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bulk_result_requires_exact_order_duplicate_rows_and_plain_error() {
        let mut value = json!({"object":"list","data":[{"object":"OrganizationBulkConfirmResponseModel","id":"same","error":""},{"object":"OrganizationBulkConfirmResponseModel","id":"same","error":STATE}],"continuationToken":null});
        assert!(result(&value, &[("same", ""), ("same", STATE)]).is_ok());
        value["data"].as_array_mut().unwrap().swap(0, 1);
        assert!(result(&value, &[("same", ""), ("same", STATE)]).is_err());
        value["data"].as_array_mut().unwrap().swap(0, 1);
        value["data"][1]["error"] = json!({"message":STATE});
        assert!(result(&value, &[("same", ""), ("same", STATE)]).is_err());
    }
}
