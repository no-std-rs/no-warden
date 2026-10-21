//! Independently authored MIT/Apache-2.0 actual mini-member discovery contracts.
//! Exact public seven-field rows are distinct from nineteen-field member detail.
use crate::{
    fixture,
    organization_collections::{self, create_organization},
    organization_confirmations as confirmation, organization_invites as invites,
    organization_member_removal as removal, organization_member_status as status,
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
// Setup60 + guards38 + projection30 + states69 + freshness175 + actors201 + transport46.
pub const HTTP_REQUEST_COUNT: usize = 619;
const FRESH_NAME: &str = "Mini metadata updated Ω\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_member_mini_details_authentication_path_and_reserved_method_guards",
        guards,
    ),
    (
        "organization_member_mini_details_exact_seven_field_projection_and_scope",
        projection,
    ),
    (
        "organization_member_mini_details_all_native_target_states_and_unfiltered_names",
        states,
    ),
    (
        "organization_member_mini_details_live_and_empty_names_without_private_fields",
        freshness,
    ),
    (
        "organization_member_mini_details_admin_and_restricted_manager_admission",
        actors,
    ),
    (
        "organization_member_mini_details_ignored_body_query_encoded_paths_and_preserved_sessions",
        transport,
    ),
];
pub(crate) fn path(org: &str) -> String {
    format!("/api/organizations/{org}/users/mini-details")
}
// These fixtures use a native Invited placeholder whose stored account name equals
// email; its rich member row hides that name. This is fixture construction, not a
// generic null-name fallback rule for imported or SMTP-managed account records.
pub(crate) fn expected(member: &Value) -> Value {
    json!({"id":member["id"],"userId":member["userId"],"email":member["email"],"name":if member["name"].is_null(){&member["email"]}else{&member["name"]},"type":member["type"],"status":member["status"],"object":"organizationUserUserMiniDetails"})
}
pub(crate) fn check_projection(value: &Value, rows: &[Value]) -> Result<(), Error> {
    require(
        *value == json!({"object":"list","data":rows,"continuationToken":null}),
        "Mini-member exact ordered projection differed",
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
                "Mini-member status expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Mini-member HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Mini-member private response was not JSON"))
    }
    fn rejected(self, status: u16) -> Result<(), Error> {
        let reply = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.bytes) {
            require(
                [
                    "access_token",
                    "refresh_token",
                    "key",
                    "privateKey",
                    "publicKey",
                ]
                .iter()
                .all(|field| value.get(field).is_none()),
                "Rejected mini discovery exposed authority",
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
        let response = request
            .send()
            .map_err(|_| Error("Mini-member request failed"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Mini-member private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Mini-member private capture exceeded bound",
        )?;
        Ok(Reply { status, bytes })
    }
    fn get(&mut self, path: &str, token: &str) -> Result<Value, Error> {
        self.owner.json(Method::GET, path, token, None)
    }
    fn refresh(&mut self, proof: &str) -> Result<Value, Error> {
        self.owner.requests += 1;
        self.refreshes += 1;
        let response = self
            .client
            .post(format!("{}/identity/connect/token", self.owner.server))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", proof),
                ("client_id", "cli"),
            ])
            .send()
            .map_err(|_| Error("Mini-member session refresh failed"))?;
        require(
            response.status() == 200,
            "Mini-member session refresh status differed",
        )?;
        response
            .json()
            .map_err(|_| Error("Mini-member private refresh malformed"))
    }
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    members: Vec<Value>,
    original: Value,
    side: Value,
    baseline: Value,
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
    fn receipt(&mut self, state: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":state,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":3,"registrationHttpRequests":6,"directProfileFixtureMutations":3,"cliMiniDetailsCallerClaimed":false,"browserTraceClaimed":false,"capturedRouteTrace":false,"configuredGroups":false,"importedUnknownStateHttpClaimed":false,"crossBackendOrderClaimed":false,"invitedNameEmailFixtureOnly":true,"smtpEnabled":false,"adjacentPutMemberEditParityClaimed":false}),
        )
    }
    fn lists(&mut self) -> Result<Vec<Value>, Error> {
        let mut result = Vec::new();
        for i in 0..5 {
            result.push(self.http.get(
                &invites::member_path(&self.orgs[i].id),
                &self.accounts[usize::from(i == 4)].token,
            )?);
        }
        Ok(result)
    }
    fn snapshot(&mut self) -> Result<Value, Error> {
        let mut accounts = Vec::new();
        for account in &self.accounts {
            accounts.push(json!({"personal":self.http.owner.personal(&account.token)?,"revision":self.http.owner.revision(&account.token)?,"profile":self.http.get("/api/accounts/profile",&account.token)?}));
        }
        let mut groups = Vec::new();
        for i in 0..5 {
            let token = &self.accounts[usize::from(i == 4)].token;
            groups.push(json!({"members":self.http.get(&invites::member_path(&self.orgs[i].id),token)?,"organization":self.http.get(&format!("/api/organizations/{}",self.orgs[i].id),token)?,"collections":self.http.get(&organization_collections::path(&self.orgs[i].id),token)?}));
        }
        Ok(json!({"accounts":accounts,"groups":groups}))
    }
    fn readonly(&mut self) -> Result<(), Error> {
        require(
            self.snapshot()? == self.baseline,
            "Mini discovery changed account, vault, key, revision, membership, grants, organization or session state",
        )
    }
    fn rows(&self, group: usize) -> Result<Vec<Value>, Error> {
        Ok(crate::organization_members::rows(&self.members[group])?
            .iter()
            .map(expected)
            .collect())
    }
    fn query(&mut self, group: usize, actor: usize) -> Result<(), Error> {
        let value = self
            .http
            .get(&path(&self.orgs[group].id), &self.accounts[actor].token)?;
        check_projection(&value, &self.rows(group)?)
    }
    fn status(&mut self, group: usize, id: &str, state: i64) -> Result<(), Error> {
        let member = self.members[group]["data"]
            .as_array_mut()
            .and_then(|rows| rows.iter_mut().find(|row| row["id"] == id))
            .ok_or(Error("Mini expected membership missing"))?;
        member["status"] = json!(state);
        Ok(())
    }
    fn name(&mut self, value: &str) -> Result<(), Error> {
        self.http.owner.json(
            Method::PUT,
            "/api/accounts/profile",
            &self.accounts[1].token,
            Some(&json!({"name":value})),
        )?;
        for group in &mut self.members {
            for row in group["data"]
                .as_array_mut()
                .ok_or(Error("Mini expected member list malformed"))?
            {
                if row["userId"] == self.accounts[1].user_id {
                    row["name"] = json!(value);
                }
            }
        }
        self.baseline = self.snapshot()?;
        Ok(())
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let token = s.accounts[0].token.clone();
    let p = path(&s.orgs[0].id);
    for bearer in [
        None,
        Some("invalid-mini-details-bearer"),
        Some(s.accounts[1].token.as_str()),
    ] {
        s.http
            .raw(
                Method::GET,
                &p,
                bearer,
                Some(b"\xff{"),
                Some("application/json"),
            )?
            .rejected(401)?;
    }
    for (p, bearer, expected) in [
        (path("bad.id"), token.as_str(), 401),
        (
            format!("{}?organizationId={}", path("bad.id"), s.orgs[0].id),
            token.as_str(),
            422,
        ),
        (path(&s.orgs[0].id.to_uppercase()), token.as_str(), 401),
        (path(&s.orgs[4].id), token.as_str(), 401),
        (path(&s.orgs[1].id), s.accounts[1].token.as_str(), 401),
    ] {
        s.http
            .raw(Method::GET, &p, Some(bearer), Some(b"{"), None)?
            .rejected(expected)?;
    }
    for (method, expected) in [
        (Method::POST, 404),
        (Method::DELETE, 422),
        (Method::PATCH, 404),
    ] {
        s.http
            .raw(
                method,
                &p,
                Some(&token),
                Some(b"{"),
                Some("application/json"),
            )?
            .rejected(expected)?;
    }
    s.readonly()
}
fn projection(s: &mut Suite) -> Result<(), Error> {
    require(
        crate::organization_members::rows(&s.members[0])?.len() == 4
            && crate::organization_members::rows(&s.members[4])?.len() == 1,
        "Mini projection fixtures differ",
    )?;
    s.query(0, 0)?;
    s.query(4, 1)?;
    s.query(0, 0)?;
    let rows = s.rows(0)?;
    let placeholder = rows
        .iter()
        .find(|r| r["status"] == 0)
        .ok_or(Error("Mini placeholder fixture absent"))?;
    require(
        placeholder["name"] == placeholder["email"]
            && placeholder["id"] != placeholder["userId"]
            && rows.iter().all(|r| r["id"] != r["userId"]),
        "Mini identity or unfiltered placeholder account name differed",
    )?;
    s.readonly()
}
fn states(s: &mut Suite) -> Result<(), Error> {
    let id = text(&s.original["id"])?.to_owned();
    removal::confirm_fixture_member(
        &mut s.http.owner,
        &s.orgs[0],
        &id,
        &s.accounts[0].token,
        &s.accounts[1].fixture,
    )?;
    s.status(0, &id, 2)?;
    for (action, state) in [(None, 2), (Some("revoke"), -1), (Some("restore"), 2)] {
        if let Some(action) = action {
            status::put_fixture_status(
                &mut s.http.owner,
                &s.orgs[0].id,
                &id,
                action,
                &s.accounts[0].token,
            )?;
            s.status(0, &id, state)?;
        }
        let revision = s.http.owner.revision(&s.accounts[1].token)?;
        s.query(0, 0)?;
        require(
            s.http.owner.revision(&s.accounts[1].token)? == revision,
            "Mini target-state read changed revision",
        )?;
        let detail = s.http.get(
            &format!(
                "{}?includeGroups=true&includeCollections=true",
                crate::organization_members::detail_path(&s.orgs[0].id, &id)
            ),
            &s.accounts[0].token,
        )?;
        let mut original = s.original.clone();
        original["status"] = json!(state);
        require(
            detail == original,
            "Mini target-state read changed membership identity, role, grants or name",
        )?;
    }
    s.baseline = s.snapshot()?;
    s.readonly()
}
fn freshness(s: &mut Suite) -> Result<(), Error> {
    let original = text(&s.accounts[1].fixture["name"])?.to_owned();
    for name in [FRESH_NAME, ""] {
        s.name(name)?;
        for group in 0..5 {
            s.query(group, usize::from(group == 4))?;
        }
        s.readonly()?;
    }
    s.name(&original)?;
    s.readonly()
}
fn actors(s: &mut Suite) -> Result<(), Error> {
    let b = s.accounts[1].token.clone();
    for group in [0, 1] {
        s.http
            .raw(Method::GET, &path(&s.orgs[group].id), Some(&b), None, None)?
            .rejected(401)?;
    }
    s.query(2, 1)?;
    s.query(3, 1)?;
    s.http
        .raw(
            Method::GET,
            &invites::member_path(&s.orgs[2].id),
            Some(&b),
            None,
            None,
        )?
        .rejected(404)?;
    s.readonly()?;
    let id = text(&s.side["id"])?.to_owned();
    removal::confirm_fixture_member(
        &mut s.http.owner,
        &s.orgs[1],
        &id,
        &s.accounts[0].token,
        &s.accounts[1].fixture,
    )?;
    s.status(1, &id, 2)?;
    s.baseline = s.snapshot()?;
    s.query(1, 1)?;
    s.readonly()?;
    status::put_fixture_status(
        &mut s.http.owner,
        &s.orgs[1].id,
        &id,
        "revoke",
        &s.accounts[0].token,
    )?;
    s.status(1, &id, -1)?;
    s.baseline = s.snapshot()?;
    s.http
        .raw(
            Method::GET,
            &path(&s.orgs[1].id),
            Some(&b),
            Some(b"{"),
            None,
        )?
        .rejected(401)?;
    s.query(1, 0)?;
    s.readonly()?;
    status::put_fixture_status(
        &mut s.http.owner,
        &s.orgs[1].id,
        &id,
        "restore",
        &s.accounts[0].token,
    )?;
    s.status(1, &id, 2)?;
    s.baseline = s.snapshot()?;
    s.query(1, 1)?;
    s.readonly()
}
fn transport(s: &mut Suite) -> Result<(), Error> {
    let p = path(&s.orgs[0].id);
    let token = s.accounts[0].token.clone();
    let expected = s.rows(0)?;
    for (body, media) in [
        (b"\xff{".as_slice(), Some("application/json")),
        (b"{}", Some("application/json")),
        (b"[]", Some("application/problem+json")),
        (b"ignored non-JSON", None),
        (b"", None),
    ] {
        let value = s
            .http
            .raw(Method::GET, &p, Some(&token), Some(body), media)?
            .status(200)?
            .json()?;
        check_projection(&value, &expected)?;
    }
    for suffix in [
        "?includeGroups=true&includeCollections=true".to_owned(),
        "?includeGroups=false&includeCollections=invalid".to_owned(),
        "?unknown=42".to_owned(),
        format!("?organizationId={}", s.orgs[4].id),
        "?organizationId=bad.id".to_owned(),
    ] {
        let value = s.http.get(&format!("{p}{suffix}"), &token)?;
        check_projection(&value, &expected)?;
    }
    for path in [
        format!("{p}/"),
        p.replace("mini-details", "%6dini-details"),
        p.replace("mini-details", "mini%2Ddetails"),
    ] {
        check_projection(&s.http.get(&path, &token)?, &expected)?;
    }
    for i in 0..2 {
        let refreshed = s.http.refresh(&s.accounts[i].refresh)?;
        let token = text(&refreshed["access_token"])?;
        require(
            s.http.get("/api/accounts/profile", token)?["id"] == s.accounts[i].user_id,
            "Mini refreshed account identity changed",
        )?;
        let cipher = s
            .http
            .get(&format!("/api/ciphers/{}", s.accounts[i].cipher_id), token)?;
        let key = fixture::fixture_user_key(&s.accounts[i].fixture, &s.accounts[i].password)
            .map_err(|_| Error("Mini personal key unwrap failed"))?;
        require(
            fixture::decrypt(text(&cipher["notes"])?, &key)
                .map_err(|_| Error("Mini personal note authentication failed"))?
                == organization_owner::NOTE.as_bytes(),
            "Mini read changed personal plaintext",
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
    let main = create_organization(&mut http.owner, &a)?;
    let admin = create_organization(&mut http.owner, &a)?;
    let restricted = create_organization(&mut http.owner, &a)?;
    let full = create_organization(&mut http.owner, &a)?;
    let foreign = create_organization(&mut http.owner, &b)?;
    for (group, role, access) in [
        (&main, 2, false),
        (&admin, 1, false),
        (&restricted, 3, false),
        (&full, 3, true),
    ] {
        let mut body = confirmation::invitation(
            text(&b.fixture["email"])?,
            role,
            if role == 2 {
                Some(&group.collection_id)
            } else {
                None
            },
        );
        body["accessAll"] = json!(access);
        invites::invite_owner(&mut http.owner, &group.id, &a.token, &body)?;
    }
    let email = format!("mini-accepted-owner-{}@example.test", Uuid::new_v4());
    let document = fixture::registration(&email, &Uuid::new_v4().to_string(), 600000)
        .map_err(|_| Error("Mini third-account fixture generation failed"))?;
    fixture::register_modern_fixture(&http.owner.server, &document)
        .map_err(|_| Error("Mini third-account registration failed"))?;
    invites::invite_owner(
        &mut http.owner,
        &main.id,
        &a.token,
        &confirmation::invitation(&email, 0, None),
    )?;
    let invited = format!("mini-invited-{}@example.test", Uuid::new_v4());
    invites::invite_owner(
        &mut http.owner,
        &main.id,
        &a.token,
        &confirmation::invitation(&invited, 2, None),
    )?;
    let list = http.get(&invites::member_path(&main.id), &a.token)?;
    let original = invites::member(&list, text(&b.fixture["email"])?)?.clone();
    let side = confirmation::member_row(
        &mut http.owner,
        &admin.id,
        &a.token,
        text(&b.fixture["email"])?,
    )?;
    for group in [&restricted, &full] {
        let row = confirmation::member_row(
            &mut http.owner,
            &group.id,
            &a.token,
            text(&b.fixture["email"])?,
        )?;
        removal::confirm_fixture_member(
            &mut http.owner,
            group,
            text(&row["id"])?,
            &a.token,
            &b.fixture,
        )?;
    }
    let mut s = Suite {
        http,
        accounts: vec![a, b],
        orgs: vec![main, admin, restricted, full, foreign],
        members: Vec::new(),
        original,
        side,
        baseline: Value::Null,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_MEMBER_MINI_DETAILS_RECEIPT")?,
        finished: false,
    };
    s.members = s.lists()?;
    require(
        s.original["status"] == 1
            && s.original["type"] == 2
            && s.side["status"] == 1
            && s.side["type"] == 1
            && invites::member(&s.members[2], text(&s.accounts[1].fixture["email"])?)?["type"] == 4,
        "Mini fixture role or status differs",
    )?;
    s.baseline = s.snapshot()?;
    s.receipt("running")?;
    for (name, case) in CASES {
        eprintln!("Mini-member case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 2
            && s.passed.len() == CASE_COUNT,
        "Mini exact request budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-member-mini-details: {CASE_COUNT} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mini_projection_requires_exact_seven_fields_raw_names_and_identity() {
        let placeholder = json!({"id":"membership","userId":"account","email":"placeholder@example.test","name":null,"status":0,"type":2});
        let expected = [expected(&placeholder)];
        let good = json!({"object":"list","continuationToken":null,"data":expected});
        assert!(check_projection(&good, &expected).is_ok());
        for field in ["id", "userId", "email", "name", "type", "status", "object"] {
            let mut bad = good.clone();
            bad["data"][0].as_object_mut().unwrap().remove(field);
            assert!(check_projection(&bad, &expected).is_err());
        }
        let mut bad = good.clone();
        bad["data"][0]["name"] = Value::Null;
        assert!(check_projection(&bad, &expected).is_err());
        let mut bad = good.clone();
        bad["data"][0]["key"] = json!("unwanted");
        assert!(check_projection(&bad, &expected).is_err());
        let mut bad = good.clone();
        bad["data"][0]["object"] = json!("organizationUserUserDetails");
        assert!(check_projection(&bad, &expected).is_err());
        let mut bad = good;
        bad["data"][0]["id"] = bad["data"][0]["userId"].clone();
        assert!(check_projection(&bad, &expected).is_err());
    }
}
