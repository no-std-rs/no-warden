//! Independently authored MIT/Apache-2.0 confirmed-owner member discovery.
//! Invitations, shared cipher access and general membership management are excluded.
use crate::{
    fixture,
    organization_collections::{create_organization, path as collections_path},
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
pub const HTTP_REQUEST_COUNT: usize = 240;
pub(crate) const MEMBER_NAME: &str = "Fresh owner 雪\0";
pub(crate) const AVATAR: &str = "雪abcd";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_members_authentication_and_path_guards",
        guards,
    ),
    (
        "organization_members_confirmed_owner_projection",
        projection,
    ),
    (
        "organization_members_query_inclusion_and_ignored_body",
        queries,
    ),
    (
        "organization_members_profile_and_avatar_freshness",
        freshness,
    ),
    ("organization_members_organization_isolation", isolation),
    (
        "organization_members_preserved_vault_keys_and_sessions",
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
                "Organization members status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Organization member HTTP status differed",
        )?;
        Ok(self)
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Organization member response was not JSON"))
    }
    fn rejected(self, expected: u16) -> Result<(), Error> {
        let response = self.status(expected)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&response.bytes) {
            require(
                ["access_token", "refresh_token", "key", "privateKey"]
                    .iter()
                    .all(|k| value.get(k).is_none()),
                "Rejected member request exposed authority",
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
            .map_err(|_| Error("Member private response capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Member response exceeded private bound",
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
                .map_err(|_| Error("Organization member request failed"))?,
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
                .map_err(|_| Error("Member refresh failed"))?,
        )?
        .status(200)?
        .json()
    }
}
pub(crate) fn path(org: &str) -> String {
    format!("/api/organizations/{org}/users")
}
pub(crate) fn detail_path(org: &str, member: &str) -> String {
    format!("{}/{member}", path(org))
}
fn array(value: &Value) -> Result<&[Value], Error> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(Error("Organization member array missing"))
}
pub(crate) fn rows(value: &Value) -> Result<&[Value], Error> {
    require(
        value.as_object().is_some_and(|o| o.len() == 3)
            && value["object"] == "list"
            && value.get("continuationToken").is_some_and(Value::is_null),
        "Organization member list envelope differed",
    )?;
    array(&value["data"])
}
pub(crate) fn membership_id<'a>(profile: &'a Value, org: &str) -> Result<&'a str, Error> {
    let member = array(&profile["organizations"])?
        .iter()
        .find(|v| v["id"] == org)
        .ok_or(Error("Confirmed owner membership missing"))?;
    text(&member["organizationUserId"])
}
pub(crate) fn member_shape(
    value: &Value,
    user_id: &str,
    membership_id: &str,
    email: &str,
    name: &Value,
    avatar: &Value,
) -> Result<(), Error> {
    require(
        value.as_object().is_some_and(|o| o.len() == 19)
            && value["id"] == membership_id
            && value["userId"] == user_id
            && value["id"] != value["userId"]
            && value["email"] == email
            && value["name"] == *name
            && value.get("avatarColor") == Some(avatar)
            && value["status"] == 2
            && value["type"] == 0
            && value["hasMasterPassword"] == true
            && value["collections"] == json!([])
            && value["groups"] == json!([])
            && value["object"] == "organizationUserUserDetails",
        "Confirmed owner member projection differed",
    )?;
    for field in ["externalId", "permissions"] {
        require(
            value.get(field).is_some_and(Value::is_null),
            "Owner member nullable default differed",
        )?;
    }
    for field in [
        "twoFactorEnabled",
        "resetPasswordEnrolled",
        "ssoBound",
        "claimedByOrganization",
        "usesKeyConnector",
        "accessSecretsManager",
    ] {
        require(
            value.get(field) == Some(&Value::Bool(false)),
            "Owner member boolean default differed",
        )?;
    }
    Ok(())
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    organizations: Vec<Organization>,
    profiles: Vec<Value>,
    personal: Vec<Value>,
    revisions: Vec<Value>,
    authority: Value,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":self.accounts.len(),"fixtureRegistrationHttpRequests":self.accounts.len()*2,"setupOrganizationCreates":self.organizations.len(),"ownerAccessAllOnly":true}),
        )
    }
    fn owner(&self, org: usize) -> usize {
        usize::from(org == 1)
    }
    fn inspect(&self, value: &Value, org: usize) -> Result<(), Error> {
        let owner = self.owner(org);
        let account = &self.accounts[owner];
        let profile = &self.profiles[owner];
        let members = rows(value)?;
        require(
            members.len() == 1,
            "Owner organization list leaked or omitted a membership",
        )?;
        member_shape(
            &members[0],
            &account.user_id,
            membership_id(profile, &self.organizations[org].id)?,
            text(&account.fixture["email"])?,
            &profile["name"],
            &profile["avatarColor"],
        )
    }
    fn get(&mut self, org: usize) -> Result<Value, Error> {
        let value = self.http.json(
            Method::GET,
            &path(&self.organizations[org].id),
            &self.accounts[self.owner(org)].token,
            None,
        )?;
        self.inspect(&value, org)?;
        let member = membership_id(&self.profiles[self.owner(org)], &self.organizations[org].id)?;
        let single = self.http.json(
            Method::GET,
            &detail_path(&self.organizations[org].id, member),
            &self.accounts[self.owner(org)].token,
            None,
        )?;
        require(
            single == rows(&value)?[0],
            "Single-member projection differed from the current list member",
        )?;
        Ok(value)
    }
    fn authority_snapshot(&mut self) -> Result<Value, Error> {
        let mut profiles = Vec::new();
        for account in &self.accounts {
            let profile =
                self.http
                    .json(Method::GET, "/api/accounts/profile", &account.token, None)?;
            require(
                profile["organizations"].is_array() && profile["organizationsNew"].is_array(),
                "Member authority snapshot malformed",
            )?;
            profiles.push(json!({"organizations":profile["organizations"],"organizationsNew":profile["organizationsNew"]}));
        }
        let mut collections = Vec::new();
        for i in 0..self.organizations.len() {
            collections.push(self.http.json(
                Method::GET,
                &collections_path(&self.organizations[i].id),
                &self.accounts[self.owner(i)].token,
                None,
            )?);
        }
        Ok(json!({"memberships":profiles,"collections":collections}))
    }
    fn readonly(&mut self) -> Result<(), Error> {
        for i in 0..self.accounts.len() {
            require(
                self.http.owner.personal(&self.accounts[i].token)? == self.personal[i]
                    && self.http.owner.revision(&self.accounts[i].token)? == self.revisions[i],
                "Member read changed personal vault, keys, settings, device or revision",
            )?;
        }
        require(
            self.authority_snapshot()? == self.authority,
            "Member discovery changed membership or organization collections",
        )
    }
    fn updated_profile(&mut self, body: &Value, avatar: bool) -> Result<(), Error> {
        let p = if avatar {
            "/api/accounts/avatar"
        } else {
            "/api/accounts/profile"
        };
        self.http
            .json(Method::PUT, p, &self.accounts[0].token, Some(body))?;
        let field = if avatar { "avatarColor" } else { "name" };
        self.profiles[0][field] = body[field].clone();
        self.personal[0]["sync"]["profile"][field] = body[field].clone();
        require(
            self.http.owner.revision(&self.accounts[0].token)? != self.revisions[0]
                && self.http.owner.revision(&self.accounts[1].token)? == self.revisions[1],
            "Member profile fixture changed wrong account revision",
        )?;
        self.revisions[0] = self.http.owner.revision(&self.accounts[0].token)?;
        self.get(0)?;
        Ok(())
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.organizations[0].id.clone();
    let own = s.accounts[0].token.clone();
    let member = membership_id(&s.profiles[0], &org)?.to_owned();
    for bearer in [None, Some("invalid-member-bearer")] {
        for p in [
            path(&org),
            path("bad.id"),
            detail_path(&org, &member),
            detail_path(&org, "bad.id"),
        ] {
            s.http
                .raw(Method::GET, &p, bearer, Some(b"{"), None)?
                .rejected(401)?;
        }
    }
    for (p, bearer, status) in [
        (path(&org), s.accounts[1].token.as_str(), 401),
        (path(&Uuid::new_v4().to_string()), own.as_str(), 401),
        (path("bad.id"), own.as_str(), 401),
        (
            format!("{}?organizationId={org}", path("bad.id")),
            own.as_str(),
            422,
        ),
        (
            format!("{}?.organizationId={org}", path("bad.id")),
            own.as_str(),
            422,
        ),
        (
            format!("{}?OrganizationId={org}", path("bad.id")),
            own.as_str(),
            401,
        ),
        (
            format!("{}?organizationId={org}", path(&s.organizations[1].id)),
            own.as_str(),
            401,
        ),
        (detail_path(&org, "bad.id"), own.as_str(), 422),
        (detail_path("bad.id", &member), own.as_str(), 401),
        (
            format!("{}?organizationId={org}", detail_path("bad.id", &member)),
            own.as_str(),
            422,
        ),
        (
            detail_path(&s.organizations[1].id, "bad.id"),
            own.as_str(),
            401,
        ),
        (
            format!("{}?memberId={member}", detail_path(&org, "bad.id")),
            own.as_str(),
            422,
        ),
        (
            format!(
                "{}?organizationUserId={member}",
                detail_path(&org, "bad.id")
            ),
            own.as_str(),
            422,
        ),
    ] {
        s.http
            .raw(Method::GET, &p, Some(bearer), None, None)?
            .rejected(status)?;
    }
    let (first, tail) = org
        .split_at_checked(1)
        .ok_or(Error("Member fixture UUID empty"))?;
    let encoded = format!("%{:02X}{tail}", first.as_bytes()[0]);
    let value = s.http.json(Method::GET, &path(&encoded), &own, None)?;
    s.inspect(&value, 0)?;
    let (first, tail) = member
        .split_at_checked(1)
        .ok_or(Error("Member fixture identifier empty"))?;
    let encoded_member = format!("%{:02X}{tail}", first.as_bytes()[0]);
    let single = s.http.json(
        Method::GET,
        &detail_path(&encoded, &encoded_member),
        &own,
        None,
    )?;
    require(
        single == rows(&value)?[0],
        "Percent-decoded single member differed from list member",
    )?;
    s.http
        .raw(
            Method::PATCH,
            &detail_path(&org, &member),
            Some(&own),
            None,
            None,
        )?
        .rejected(404)?;
    for method in [Method::POST, Method::PUT, Method::PATCH] {
        s.http
            .raw(method, &path(&org), Some(&own), None, None)?
            .rejected(404)?;
    }
    s.readonly()
}
fn projection(s: &mut Suite) -> Result<(), Error> {
    let value = s.get(0)?;
    let profile = s.http.json(
        Method::GET,
        "/api/accounts/profile",
        &s.accounts[0].token,
        None,
    )?;
    let row = &rows(&value)?[0];
    require(
        row["id"] == membership_id(&profile, &s.organizations[0].id)?
            && row["name"] == profile["name"]
            && row["avatarColor"] == profile["avatarColor"],
        "Member projection disagreed with authoritative profile",
    )?;
    s.readonly()
}
fn queries(s: &mut Suite) -> Result<(), Error> {
    let baseline = s.get(0)?;
    let org = s.organizations[0].id.clone();
    let token = s.accounts[0].token.clone();
    let member = membership_id(&s.profiles[0], &org)?.to_owned();
    // Owner accessAll and disabled groups both project []. These requests prove
    // acceptance and that projection, not observable parsing of a non-full ACL.
    for query in [
        "includeCollections=true",
        "includeCollections=false",
        "includeCollections=TRUE",
        "includeCollections=off",
        "includeCollections=yes",
        "includeCollections=",
        "includeCollections=invalid",
        "includeCollections=true&includeCollections=false",
        "includeGroups=true",
        "includeGroups=false",
        "includeGroups=invalid",
        "includeGroups=true&includeGroups=false",
        "includeCollections=true&includeGroups=true",
        "includeCollections=false&includeGroups=true",
        "includeCollections=invalid&includeGroups=true",
        "includeCollections.foo=true",
        "%5BincludeCollections%5D=true",
        ".includeGroups=true",
        "IncludeCollections=true&IncludeGroups=true",
        "unknown=ignored",
    ] {
        let value = s.http.json(
            Method::GET,
            &format!("{}?{query}", path(&org)),
            &token,
            None,
        )?;
        require(
            value == baseline,
            "Owner member query changed projection or ownership",
        )?;
        let single = s.http.json(
            Method::GET,
            &format!("{}?{query}", detail_path(&org, &member)),
            &token,
            None,
        )?;
        require(
            single == rows(&baseline)?[0],
            "Owner single-member query changed projection or ownership",
        )?;
    }
    let ignored = s
        .http
        .raw(
            Method::GET,
            &format!("{}?organizationId=foreign", path(&org)),
            Some(&token),
            Some(b"not-json"),
            Some("application/json"),
        )?
        .status(200)?
        .json()?;
    require(
        ignored == baseline,
        "Member GET body or unrelated query changed selection",
    )?;
    // Single GET defaults includeCollections from includeGroups when absent;
    // Owner accessAll [] cannot expose that branch in this portable fixture.
    let single = s
        .http
        .raw(
            Method::GET,
            &format!(
                "{}?organizationId=foreign&memberId=ignored",
                detail_path(&org, &member)
            ),
            Some(&token),
            Some(b"not-json"),
            Some("application/json"),
        )?
        .status(200)?
        .json()?;
    require(
        single == rows(&baseline)?[0],
        "Single-member GET body or unrelated query changed selection",
    )?;
    s.readonly()
}
fn freshness(s: &mut Suite) -> Result<(), Error> {
    s.updated_profile(&json!({"name":""}), false)?;
    s.updated_profile(&json!({"avatarColor":AVATAR}), true)?;
    s.updated_profile(&json!({"name":MEMBER_NAME}), false)?;
    s.updated_profile(&json!({"avatarColor":null}), true)?;
    s.readonly()
}
fn isolation(s: &mut Suite) -> Result<(), Error> {
    let own = s.get(0)?;
    let foreign = s.get(1)?;
    let other = s.get(2)?;
    for member in [
        Uuid::new_v4().to_string(),
        s.accounts[0].user_id.clone(),
        text(&rows(&foreign)?[0]["id"])?.to_owned(),
        text(&rows(&other)?[0]["id"])?.to_owned(),
    ] {
        let error = s
            .http
            .raw(
                Method::GET,
                &detail_path(&s.organizations[0].id, &member),
                Some(&s.accounts[0].token),
                None,
                None,
            )?
            .status(400)?
            .json()?;
        require(
            error["message"] == "The specified user isn't a member of the organization",
            "Missing or wrong-organization single-member error differed",
        )?;
        require(
            ["key", "privateKey", "publicKey", "access_token"]
                .iter()
                .all(|key| error.get(key).is_none()),
            "Single-member error exposed private authority",
        )?;
    }
    require(
        rows(&own)?[0]["id"] != rows(&other)?[0]["id"]
            && rows(&own)?[0]["userId"] == rows(&other)?[0]["userId"]
            && rows(&foreign)?[0]["userId"] != rows(&own)?[0]["userId"],
        "Organization member identities crossed organization or user boundaries",
    )?;
    for (org, owner) in [(0, 1), (1, 0)] {
        s.http
            .raw(
                Method::GET,
                &path(&s.organizations[org].id),
                Some(&s.accounts[owner].token),
                None,
                None,
            )?
            .rejected(401)?;
    }
    let ignored = s.http.json(
        Method::GET,
        &format!(
            "{}?organizationId={}&userId={}",
            path(&s.organizations[0].id),
            s.organizations[1].id,
            s.accounts[1].user_id
        ),
        &s.accounts[0].token,
        None,
    )?;
    require(
        ignored == own,
        "Member query overrode authoritative path organization",
    )?;
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
            "Member discovery rebound refresh authority",
        )?;
        let cipher = s.http.json(
            Method::GET,
            &format!("/api/ciphers/{}", account.cipher_id),
            &account.token,
            None,
        )?;
        let key = fixture::fixture_user_key(&account.fixture, &account.password)
            .map_err(|_| Error("Member fixture key unwrap failed"))?;
        require(
            fixture::decrypt(text(&cipher["notes"])?, &key)
                .is_ok_and(|p| p == organization_owner::NOTE.as_bytes()),
            "Member discovery changed authenticated personal note",
        )?;
    }
    s.get(0)?;
    s.get(1)?;
    s.readonly()
}
pub fn run() -> Result<(), Error> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        organizations: Vec::new(),
        profiles: Vec::new(),
        personal: Vec::new(),
        revisions: Vec::new(),
        authority: Value::Null,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_MEMBERS_RECEIPT")?,
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
        s.profiles.push(
            s.http
                .json(Method::GET, "/api/accounts/profile", &account.token, None)?,
        );
        s.personal.push(s.http.owner.personal(&account.token)?);
        s.revisions.push(s.http.owner.revision(&account.token)?);
    }
    s.authority = s.authority_snapshot()?;
    for (name, case) in CASES {
        eprintln!("Organization member case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.logins == 2
            && s.http.refreshes == 2
            && s.passed.len() == CASE_COUNT
            && s.http.owner.requests == HTTP_REQUEST_COUNT,
        "Organization member fixture budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-members: {CASE_COUNT} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn member_projection_rejects_account_id_substitution_and_private_extensions() {
        let mut value = json!({"id":"membership","userId":"user","name":"opaque","email":"test@example.test","externalId":null,"avatarColor":null,"groups":[],"collections":[],"status":2,"type":0,"twoFactorEnabled":false,"resetPasswordEnrolled":false,"hasMasterPassword":true,"permissions":null,"ssoBound":false,"claimedByOrganization":false,"usesKeyConnector":false,"accessSecretsManager":false,"object":"organizationUserUserDetails"});
        assert!(
            member_shape(
                &value,
                "user",
                "membership",
                "test@example.test",
                &json!("opaque"),
                &Value::Null
            )
            .is_ok()
        );
        value["id"] = json!("user");
        assert!(
            member_shape(
                &value,
                "user",
                "membership",
                "test@example.test",
                &json!("opaque"),
                &Value::Null
            )
            .is_err()
        );
        value["id"] = json!("membership");
        value["key"] = json!("must-not-serialize");
        assert!(
            member_shape(
                &value,
                "user",
                "membership",
                "test@example.test",
                &json!("opaque"),
                &Value::Null
            )
            .is_err()
        );
    }
}
