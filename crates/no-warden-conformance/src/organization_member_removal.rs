//! Independently authored MIT/Apache-2.0 single organization-member removal proof.
//! Setup and removal use direct HTTP; no CLI removal caller or route trace is claimed.
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
// Setup43 + guards31 + scope27 + hierarchy26 + removal27 + rejoin31 + preservation27.
pub const HTTP_REQUEST_COUNT: usize = 212;
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_member_removal_authentication_path_and_bodyless_guards",
        guards,
    ),
    (
        "organization_member_removal_scoped_identity_and_last_owner",
        scope,
    ),
    (
        "organization_member_removal_admin_hierarchy_and_user_states",
        hierarchy,
    ),
    (
        "organization_member_removal_confirmed_access_revocation",
        remove,
    ),
    (
        "organization_member_removal_rejoin_does_not_restore_stale_grants",
        rejoin,
    ),
    (
        "organization_member_removal_preserved_accounts_keys_and_sessions",
        preservation,
    ),
];
const MISSING: &str = "User to delete isn't member of the organization";
const OWNER_ONLY: &str = "Only Owners can delete Admins or Owners";
pub(crate) fn path(org: &str, member: &str) -> String {
    format!("/api/organizations/{org}/users/{member}")
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

pub(crate) fn confirm_fixture_member(
    http: &mut OwnerHttp,
    org: &Organization,
    member: &str,
    actor: &str,
    fixture: &Value,
) -> Result<String, Error> {
    let wrapped = fixture::organization_key_for_account(fixture, &org.key)
        .map_err(|_| Error("Removal fixture RSA wrapping failed"))?;
    http.requests += 1;
    let reply = Http::read(
        http_client()?
            .post(format!("{}{}", http.server, single::path(&org.id, member)))
            .bearer_auth(actor)
            .json(&json!({"key":wrapped}))
            .send()
            .map_err(|_| Error("Removal fixture confirmation failed"))?,
    )?;
    reply.empty()?;
    Ok(wrapped)
}
pub(crate) fn remove_member(
    http: &mut OwnerHttp,
    org: &str,
    member: &str,
    actor: &str,
) -> Result<(), Error> {
    http.requests += 1;
    Http::read(
        http_client()?
            .delete(format!("{}{}", http.server, path(org, member)))
            .bearer_auth(actor)
            .body(b"ignored invalid JSON".to_vec())
            .header("Content-Type", "text/plain")
            .send()
            .map_err(|_| Error("Member removal request failed"))?,
    )?
    .empty()
}
fn array(value: &Value) -> Result<&[Value], Error> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(Error("Removal array missing"))
}
fn canonical(mut list: Value) -> Result<Value, Error> {
    crate::organization_members::rows(&list)?;
    list["data"]
        .as_array_mut()
        .ok_or(Error("Removal member list missing"))?
        .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(list)
}
fn omit_member(list: &mut Value, id: &str) -> Result<(), Error> {
    let rows = list["data"]
        .as_array_mut()
        .ok_or(Error("Removal expected list missing"))?;
    let count = rows.len();
    rows.retain(|r| r["id"] != id);
    require(
        rows.len() + 1 == count,
        "Removal expected membership was absent or duplicated",
    )
}
pub(crate) fn absent(profile: &Value, org: &str) -> Result<(), Error> {
    require(
        single::org_in(profile, "organizations", org)?.is_none()
            && single::org_in(profile, "organizationsNew", org)?.is_none(),
        "Removed organization remained in recipient profile",
    )
}
pub(crate) fn visible(
    value: &Value,
    removed: &str,
    sibling: &Organization,
    sync: bool,
) -> Result<(), Error> {
    let rows = if sync {
        array(&value["collections"])?
    } else {
        require(
            value["object"] == "list" && value["continuationToken"].is_null(),
            "Removal collection envelope differed",
        )?;
        array(&value["data"])?
    };
    require(
        !rows.iter().any(|r| r["organizationId"] == removed),
        "Removed or ungranted organization still exposed collections",
    )?;
    let selected = rows
        .iter()
        .filter(|r| r["organizationId"] == sibling.id)
        .collect::<Vec<_>>();
    require(
        selected.len() == 1
            && selected[0]["id"] == sibling.collection_id
            && selected[0]["name"] == sibling.body["collectionName"],
        "Removal changed sibling collection",
    )?;
    if sync {
        require(
            selected[0]["readOnly"] == false
                && selected[0]["hidePasswords"] == false
                && selected[0]["manage"] == true,
            "Removal changed sibling Admin access",
        )?;
    }
    let plain = fixture::decrypt(text(&selected[0]["name"])?, &sibling.key)
        .map_err(|_| Error("Sibling collection MAC/decrypt failed"))?;
    require(
        plain == organization_owner::COLLECTION_NAME.as_bytes(),
        "Removal changed sibling collection plaintext",
    )
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    members: Vec<Value>,
    original: Value,
    role_rows: Vec<Value>,
    keys: Vec<String>,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":4,"registrationHttpRequests":8,"cliRemovalCallerClaimed":false,"capturedRouteTrace":false,"smtpEnabled":false}),
        )
    }
    fn lists(&mut self) -> Result<Vec<Value>, Error> {
        let mut rows = Vec::new();
        for i in 0..3 {
            rows.push(canonical(self.http.json(
                &organization_invites::member_path(&self.orgs[i].id),
                &self.accounts[usize::from(i == 2)].token,
            )?)?);
        }
        Ok(rows)
    }
    fn stable_snapshot(&mut self) -> Result<Value, Error> {
        let owner = self
            .http
            .json("/api/accounts/profile", &self.accounts[0].token)?;
        let recipient = self
            .http
            .json("/api/accounts/profile", &self.accounts[1].token)?;
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
        Ok(
            json!({"ownerOrganizations":owner["organizations"],"ownerOrganizationsNew":owner["organizationsNew"],"sibling":single::org_in(&recipient,"organizations",&self.orgs[1].id)?,"foreign":single::org_in(&recipient,"organizations",&self.orgs[2].id)?,"orgs":orgs,"collections":collections}),
        )
    }
    fn readonly(&mut self) -> Result<(), Error> {
        for i in 0..2 {
            require(
                self.http.owner.personal(&self.accounts[i].token)? == self.personal[i]
                    && self.http.owner.revision(&self.accounts[i].token)? == self.revisions[i],
                "Member removal changed personal account, vault or unexpected revision",
            )?;
        }
        require(
            self.stable_snapshot()? == self.stable && self.lists()? == self.members,
            "Member removal changed unexpected membership, sibling or foreign state",
        )
    }
    fn bump_recipient(&mut self) -> Result<(), Error> {
        let rev = self.http.owner.revision(&self.accounts[1].token)?;
        require(
            rev != self.revisions[1],
            "Member mutation did not advance recipient revision",
        )?;
        self.revisions[1] = rev;
        Ok(())
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let id = text(&s.original["id"])?.to_owned();
    let p = path(&org, &id);
    let a = s.accounts[0].token.clone();
    let b = s.accounts[1].token.clone();
    for token in [None, Some("invalid-removal-bearer"), Some(b.as_str())] {
        s.http
            .raw(Method::DELETE, &p, token, Some(b"{"), None)?
            .rejected(401)?;
    }
    for (p, status) in [
        (path("bad.id", &id), 401),
        (format!("{}?organizationId={org}", path("bad.id", &id)), 422),
        (path(&org, "bad.id"), 422),
        (format!("{}?memberId={id}", path(&org, "bad.id")), 422),
    ] {
        s.http
            .raw(Method::DELETE, &p, Some(&a), Some(b"{"), None)?
            .rejected(status)?;
    }
    for method in [Method::POST, Method::PATCH] {
        s.http
            .raw(method, &p, Some(&a), None, None)?
            .rejected(404)?;
    }
    let row = s.http.json(
        &format!("{p}?includeCollections=true&includeGroups=true"),
        &a,
    )?;
    require(
        row == s.original,
        "Existing member read differed before removal",
    )?;
    s.readonly()
}
fn scope(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let token = s.accounts[0].token.clone();
    let absent = Uuid::new_v4().to_string();
    let foreign =
        organization_invites::member(&s.members[2], text(&s.accounts[1].fixture["email"])?)?["id"]
            .clone();
    let owner =
        organization_invites::member(&s.members[0], text(&s.accounts[0].fixture["email"])?)?["id"]
            .clone();
    for id in [&absent, text(&foreign)?, s.accounts[1].user_id.as_str()] {
        s.http
            .raw(Method::DELETE, &path(&org, id), Some(&token), None, None)?
            .error(MISSING)?;
    }
    s.http
        .raw(
            Method::DELETE,
            &path(&org, text(&owner)?),
            Some(&token),
            None,
            None,
        )?
        .error("Can't delete the last owner")?;
    s.http
        .raw(
            Method::DELETE,
            &path(&s.orgs[2].id, text(&s.original["id"])?),
            Some(&token),
            None,
            None,
        )?
        .rejected(401)?;
    s.http
        .raw(
            Method::DELETE,
            &format!("{}?organizationId={}", path(&org, &absent), s.orgs[2].id),
            Some(&token),
            None,
            None,
        )?
        .error(MISSING)?;
    s.readonly()
}
fn hierarchy(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[1].id.clone();
    let token = s.accounts[1].token.clone();
    let owner =
        organization_invites::member(&s.members[1], text(&s.accounts[0].fixture["email"])?)?["id"]
            .clone();
    let admin =
        organization_invites::member(&s.members[1], text(&s.accounts[1].fixture["email"])?)?["id"]
            .clone();
    for id in [text(&s.role_rows[1]["id"])?, text(&owner)?, text(&admin)?] {
        s.http
            .raw(Method::DELETE, &path(&org, id), Some(&token), None, None)?
            .error(OWNER_ONLY)?;
    }
    for (index, body) in [
        (0, b"{malformed".as_slice()),
        (2, b"\xffignored".as_slice()),
    ] {
        let id = text(&s.role_rows[index]["id"])?.to_owned();
        s.http
            .raw(
                Method::DELETE,
                &path(&org, &id),
                Some(&token),
                Some(body),
                Some("application/problem+json"),
            )?
            .empty()?;
        omit_member(&mut s.members[1], &id)?;
    }
    s.readonly()
}
fn remove(s: &mut Suite) -> Result<(), Error> {
    let id = text(&s.original["id"])?.to_owned();
    let org = s.orgs[0].id.clone();
    let p = format!(
        "{}?organizationId={}&memberId=ignored",
        path(&org, &id),
        s.orgs[2].id
    );
    s.http
        .raw(
            Method::DELETE,
            &p,
            Some(&s.accounts[0].token),
            Some(b"\xffignored"),
            Some("application/json"),
        )?
        .empty()?;
    omit_member(&mut s.members[0], &id)?;
    s.bump_recipient()?;
    let profile = s.http.json("/api/accounts/profile", &s.accounts[1].token)?;
    absent(&profile, &org)?;
    require(
        single::org_in(&profile, "organizations", &s.orgs[1].id)?
            .is_some_and(|o| o["key"] == s.keys[1]),
        "Removal lost sibling key",
    )?;
    let value = s.http.json("/api/collections", &s.accounts[1].token)?;
    visible(&value, &org, &s.orgs[1], false)?;
    let value = s.http.json("/api/sync", &s.accounts[1].token)?;
    absent(&value["profile"], &org)?;
    visible(&value, &org, &s.orgs[1], true)?;
    s.http
        .raw(
            Method::DELETE,
            &path(&org, &id),
            Some(&s.accounts[0].token),
            None,
            None,
        )?
        .error(MISSING)?;
    s.readonly()
}
fn rejoin(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let email = text(&s.accounts[1].fixture["email"])?.to_owned();
    organization_invites::invite_owner(
        &mut s.http.owner,
        &org,
        &s.accounts[0].token,
        &single::invitation(&email, 2, None),
    )?;
    let list = canonical(s.http.json(
        &organization_invites::member_path(&org),
        &s.accounts[0].token,
    )?)?;
    let row = organization_invites::member(&list, &email)?.clone();
    let id = text(&row["id"])?.to_owned();
    require(
        id != text(&s.original["id"])? && Uuid::parse_str(&id).is_ok(),
        "Reinvite reused removed membership identity",
    )?;
    let mut expected = s.original.clone();
    expected["id"] = json!(id);
    expected["status"] = json!(1);
    expected["collections"] = json!([]);
    require(
        row == expected,
        "Reinvite changed retained account identity or restored grants",
    )?;
    s.members[0]["data"]
        .as_array_mut()
        .ok_or(Error("Reinvite expected list missing"))?
        .push(expected);
    s.members[0] = canonical(s.members[0].clone())?;
    s.bump_recipient()?;
    let profile = s.http.json("/api/accounts/profile", &s.accounts[1].token)?;
    require(
        single::org_in(&profile, "organizations", &org)?.is_none()
            && single::org_in(&profile, "organizationsNew", &org)?.is_some_and(|o| o["key"] == ""),
        "Reinvite retained confirmed key/status",
    )?;
    s.http
        .post(
            &single::path(&org, &id),
            &s.accounts[0].token,
            &json!({"key":s.keys[0]}),
        )?
        .empty()?;
    let rows = s.members[0]["data"]
        .as_array_mut()
        .ok_or(Error("Reconfirm expected list missing"))?;
    rows.iter_mut()
        .find(|r| r["id"] == id)
        .ok_or(Error("Reconfirm expected member missing"))?["status"] = json!(2);
    s.bump_recipient()?;
    let profile = s.http.json("/api/accounts/profile", &s.accounts[1].token)?;
    require(
        single::org_in(&profile, "organizations", &org)?.is_some_and(|o| o["key"] == s.keys[0]),
        "Reconfirm failed to restore only organization key",
    )?;
    let value = s.http.json("/api/collections", &s.accounts[1].token)?;
    visible(&value, &org, &s.orgs[1], false)?;
    let value = s.http.json("/api/sync", &s.accounts[1].token)?;
    visible(&value, &org, &s.orgs[1], true)?;
    s.http
        .raw(
            Method::DELETE,
            &path(&org, text(&s.original["id"])?),
            Some(&s.accounts[0].token),
            None,
            None,
        )?
        .error(MISSING)?;
    s.readonly()
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for i in 0..2 {
        let value = s.http.refresh(&s.accounts[i].refresh)?;
        let token = text(&value["access_token"])?;
        let profile = s.http.json("/api/accounts/profile", token)?;
        require(
            profile["id"] == s.accounts[i].user_id,
            "Member removal refresh changed retained account",
        )?;
        let cipher = s
            .http
            .json(&format!("/api/ciphers/{}", s.accounts[i].cipher_id), token)?;
        let key = fixture::fixture_user_key(&s.accounts[i].fixture, &s.accounts[i].password)
            .map_err(|_| Error("Removal personal key unwrap failed"))?;
        let plain = fixture::decrypt(text(&cipher["notes"])?, &key)
            .map_err(|_| Error("Removal personal note MAC failed"))?;
        require(
            plain == organization_owner::NOTE.as_bytes(),
            "Removal changed retained personal plaintext",
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
    single::hidden_collection(&mut http.owner, &a, &org)?;
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
    for role in [2, 3] {
        let email = format!("removal-role-{}@example.test", Uuid::new_v4());
        let document = fixture::registration(&email, &Uuid::new_v4().to_string(), 600000)
            .map_err(|_| Error("Removal role fixture creation failed"))?;
        fixture::register_modern_fixture(&http.owner.server, &document)
            .map_err(|_| Error("Removal role registration failed"))?;
        organization_invites::invite_owner(
            &mut http.owner,
            &sibling.id,
            &a.token,
            &single::invitation(&email, role, Some(&sibling.collection_id)),
        )?;
        emails.push(email);
    }
    let stub = format!("removal-invited-{}@example.test", Uuid::new_v4());
    organization_invites::invite_owner(
        &mut http.owner,
        &sibling.id,
        &a.token,
        &single::invitation(&stub, 2, Some(&sibling.collection_id)),
    )?;
    let first = single::member_row(
        &mut http.owner,
        &org.id,
        &a.token,
        text(&b.fixture["email"])?,
    )?;
    let second = single::member_row(
        &mut http.owner,
        &sibling.id,
        &a.token,
        text(&b.fixture["email"])?,
    )?;
    let keys = vec![
        confirm_fixture_member(
            &mut http.owner,
            &org,
            text(&first["id"])?,
            &a.token,
            &b.fixture,
        )?,
        confirm_fixture_member(
            &mut http.owner,
            &sibling,
            text(&second["id"])?,
            &a.token,
            &b.fixture,
        )?,
    ];
    let mut s = Suite {
        http,
        accounts: vec![a, b],
        orgs: vec![org, sibling, foreign],
        members: Vec::new(),
        original: Value::Null,
        role_rows: Vec::new(),
        keys,
        personal: Vec::new(),
        revisions: Vec::new(),
        stable: Value::Null,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_MEMBER_REMOVAL_RECEIPT")?,
        finished: false,
    };
    s.members = s.lists()?;
    s.original =
        organization_invites::member(&s.members[0], text(&s.accounts[1].fixture["email"])?)?
            .clone();
    require(
        s.original["status"] == 2,
        "Removal fixture was not confirmed",
    )?;
    for email in [&emails[0], &emails[1], &stub] {
        s.role_rows
            .push(organization_invites::member(&s.members[1], email)?.clone());
    }
    require(
        s.role_rows[0]["status"] == 1
            && s.role_rows[1]["type"] == 4
            && s.role_rows[2]["status"] == 0,
        "Removal fixture user states differed",
    )?;
    for account in &s.accounts {
        s.personal.push(s.http.owner.personal(&account.token)?);
        s.revisions.push(s.http.owner.revision(&account.token)?);
    }
    s.stable = s.stable_snapshot()?;
    s.receipt("running")?;
    for (name, case) in CASES {
        eprintln!("Organization member removal case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 2
            && s.passed.len() == CASE_COUNT,
        "Member removal request budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-member-removal: {CASE_COUNT} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revoked_projection_rejects_duplicate_or_still_confirmed_profile_membership() {
        let profile = json!({"organizations":[],"organizationsNew":[]});
        assert!(absent(&profile, "removed").is_ok());
        for field in ["organizations", "organizationsNew"] {
            let mut leaked = profile.clone();
            leaked[field] = json!([{"id":"removed","key":""}]);
            assert!(absent(&leaked, "removed").is_err());
        }
    }
}
