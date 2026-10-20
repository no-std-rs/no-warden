//! Independently authored MIT/Apache-2.0 member revoke/restore wire contracts.
//! No CLI mutation caller, bulk operation, SMTP, notification or policy-admin claim.
use crate::{
    fixture,
    organization_collections::{self, create_organization},
    organization_confirmations as single, organization_invites,
    organization_member_removal as removal,
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
// Setup47 + guards48 + errors37 + confirmed42 + hierarchy35 + invited29 + preservation27.
pub const HTTP_REQUEST_COUNT: usize = 265;
const ROUTES: [&str; 3] = ["revoke", "restore", "restore/vnext"];
const MISSING: &str = "User not found in organization";
const REVOKED: &str = "User is already revoked";
const ACTIVE: &str = "User is already active";
const SELF_REVOKE: &str = "You cannot revoke yourself";
const OWNER_REVOKE: &str = "Only owners can revoke other owners";
const OWNER_RESTORE: &str = "Only owners can restore other owners";
const LAST_OWNER: &str = "Organization must have at least one confirmed owner";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_member_status_authentication_path_and_bodyless_guards",
        guards,
    ),
    (
        "organization_member_status_scoped_errors_self_and_owner_order",
        errors,
    ),
    (
        "organization_member_status_confirmed_key_hiding_and_restore_aliases",
        confirmed,
    ),
    (
        "organization_member_status_admin_peer_and_owner_hierarchy",
        hierarchy,
    ),
    (
        "organization_member_status_invited_noop_restore_and_state_recovery",
        invited,
    ),
    (
        "organization_member_status_preserved_accounts_keys_grants_and_sessions",
        preservation,
    ),
];
pub(crate) fn path(org: &str, member: &str, action: &str) -> String {
    format!("/api/organizations/{org}/users/{member}/{action}")
}
pub(crate) fn put_fixture_status(
    http: &mut OwnerHttp,
    org: &str,
    member: &str,
    action: &str,
    actor: &str,
) -> Result<(), Error> {
    http.requests += 1;
    Http::read(
        http_client()?
            .put(format!("{}{}", http.server, path(org, member, action)))
            .bearer_auth(actor)
            .header("Content-Type", "application/problem+json")
            .body(b"\xffignored invalid JSON".to_vec())
            .send()
            .map_err(|_| Error("Member status mutation failed"))?,
    )?
    .empty()
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

fn canonical(mut list: Value) -> Result<Value, Error> {
    crate::organization_members::rows(&list)?;
    list["data"]
        .as_array_mut()
        .ok_or(Error("Removal member list missing"))?
        .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(list)
}

struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    members: Vec<Value>,
    original: Value,
    roles: Vec<Value>,
    keys: Vec<String>,
    hidden: String,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":5,"registrationHttpRequests":10,"cliMutationCallerClaimed":false,"capturedRouteTrace":false,"invitedRevisionHttpClaimed":false,"smtpEnabled":false}),
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
            json!({"ownerOrganizations":owner["organizations"],"ownerOrganizationsNew":owner["organizationsNew"],"sibling":single::org_in(&recipient,"organizations",&self.orgs[1].id)?,"foreign":single::org_in(&recipient,"organizations",&self.orgs[2].id)?,"organizations":orgs,"collections":collections}),
        )
    }
    fn readonly(&mut self) -> Result<(), Error> {
        for i in 0..2 {
            require(
                self.http.owner.personal(&self.accounts[i].token)? == self.personal[i]
                    && self.http.owner.revision(&self.accounts[i].token)? == self.revisions[i],
                "Member status changed personal account, payloads or unexpected revision",
            )?;
        }
        require(
            self.stable_snapshot()? == self.stable && self.lists()? == self.members,
            "Member status changed unexpected grants, membership or foreign/sibling authority",
        )
    }
    fn status(&mut self, group: usize, id: &str, status: i64) -> Result<(), Error> {
        let rows = self.members[group]["data"]
            .as_array_mut()
            .ok_or(Error("Status expected member list missing"))?;
        let row = rows
            .iter_mut()
            .find(|r| r["id"] == id)
            .ok_or(Error("Status expected member missing"))?;
        row["status"] = json!(status);
        Ok(())
    }
    fn detail(&mut self, group: usize, id: &str) -> Result<(), Error> {
        let value = self.http.json(
            &format!(
                "/api/organizations/{}/users/{id}?includeCollections=true&includeGroups=true",
                self.orgs[group].id
            ),
            &self.accounts[0].token,
        )?;
        let expected = self.members[group]["data"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["id"] == id))
            .ok_or(Error("Status expected detail missing"))?;
        require(
            value == *expected,
            "Status transition changed membership identity, role or grants",
        )
    }
    fn mutate(
        &mut self,
        actor: usize,
        group: usize,
        id: &str,
        action: &str,
        status: i64,
    ) -> Result<(), Error> {
        put_fixture_status(
            &mut self.http.owner,
            &self.orgs[group].id,
            id,
            action,
            &self.accounts[actor].token,
        )?;
        self.status(group, id, status)
    }
    fn error(
        &mut self,
        actor: usize,
        group: usize,
        id: &str,
        action: &str,
        message: &str,
    ) -> Result<(), Error> {
        self.http
            .raw(
                Method::PUT,
                &path(&self.orgs[group].id, id, action),
                Some(&self.accounts[actor].token),
                Some(b"{ignored"),
                None,
            )?
            .error(message)
    }
    fn bump_recipient(&mut self) -> Result<(), Error> {
        let rev = self.http.owner.revision(&self.accounts[1].token)?;
        require(
            rev != self.revisions[1],
            "Status transition did not advance recipient revision",
        )?;
        self.revisions[1] = rev;
        Ok(())
    }
    fn unchanged_recipient(&mut self) -> Result<(), Error> {
        require(
            self.http.owner.revision(&self.accounts[1].token)? == self.revisions[1],
            "Rejected status transition changed recipient revision",
        )
    }
    fn revoked_views(&mut self) -> Result<(), Error> {
        let profile = self
            .http
            .json("/api/accounts/profile", &self.accounts[1].token)?;
        removal::absent(&profile, &self.orgs[0].id)?;
        let collections = self
            .http
            .json("/api/collections", &self.accounts[1].token)?;
        removal::visible(&collections, &self.orgs[0].id, &self.orgs[1], false)?;
        let sync = self.http.json("/api/sync", &self.accounts[1].token)?;
        removal::absent(&sync["profile"], &self.orgs[0].id)?;
        removal::visible(&sync, &self.orgs[0].id, &self.orgs[1], true)
    }
    fn confirmed_views(&mut self) -> Result<(), Error> {
        let profile = self
            .http
            .json("/api/accounts/profile", &self.accounts[1].token)?;
        require(
            single::org_in(&profile, "organizations", &self.orgs[0].id)?
                .is_some_and(|o| o["key"] == self.keys[0]),
            "Restored membership lost original wrapped organization key",
        )?;
        let collections = self
            .http
            .json("/api/collections", &self.accounts[1].token)?;
        single::selective(&collections, &self.orgs[0], &self.hidden, false)?;
        let sync = self.http.json("/api/sync", &self.accounts[1].token)?;
        single::selective(&sync, &self.orgs[0], &self.hidden, true)
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let member = text(&s.original["id"])?.to_owned();
    let a = s.accounts[0].token.clone();
    let b = s.accounts[1].token.clone();
    for action in ROUTES {
        let p = path(&org, &member, action);
        for token in [None, Some("invalid-status-bearer"), Some(b.as_str())] {
            s.http
                .raw(
                    Method::PUT,
                    &p,
                    token,
                    Some(b"\xffignored"),
                    Some("application/json"),
                )?
                .rejected(401)?;
        }
        for (p, status) in [
            (path("bad.id", &member, action), 401),
            (
                format!("{}?organizationId={org}", path("bad.id", &member, action)),
                422,
            ),
            (path(&org, "bad.id", action), 422),
            (
                format!("{}?memberId={member}", path(&org, "bad.id", action)),
                422,
            ),
        ] {
            s.http
                .raw(Method::PUT, &p, Some(&a), Some(b"{ignored"), None)?
                .rejected(status)?;
        }
        for method in [Method::POST, Method::PATCH] {
            s.http
                .raw(method, &p, Some(&a), None, None)?
                .rejected(404)?;
        }
    }
    s.readonly()
}
fn errors(s: &mut Suite) -> Result<(), Error> {
    let missing = Uuid::new_v4().to_string();
    let foreign =
        organization_invites::member(&s.members[2], text(&s.accounts[1].fixture["email"])?)?["id"]
            .clone();
    let owner =
        organization_invites::member(&s.members[0], text(&s.accounts[0].fixture["email"])?)?["id"]
            .clone();
    let admin =
        organization_invites::member(&s.members[1], text(&s.accounts[1].fixture["email"])?)?["id"]
            .clone();
    let user_id = s.accounts[1].user_id.clone();
    for action in ROUTES {
        for id in [&missing, text(&foreign)?, &user_id] {
            s.error(0, 0, id, action, MISSING)?;
        }
    }
    s.error(0, 0, text(&owner)?, "revoke", SELF_REVOKE)?;
    s.error(0, 0, text(&owner)?, "restore", ACTIVE)?;
    s.error(1, 1, text(&admin)?, "revoke", SELF_REVOKE)?;
    s.error(1, 1, text(&admin)?, "restore/vnext", ACTIVE)?;
    for index in [4, 5] {
        s.error(
            0,
            0,
            text(&s.roles[index]["id"])?.to_owned().as_str(),
            "revoke",
            LAST_OWNER,
        )?;
    }
    s.http
        .raw(
            Method::PUT,
            &format!(
                "{}?organizationId={}",
                path(&s.orgs[0].id, &missing, "revoke"),
                s.orgs[2].id
            ),
            Some(&s.accounts[0].token),
            None,
            None,
        )?
        .error(MISSING)?;
    s.readonly()
}
fn confirmed(s: &mut Suite) -> Result<(), Error> {
    let id = text(&s.original["id"])?.to_owned();
    s.mutate(0, 0, &id, "revoke", -1)?;
    s.bump_recipient()?;
    s.revoked_views()?;
    s.error(0, 0, &id, "revoke", REVOKED)?;
    s.unchanged_recipient()?;
    s.mutate(0, 0, &id, "restore/vnext", 2)?;
    s.bump_recipient()?;
    s.confirmed_views()?;
    s.error(0, 0, &id, "restore", ACTIVE)?;
    s.unchanged_recipient()?;
    s.mutate(0, 0, &id, "revoke", -1)?;
    s.bump_recipient()?;
    s.mutate(0, 0, &id, "restore", 2)?;
    s.bump_recipient()?;
    s.confirmed_views()?;
    s.readonly()
}
fn hierarchy(s: &mut Suite) -> Result<(), Error> {
    for index in [2, 1] {
        let id = text(&s.roles[index]["id"])?.to_owned();
        s.mutate(1, 1, &id, "revoke", -1)?;
        s.detail(1, &id)?;
        s.mutate(1, 1, &id, "restore/vnext", 1)?;
        s.detail(1, &id)?;
    }
    let owner = text(&s.roles[0]["id"])?.to_owned();
    s.error(1, 1, &owner, "revoke", OWNER_REVOKE)?;
    s.mutate(0, 1, &owner, "revoke", -1)?;
    s.detail(1, &owner)?;
    s.error(1, 1, &owner, "restore/vnext", OWNER_RESTORE)?;
    s.mutate(0, 1, &owner, "restore", 2)?;
    s.detail(1, &owner)?;
    s.readonly()
}
fn invited(s: &mut Suite) -> Result<(), Error> {
    let id = text(&s.roles[3]["id"])?.to_owned();
    for action in ["restore", "restore/vnext"] {
        s.mutate(0, 1, &id, action, 0)?;
        s.detail(1, &id)?;
    }
    s.mutate(0, 1, &id, "revoke", -1)?;
    s.detail(1, &id)?;
    s.mutate(0, 1, &id, "restore/vnext", 0)?;
    s.detail(1, &id)?;
    s.readonly()
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for i in 0..2 {
        let value = s.http.refresh(&s.accounts[i].refresh)?;
        let token = text(&value["access_token"])?;
        let profile = s.http.json("/api/accounts/profile", token)?;
        require(
            profile["id"] == s.accounts[i].user_id,
            "Status transition refresh changed account identity",
        )?;
        let cipher = s
            .http
            .json(&format!("/api/ciphers/{}", s.accounts[i].cipher_id), token)?;
        let key = fixture::fixture_user_key(&s.accounts[i].fixture, &s.accounts[i].password)
            .map_err(|_| Error("Status personal key unwrap failed"))?;
        let plain = fixture::decrypt(text(&cipher["notes"])?, &key)
            .map_err(|_| Error("Status personal note MAC failed"))?;
        require(
            plain == organization_owner::NOTE.as_bytes(),
            "Status transition changed personal plaintext",
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
    let mut documents = Vec::new();
    for role in [0, 3, 1] {
        let email = format!("member-status-role-{}@example.test", Uuid::new_v4());
        let document = fixture::registration(&email, &Uuid::new_v4().to_string(), 600000)
            .map_err(|_| Error("Status role fixture creation failed"))?;
        fixture::register_modern_fixture(&http.owner.server, &document)
            .map_err(|_| Error("Status role registration failed"))?;
        organization_invites::invite_owner(
            &mut http.owner,
            &sibling.id,
            &a.token,
            &single::invitation(&email, role, Some(&sibling.collection_id)),
        )?;
        documents.push(document);
    }
    let c_email = text(&documents[0]["email"])?.to_owned();
    organization_invites::invite_owner(
        &mut http.owner,
        &org.id,
        &a.token,
        &single::invitation(&c_email, 0, None),
    )?;
    let invited = format!("member-status-invited-{}@example.test", Uuid::new_v4());
    let owner_invited = format!(
        "member-status-owner-invited-{}@example.test",
        Uuid::new_v4()
    );
    organization_invites::invite_owner(
        &mut http.owner,
        &sibling.id,
        &a.token,
        &single::invitation(&invited, 2, Some(&sibling.collection_id)),
    )?;
    organization_invites::invite_owner(
        &mut http.owner,
        &org.id,
        &a.token,
        &single::invitation(&owner_invited, 0, None),
    )?;
    let before = http.owner.json(
        Method::GET,
        &organization_invites::member_path(&org.id),
        &a.token,
        None,
    )?;
    let side = http.owner.json(
        Method::GET,
        &organization_invites::member_path(&sibling.id),
        &a.token,
        None,
    )?;
    let first = organization_invites::member(&before, text(&b.fixture["email"])?)?;
    let second = organization_invites::member(&side, text(&b.fixture["email"])?)?;
    let c = organization_invites::member(&side, &c_email)?;
    let keys = vec![
        removal::confirm_fixture_member(
            &mut http.owner,
            &org,
            text(&first["id"])?,
            &a.token,
            &b.fixture,
        )?,
        removal::confirm_fixture_member(
            &mut http.owner,
            &sibling,
            text(&second["id"])?,
            &a.token,
            &b.fixture,
        )?,
        removal::confirm_fixture_member(
            &mut http.owner,
            &sibling,
            text(&c["id"])?,
            &a.token,
            &documents[0],
        )?,
    ];
    let mut s = Suite {
        http,
        accounts: vec![a, b],
        orgs: vec![org, sibling, foreign],
        members: Vec::new(),
        original: Value::Null,
        roles: Vec::new(),
        keys,
        hidden: text(&hidden["id"])?.to_owned(),
        personal: Vec::new(),
        revisions: Vec::new(),
        stable: Value::Null,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_MEMBER_STATUS_RECEIPT")?,
        finished: false,
    };
    s.members = s.lists()?;
    s.original =
        organization_invites::member(&s.members[0], text(&s.accounts[1].fixture["email"])?)?
            .clone();
    for document in &documents {
        s.roles
            .push(organization_invites::member(&s.members[1], text(&document["email"])?)?.clone());
    }
    s.roles
        .push(organization_invites::member(&s.members[1], &invited)?.clone());
    s.roles
        .push(organization_invites::member(&s.members[0], &c_email)?.clone());
    s.roles
        .push(organization_invites::member(&s.members[0], &owner_invited)?.clone());
    require(
        s.original["status"] == 2
            && s.roles[0]["status"] == 2
            && s.roles[1]["type"] == 4
            && s.roles[2]["type"] == 1
            && s.roles[3]["status"] == 0
            && s.roles[4]["status"] == 1
            && s.roles[5]["status"] == 0,
        "Status fixture roles or states differed",
    )?;
    for account in &s.accounts {
        s.personal.push(s.http.owner.personal(&account.token)?);
        s.revisions.push(s.http.owner.revision(&account.token)?);
    }
    s.stable = s.stable_snapshot()?;
    s.receipt("running")?;
    for (name, case) in CASES {
        eprintln!("Organization member status case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 2
            && s.passed.len() == CASE_COUNT,
        "Member status request budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-member-status: {CASE_COUNT} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
