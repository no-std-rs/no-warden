//! Independently authored MIT/Apache-2.0 ordered bulk member-removal contracts.
//! The official CLI observes direct-HTTP removals; no bulk CLI caller is claimed.
use crate::{
    fixture, organization_bulk_confirmations as projection,
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
// Setup53 + guards50 + ordered29 + hierarchy25 + cached-self30 + rejoin34 + preservation30.
pub const HTTP_REQUEST_COUNT: usize = 251;
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_bulk_member_removal_authentication_and_whole_batch_guards",
        guards,
    ),
    (
        "organization_bulk_member_removal_ordered_duplicates_and_opaque_ids",
        ordered,
    ),
    (
        "organization_bulk_member_removal_admin_hierarchy_and_user_states",
        hierarchy,
    ),
    (
        "organization_bulk_member_removal_cached_authority_after_actor_self_removal",
        cached_self,
    ),
    (
        "organization_bulk_member_removal_rejoin_without_stale_collection_grants",
        rejoin,
    ),
    (
        "organization_bulk_member_removal_preserved_accounts_keys_and_sessions",
        preservation,
    ),
];
const MISSING: &str = "User to delete isn't member of the organization";
const OWNER_ONLY: &str = "Only Owners can delete Admins or Owners";
const LAST_OWNER: &str = "Can't delete the last owner";
pub(crate) fn path(org: &str) -> String {
    format!("/api/organizations/{org}/users")
}
fn result(value: &Value, expected: &[(&str, &str)]) -> Result<(), Error> {
    projection::result(value, expected)
        .map_err(|_| Error("Bulk member removal ordered result differed"))
}
pub(crate) fn remove_members_probe(
    http: &mut OwnerHttp,
    org: &str,
    member: &str,
    actor: &str,
) -> Result<(), Error> {
    let missing = Uuid::new_v4().to_string();
    http.requests += 1;
    let reply = Http::read(
        http_client()?
            .delete(format!("{}{}", http.server, path(org)))
            .bearer_auth(actor)
            .json(&json!({"ids":[missing,member,member]}))
            .send()
            .map_err(|_| Error("Bulk removal observer setup failed"))?,
    )?
    .status(200)?
    .json()?;
    result(
        &reply,
        &[(&missing, MISSING), (member, ""), (member, MISSING)],
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

impl Http {
    fn batch(&mut self, org: &str, token: &str, body: &Value) -> Result<Value, Error> {
        self.raw(
            Method::DELETE,
            &path(org),
            Some(token),
            Some(body.to_string().as_bytes()),
            Some("application/json"),
        )?
        .status(200)?
        .json()
    }
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
    actor_removed: bool,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":4,"registrationHttpRequests":8,"cliBulkRemovalCallerClaimed":false,"cachedActorAuthorityAfterSelfRemovalTested":true,"capturedRouteTrace":false,"smtpEnabled":false}),
        )
    }
    fn lists(&mut self) -> Result<Vec<Value>, Error> {
        let mut rows = Vec::new();
        for i in 0..4 {
            rows.push(canonical(self.http.json(
                &organization_invites::member_path(&self.orgs[i].id),
                &self.accounts[usize::from(i >= 2)].token,
            )?)?);
        }
        Ok(rows)
    }
    fn stable_snapshot(&mut self) -> Result<Value, Error> {
        let mut owner = self
            .http
            .json("/api/accounts/profile", &self.accounts[0].token)?;
        let recipient = self
            .http
            .json("/api/accounts/profile", &self.accounts[1].token)?;
        if self.actor_removed {
            removal::absent(&owner, &self.orgs[3].id)?;
        } else {
            require(
                single::org_in(&owner, "organizations", &self.orgs[3].id)?
                    .is_some_and(|o| o["type"] == 0 && o["key"] == self.orgs[3].body["key"]),
                "Bulk actor lost self-org Owner authority before intentional removal",
            )?;
        }
        // Only the self-org membership is intentionally removed from A in this matrix.
        for field in ["organizations", "organizationsNew"] {
            owner[field]
                .as_array_mut()
                .ok_or(Error("Bulk removal owner profile missing"))?
                .retain(|o| o["id"] != self.orgs[3].id);
        }
        let mut orgs = Vec::new();
        let mut collections = Vec::new();
        for i in 0..4 {
            let token = &self.accounts[usize::from(i >= 2)].token;
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
            json!({"ownerOrganizations":owner["organizations"],"ownerOrganizationsNew":owner["organizationsNew"],"sibling":single::org_in(&recipient,"organizations",&self.orgs[1].id)?,"foreign":single::org_in(&recipient,"organizations",&self.orgs[2].id)?,"remainingSelfOwner":single::org_in(&recipient,"organizations",&self.orgs[3].id)?,"orgs":orgs,"collections":collections}),
        )
    }
    fn readonly(&mut self) -> Result<(), Error> {
        for i in 0..2 {
            require(
                self.http.owner.personal(&self.accounts[i].token)? == self.personal[i]
                    && self.http.owner.revision(&self.accounts[i].token)? == self.revisions[i],
                "Bulk removal changed personal account, payloads or unexpected revision",
            )?;
        }
        require(
            self.stable_snapshot()? == self.stable && self.lists()? == self.members,
            "Bulk removal changed unexpected authority, sibling or foreign data",
        )
    }
    fn bump(&mut self, index: usize) -> Result<(), Error> {
        let rev = self.http.owner.revision(&self.accounts[index].token)?;
        require(
            rev != self.revisions[index],
            "Bulk member mutation did not advance target revision",
        )?;
        self.revisions[index] = rev;
        Ok(())
    }
    fn bump_recipient(&mut self) -> Result<(), Error> {
        self.bump(1)
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let token = s.accounts[0].token.clone();
    let recipient = s.accounts[1].token.clone();
    let p = path(&org);
    for bearer in [
        None,
        Some("invalid-bulk-removal-bearer"),
        Some(recipient.as_str()),
    ] {
        s.http
            .raw(Method::DELETE, &p, bearer, Some(b"{"), None)?
            .rejected(401)?;
    }
    for (p, status) in [
        (path("bad.id"), 401),
        (format!("{}?organizationId={org}", path("bad.id")), 422),
    ] {
        s.http
            .raw(Method::DELETE, &p, Some(&token), Some(b"{"), None)?
            .rejected(status)?;
    }
    let invalids: Vec<(Vec<u8>, u16)> = vec![
        (b"{}".to_vec(), 422),
        (br#"{"ids":null}"#.to_vec(), 422),
        (br#"{"ids":true}"#.to_vec(), 422),
        (br#"{"ids":"raw"}"#.to_vec(), 422),
        (br#"{"ids":{}}"#.to_vec(), 422),
        (br#"{"ids":[null]}"#.to_vec(), 422),
        (br#"{"ids":[1]}"#.to_vec(), 422),
        (br#"{"ids":[[]]}"#.to_vec(), 422),
        (br#"{"ids":[],"ids":[]}"#.to_vec(), 422),
        (b"[]".to_vec(), 422),
        (b"[[],0]".to_vec(), 400),
        (b"{".to_vec(), 400),
        (b"{\"ids\":[],\"ignored\":\"\xff\"}".to_vec(), 400),
        (br#"{"Ids":[]}"#.to_vec(), 422),
    ];
    for (body, status) in invalids {
        s.http
            .raw(
                Method::DELETE,
                &p,
                Some(&token),
                Some(&body),
                Some("application/json"),
            )?
            .rejected(status)?;
    }
    // Both logged-in accounts would mutate if any entry ran before whole-body decoding.
    let actor =
        organization_invites::member(&s.members[3], text(&s.accounts[0].fixture["email"])?)?["id"]
            .clone();
    for (group, first) in [
        (&s.orgs[0].id, s.original["id"].clone()),
        (&s.orgs[3].id, actor),
    ] {
        let body = json!({"ids":[first,42]});
        s.http
            .raw(
                Method::DELETE,
                &path(group),
                Some(&token),
                Some(body.to_string().as_bytes()),
                Some("application/json"),
            )?
            .rejected(422)?;
    }
    let value = s
        .http
        .raw(Method::DELETE, &p, Some(&token), Some(b"[[]]"), None)?
        .status(200)?
        .json()?;
    result(&value, &[])?;
    for method in [Method::POST, Method::PUT, Method::PATCH] {
        s.http
            .raw(method, &p, Some(&token), None, None)?
            .rejected(404)?;
    }
    let value = canonical(s.http.json(
        &format!("{p}?includeCollections=true&includeGroups=true"),
        &token,
    )?)?;
    require(
        value == s.members[0],
        "Bulk path GET member list projection differed",
    )?;
    s.readonly()
}
fn ordered(s: &mut Suite) -> Result<(), Error> {
    let id = text(&s.original["id"])?.to_owned();
    let later = text(&s.role_rows[3]["id"])?.to_owned();
    let foreign =
        organization_invites::member(&s.members[2], text(&s.accounts[1].fixture["email"])?)?["id"]
            .clone();
    let owner =
        organization_invites::member(&s.members[0], text(&s.accounts[0].fixture["email"])?)?["id"]
            .clone();
    let missing = Uuid::new_v4().to_string();
    let raw = "opaque 雪\0not-a-UUID";
    let ids = json!({"ids":[id,id,missing,foreign,"",raw,later,owner],"owner":"ignored"});
    let value = s.http.batch(&s.orgs[0].id, &s.accounts[0].token, &ids)?;
    result(
        &value,
        &[
            (&id, ""),
            (&id, MISSING),
            (&missing, MISSING),
            (text(&foreign)?, MISSING),
            ("", MISSING),
            (raw, MISSING),
            (&later, ""),
            (text(&owner)?, LAST_OWNER),
        ],
    )?;
    omit_member(&mut s.members[0], &id)?;
    omit_member(&mut s.members[0], &later)?;
    s.bump_recipient()?;
    let profile = s.http.json("/api/accounts/profile", &s.accounts[1].token)?;
    removal::absent(&profile, &s.orgs[0].id)?;
    let value = s.http.json("/api/collections", &s.accounts[1].token)?;
    removal::visible(&value, &s.orgs[0].id, &s.orgs[1], false)?;
    let value = s.http.json("/api/sync", &s.accounts[1].token)?;
    removal::absent(&value["profile"], &s.orgs[0].id)?;
    removal::visible(&value, &s.orgs[0].id, &s.orgs[1], true)?;
    s.readonly()
}
fn hierarchy(s: &mut Suite) -> Result<(), Error> {
    let owner =
        organization_invites::member(&s.members[1], text(&s.accounts[0].fixture["email"])?)?["id"]
            .clone();
    let admin =
        organization_invites::member(&s.members[1], text(&s.accounts[1].fixture["email"])?)?["id"]
            .clone();
    let manager = text(&s.role_rows[1]["id"])?.to_owned();
    let user = text(&s.role_rows[0]["id"])?.to_owned();
    let stub = text(&s.role_rows[2]["id"])?.to_owned();
    let value = s.http.batch(
        &s.orgs[1].id,
        &s.accounts[1].token,
        &json!({"ids":[manager,owner,admin,user,stub,user]}),
    )?;
    result(
        &value,
        &[
            (&manager, OWNER_ONLY),
            (text(&owner)?, OWNER_ONLY),
            (text(&admin)?, OWNER_ONLY),
            (&user, ""),
            (&stub, ""),
            (&user, MISSING),
        ],
    )?;
    omit_member(&mut s.members[1], &user)?;
    omit_member(&mut s.members[1], &stub)?;
    s.readonly()
}
fn cached_self(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[3].id.clone();
    let a =
        organization_invites::member(&s.members[3], text(&s.accounts[0].fixture["email"])?)?["id"]
            .clone();
    let b =
        organization_invites::member(&s.members[3], text(&s.accounts[1].fixture["email"])?)?["id"]
            .clone();
    let user = text(&s.role_rows[4]["id"])?.to_owned();
    let missing = Uuid::new_v4().to_string();
    let value = s.http.batch(
        &org,
        &s.accounts[0].token,
        &json!({"ids":[a,missing,b,user]}),
    )?;
    result(
        &value,
        &[
            (text(&a)?, ""),
            (&missing, MISSING),
            (text(&b)?, LAST_OWNER),
            (&user, ""),
        ],
    )?;
    omit_member(&mut s.members[3], text(&a)?)?;
    omit_member(&mut s.members[3], &user)?;
    s.actor_removed = true;
    s.bump(0)?;
    let profile = s.http.json("/api/accounts/profile", &s.accounts[0].token)?;
    removal::absent(&profile, &org)?;
    s.http
        .raw(
            Method::GET,
            &organization_invites::member_path(&org),
            Some(&s.accounts[0].token),
            None,
            None,
        )?
        .rejected(401)?;
    let members = canonical(s.http.json(
        &organization_invites::member_path(&org),
        &s.accounts[1].token,
    )?)?;
    require(
        members == s.members[3],
        "Remaining Owner did not observe self-removal and later User deletion",
    )?;
    let profile = s.http.json("/api/accounts/profile", &s.accounts[1].token)?;
    require(
        single::org_in(&profile, "organizations", &org)?
            .is_some_and(|o| o["key"] == s.keys[2] && o["type"] == 0),
        "Self-removal changed remaining Owner key or role",
    )?;
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
    removal::visible(&value, &org, &s.orgs[1], false)?;
    let value = s.http.json("/api/sync", &s.accounts[1].token)?;
    removal::visible(&value, &org, &s.orgs[1], true)?;
    let old_id = text(&s.original["id"])?.to_owned();
    let value = s
        .http
        .batch(&org, &s.accounts[0].token, &json!({"ids":[old_id]}))?;
    result(&value, &[(&old_id, MISSING)])?;
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
    let self_org = create_organization(&mut http.owner, &a)?;
    single::hidden_collection(&mut http.owner, &a, &org)?;
    for (group, role, grant) in [
        (&org, 2, Some(org.collection_id.as_str())),
        (&sibling, 1, None),
        (&self_org, 0, None),
    ] {
        organization_invites::invite_owner(
            &mut http.owner,
            &group.id,
            &a.token,
            &single::invitation(text(&b.fixture["email"])?, role, grant),
        )?;
    }
    let mut emails = Vec::new();
    for role in [2, 3] {
        let email = format!("bulk-removal-role-{}@example.test", Uuid::new_v4());
        let document = fixture::registration(&email, &Uuid::new_v4().to_string(), 600000)
            .map_err(|_| Error("Bulk removal role fixture failed"))?;
        fixture::register_modern_fixture(&http.owner.server, &document)
            .map_err(|_| Error("Bulk removal role registration failed"))?;
        organization_invites::invite_owner(
            &mut http.owner,
            &sibling.id,
            &a.token,
            &single::invitation(&email, role, Some(&sibling.collection_id)),
        )?;
        emails.push(email);
    }
    for group in [&org, &self_org] {
        organization_invites::invite_owner(
            &mut http.owner,
            &group.id,
            &a.token,
            &single::invitation(&emails[0], 2, None),
        )?;
    }
    let stub = format!("bulk-removal-invited-{}@example.test", Uuid::new_v4());
    organization_invites::invite_owner(
        &mut http.owner,
        &sibling.id,
        &a.token,
        &single::invitation(&stub, 2, Some(&sibling.collection_id)),
    )?;
    let mut keys = Vec::new();
    for group in [&org, &sibling, &self_org] {
        let row = single::member_row(
            &mut http.owner,
            &group.id,
            &a.token,
            text(&b.fixture["email"])?,
        )?;
        keys.push(removal::confirm_fixture_member(
            &mut http.owner,
            group,
            text(&row["id"])?,
            &a.token,
            &b.fixture,
        )?);
    }
    let mut s = Suite {
        http,
        accounts: vec![a, b],
        orgs: vec![org, sibling, foreign, self_org],
        members: Vec::new(),
        original: Value::Null,
        role_rows: Vec::new(),
        keys,
        personal: Vec::new(),
        revisions: Vec::new(),
        stable: Value::Null,
        actor_removed: false,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_BULK_MEMBER_REMOVAL_RECEIPT")?,
        finished: false,
    };
    s.members = s.lists()?;
    s.original =
        organization_invites::member(&s.members[0], text(&s.accounts[1].fixture["email"])?)?
            .clone();
    require(
        s.original["status"] == 2,
        "Bulk removal target was not confirmed",
    )?;
    for email in [&emails[0], &emails[1], &stub] {
        s.role_rows
            .push(organization_invites::member(&s.members[1], email)?.clone());
    }
    s.role_rows
        .push(organization_invites::member(&s.members[0], &emails[0])?.clone());
    s.role_rows
        .push(organization_invites::member(&s.members[3], &emails[0])?.clone());
    require(
        s.role_rows[0]["status"] == 1
            && s.role_rows[1]["type"] == 4
            && s.role_rows[2]["status"] == 0,
        "Bulk removal role fixtures differed",
    )?;
    for account in &s.accounts {
        s.personal.push(s.http.owner.personal(&account.token)?);
        s.revisions.push(s.http.owner.revision(&account.token)?);
    }
    s.stable = s.stable_snapshot()?;
    s.receipt("running")?;
    for (name, case) in CASES {
        eprintln!("Organization bulk member removal case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 2
            && s.passed.len() == CASE_COUNT,
        "Bulk member removal request budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-bulk-member-removal: {CASE_COUNT} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bulk_removal_result_rejects_wrong_error_kind_or_reordered_duplicate() {
        let expected = [("missing", MISSING), ("target", ""), ("target", MISSING)];
        let mut value = json!({"object":"list","continuationToken":null,"data":[{"object":"OrganizationBulkConfirmResponseModel","id":"missing","error":MISSING},{"object":"OrganizationBulkConfirmResponseModel","id":"target","error":""},{"object":"OrganizationBulkConfirmResponseModel","id":"target","error":MISSING}]});
        assert!(result(&value, &expected).is_ok());
        value["data"].as_array_mut().unwrap().swap(1, 2);
        assert!(result(&value, &expected).is_err());
        value["data"].as_array_mut().unwrap().swap(1, 2);
        value["data"][2]["error"] = json!("Unexpected server failure");
        assert!(result(&value, &expected).is_err());
    }
}
