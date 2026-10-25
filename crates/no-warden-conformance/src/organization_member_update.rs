//! Independently authored native member PUT contracts; MIT OR Apache-2.0.
//! Direct setup/observations are separate from CLI callers, traces and full parity.
use crate::{
    organization_collections::create_organization,
    organization_confirmations as confirmation, organization_invites,
    organization_member_removal as removal, organization_member_status as status,
    organization_owner::{self, Account, Http as OwnerHttp, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{fs, io::Read, time::Duration};
use uuid::Uuid;

pub const CASE_COUNT: usize = 6;
pub const HTTP_REQUEST_COUNT: usize = 730;
const MISSING: &str = "The specified user isn't member of the organization";
const INVALID_TYPE: &str = "Invalid type";
const COLLECTION: &str = "Collection not found in Organization";
const GROUP: &str = "Group not found in Organization";
const PRIVILEGED: &str = "Only Owners can grant and remove Admin or Owner privileges";
const OWNER: &str = "Only Owners can edit Owner users";
const LAST: &str = "Can't delete the last owner";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_member_update_authentication_path_and_native_schema",
        guards,
    ),
    (
        "organization_member_update_role_aliases_and_ignored_identity_fields",
        aliases,
    ),
    (
        "organization_member_update_ordered_replacement_prefix_and_target_revisions",
        replacement,
    ),
    (
        "organization_member_update_confirmed_actor_and_privilege_hierarchy",
        hierarchy,
    ),
    (
        "organization_member_update_status_and_last_confirmed_owner",
        states,
    ),
    (
        "organization_member_update_preserved_personal_vault_keys_and_scope",
        preservation,
    ),
];
pub(crate) fn path(org: &str, member: &str) -> String {
    format!("/api/organizations/{org}/users/{member}")
}
pub(crate) fn selection(id: &str, read_only: bool, hide: bool, manage: bool) -> Value {
    json!({"id":id,"readOnly":read_only,"hidePasswords":hide,"manage":manage})
}
pub(crate) fn body(role: Value, collections: Value) -> Value {
    json!({"type":role,"collections":collections,"groups":[],"permissions":{}})
}
struct Reply {
    status: u16,
    content_type: bool,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, Error> {
        if self.status != expected {
            eprintln!(
                "Member update status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Member update HTTP status differed",
        )?;
        Ok(self)
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Member update response was not JSON"))
    }
    fn empty(self) -> Result<(), Error> {
        let reply = self.status(200)?;
        require(
            reply.bytes.is_empty() && !reply.content_type,
            "Member update success body or Content-Type differed",
        )
    }
    fn single_error(self, code: u16) -> Result<(), Error> {
        let value = self.status(code)?.json()?;
        require(
            value
                .as_object()
                .is_some_and(|o| o.len() == 1 && o.contains_key("error")),
            "Member update guard error shape differed",
        )
    }
    fn business(self, message: &str) -> Result<(), Error> {
        let value = self.status(400)?.json()?;
        let mut keys = value
            .as_object()
            .ok_or(Error("Member update business error was not object"))?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort();
        require(
            keys == [
                "error",
                "errorModel",
                "error_description",
                "exceptionMessage",
                "exceptionStackTrace",
                "innerExceptionMessage",
                "message",
                "object",
                "validationErrors",
            ] && value["object"] == "error"
                && value["message"] == message
                && value["errorModel"]["object"] == "error"
                && value["errorModel"]["message"] == message,
            "Member update business error envelope differed",
        )
    }
}
struct Http {
    owner: OwnerHttp,
    client: Client,
}
impl Http {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            owner: OwnerHttp::new()?,
            client: http_client()?,
        })
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, Error> {
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .contains_key(reqwest::header::CONTENT_TYPE);
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Member update private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Member update private response bound exceeded",
        )?;
        Ok(Reply {
            status,
            content_type,
            bytes,
        })
    }
    fn raw(
        &mut self,
        path: &str,
        token: Option<&str>,
        bytes: Option<&[u8]>,
        media: Option<&str>,
    ) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let mut request = self
            .client
            .put(format!("{}{path}", self.owner.server))
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(bytes) = bytes {
            request = request.body(bytes.to_vec());
        }
        if let Some(media) = media {
            request = request.header(reqwest::header::CONTENT_TYPE, media);
        }
        Self::read(
            request
                .send()
                .map_err(|_| Error("Member update request failed"))?,
        )
    }
    fn put(&mut self, org: &str, member: &str, actor: &str, value: &Value) -> Result<Reply, Error> {
        self.raw(
            &path(org, member),
            Some(actor),
            Some(value.to_string().as_bytes()),
            Some("application/json"),
        )
    }
}
pub(crate) fn put_fixture(
    http: &mut OwnerHttp,
    org: &str,
    member: &str,
    actor: &str,
    value: &Value,
) -> Result<(), Error> {
    http.requests += 1;
    Http::read(
        http_client()?
            .put(format!("{}{}", http.server, path(org, member)))
            .bearer_auth(actor)
            .json(value)
            .send()
            .map_err(|_| Error("Member update direct fixture mutation failed"))?,
    )?
    .empty()
}
struct Effect {
    full: bool,
    role: i64,
    grants: Value,
    target: Option<usize>,
    error: Option<&'static str>,
}
fn effect(role: i64, grants: Value, target: Option<usize>, error: Option<&'static str>) -> Effect {
    Effect {
        full: false,
        role,
        grants,
        target,
        error,
    }
}
struct Snapshot {
    detail: Value,
    revisions: Vec<Value>,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    members: Vec<String>,
    second: String,
    personal: Vec<Value>,
    wrapped_main: String,
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
            &json!({"schemaVersion":1,"status":state,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"fixtureRegistrations":3,"fixtureRegistrationHttpRequests":6,"refreshRequests":0,"nativePutCaller":"directHTTP","cliMutationCallerClaimed":false,"capturedRouteTrace":false,"browserTraceClaimed":false,"configuredGroups":false,"configuredPolicies":false,"smtpEnabled":false,"concurrencyClaimed":false,"providerFailureParityClaimed":false,"fullParityClaimed":false,"personalCipherFixtureNonempty":true,"personalCipherDecryptionClaimed":false,"orderedGrantReplacementAsserted":self.passed.contains(&CASES[2].0),"targetOnlyRevisionAsserted":self.passed.contains(&CASES[2].0),"oldRoleUntilFinalSuccessAsserted":self.passed.contains(&CASES[2].0),"invitedAccountRevisionClaimed":false}),
        )
    }
    fn detail(&mut self, group: usize, id: &str) -> Result<Value, Error> {
        self.http.owner.json(
            Method::GET,
            &format!(
                "{}?includeCollections=true&includeGroups=true",
                path(&self.orgs[group].id, id)
            ),
            &self.accounts[if group == 1 {
                2
            } else if group == 3 {
                1
            } else {
                0
            }]
            .token,
            None,
        )
    }
    fn revisions(&mut self) -> Result<Vec<Value>, Error> {
        let mut out = Vec::new();
        for a in &self.accounts {
            out.push(self.http.owner.revision(&a.token)?);
        }
        Ok(out)
    }
    fn snapshot(&mut self, group: usize, id: &str) -> Result<Snapshot, Error> {
        Ok(Snapshot {
            detail: self.detail(group, id)?,
            revisions: self.revisions()?,
        })
    }
    fn unchanged(
        &mut self,
        group: usize,
        id: &str,
        actor: usize,
        value: &Value,
        code: u16,
        message: Option<&str>,
    ) -> Result<(), Error> {
        let before = self.snapshot(group, id)?;
        // The native revision clock is millisecond-granular; avoid accepting or
        // rejecting a mutation because two real writes share one clock tick.
        std::thread::sleep(Duration::from_millis(8));
        let reply = self
            .http
            .put(&self.orgs[group].id, id, &self.accounts[actor].token, value)?;
        if let Some(message) = message {
            reply.business(message)?;
        } else {
            reply.single_error(code)?;
        }
        let after = self.snapshot(group, id)?;
        require(
            before.detail == after.detail && before.revisions == after.revisions,
            "Rejected member update changed grants, identity or revisions",
        )
    }
    fn reset(&mut self, group: usize, id: &str, role: i64, grants: Value) -> Result<(), Error> {
        self.http
            .put(
                &self.orgs[group].id,
                id,
                &self.accounts[0].token,
                &body(json!(role), grants),
            )?
            .empty()
    }
    fn mutate(
        &mut self,
        group: usize,
        id: &str,
        actor: usize,
        value: &Value,
        effect: Effect,
    ) -> Result<(), Error> {
        let before = self.snapshot(group, id)?;
        // The native revision clock is millisecond-granular; avoid accepting or
        // rejecting a mutation because two real writes share one clock tick.
        std::thread::sleep(Duration::from_millis(8));
        let reply = self
            .http
            .put(&self.orgs[group].id, id, &self.accounts[actor].token, value)?;
        if let Some(message) = effect.error {
            reply.business(message)?;
        } else {
            reply.empty()?;
        }
        let after = self.snapshot(group, id)?;
        check_projection(
            &before.detail,
            &after.detail,
            effect.role,
            &effect.grants,
            effect.full,
        )?;
        for (index, (a, b)) in before.revisions.iter().zip(&after.revisions).enumerate() {
            require(
                if effect.target == Some(index) {
                    a != b
                } else {
                    a == b
                },
                "Member update target-only revision effect differed",
            )?;
        }
        Ok(())
    }
    fn current_target(&self) -> String {
        self.members[1].clone()
    }
}
fn permissions(full: bool) -> Value {
    if full {
        json!({"accessEventLogs":false,"accessImportExport":false,"accessReports":false,"createNewCollections":true,"deleteAnyCollection":true,"editAnyCollection":true,"manageGroups":false,"managePolicies":false,"manageResetPassword":false,"manageScim":false,"manageSso":false,"manageUsers":false})
    } else {
        Value::Null
    }
}
fn visible_main(s: &mut Suite, full: bool) -> Result<(), Error> {
    let mut expected = if full {
        vec![s.orgs[0].collection_id.clone(), s.second.clone()]
    } else {
        vec![]
    };
    expected.sort();
    for (path, key) in [("/api/collections", "data"), ("/api/sync", "collections")] {
        let value = s
            .http
            .owner
            .json(Method::GET, path, &s.accounts[1].token, None)?;
        let mut ids = value[key]
            .as_array()
            .ok_or(Error("Member update visible collections missing"))?
            .iter()
            .filter(|v| v["organizationId"] == s.orgs[0].id)
            .map(|v| text(&v["id"]).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        ids.sort();
        require(
            ids == expected,
            "Member update native full-access collection visibility differed",
        )?;
    }
    Ok(())
}
fn check_projection(
    before: &Value,
    after: &Value,
    role: i64,
    grants: &Value,
    full: bool,
) -> Result<(), Error> {
    let mut identity = before.clone();
    let mut observed = after.clone();
    for name in ["type", "collections", "permissions"] {
        identity
            .as_object_mut()
            .ok_or(Error("Member fixture malformed"))?
            .remove(name);
        observed
            .as_object_mut()
            .ok_or(Error("Member projection malformed"))?
            .remove(name);
    }
    require(
        identity == observed,
        "Member update changed identity, status, keys or unrelated public fields",
    )?;
    if after["type"] != if role >= 3 { 4 } else { role }
        || after["collections"] != *grants
        || after["permissions"] != permissions(full)
    {
        eprintln!(
            "Member update projection metadata: role {}, expected {role}, grantsEqual {}, permissionsNull {}",
            after["type"].as_i64().unwrap_or(-999),
            after["collections"] == *grants,
            after["permissions"].is_null()
        );
    }
    require(
        after["type"] == if role >= 3 { 4 } else { role }
            && after["collections"] == *grants
            && after["permissions"] == permissions(full),
        "Member update role/grant projection differed",
    )
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let id = s.current_target();
    let token = s.accounts[0].token.clone();
    s.reset(
        0,
        &id,
        2,
        json!([selection(&s.orgs[0].collection_id, false, false, false)]),
    )?;
    let before = s.snapshot(0, &id)?;
    for bearer in [None, Some("invalid-member-update-bearer")] {
        s.http
            .raw(
                &path(&org, &id),
                bearer,
                Some(br#"{"type":2}"#),
                Some("application/json"),
            )?
            .single_error(401)?;
    }
    for (p, code) in [
        (path("not-a-uuid", &id), 401),
        (path(&org.to_uppercase(), &id), 401),
        (path(&org, "not-a-uuid"), 422),
    ] {
        s.http
            .raw(
                &p,
                Some(&token),
                Some(br#"{"type":2}"#),
                Some("application/json"),
            )?
            .single_error(code)?;
    }
    for other in [
        Uuid::new_v4().to_string(),
        s.members[3].clone(),
        s.accounts[1].user_id.clone(),
    ] {
        s.http
            .raw(
                &path(&org, &other),
                Some(&token),
                Some(br#"{"type":2}"#),
                Some("application/json"),
            )?
            .business(MISSING)?;
    }
    let mut invalid = vec![
        (b"{".to_vec(), 400),
        (b"{}".to_vec(), 422),
        (b"null".to_vec(), 422),
        (b"[]".to_vec(), 422),
        (b"[2,false,[],[]]".to_vec(), 422),
        (b"[2]".to_vec(), 422),
        (b"[2,[]]".to_vec(), 422),
        (b"[2,[],[],null]".to_vec(), 422),
        (b"[2,[],[],{},false]".to_vec(), 400),
        (br#"{"type":2,"type":1}"#.to_vec(), 422),
    ];
    for value in [
        json!({"collections":[]}),
        json!({"type":null}),
        json!({"type":true}),
        json!({"Type":2,"Collections":[]}),
        json!({"type":2,"collections":"bad"}),
        json!({"type":4,"permissions":null}),
        json!({"type":4,"permissions":"bad"}),
        json!({"type":2,"groups":"bad"}),
    ] {
        invalid.push((value.to_string().into_bytes(), 422));
    }
    for value in [
        json!({"id":s.orgs[0].collection_id}),
        json!({"id":s.orgs[0].collection_id,"readOnly":false,"hidePasswords":false}),
        json!({"id":s.orgs[0].collection_id,"readOnly":false,"hidePasswords":false,"manage":null}),
        json!({"Id":s.orgs[0].collection_id,"ReadOnly":false,"HidePasswords":false,"Manage":false}),
        json!({"id":s.orgs[0].collection_id,"readOnly":"false","hidePasswords":false,"manage":false}),
    ] {
        invalid.push((body(json!(2), json!([value])).to_string().into_bytes(), 422));
    }
    for (bytes, code) in invalid {
        s.http
            .raw(
                &path(&org, &id),
                Some(&token),
                Some(&bytes),
                Some("application/json"),
            )?
            .single_error(code)?;
    }
    s.http
        .raw(&path(&org, &id), Some(&token), Some(b"{}"), None)?
        .single_error(422)?;
    let after = s.snapshot(0, &id)?;
    require(
        before.detail == after.detail && before.revisions == after.revisions,
        "Native guard rejection changed member state",
    )
}
fn aliases(s: &mut Suite) -> Result<(), Error> {
    let id = s.current_target();
    for (value, role) in [
        (json!(0), 0),
        (json!(1), 1),
        (json!(2), 2),
        (json!(3), 3),
        (json!(4), 4),
        (json!("Owner"), 0),
        (json!("Admin"), 1),
        (json!("User"), 2),
        (json!("Manager"), 3),
        (json!("Custom"), 4),
        (json!("2"), 2),
        (json!("3"), 3),
        (json!("4"), 4),
    ] {
        s.mutate(
            0,
            &id,
            0,
            &body(value, json!([])),
            effect(role, json!([]), Some(1), None),
        )?;
    }
    // Native serde positional layouts are independently observed alongside objects.
    for value in [json!([2, null, null]), json!([2, [], [], {}])] {
        s.mutate(0, &id, 0, &value, effect(2, json!([]), Some(1), None))?;
    }
    for value in [
        json!("user"),
        json!(5),
        json!(-1),
        json!(2147483648i64),
        json!("2.0"),
    ] {
        s.unchanged(0, &id, 0, &body(value, json!([])), 400, Some(INVALID_TYPE))?;
    }
    let full_bits = json!({"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true,"manageUsers":true});
    let mut full = effect(4, json!([]), Some(1), None);
    full.full = true;
    s.mutate(
        0,
        &id,
        0,
        &json!({"type":4,"collections":[],"permissions":full_bits}),
        full,
    )?;
    visible_main(s, true)?;
    // Manager ignores the same full bits; raw numeric Custom has distinct provenance.
    s.mutate(
        0,
        &id,
        0,
        &json!({"type":3,"collections":[],"permissions":full_bits}),
        effect(3, json!([]), Some(1), None),
    )?;
    visible_main(s, false)?;
    let value = json!({"type":2,"accessAll":"false","email":"ignored@example.test","name":"ignored","status":0,"key":"ignored","resetPasswordKey":"ignored","externalId":"ignored","accessSecretsManager":true,"accessPam":true,"defaultUserCollectionName":"ignored","organizationId":s.orgs[1].id});
    s.mutate(0, &id, 0, &value, effect(2, json!([]), Some(1), None))?;
    for access in [Value::Null, json!(true)] {
        s.mutate(
            0,
            &id,
            0,
            &json!({"type":2,"accessAll":access,"groups":null}),
            effect(2, json!([]), Some(1), None),
        )?;
    }
    for (p, media) in [
        (
            format!(
                "{}?organizationId={}",
                path(&s.orgs[0].id, &id),
                s.orgs[1].id
            ),
            Some("application/json"),
        ),
        (path(&s.orgs[0].id, &id), None),
    ] {
        let before = s.snapshot(0, &id)?;
        std::thread::sleep(Duration::from_millis(8));
        s.http
            .raw(
                &p,
                Some(&s.accounts[0].token),
                Some(br#"{"type":2}"#),
                media,
            )?
            .empty()?;
        let after = s.snapshot(0, &id)?;
        check_projection(&before.detail, &after.detail, 2, &json!([]), false)?;
        require(
            after.revisions[0] == before.revisions[0]
                && after.revisions[1] != before.revisions[1]
                && after.revisions[2] == before.revisions[2],
            "Path/query or missing media update revision scope differed",
        )?;
    }
    Ok(())
}
fn replacement(s: &mut Suite) -> Result<(), Error> {
    let id = s.current_target();
    let first = selection(&s.orgs[0].collection_id, false, false, false);
    let next = selection(&s.second, true, true, false);
    let missing = selection(&Uuid::new_v4().to_string(), false, false, false);
    let foreign = selection(&s.orgs[1].collection_id, false, false, false);
    for value in [
        json!({"type":2}),
        json!({"type":2,"collections":null}),
        json!({"type":2,"Collections":[next.clone()]}),
    ] {
        s.reset(0, &id, 2, json!([first.clone()]))?;
        s.mutate(0, &id, 0, &value, effect(2, json!([]), Some(1), None))?;
    }
    s.reset(0, &id, 2, json!([first.clone()]))?;
    s.mutate(
        0,
        &id,
        0,
        &body(json!(2), json!([next.clone()])),
        effect(2, json!([next.clone()]), Some(1), None),
    )?;
    let a = selection(&s.second, true, false, false);
    let b = selection(&s.second, false, true, true);
    s.mutate(
        0,
        &id,
        0,
        &body(json!(2), json!([a, b.clone()])),
        effect(2, json!([b]), Some(1), None),
    )?;
    for (values, expected) in [
        (json!([missing.clone()]), json!([])),
        (json!([foreign]), json!([])),
        (
            json!([next.clone(), missing.clone()]),
            json!([next.clone()]),
        ),
        (json!([missing.clone(), next.clone()]), json!([])),
    ] {
        s.reset(0, &id, 2, json!([first.clone()]))?;
        s.mutate(
            0,
            &id,
            0,
            &body(json!(3), values),
            effect(2, expected, Some(1), Some(COLLECTION)),
        )?;
    }
    s.reset(0, &id, 2, json!([first.clone()]))?;
    let mut group = body(json!(3), json!([next.clone()]));
    group["groups"] = json!([Uuid::new_v4().to_string()]);
    s.mutate(
        0,
        &id,
        0,
        &group,
        effect(2, json!([next.clone()]), Some(1), Some(GROUP)),
    )?;
    for role in [0, 1] {
        s.reset(0, &id, 2, json!([first.clone()]))?;
        s.mutate(
            0,
            &id,
            0,
            &body(json!(role), json!([missing.clone()])),
            effect(role, json!([]), Some(1), None),
        )?;
    }
    for role in [3, 4] {
        s.mutate(
            0,
            &id,
            0,
            &body(json!(role), json!([next.clone()])),
            effect(role, json!([next.clone()]), Some(1), None),
        )?;
    }
    s.reset(0, &id, 2, json!([first]))
}
fn hierarchy(s: &mut Suite) -> Result<(), Error> {
    let id = s.current_target();
    let actor = s.members[2].clone();
    let own = s.members[0].clone();
    for role in [2, 3, 4] {
        let mut v = body(json!(role), json!([]));
        if role == 4 {
            v["permissions"] = json!({"manageUsers":true,"editAnyCollection":true,"deleteAnyCollection":true,"createNewCollections":true});
        }
        s.http
            .put(&s.orgs[0].id, &actor, &s.accounts[0].token, &v)?
            .empty()?;
        s.unchanged(0, &id, 2, &body(json!(2), json!([])), 401, None)?;
    }
    s.reset(0, &actor, 1, json!([]))?;
    let next = selection(&s.second, true, true, false);
    s.mutate(
        0,
        &id,
        2,
        &body(json!(2), json!([next.clone()])),
        effect(2, json!([next.clone()]), Some(1), None),
    )?;
    s.mutate(
        0,
        &id,
        2,
        &body(json!(3), json!([next.clone()])),
        effect(3, json!([next.clone()]), Some(1), None),
    )?;
    s.mutate(
        0,
        &id,
        2,
        &body(json!(2), json!([next])),
        effect(
            2,
            json!([selection(&s.second, true, true, false)]),
            Some(1),
            None,
        ),
    )?;
    for role in [0, 1] {
        s.unchanged(
            0,
            &id,
            2,
            &body(json!(role), json!([])),
            400,
            Some(PRIVILEGED),
        )?;
    }
    s.unchanged(0, &own, 2, &body(json!(0), json!([])), 400, Some(OWNER))?;
    s.reset(0, &id, 1, json!([]))?;
    s.mutate(
        0,
        &id,
        2,
        &body(json!(1), json!([])),
        effect(1, json!([]), Some(1), None),
    )?;
    s.mutate(
        0,
        &actor,
        2,
        &body(json!(1), json!([])),
        effect(1, json!([]), Some(2), None),
    )?;
    s.unchanged(
        0,
        &actor,
        2,
        &body(json!(2), json!([])),
        400,
        Some(PRIVILEGED),
    )?;
    s.reset(0, &id, 2, json!([]))?;
    s.unchanged(0, &id, 1, &body(json!(2), json!([])), 401, None)?;
    status::put_fixture_status(
        &mut s.http.owner,
        &s.orgs[0].id,
        &actor,
        "revoke",
        &s.accounts[0].token,
    )?;
    s.unchanged(0, &id, 2, &body(json!(2), json!([])), 401, None)?;
    status::put_fixture_status(
        &mut s.http.owner,
        &s.orgs[0].id,
        &actor,
        "restore",
        &s.accounts[0].token,
    )?;
    s.mutate(
        0,
        &id,
        2,
        &body(json!(2), json!([])),
        effect(2, json!([]), Some(1), None),
    )
}
fn states(s: &mut Suite) -> Result<(), Error> {
    let id = s.current_target();
    let own = s.members[0].clone();
    s.unchanged(0, &own, 0, &body(json!(2), json!([])), 400, Some(LAST))?;
    status::put_fixture_status(
        &mut s.http.owner,
        &s.orgs[0].id,
        &id,
        "revoke",
        &s.accounts[0].token,
    )?;
    s.mutate(
        0,
        &id,
        0,
        &body(json!(1), json!([])),
        effect(1, json!([]), Some(1), None),
    )?;
    require(
        s.detail(0, &id)?["status"] == -1,
        "Revoked target status changed during update",
    )?;
    s.mutate(
        0,
        &id,
        0,
        &body(json!(0), json!([])),
        effect(0, json!([]), Some(1), None),
    )?;
    s.unchanged(0, &own, 0, &body(json!(2), json!([])), 400, Some(LAST))?;
    s.mutate(
        0,
        &id,
        0,
        &body(json!(2), json!([])),
        effect(2, json!([]), Some(1), None),
    )?;
    status::put_fixture_status(
        &mut s.http.owner,
        &s.orgs[0].id,
        &id,
        "restore",
        &s.accounts[0].token,
    )?;
    require(
        s.detail(0, &id)?["status"] == 2,
        "Restore lost confirmed target state",
    )?;
    s.reset(0, &id, 2, json!([]))?;
    let accepted = s.members[4].clone();
    let accepted_owner = s.members[5].clone();
    s.unchanged(
        2,
        &accepted_owner,
        0,
        &body(json!(2), json!([])),
        400,
        Some(LAST),
    )?;
    s.reset(2, &accepted, 1, json!([]))?;
    s.unchanged(2, &accepted, 1, &body(json!(1), json!([])), 401, None)?;
    s.mutate(
        2,
        &accepted,
        0,
        &body(json!(2), json!([])),
        effect(2, json!([]), Some(1), None),
    )?;
    require(
        s.detail(2, &accepted)?["status"] == 1,
        "Accepted target status changed",
    )?;
    let invited = s.members[6].clone();
    s.mutate(
        2,
        &invited,
        0,
        &body(json!(1), json!([])),
        effect(1, json!([]), None, None),
    )?;
    require(
        s.detail(2, &invited)?["status"] == 0,
        "Invited target status changed",
    )?;
    let other = s.members[7].clone();
    s.reset(3, &other, 0, json!([]))?;
    let owner = s.members[8].clone();
    s.mutate(
        3,
        &owner,
        0,
        &body(json!(2), json!([])),
        effect(2, json!([]), Some(0), None),
    )?;
    Ok(())
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for (index, account) in s.accounts.iter().enumerate() {
        require(
            s.http.owner.personal(&account.token)? == s.personal[index],
            "Member update changed nonempty personal vault, account keys, devices or settings",
        )?;
    }
    let foreign = s.http.owner.json(
        Method::GET,
        &organization_invites::member_path(&s.orgs[1].id),
        &s.accounts[2].token,
        None,
    )?;
    require(
        foreign["data"]
            .as_array()
            .is_some_and(|v| v.len() == 1 && v[0]["id"] == s.members[3]),
        "Member update changed foreign organization membership",
    )?;
    let profile = s.http.owner.json(
        Method::GET,
        "/api/accounts/profile",
        &s.accounts[1].token,
        None,
    )?;
    require(
        confirmation::org_in(&profile, "organizations", &s.orgs[0].id)?
            .is_some_and(|v| v["status"] == 2 && v["key"] == s.wrapped_main),
        "Member update lost confirmed target authority",
    )
}
pub(crate) fn seed(http: &mut OwnerHttp) -> Result<Account, Error> {
    let mut separate = OwnerHttp::new()?;
    let account = organization_owner::seed(&mut separate)?;
    http.requests += separate.requests;
    http.logins += separate.logins;
    Ok(account)
}
fn invite(
    http: &mut OwnerHttp,
    org: &Organization,
    owner: &Account,
    target: &Account,
    role: i64,
    confirmed: bool,
) -> Result<String, Error> {
    organization_invites::invite_owner(
        http,
        &org.id,
        &owner.token,
        &confirmation::invitation(text(&target.fixture["email"])?, role, None),
    )?;
    let row =
        confirmation::member_row(http, &org.id, &owner.token, text(&target.fixture["email"])?)?;
    let id = text(&row["id"])?.to_owned();
    if confirmed {
        removal::confirm_fixture_member(http, org, &id, &owner.token, &target.fixture)?;
    }
    Ok(id)
}
pub fn run() -> Result<(), Error> {
    let mut http = Http::new()?;
    let mut accounts = Vec::new();
    for _ in 0..3 {
        accounts.push(seed(&mut http.owner)?);
    }
    let org = create_organization(&mut http.owner, &accounts[0])?;
    let foreign = create_organization(&mut http.owner, &accounts[2])?;
    let accepted = create_organization(&mut http.owner, &accounts[0])?;
    let two = create_organization(&mut http.owner, &accounts[0])?;
    let second = confirmation::hidden_collection(&mut http.owner, &accounts[0], &org)?;
    let owner = confirmation::member_row(
        &mut http.owner,
        &org.id,
        &accounts[0].token,
        text(&accounts[0].fixture["email"])?,
    )?;
    let target = invite(&mut http.owner, &org, &accounts[0], &accounts[1], 2, true)?;
    let actor = invite(&mut http.owner, &org, &accounts[0], &accounts[2], 1, true)?;
    let foreign_owner = confirmation::member_row(
        &mut http.owner,
        &foreign.id,
        &accounts[2].token,
        text(&accounts[2].fixture["email"])?,
    )?;
    let accepted_target = invite(
        &mut http.owner,
        &accepted,
        &accounts[0],
        &accounts[1],
        0,
        false,
    )?;
    let accepted_owner = confirmation::member_row(
        &mut http.owner,
        &accepted.id,
        &accounts[0].token,
        text(&accounts[0].fixture["email"])?,
    )?;
    let email = format!("member-update-invited-{}@example.test", Uuid::new_v4());
    organization_invites::invite_owner(
        &mut http.owner,
        &accepted.id,
        &accounts[0].token,
        &confirmation::invitation(&email, 0, None),
    )?;
    let invited =
        confirmation::member_row(&mut http.owner, &accepted.id, &accounts[0].token, &email)?;
    let second_owner = invite(&mut http.owner, &two, &accounts[0], &accounts[1], 0, true)?;
    let two_owner = confirmation::member_row(
        &mut http.owner,
        &two.id,
        &accounts[0].token,
        text(&accounts[0].fixture["email"])?,
    )?;
    let profile = http.owner.json(
        Method::GET,
        "/api/accounts/profile",
        &accounts[1].token,
        None,
    )?;
    let wrapped_main = text(
        &confirmation::org_in(&profile, "organizations", &org.id)?
            .ok_or(Error("Confirmed update fixture organization missing"))?["key"],
    )?
    .to_owned();
    let mut personal = Vec::new();
    for a in &accounts {
        personal.push(http.owner.personal(&a.token)?);
    }
    let members = vec![
        text(&owner["id"])?.into(),
        target,
        actor,
        text(&foreign_owner["id"])?.into(),
        accepted_target,
        text(&accepted_owner["id"])?.into(),
        text(&invited["id"])?.into(),
        second_owner,
        text(&two_owner["id"])?.into(),
    ];
    let mut s = Suite {
        http,
        accounts,
        orgs: vec![org, foreign, accepted, two],
        members,
        second: text(&second["id"])?.into(),
        personal,
        wrapped_main,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_MEMBER_UPDATE_RECEIPT")?,
        finished: false,
    };
    s.receipt("running")?;
    for (name, case) in CASES {
        eprintln!("Member update case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    if s.http.owner.requests != HTTP_REQUEST_COUNT {
        eprintln!(
            "Member update HTTP count actual {}, expected {HTTP_REQUEST_COUNT}",
            s.http.owner.requests
        );
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT && s.http.owner.logins == 3,
        "Member update request/identity budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-member-update: {CASE_COUNT} cases, {HTTP_REQUEST_COUNT} HTTP requests"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn update_success_rejects_nonempty_json_null_and_wrong_status() {
        for (status, content_type, bytes) in [
            (200, false, b"null".to_vec()),
            (200, true, vec![]),
            (204, false, vec![]),
        ] {
            assert!(
                Reply {
                    status,
                    content_type,
                    bytes
                }
                .empty()
                .is_err()
            );
        }
    }
    #[test]
    fn update_projection_rejects_reordered_flags_identity_or_role() {
        let before = json!({"id":"member","userId":"account","status":2,"type":2,"collections":[],"permissions":null});
        let grant = selection("collection", true, true, false);
        let mut after = before.clone();
        after["collections"] = json!([grant]);
        assert!(check_projection(&before, &after, 2, &after["collections"], false).is_ok());
        for field in ["id", "userId", "status", "type"] {
            let mut bad = after.clone();
            bad[field] = json!("changed");
            assert!(check_projection(&before, &bad, 2, &after["collections"], false).is_err());
        }
        assert!(check_projection(&before, &after, 2, &json!([]), false).is_err());
        let mut full = after.clone();
        full["type"] = json!(4);
        full["permissions"] = permissions(true);
        assert!(check_projection(&before, &full, 4, &after["collections"], true).is_ok());
        full["permissions"]["manageUsers"] = json!(true);
        assert!(check_projection(&before, &full, 4, &after["collections"], true).is_err());
    }
}
