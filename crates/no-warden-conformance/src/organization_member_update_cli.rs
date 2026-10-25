//! Actual CLI observation of direct member PUT setup; no CLI edit caller claimed.
//! Independently authored MIT OR Apache-2.0. Client-internal traffic is not counted.
use crate::{
    capture, organization_collections, organization_confirmations as confirmation,
    organization_invites, organization_member_removal as removal,
    organization_member_update as update,
    organization_owner::{self, Http, Organization},
    text_sends::{TextSendsError as Error, receipt_file, require, text, write_receipt},
    transport::TlsProxy,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;
pub const COMMAND_COUNT: usize = 27;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 32;
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    direct: Option<usize>,
    receipt: Option<fs::File>,
    finished: bool,
    member_puts: usize,
    cache_observed: bool,
    fresh_observed: bool,
}
impl Drop for Cli {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.receipt("failed");
        }
    }
}
impl Cli {
    fn receipt(&mut self, status: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":2,"directHttpRequests":self.direct,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"directMemberPutMutations":self.member_puts,"expectedDirectMemberPutMutations":3,"cliMutationCallerClaimed":false,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,"browserTraceClaimed":false,"configuredGroups":false,"configuredPolicies":false,"smtpEnabled":false,"fullParityClaimed":false,"separateFromBaseline120":true,"cachedGrantBeforeExplicitSyncAsserted":self.cache_observed,"freshCacheSelectiveCollectionDecryptionAsserted":self.fresh_observed,"personalNoteDecryptionAsserted":self.fresh_observed}),
        )
    }
    fn command(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: Option<&str>,
    ) -> Result<String, Error> {
        self.commands += 1;
        require(
            self.commands <= COMMAND_COUNT,
            "Member update CLI command budget exceeded",
        )?;
        if args.first() == Some(&"login") {
            self.logins += 1;
        }
        let mut env = self.environment.clone();
        env.insert(
            "BITWARDENCLI_APPDATA_DIR".into(),
            cache.as_os_str().to_owned(),
        );
        if let Some(session) = session {
            env.insert("BW_SESSION".into(), session.into());
        } else {
            env.remove(&OsString::from("BW_SESSION"));
        }
        let args = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect::<Vec<_>>();
        let result = capture::run(&self.binary, &args, &env, Duration::from_secs(90))
            .map_err(|_| Error("Member update CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Member update CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Member update CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|v| v.trim().to_owned())
            .map_err(|_| Error("Member update CLI returned non-UTF8"))
    }
    fn json(&mut self, args: &[&str], cache: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, cache, Some(session))?)
            .map_err(|_| Error("Member update CLI JSON malformed"))
    }
    fn collections(
        &mut self,
        org: &Organization,
        expected: &[(&str, &str)],
        cache: &Path,
        session: &str,
    ) -> Result<(), Error> {
        let value = self.json(
            &["list", "collections", "--organizationid", &org.id],
            cache,
            session,
        )?;
        check_collections(&value, &org.id, expected)
    }
    fn members(
        &mut self,
        org: &Organization,
        expected: &Value,
        cache: &Path,
        session: &str,
    ) -> Result<(), Error> {
        let value = self.json(
            &["list", "org-members", "--organizationid", &org.id],
            cache,
            session,
        )?;
        check_members(&value, expected)
    }
    fn note(&mut self, id: &str, cache: &Path, session: &str) -> Result<(), Error> {
        let value = self.json(&["get", "item", id], cache, session)?;
        require(
            value["name"] == organization_owner::NOTE
                && value["notes"] == organization_owner::NOTE
                && value["secureNote"]["type"] == 0,
            "Member update CLI personal note did not decrypt",
        )
    }
}
fn check_collections(value: &Value, org: &str, expected: &[(&str, &str)]) -> Result<(), Error> {
    let rows = value
        .as_array()
        .ok_or(Error("Member update CLI collection list missing"))?
        .iter()
        .filter(|v| v["organizationId"] == org)
        .collect::<Vec<_>>();
    require(
        rows.len() == expected.len()
            && expected
                .iter()
                .all(|(id, name)| rows.iter().any(|r| r["id"] == *id && r["name"] == *name)),
        "Member update CLI collection scope or decryption differed",
    )
}
fn check_members(value: &Value, expected: &Value) -> Result<(), Error> {
    require(
        value.as_array().is_some_and(|rows| {
            rows.len() == 2
                && rows.contains(expected)
                && rows.iter().any(|r| r["type"] == 0 && r["status"] == 2)
        }),
        "Member update CLI member role or identity differed",
    )
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Member update CLI private directory failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Member update CLI directory permissions failed"))?;
    }
    Ok(dir)
}
fn personal(mut value: Value) -> Result<Value, Error> {
    require(
        value.get("devices").is_some(),
        "Member update CLI personal snapshot missing devices",
    )?;
    value
        .as_object_mut()
        .ok_or(Error("Member update CLI personal snapshot malformed"))?
        .remove("devices");
    crate::user_key_id::sync_key_id(&value["sync"])?;
    value["sync"]["userDecryption"]["userKeyId"] = Value::Null;
    Ok(value)
}
pub fn run() -> Result<(), Error> {
    let owner_cache = private_dir("no-warden-member-update-owner-")?;
    let cache = private_dir("no-warden-member-update-recipient-")?;
    let fresh = private_dir("no-warden-member-update-fresh-")?;
    let tls = private_dir("no-warden-member-update-tls-")?;
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let recipient = organization_owner::seed(&mut http)?;
    let org = organization_collections::create_organization(&mut http, &owner)?;
    let hidden = confirmation::hidden_collection(&mut http, &owner, &org)?;
    let hidden_id = text(&hidden["id"])?.to_owned();
    organization_invites::invite_owner(
        &mut http,
        &org.id,
        &owner.token,
        &confirmation::invitation(
            text(&recipient.fixture["email"])?,
            2,
            Some(&org.collection_id),
        ),
    )?;
    let member = confirmation::member_row(
        &mut http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    let member_id = text(&member["id"])?.to_owned();
    let wrapped = removal::confirm_fixture_member(
        &mut http,
        &org,
        &member_id,
        &owner.token,
        &recipient.fixture,
    )?;
    let before = [
        personal(http.personal(&owner.token)?)?,
        personal(http.personal(&recipient.token)?)?,
    ];
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Member update CLI TLS setup failed"))?,
        )
    } else {
        None
    };
    let configured = proxy
        .as_ref()
        .map_or(http.server.as_str(), TlsProxy::url)
        .to_owned();
    let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/node_modules/.bin/bw");
    let binary = std::env::var_os("BW_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| if local.exists() { local } else { "bw".into() });
    let mut environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for key in [
        "BW_SESSION",
        "BW_CLIENTID",
        "BW_CLIENTSECRET",
        "BW_RESPONSE",
        "BW_QUIET",
        "BW_CLEANEXIT",
        "BW_RAW",
        "DEBUG",
        "DEBUG_FILE",
        "NODE_DEBUG",
        "NODE_DEBUG_NATIVE",
        "LOG_FILE",
    ] {
        environment.remove(&OsString::from(key));
    }
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    environment.insert(
        "BW_MEMBER_UPDATE_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    environment.insert(
        "BW_MEMBER_UPDATE_RECIPIENT_PASSWORD".into(),
        recipient.password.clone().into(),
    );
    if let Some(proxy) = &proxy {
        environment.insert(
            "NODE_EXTRA_CA_CERTS".into(),
            proxy.certificate().as_os_str().to_owned(),
        );
    }
    let mut c = Cli {
        binary,
        environment,
        commands: 0,
        logins: 0,
        direct: None,
        receipt: receipt_file("BW_ORGANIZATION_MEMBER_UPDATE_CLI_RECEIPT")?,
        finished: false,
        member_puts: 0,
        cache_observed: false,
        fresh_observed: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], owner_cache.path(), None)? == "2026.10.0",
        "Member update CLI version differed",
    )?;
    c.command(&["config", "server", &configured], owner_cache.path(), None)?;
    let owner_session = c.command(
        &[
            "login",
            text(&owner.fixture["email"])?,
            "--passwordenv",
            "BW_MEMBER_UPDATE_OWNER_PASSWORD",
            "--raw",
        ],
        owner_cache.path(),
        None,
    )?;
    require(
        owner_session.len() > 20,
        "Member update owner login did not unlock",
    )?;
    c.command(&["config", "server", &configured], cache.path(), None)?;
    let login = [
        "login",
        text(&recipient.fixture["email"])?,
        "--passwordenv",
        "BW_MEMBER_UPDATE_RECIPIENT_PASSWORD",
        "--raw",
    ];
    let mut session = c.command(&login, cache.path(), None)?;
    require(
        session.len() > 20,
        "Member update recipient login did not unlock",
    )?;
    c.command(&["sync"], cache.path(), Some(&session))?;
    c.collections(
        &org,
        &[(&org.collection_id, organization_owner::COLLECTION_NAME)],
        cache.path(),
        &session,
    )?;
    c.note(&recipient.cipher_id, cache.path(), &session)?;
    update::put_fixture(
        &mut http,
        &org.id,
        &member_id,
        &owner.token,
        &update::body(
            json!(2),
            json!([update::selection(&hidden_id, true, true, false)]),
        ),
    )?;
    c.member_puts += 1;
    c.collections(
        &org,
        &[(&org.collection_id, organization_owner::COLLECTION_NAME)],
        cache.path(),
        &session,
    )?;
    c.cache_observed = true;
    c.command(&["sync"], cache.path(), Some(&session))?;
    c.collections(
        &org,
        &[(&hidden_id, confirmation::HIDDEN_NAME)],
        cache.path(),
        &session,
    )?;
    let mut expected = json!({"object":"org-member","id":member_id,"email":recipient.fixture["email"],"name":recipient.fixture["name"],"status":2,"type":2,"twoFactorEnabled":false});
    c.members(&org, &expected, owner_cache.path(), &owner_session)?;
    update::put_fixture(
        &mut http,
        &org.id,
        &member_id,
        &owner.token,
        &update::body(
            json!(1),
            json!([update::selection(&hidden_id, true, true, false)]),
        ),
    )?;
    c.member_puts += 1;
    expected["type"] = json!(1);
    c.members(&org, &expected, owner_cache.path(), &owner_session)?;
    c.command(&["lock"], cache.path(), Some(&session))?;
    session = c.command(
        &[
            "unlock",
            "--passwordenv",
            "BW_MEMBER_UPDATE_RECIPIENT_PASSWORD",
            "--raw",
        ],
        cache.path(),
        None,
    )?;
    require(session.len() > 20, "Member update password unlock failed")?;
    c.command(&["sync"], cache.path(), Some(&session))?;
    c.collections(
        &org,
        &[
            (&org.collection_id, organization_owner::COLLECTION_NAME),
            (&hidden_id, confirmation::HIDDEN_NAME),
        ],
        cache.path(),
        &session,
    )?;
    c.note(&recipient.cipher_id, cache.path(), &session)?;
    update::put_fixture(
        &mut http,
        &org.id,
        &member_id,
        &owner.token,
        &update::body(
            json!(2),
            json!([update::selection(&hidden_id, true, true, false)]),
        ),
    )?;
    c.member_puts += 1;
    c.command(&["logout"], cache.path(), Some(&session))?;
    c.command(&["config", "server", &configured], fresh.path(), None)?;
    session = c.command(&login, fresh.path(), None)?;
    require(session.len() > 20, "Member update fresh login failed")?;
    c.command(&["sync"], fresh.path(), Some(&session))?;
    c.collections(
        &org,
        &[(&hidden_id, confirmation::HIDDEN_NAME)],
        fresh.path(),
        &session,
    )?;
    c.note(&recipient.cipher_id, fresh.path(), &session)?;
    c.fresh_observed = true;
    expected["type"] = json!(2);
    c.members(&org, &expected, owner_cache.path(), &owner_session)?;
    c.command(&["logout"], fresh.path(), Some(&session))?;
    c.command(&["logout"], owner_cache.path(), Some(&owner_session))?;
    require(
        personal(http.personal(&owner.token)?)? == before[0]
            && personal(http.personal(&recipient.token)?)? == before[1],
        "Member update CLI changed personal keys, payloads or settings",
    )?;
    let profile = http.json(
        reqwest::Method::GET,
        "/api/accounts/profile",
        &recipient.token,
        None,
    )?;
    require(
        confirmation::org_in(&profile, "organizations", &org.id)?
            .is_some_and(|v| v["key"] == wrapped),
        "Member update CLI lost original organization key",
    )?;
    c.direct = Some(http.requests);
    if http.requests != DIRECT_HTTP_REQUEST_COUNT {
        eprintln!(
            "Member update CLI directHTTP actual {}, expected {DIRECT_HTTP_REQUEST_COUNT}",
            http.requests
        );
    }
    require(
        c.commands == COMMAND_COUNT
            && c.member_puts == 3
            && c.logins == 3
            && http.logins == 2
            && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Member update CLI command or directHTTP budget differed",
    )?;
    c.receipt("passed")?;
    c.finished = true;
    println!(
        "PASS organization-member-update CLI: {COMMAND_COUNT} commands, {DIRECT_HTTP_REQUEST_COUNT} directHTTP requests"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observer_rejects_wrong_collection_scope_and_undecrypted_name() {
        let value = json!([{"organizationId":"org","id":"collection","name":"plain"}]);
        assert!(check_collections(&value, "org", &[("collection", "plain")]).is_ok());
        assert!(check_collections(&value, "org", &[("collection", "opaque")]).is_err());
        assert!(check_collections(&value, "other", &[("collection", "plain")]).is_err());
        assert!(
            check_collections(
                &json!([value[0], value[0]]),
                "org",
                &[("collection", "plain")]
            )
            .is_err()
        );
    }
    #[test]
    fn observer_rejects_stale_role_and_wrong_member_identity() {
        let expected = json!({"id":"member","type":2,"status":2});
        let value = json!([{"id":"owner","type":0,"status":2},expected]);
        assert!(check_members(&value, &expected).is_ok());
        let mut stale = expected.clone();
        stale["type"] = json!(1);
        assert!(check_members(&value, &stale).is_err());
        stale = expected.clone();
        stale["id"] = json!("other");
        assert!(check_members(&value, &stale).is_err());
    }
}
