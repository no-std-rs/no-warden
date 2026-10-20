//! Independently authored actual CLI observation of direct HTTP revoke/restore.
//! Calls are established by pinned source; this runner captures no HTTP trace.
use crate::{
    capture, organization_collections, organization_confirmations as confirmation,
    organization_invites, organization_member_removal as removal,
    organization_member_status as status,
    organization_owner::{self, Http, Organization},
    text_sends::{TextSendsError as Error, receipt_file, require, text, write_receipt},
    transport::TlsProxy,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

pub const COMMAND_COUNT: usize = 31;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 43;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokedResponse {
    success: bool,
    message: String,
}
fn validate_revoked(code: Option<i32>, bytes: &[u8]) -> Result<(), Error> {
    require(code == Some(1), "Revoked confirmation CLI exit differed")?;
    let value: RevokedResponse = serde_json::from_slice(bytes)
        .map_err(|_| Error("Revoked confirmation CLI response malformed"))?;
    require(
        !value.success && value.message == "Error: User is revoked and cannot be confirmed.",
        "Revoked confirmation CLI category differed",
    )
}
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    rejections: usize,
    direct_requests: Option<usize>,
    receipt: Option<fs::File>,
    finished: bool,
}
impl Drop for Cli {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.receipt("failed");
        }
    }
}
impl Cli {
    fn receipt(&mut self, state: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":state,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":2,"directHttpRequests":self.direct_requests,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"directHttpStatusMutations":2,"revokedConfirmationChecks":self.rejections,"expectedRevokedConfirmationChecks":1,"cliMutationCallerClaimed":false,"successfulConfirmationClaimed":false,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,"separateFromBaseline120":true}),
        )
    }
    fn execute(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: Option<&str>,
        revoked: bool,
    ) -> Result<String, Error> {
        self.commands += 1;
        require(
            self.commands <= COMMAND_COUNT,
            "Status CLI command budget exceeded",
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
        if revoked {
            env.insert("BW_RESPONSE".into(), "true".into());
        }
        let args = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect::<Vec<_>>();
        let result = capture::run(&self.binary, &args, &env, Duration::from_secs(90))
            .map_err(|_| Error("Status CLI private capture failed"))?;
        if revoked {
            validate_revoked(result.status.code(), &result.stdout)?;
            self.rejections += 1;
            self.receipt("running")?;
            return Ok(String::new());
        }
        if !result.status.success() {
            eprintln!(
                "Status CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Status CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Status CLI output was not UTF-8"))
    }
    fn command(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: Option<&str>,
    ) -> Result<String, Error> {
        self.execute(args, cache, session, false)
    }
    fn json(&mut self, args: &[&str], cache: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, cache, Some(session))?)
            .map_err(|_| Error("Status CLI JSON output malformed"))
    }
    fn members(
        &mut self,
        org: &Organization,
        expected: &Value,
        cache: &Path,
        session: &str,
    ) -> Result<Value, Error> {
        let value = self.json(
            &["list", "org-members", "--organizationid", &org.id],
            cache,
            session,
        )?;
        require(
            value.as_array().is_some_and(|rows| {
                rows.len() == 2
                    && rows.contains(expected)
                    && rows
                        .iter()
                        .any(|r| r["object"] == "org-member" && r["type"] == 0 && r["status"] == 2)
            }),
            "Status CLI member metadata differed",
        )?;
        value
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["type"] == 0))
            .cloned()
            .ok_or(Error("Status CLI owner row missing"))
    }
    fn collections(
        &mut self,
        org: &Organization,
        present: bool,
        cache: &Path,
        session: &str,
    ) -> Result<(), Error> {
        let value = self.json(
            &["list", "collections", "--organizationid", &org.id],
            cache,
            session,
        )?;
        let selected = value
            .as_array()
            .ok_or(Error("Status CLI collection array missing"))?
            .iter()
            .filter(|v| v["organizationId"] == org.id)
            .collect::<Vec<_>>();
        require(
            if present {
                selected.len() == 1
                    && selected[0]["id"] == org.collection_id
                    && selected[0]["name"] == organization_owner::COLLECTION_NAME
            } else {
                selected.is_empty()
            },
            "Status CLI collection visibility or decryption differed",
        )
    }
    fn note(&mut self, id: &str, cache: &Path, session: &str) -> Result<(), Error> {
        let value = self.json(&["get", "item", id], cache, session)?;
        require(
            value["name"] == organization_owner::NOTE
                && value["notes"] == organization_owner::NOTE
                && value["secureNote"]["type"] == 0,
            "Status CLI personal note decryption differed",
        )
    }
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Collection CLI private directory creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Collection CLI private permissions failed"))?;
    }
    Ok(dir)
}
fn normalize_cli(mut value: Value) -> Result<Value, Error> {
    require(
        value.get("devices").is_some(),
        "Collection CLI device snapshot missing",
    )?;
    value
        .as_object_mut()
        .ok_or(Error("Collection CLI snapshot malformed"))?
        .remove("devices");
    crate::user_key_id::sync_key_id(&value["sync"])?;
    value["sync"]["userDecryption"]["userKeyId"] = Value::Null;
    Ok(value)
}
pub fn run() -> Result<(), Error> {
    let owner_cache = private_dir("no-warden-status-owner-cli-")?;
    let recipient_cache = private_dir("no-warden-status-recipient-cli-")?;
    let fresh = private_dir("no-warden-status-fresh-cli-")?;
    let tls = private_dir("no-warden-status-tls-")?;
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let recipient = organization_owner::seed(&mut http)?;
    let org = organization_collections::create_organization(&mut http, &owner)?;
    let sibling = organization_collections::create_organization(&mut http, &owner)?;
    let hidden = confirmation::hidden_collection(&mut http, &owner, &org)?;
    for (group, role, grant) in [
        (&org, 2, Some(org.collection_id.as_str())),
        (&sibling, 1, None),
    ] {
        organization_invites::invite_owner(
            &mut http,
            &group.id,
            &owner.token,
            &confirmation::invitation(text(&recipient.fixture["email"])?, role, grant),
        )?;
    }
    let row = confirmation::member_row(
        &mut http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    let side = confirmation::member_row(
        &mut http,
        &sibling.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    let main_key = removal::confirm_fixture_member(
        &mut http,
        &org,
        text(&row["id"])?,
        &owner.token,
        &recipient.fixture,
    )?;
    let side_key = removal::confirm_fixture_member(
        &mut http,
        &sibling,
        text(&side["id"])?,
        &owner.token,
        &recipient.fixture,
    )?;
    let personal = [
        normalize_cli(http.personal(&owner.token)?)?,
        normalize_cli(http.personal(&recipient.token)?)?,
    ];
    let profile = http.json(
        reqwest::Method::GET,
        "/api/accounts/profile",
        &recipient.token,
        None,
    )?;
    require(
        confirmation::org_in(&profile, "organizations", &org.id)?
            .is_some_and(|o| o["key"] == main_key)
            && confirmation::org_in(&profile, "organizations", &sibling.id)?
                .is_some_and(|o| o["key"] == side_key),
        "Status CLI setup did not deliver both original keys",
    )?;
    let before = http.json(
        reqwest::Method::GET,
        "/api/collections",
        &recipient.token,
        None,
    )?;
    confirmation::selective(&before, &org, text(&hidden["id"])?, false)?;
    let mut cli_member = json!({"object":"org-member","id":row["id"],"email":recipient.fixture["email"],"name":recipient.fixture["name"],"status":2,"type":2,"twoFactorEnabled":false});
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Status CLI TLS setup failed"))?,
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
    ] {
        environment.remove(&OsString::from(key));
    }
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    environment.insert(
        "BW_STATUS_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    environment.insert(
        "BW_STATUS_RECIPIENT_PASSWORD".into(),
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
        rejections: 0,
        direct_requests: None,
        receipt: receipt_file("BW_ORGANIZATION_MEMBER_STATUS_CLI_RECEIPT")?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], owner_cache.path(), None)? == "2026.10.0",
        "Status CLI version differed",
    )?;
    c.command(&["config", "server", &configured], owner_cache.path(), None)?;
    let owner_session = c.command(
        &[
            "login",
            text(&owner.fixture["email"])?,
            "--passwordenv",
            "BW_STATUS_OWNER_PASSWORD",
            "--raw",
        ],
        owner_cache.path(),
        None,
    )?;
    require(owner_session.len() > 20, "Status owner CLI login failed")?;
    c.command(&["sync"], owner_cache.path(), Some(&owner_session))?;
    let owner_row = c.members(&org, &cli_member, owner_cache.path(), &owner_session)?;
    c.command(
        &["config", "server", &configured],
        recipient_cache.path(),
        None,
    )?;
    let login = [
        "login",
        text(&recipient.fixture["email"])?,
        "--passwordenv",
        "BW_STATUS_RECIPIENT_PASSWORD",
        "--raw",
    ];
    let session = c.command(&login, recipient_cache.path(), None)?;
    require(session.len() > 20, "Status recipient CLI login failed")?;
    c.command(&["sync"], recipient_cache.path(), Some(&session))?;
    c.collections(&org, true, recipient_cache.path(), &session)?;
    c.collections(&sibling, true, recipient_cache.path(), &session)?;
    c.note(&recipient.cipher_id, recipient_cache.path(), &session)?;
    status::put_fixture_status(
        &mut http,
        &org.id,
        text(&row["id"])?,
        "revoke",
        &owner.token,
    )?;
    let profile = http.json(
        reqwest::Method::GET,
        "/api/accounts/profile",
        &recipient.token,
        None,
    )?;
    removal::absent(&profile, &org.id)?;
    let value = http.json(
        reqwest::Method::GET,
        "/api/collections",
        &recipient.token,
        None,
    )?;
    removal::visible(&value, &org.id, &sibling, false)?;
    let value = http.json(reqwest::Method::GET, "/api/sync", &recipient.token, None)?;
    removal::absent(&value["profile"], &org.id)?;
    removal::visible(&value, &org.id, &sibling, true)?;
    cli_member["status"] = json!(-1);
    require(
        c.members(&org, &cli_member, owner_cache.path(), &owner_session)? == owner_row,
        "Revoke changed owner CLI member row",
    )?;
    c.execute(
        &[
            "confirm",
            "org-member",
            text(&row["id"])?,
            "--organizationid",
            &org.id,
        ],
        owner_cache.path(),
        Some(&owner_session),
        true,
    )?;
    c.command(&["sync"], recipient_cache.path(), Some(&session))?;
    c.collections(&org, false, recipient_cache.path(), &session)?;
    c.collections(&sibling, true, recipient_cache.path(), &session)?;
    c.note(&recipient.cipher_id, recipient_cache.path(), &session)?;
    c.command(&["logout"], recipient_cache.path(), Some(&session))?;
    c.command(&["config", "server", &configured], fresh.path(), None)?;
    let session = c.command(&login, fresh.path(), None)?;
    require(
        session.len() > 20,
        "Revoked fresh-cache personal login failed",
    )?;
    c.command(&["sync"], fresh.path(), Some(&session))?;
    c.collections(&org, false, fresh.path(), &session)?;
    c.collections(&sibling, true, fresh.path(), &session)?;
    c.note(&recipient.cipher_id, fresh.path(), &session)?;
    status::put_fixture_status(
        &mut http,
        &org.id,
        text(&row["id"])?,
        "restore/vnext",
        &owner.token,
    )?;
    let profile = http.json(
        reqwest::Method::GET,
        "/api/accounts/profile",
        &recipient.token,
        None,
    )?;
    require(
        confirmation::org_in(&profile, "organizations", &org.id)?
            .is_some_and(|o| o["key"] == main_key)
            && confirmation::org_in(&profile, "organizations", &sibling.id)?
                .is_some_and(|o| o["key"] == side_key),
        "Restore lost original main or sibling key",
    )?;
    let value = http.json(
        reqwest::Method::GET,
        "/api/collections",
        &recipient.token,
        None,
    )?;
    confirmation::selective(&value, &org, text(&hidden["id"])?, false)?;
    let value = http.json(reqwest::Method::GET, "/api/sync", &recipient.token, None)?;
    confirmation::selective(&value, &org, text(&hidden["id"])?, true)?;
    cli_member["status"] = json!(2);
    require(
        c.members(&org, &cli_member, owner_cache.path(), &owner_session)? == owner_row,
        "Restore changed owner CLI member row",
    )?;
    c.command(&["sync"], fresh.path(), Some(&session))?;
    c.collections(&org, true, fresh.path(), &session)?;
    c.collections(&sibling, true, fresh.path(), &session)?;
    c.note(&recipient.cipher_id, fresh.path(), &session)?;
    c.command(&["logout"], fresh.path(), Some(&session))?;
    c.command(&["logout"], owner_cache.path(), Some(&owner_session))?;
    for (i, account) in [&owner, &recipient].into_iter().enumerate() {
        require(
            normalize_cli(http.personal(&account.token)?)? == personal[i],
            "Status CLI changed personal ciphertext, credentials or settings",
        )?;
    }
    require(
        c.commands == COMMAND_COUNT
            && c.logins == 3
            && c.rejections == 1
            && http.logins == 2
            && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Status CLI command or direct-request budget differed",
    )?;
    c.direct_requests = Some(http.requests);
    c.receipt("passed")?;
    c.finished = true;
    println!(
        "PASS organization-member-status CLI: {COMMAND_COUNT} commands, 3 CLI logins, 2 direct setup logins"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revoked_confirmation_requires_exact_category_and_rejects_server_failure() {
        let valid =
            br#"{"success":false,"message":"Error: User is revoked and cannot be confirmed."}"#;
        assert!(validate_revoked(Some(1), valid).is_ok());
        assert!(validate_revoked(Some(0), valid).is_err());
        for bad in[br#"{"success":false,"message":"Server error: 500"}"#.as_slice(),br#"{"success":true,"message":"Error: User is revoked and cannot be confirmed."}"#.as_slice(),br#"{"success":false,"message":"Error: User is revoked and cannot be confirmed.","data":{}}"#.as_slice(),br#"{"success":false,"success":false,"message":"Error: User is revoked and cannot be confirmed."}"#.as_slice(),b"not-json"]{assert!(validate_revoked(Some(1),bad).is_err());}
    }
}
