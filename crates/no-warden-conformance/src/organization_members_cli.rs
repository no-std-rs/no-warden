//! Independently authored official CLI confirmed-owner member discovery proof.
//! Calls are established by pinned source; this runner captures no HTTP trace.
use crate::{
    capture, organization_collections,
    organization_members::{self, AVATAR, MEMBER_NAME},
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

pub const COMMAND_COUNT: usize = 18;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 18;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AlreadyConfirmedResponse {
    success: bool,
    message: String,
}
fn validate_already_confirmed(exit_code: Option<i32>, output: &[u8]) -> Result<(), Error> {
    require(
        exit_code == Some(1),
        "Member confirmation preflight exit status differed",
    )?;
    let response: AlreadyConfirmedResponse = serde_json::from_slice(output)
        .map_err(|_| Error("Member confirmation preflight response was malformed"))?;
    require(
        !response.success && response.message == "Error: User is already confirmed.",
        "Member confirmation preflight rejection category differed",
    )
}
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    confirmed_checks: usize,
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
    fn receipt(&mut self, status: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"alreadyConfirmedChecks":self.confirmed_checks,"expectedAlreadyConfirmedChecks":2,"successfulConfirmationClaimed":false,"directPasswordLoginRequests":1,"directHttpRequests":self.direct_requests,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":1,"fixtureRegistrationHttpRequests":2,"separateFromBaseline120":true,"clientInternalRequestsCounted":false,"capturedRouteTrace":false}),
        )
    }
    fn command(
        &mut self,
        args: &[&str],
        store: &Path,
        session: Option<&str>,
    ) -> Result<String, Error> {
        self.execute(args, store, session, false)
    }
    fn execute(
        &mut self,
        args: &[&str],
        store: &Path,
        session: Option<&str>,
        already_confirmed: bool,
    ) -> Result<String, Error> {
        self.commands += 1;
        require(
            self.commands <= COMMAND_COUNT,
            "Collection CLI command budget exceeded",
        )?;
        if args.first() == Some(&"login") {
            self.logins += 1;
        }
        let mut env = self.environment.clone();
        env.insert(
            "BITWARDENCLI_APPDATA_DIR".into(),
            store.as_os_str().to_owned(),
        );
        if let Some(session) = session {
            env.insert("BW_SESSION".into(), session.into());
        } else {
            env.remove(&OsString::from("BW_SESSION"));
        }
        if already_confirmed {
            env.insert("BW_RESPONSE".into(), "true".into());
            env.remove(&OsString::from("BW_QUIET"));
            env.remove(&OsString::from("BW_CLEANEXIT"));
        }
        let args = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect::<Vec<_>>();
        let result = capture::run(&self.binary, &args, &env, Duration::from_secs(90))
            .map_err(|_| Error("Collection CLI private capture failed"))?;
        if already_confirmed {
            validate_already_confirmed(result.status.code(), &result.stdout)?;
            self.confirmed_checks += 1;
            self.receipt("running")?;
            return Ok(String::new());
        }
        if !result.status.success() {
            eprintln!(
                "Collection CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Collection CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Collection CLI output was not UTF-8"))
    }
    fn json(&mut self, args: &[&str], store: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, store, Some(session))?)
            .map_err(|_| Error("Collection CLI JSON output invalid"))
    }
    fn already_confirmed(
        &mut self,
        organization: &Organization,
        membership: &str,
        store: &Path,
        session: &str,
    ) -> Result<(), Error> {
        self.execute(
            &[
                "confirm",
                "org-member",
                membership,
                "--organizationid",
                &organization.id,
            ],
            store,
            Some(session),
            true,
        )?;
        Ok(())
    }
    fn list(
        &mut self,
        org: &Organization,
        id: &str,
        name: &str,
        store: &Path,
        session: &str,
        cached: bool,
    ) -> Result<(), Error> {
        let kind = if cached {
            "collections"
        } else {
            "org-collections"
        };
        let value = self.json(&["list", kind, "--organizationid", &org.id], store, session)?;
        require(
            value.as_array().is_some_and(|a| {
                a.iter()
                    .any(|v| v["id"] == id && v["organizationId"] == org.id && v["name"] == name)
            }),
            "Official CLI did not decrypt listed collection name",
        )
    }
    fn members(
        &mut self,
        organization: &Organization,
        expected: &Value,
        store: &Path,
        session: &str,
    ) -> Result<(), Error> {
        let value = self.json(
            &["list", "org-members", "--organizationid", &organization.id],
            store,
            session,
        )?;
        require(
            value == json!([expected]),
            "Official CLI owner member list differed",
        )
    }
    fn note(&mut self, id: &str, store: &Path, session: &str) -> Result<(), Error> {
        let value = self.json(&["get", "item", id], store, session)?;
        require(
            value["notes"] == organization_owner::NOTE
                && value["name"] == organization_owner::NOTE
                && value["secureNote"]["type"] == 0,
            "Collection CLI flow changed personal note decryption",
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
    let cache = private_dir("no-warden-members-cli-")?;
    let fresh = private_dir("no-warden-members-cli-fresh-")?;
    let tls = private_dir("no-warden-members-cli-tls-")?;
    let mut http = Http::new()?;
    let account = organization_owner::seed(&mut http)?;
    let organization = organization_collections::create_organization(&mut http, &account)?;
    let profile = http.json(
        reqwest::Method::GET,
        "/api/accounts/profile",
        &account.token,
        None,
    )?;
    let membership_id = organization_members::membership_id(&profile, &organization.id)?.to_owned();
    let mut expected_member = json!({"object":"org-member","id":membership_id,"email":account.fixture["email"],"name":profile["name"],"status":2,"type":0,"twoFactorEnabled":false});
    let mut expected_personal = normalize_cli(http.personal(&account.token)?)?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Member CLI TLS setup failed"))?,
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
        "BW_COLLECTION_PASSWORD".into(),
        account.password.clone().into(),
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
        confirmed_checks: 0,
        direct_requests: None,
        receipt: receipt_file("BW_ORGANIZATION_MEMBERS_CLI_RECEIPT")?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], cache.path(), None)? == "2026.10.0",
        "Member CLI version differed",
    )?;
    c.command(&["config", "server", &configured], cache.path(), None)?;
    let login = [
        "login",
        text(&account.fixture["email"])?,
        "--passwordenv",
        "BW_COLLECTION_PASSWORD",
        "--raw",
    ];
    let session = c.command(&login, cache.path(), None)?;
    require(session.len() > 20, "Member CLI login did not unlock")?;
    c.command(&["sync"], cache.path(), Some(&session))?;
    c.members(&organization, &expected_member, cache.path(), &session)?;
    c.already_confirmed(&organization, &membership_id, cache.path(), &session)?;
    http.json(
        reqwest::Method::PUT,
        "/api/accounts/profile",
        &account.token,
        Some(&json!({"name":MEMBER_NAME})),
    )?;
    http.json(
        reqwest::Method::PUT,
        "/api/accounts/avatar",
        &account.token,
        Some(&json!({"avatarColor":AVATAR})),
    )?;
    expected_member["name"] = json!(MEMBER_NAME);
    expected_personal["sync"]["profile"]["name"] = json!(MEMBER_NAME);
    expected_personal["sync"]["profile"]["avatarColor"] = json!(AVATAR);
    let full = http.json(
        reqwest::Method::GET,
        &organization_members::path(&organization.id),
        &account.token,
        None,
    )?;
    let full_rows = organization_members::rows(&full)?;
    require(
        full_rows.len() == 1,
        "Member CLI direct control omitted membership",
    )?;
    organization_members::member_shape(
        &full_rows[0],
        &account.user_id,
        &membership_id,
        text(&account.fixture["email"])?,
        &json!(MEMBER_NAME),
        &json!(AVATAR),
    )?;
    let single = http.json(
        reqwest::Method::GET,
        &organization_members::detail_path(&organization.id, &membership_id),
        &account.token,
        None,
    )?;
    require(
        single == full_rows[0],
        "Member CLI single-member control differed from list member",
    )?;
    // No intervening sync: the real command must report the fresh server name.
    // Its seven-field public output does not include avatarColor; the HTTP control above does.
    c.members(&organization, &expected_member, cache.path(), &session)?;
    c.list(
        &organization,
        &organization.collection_id,
        organization_owner::COLLECTION_NAME,
        cache.path(),
        &session,
        false,
    )?;
    c.note(&account.cipher_id, cache.path(), &session)?;
    c.command(&["logout"], cache.path(), Some(&session))?;
    c.command(&["config", "server", &configured], fresh.path(), None)?;
    let session = c.command(&login, fresh.path(), None)?;
    require(session.len() > 20, "Fresh member CLI login did not unlock")?;
    c.command(&["sync"], fresh.path(), Some(&session))?;
    c.members(&organization, &expected_member, fresh.path(), &session)?;
    c.already_confirmed(&organization, &membership_id, fresh.path(), &session)?;
    c.list(
        &organization,
        &organization.collection_id,
        organization_owner::COLLECTION_NAME,
        fresh.path(),
        &session,
        true,
    )?;
    c.note(&account.cipher_id, fresh.path(), &session)?;
    c.command(&["logout"], fresh.path(), Some(&session))?;
    require(
        normalize_cli(http.personal(&account.token)?)? == expected_personal,
        "Member CLI flow changed unrelated personal keys, ciphertext or settings",
    )?;
    require(
        c.commands == COMMAND_COUNT
            && c.logins == 2
            && c.confirmed_checks == 2
            && http.logins == 1
            && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Member CLI command or identity budget differed",
    )?;
    c.direct_requests = Some(http.requests);
    c.receipt("passed")?;
    c.finished = true;
    println!(
        "PASS organization-members CLI: {COMMAND_COUNT} commands, 2 CLI logins, 1 direct setup login"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn already_confirmed_rejection_rejects_server_failures_and_untrusted_shapes() {
        let expected = br#"{"success":false,"message":"Error: User is already confirmed."}"#;
        assert!(validate_already_confirmed(Some(1), expected).is_ok());
        for code in [None, Some(0), Some(2), Some(127)] {
            assert!(validate_already_confirmed(code, expected).is_err());
        }
        for output in [
            br#"{"success":false,"message":"Server error: 500 Internal Server Error"}"#.as_slice(),
            br#"{"success":false,"message":"Not found."}"#,
            br#"{"success":false,"message":"User is already confirmed."}"#,
            br#"{"success":true,"message":"Error: User is already confirmed."}"#,
            br#"{"success":false,"message":"Error: User is already confirmed.","data":{"key":"private marker"}}"#,
            br#"{"success":false,"success":false,"message":"Error: User is already confirmed."}"#,
            br#"{"success":false}"#,
            b"<html>500 Internal Server Error</html>",b"{",b"\xff",b"",
        ] {let error=validate_already_confirmed(Some(1),output).unwrap_err();assert!(!format!("{error:?} {error}").contains("private marker"));}
    }
}
