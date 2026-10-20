//! Actual CLI fingerprints/decryption observe the same keys returned by HTTP bulk lookup.
//! CLI 2026.10.0 uses individual public-key GETs; this runner claims no bulk CLI caller.
use crate::{
    capture, organization_collections, organization_confirmations as confirmation,
    organization_invites as invites, organization_member_public_keys as bulk,
    organization_member_removal as removal,
    organization_owner::{self, Http},
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
pub const COMMAND_COUNT: usize = 16;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 32;
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    requests: Option<usize>,
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
            &json!({"schemaVersion":1,"status":state,"cliVersion":"2026.10.0","commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliPasswordLoginCommands":self.logins,"directHttpRequests":self.requests,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"directPasswordLoginRequests":2,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"directBulkPublicKeyRequests":2,"cliBulkPublicKeyCallerClaimed":false,"browserTraceClaimed":false,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,"fingerprintEqualityChecks":3,"distinctAccountFingerprintChecks":1,"collectionDecryptionChecks":1,"personalDecryptionChecks":1,"configuredPolicies":false}),
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
            "Public-key CLI command budget exceeded",
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
        let arguments = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect::<Vec<_>>();
        let result = capture::run(&self.binary, &arguments, &env, Duration::from_secs(90))
            .map_err(|_| Error("Public-key CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Public-key CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Public-key CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Public-key CLI private output not UTF-8"))
    }
    fn json(&mut self, args: &[&str], cache: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, cache, Some(session))?)
            .map_err(|_| Error("Public-key CLI JSON malformed"))
    }
}
fn directory(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Public-key CLI private directory failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Public-key CLI private permissions failed"))?;
    }
    Ok(dir)
}
fn normalize(mut value: Value) -> Result<Value, Error> {
    value
        .as_object_mut()
        .ok_or(Error("Public-key personal snapshot malformed"))?
        .remove("devices");
    crate::user_key_id::sync_key_id(&value["sync"])?;
    value["sync"]["userDecryption"]["userKeyId"] = Value::Null;
    Ok(value)
}
pub fn run() -> Result<(), Error> {
    let a_cache = directory("no-warden-public-key-owner-cli-")?;
    let b_cache = directory("no-warden-public-key-recipient-cli-")?;
    let tls = directory("no-warden-public-key-tls-")?;
    let mut http = Http::new()?;
    let a = organization_owner::seed(&mut http)?;
    let b = organization_owner::seed(&mut http)?;
    let org = organization_collections::create_organization(&mut http, &a)?;
    invites::invite_owner(
        &mut http,
        &org.id,
        &a.token,
        &confirmation::invitation(text(&b.fixture["email"])?, 2, Some(&org.collection_id)),
    )?;
    let recipient =
        confirmation::member_row(&mut http, &org.id, &a.token, text(&b.fixture["email"])?)?;
    let owner = confirmation::member_row(&mut http, &org.id, &a.token, text(&a.fixture["email"])?)?;
    let ids = json!({"ids":[recipient["id"],owner["id"],recipient["id"]]});
    let expected = [
        bulk::row(&recipient, &b.fixture["keys"]["publicKey"]),
        bulk::row(&owner, &a.fixture["keys"]["publicKey"]),
        bulk::row(&recipient, &b.fixture["keys"]["publicKey"]),
    ];
    let value = http.json(
        reqwest::Method::POST,
        &bulk::path(&org.id),
        &a.token,
        Some(&ids),
    )?;
    bulk::projection(&value, &expected)?;
    for account in [&a, &b] {
        let individual = http.json(
            reqwest::Method::GET,
            &format!("/api/users/{}/public-key", account.user_id),
            &a.token,
            None,
        )?;
        require(
            individual["publicKey"] == account.fixture["keys"]["publicKey"],
            "Bulk and individual public-key bytes differed",
        )?;
    }
    removal::confirm_fixture_member(
        &mut http,
        &org,
        text(&recipient["id"])?,
        &a.token,
        &b.fixture,
    )?;
    let personal = [
        normalize(http.personal(&a.token)?)?,
        normalize(http.personal(&b.token)?)?,
    ];
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Public-key CLI TLS setup failed"))?,
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
    for field in [
        "BW_SESSION",
        "BW_CLIENTID",
        "BW_CLIENTSECRET",
        "BW_RESPONSE",
        "BW_QUIET",
        "BW_CLEANEXIT",
        "BW_RAW",
    ] {
        environment.remove(&OsString::from(field));
    }
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    environment.insert(
        "BW_PUBLIC_KEY_OWNER_PASSWORD".into(),
        a.password.clone().into(),
    );
    environment.insert(
        "BW_PUBLIC_KEY_RECIPIENT_PASSWORD".into(),
        b.password.clone().into(),
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
        requests: None,
        receipt: receipt_file("BW_ORGANIZATION_MEMBER_PUBLIC_KEYS_CLI_RECEIPT")?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], a_cache.path(), None)? == "2026.10.0",
        "Public-key CLI version differed",
    )?;
    c.command(&["config", "server", &configured], a_cache.path(), None)?;
    let a_session = c.command(
        &[
            "login",
            text(&a.fixture["email"])?,
            "--passwordenv",
            "BW_PUBLIC_KEY_OWNER_PASSWORD",
            "--raw",
        ],
        a_cache.path(),
        None,
    )?;
    require(a_session.len() > 20, "Public-key CLI owner session missing")?;
    c.command(&["sync"], a_cache.path(), Some(&a_session))?;
    let a_local = c.command(
        &["get", "fingerprint", "me"],
        a_cache.path(),
        Some(&a_session),
    )?;
    let a_remote = c.command(
        &["get", "fingerprint", &a.user_id],
        a_cache.path(),
        Some(&a_session),
    )?;
    let b_remote = c.command(
        &["get", "fingerprint", &b.user_id],
        a_cache.path(),
        Some(&a_session),
    )?;
    c.command(&["config", "server", &configured], b_cache.path(), None)?;
    let b_session = c.command(
        &[
            "login",
            text(&b.fixture["email"])?,
            "--passwordenv",
            "BW_PUBLIC_KEY_RECIPIENT_PASSWORD",
            "--raw",
        ],
        b_cache.path(),
        None,
    )?;
    require(
        b_session.len() > 20,
        "Public-key CLI recipient session missing",
    )?;
    c.command(&["sync"], b_cache.path(), Some(&b_session))?;
    let b_local = c.command(
        &["get", "fingerprint", "me"],
        b_cache.path(),
        Some(&b_session),
    )?;
    let a_from_b = c.command(
        &["get", "fingerprint", &a.user_id],
        b_cache.path(),
        Some(&b_session),
    )?;
    require(
        !a_local.is_empty()
            && !b_local.is_empty()
            && a_local == a_remote
            && a_local == a_from_b
            && b_local == b_remote
            && a_local != b_local,
        "Actual CLI fingerprint equality or distinct-account separation differed",
    )?;
    let note = c.json(&["get", "item", &b.cipher_id], b_cache.path(), &b_session)?;
    require(
        note["name"] == organization_owner::NOTE && note["notes"] == organization_owner::NOTE,
        "Public-key CLI personal decryption differed",
    )?;
    let collections = c.json(
        &["list", "collections", "--organizationid", &org.id],
        b_cache.path(),
        &b_session,
    )?;
    require(
        collections.as_array().is_some_and(|rows| {
            rows.len() == 1
                && rows[0]["id"] == org.collection_id
                && rows[0]["name"] == organization_owner::COLLECTION_NAME
        }),
        "Public-key CLI organization collection decryption differed",
    )?;
    c.command(&["logout"], b_cache.path(), Some(&b_session))?;
    c.command(&["logout"], a_cache.path(), Some(&a_session))?;
    let value = http.json(
        reqwest::Method::POST,
        &bulk::path(&org.id),
        &a.token,
        Some(&ids),
    )?;
    bulk::projection(&value, &expected)?;
    for (i, account) in [&a, &b].into_iter().enumerate() {
        require(
            normalize(http.personal(&account.token)?)? == personal[i],
            "Public-key CLI reads changed personal ciphertext, settings or keys",
        )?;
    }
    c.requests = Some(http.requests);
    require(
        c.commands == COMMAND_COUNT
            && c.logins == 2
            && http.logins == 2
            && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Public-key CLI exact command or request budget differed",
    )?;
    c.receipt("passed")?;
    c.finished = true;
    println!(
        "PASS organization-member-public-keys CLI: {COMMAND_COUNT} commands, {} direct HTTP requests, 2 CLI logins, 2 direct logins",
        http.requests
    );
    Ok(())
}
