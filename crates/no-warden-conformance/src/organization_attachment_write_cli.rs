//! Actual pinned CLI shared attachment uploads/deletes and readonly downloads.
//! Independently authored MIT OR Apache-2.0. No captured route or full-parity claim.
use crate::{
    capture, fixture,
    organization_collections::create_organization,
    organization_confirmations, organization_invites,
    organization_owner::{self, Account, Http, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
    transport::TlsProxy,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::{RngCore, rngs::OsRng};
use reqwest::{Method, Url};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::{NamedTempFile, TempDir};

// Freeze measured counters only after the complete native development run.
pub const COMMAND_COUNT: usize = 0;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 0;
const DEVELOPMENT_COMMAND_LIMIT: usize = 64;
const CLI_SHA256: &str = "7cad23262b9ca168f22c12d7cdf64ef168e57d49784377c2b8cd02707759e4d7";
const NOTE_NAME: &str = "Shared attachment WRITE Ω";
const NOTE_TEXT: &str = "Independent CLI opaque payload 雪\0retained";
const FOLDER_NAMES: [&str; 3] = [
    "Owner private folder Ω",
    "Writer private folder 雪",
    "Readonly private folder λ",
];
const LABELS: [&str; 3] = ["owner", "writer", "readonly"];
const PASSWORD_ENVS: [&str; 3] = [
    "BW_ATTACHMENT_OWNER_PASSWORD",
    "BW_ATTACHMENT_WRITER_PASSWORD",
    "BW_ATTACHMENT_READONLY_PASSWORD",
];
struct FileFixture {
    label: &'static str,
    name: &'static str,
    path: PathBuf,
    bytes: Vec<u8>,
    attachment: Option<String>,
}
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    private: PathBuf,
    commands: usize,
    successful_commands: usize,
    logins: usize,
    downloads: usize,
    direct: Option<usize>,
    receipt: Option<fs::File>,
    finished: bool,
    premium: bool,
    personal_delete_control: bool,
    empty_move: bool,
    login_observations: Vec<Value>,
    mutation_observations: Vec<Value>,
    readonly_read_preserved: bool,
    final_decryption: bool,
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
        let mut receipt = json!({
                "schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,
                "successfulCommands":self.successful_commands,"cliVersion":"2026.10.0","cliBundleSha256":CLI_SHA256,
                "cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":3,
                "directHttpRequests":self.direct,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,
                "fixtureRegistrations":3,"fixtureRegistrationHttpRequests":6,
                "fixturePlaintextByteCounts":[0,257,2*1024*1024+37],"profilePremiumGuardPassedForAllActors":self.premium,
                "personalDirectDeleteExactCipher30ControlPassed":self.personal_delete_control,
                "actualEmptyAttachmentMoveCommandExecuted":self.empty_move,
                "attachmentBearingMoveCommandExecuted":false,
                "loginSetupObservations":self.login_observations,
                "allThreeFreshCacheLoginsPrecedeMeasuredSharedMutations":self.login_observations.len()==3,
                "sdkKeyIdAttribution":"pinned-source-and-observed-login-transition",
                "sdkBackfillRouteCaptured":false,
        });
        let details = json!({
                "mutationObservations":self.mutation_observations,
                "actualSharedAttachmentUploadCommands":self.mutation_observations.iter().filter(|v|v["action"]=="upload").count(),
                "actualSharedAttachmentDeleteCommands":self.mutation_observations.iter().filter(|v|v["action"]=="delete").count(),
                "successfulReadonlyAttachmentDownloads":self.downloads,
                "readonlyReadIntervalAllProtectedStatePreserved":self.readonly_read_preserved,
                "finalThreeAccountNoteAndPrivateFolderDecryptionCompleted":self.final_decryption,
                "actualCliExecuted":self.successful_commands>0,"observerOnly":false,
                "actualBrowserExecuted":false,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,
                "fixedPrivateStdinWrapper":true,"cliUnmodifiedAndBundlePinned":true,
                "privatePlaintextInputsAndOutputsRemoved":self.finished,
                "personalDeleteActualCliCallerClaimed":false,"sharedReadOnlyWriteDenialCliClaimed":false,
                "legacyAttachmentOrAdminAliasCliClaimed":false,"groupsConfigured":false,
                "configuredPolicies":false,"smtpEnabled":false,"fullParityClaimed":false,"separateFromBaseline120":true
        });
        receipt
            .as_object_mut()
            .unwrap()
            .extend(details.as_object().unwrap().clone());
        write_receipt(&mut self.receipt, &receipt)
    }
    fn command(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: Option<&str>,
        input: Option<&Value>,
    ) -> Result<Vec<u8>, Error> {
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
        let mut argv: Vec<OsString> = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect();
        // capture's ordinary stdin is null. A fixed shell exec supplies an owned
        // private input file, without putting JSON/plaintext into process argv.
        // NamedTempFile is create_new/0600 and unlinks on every return path.
        let mut stdin_file = None;
        let program = if let Some(input) = input {
            let mut file = NamedTempFile::new_in(&self.private)
                .map_err(|_| Error("Attachment CLI private stdin unavailable"))?;
            file.write_all(STANDARD.encode(input.to_string()).as_bytes())
                .map_err(|_| Error("Attachment CLI private stdin write failed"))?;
            env.insert(
                "BW_ATTACHMENT_CLI".into(),
                self.binary.as_os_str().to_owned(),
            );
            env.insert(
                "BW_ATTACHMENT_INPUT".into(),
                file.path().as_os_str().to_owned(),
            );
            let mut shell = vec![
                OsString::from("-c"),
                OsString::from(r#"exec "$BW_ATTACHMENT_CLI" "$@" < "$BW_ATTACHMENT_INPUT""#),
                OsString::from("private-attachment-stdin"),
            ];
            shell.append(&mut argv);
            argv = shell;
            stdin_file = Some(file);
            PathBuf::from("/bin/sh")
        } else {
            self.binary.clone()
        };
        self.commands += 1;
        let limit = if COMMAND_COUNT == 0 {
            DEVELOPMENT_COMMAND_LIMIT
        } else {
            COMMAND_COUNT
        };
        require(
            self.commands <= limit,
            "Attachment CLI command budget exceeded",
        )?;
        if args.first() == Some(&"login") {
            self.logins += 1;
        }
        self.receipt("running")?;
        let limits = capture::CaptureLimits {
            temp_directory: Some(self.private.clone()),
            ..capture::CaptureLimits::default()
        };
        let result =
            capture::run_with_limits(&program, &argv, &env, Duration::from_secs(120), &limits)
                .map_err(|_| Error("Attachment CLI private capture failed"))?;
        drop(stdin_file);
        if !result.status.success() {
            eprintln!(
                "Attachment CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Attachment CLI command failed")?;
        self.successful_commands += 1;
        Ok(result.stdout)
    }
    fn string(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: Option<&str>,
        input: Option<&Value>,
    ) -> Result<String, Error> {
        String::from_utf8(self.command(args, cache, session, input)?)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Attachment CLI text output invalid"))
    }
    fn json(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: &str,
        input: Option<&Value>,
    ) -> Result<Value, Error> {
        serde_json::from_slice(&self.command(args, cache, Some(session), input)?)
            .map_err(|_| Error("Attachment CLI JSON output invalid"))
    }
    fn login(
        &mut self,
        account: &Account,
        cache: &Path,
        server: &str,
        password_env: &str,
    ) -> Result<String, Error> {
        self.command(&["config", "server", server], cache, None, None)?;
        let session = self.string(
            &[
                "login",
                text(&account.fixture["email"])?,
                "--passwordenv",
                password_env,
                "--raw",
            ],
            cache,
            None,
            None,
        )?;
        require(
            session.len() > 20,
            "Attachment CLI login did not return session",
        )?;
        Ok(session)
    }
    fn download(
        &mut self,
        cache: &Path,
        session: &str,
        cipher: &str,
        file: &FileFixture,
        output: &Path,
    ) -> Result<(), Error> {
        require(
            !output.exists(),
            "Attachment CLI output must be a fresh private path",
        )?;
        self.command(
            &[
                "get",
                "attachment",
                file.id()?,
                "--itemid",
                cipher,
                "--output",
                path_text(output)?,
            ],
            cache,
            Some(session),
            None,
        )?;
        let metadata = fs::symlink_metadata(output)
            .map_err(|_| Error("Attachment CLI output file missing"))?;
        require(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == file.bytes.len() as u64,
            "Attachment CLI output file shape differed",
        )?;
        permissions(output, 0o600)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::symlink_metadata(output)
                .map_err(|_| Error("Attachment CLI private output stat failed"))?;
            require(
                metadata.permissions().mode() & 0o777 == 0o600,
                "Attachment CLI plaintext file permissions differed",
            )?;
        }
        let bytes =
            fs::read(output).map_err(|_| Error("Attachment CLI private output read failed"))?;
        fs::remove_file(output)
            .map_err(|_| Error("Attachment CLI private output cleanup failed"))?;
        require(
            bytes == file.bytes,
            "Attachment CLI plaintext byte equality failed",
        )?;
        self.downloads += 1;
        Ok(())
    }
}
impl FileFixture {
    fn id(&self) -> Result<&str, Error> {
        self.attachment
            .as_deref()
            .ok_or(Error("Attachment CLI fixture ID missing"))
    }
}
fn path_text(path: &Path) -> Result<&str, Error> {
    path.to_str()
        .ok_or(Error("Attachment CLI private path encoding invalid"))
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Attachment CLI private directory unavailable"))?;
    permissions(dir.path(), 0o700)?;
    Ok(dir)
}
fn permissions(path: &Path, mode: u32) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| Error("Attachment CLI private permissions failed"))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}
fn subdir(root: &Path, name: &str) -> Result<PathBuf, Error> {
    let path = root.join(name);
    fs::create_dir(&path).map_err(|_| Error("Attachment CLI private subdirectory failed"))?;
    permissions(&path, 0o700)?;
    Ok(path)
}
fn pin(binary: &Path) -> Result<(), Error> {
    let mut file =
        fs::File::open(binary).map_err(|_| Error("Attachment CLI bundle unavailable"))?;
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| Error("Attachment CLI bundle read failed"))?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    require(
        format!("{:x}", hash.finalize()) == CLI_SHA256,
        "Attachment CLI bundle pin differed",
    )
}
fn files(root: &Path) -> Result<Vec<FileFixture>, Error> {
    let mut large = vec![0; 2 * 1024 * 1024 + 37];
    OsRng
        .try_fill_bytes(&mut large)
        .map_err(|_| Error("Attachment CLI byte randomness failed"))?;
    let rows = [
        ("empty", "empty.bin", Vec::new()),
        (
            "arbitrary257",
            "arbitrary257.bin",
            (0..257).map(|i| (i & 255) as u8).collect(),
        ),
        ("large2MiBPlus37", "large2MiBPlus37.bin", large),
    ];
    rows.into_iter()
        .map(|(label, name, bytes)| {
            let path = root.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options
                .open(&path)
                .map_err(|_| Error("Attachment CLI private fixture file unavailable"))?;
            output
                .write_all(&bytes)
                .map_err(|_| Error("Attachment CLI private fixture write failed"))?;
            Ok(FileFixture {
                label,
                name,
                path,
                bytes,
                attachment: None,
            })
        })
        .collect()
}
fn confirm(
    http: &mut Http,
    owner: &Account,
    member: &Account,
    org: &Organization,
    readonly: bool,
) -> Result<(), Error> {
    organization_invites::invite_owner(
        http,
        &org.id,
        &owner.token,
        &json!({"emails":[member.fixture["email"]],"type":2,"groups":[],"collections":[{"id":org.collection_id,"readOnly":readonly,"hidePasswords":false,"manage":false}]}),
    )?;
    let before = organization_confirmations::member_row(
        http,
        &org.id,
        &owner.token,
        text(&member.fixture["email"])?,
    )?;
    require(
        before["status"] == 1 && before["type"] == 2,
        "Attachment WRITE accepted User fixture differed",
    )?;
    let key = fixture::organization_key_for_account(&member.fixture, &org.key)
        .map_err(|_| Error("Attachment WRITE confirmation fixture failed"))?;
    http.requests += 1;
    let r = http_client()?
        .post(format!(
            "{}/api/organizations/{}/users/{}/confirm",
            http.server,
            org.id,
            text(&before["id"])?
        ))
        .bearer_auth(&owner.token)
        .json(&json!({"key":key}))
        .send()
        .map_err(|_| Error("Attachment WRITE confirmation request failed"))?;
    require(
        r.status().as_u16() == 200,
        "Attachment WRITE confirmation rejected",
    )?;
    let after = organization_confirmations::member_row(
        http,
        &org.id,
        &owner.token,
        text(&member.fixture["email"])?,
    )?;
    organization_confirmations::member_after(&before, &after, 2)?;
    require(
        after["collections"].as_array().is_some_and(|rows| {
            rows.iter().any(|r| {
                r["id"] == org.collection_id && r["readOnly"] == readonly && r["manage"] == false
            })
        }),
        "Attachment WRITE grant fixture differed",
    )
}
fn read_cipher(http: &mut Http, actor: &Account, id: &str) -> Result<Value, Error> {
    http.json(
        Method::GET,
        &format!("/api/ciphers/{id}"),
        &actor.token,
        None,
    )
}
fn normalized(mut value: Value) -> Result<Value, Error> {
    if value["attachments"].is_null() {
        return Ok(value);
    }
    for row in value["attachments"]
        .as_array_mut()
        .ok_or(Error("Attachment WRITE snapshot list invalid"))?
    {
        let mut url = Url::parse(text(&row["url"])?)
            .map_err(|_| Error("Attachment WRITE capability URL invalid"))?;
        let keys: Vec<_> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
        require(
            !keys.is_empty(),
            "Attachment WRITE capability query missing",
        )?;
        url.set_query(None);
        for key in keys {
            url.query_pairs_mut()
                .append_pair(&key, "private-capability");
        }
        row["url"] = json!(url.to_string());
    }
    Ok(value)
}
fn attachment_map(value: &Value) -> Result<BTreeMap<String, Value>, Error> {
    if value["attachments"].is_null() {
        return Ok(BTreeMap::new());
    }
    let mut rows = BTreeMap::new();
    for row in value["attachments"]
        .as_array()
        .ok_or(Error("Attachment WRITE attachment array invalid"))?
    {
        require(
            rows.insert(text(&row["id"])?.to_owned(), row.clone())
                .is_none(),
            "Attachment WRITE duplicate attachment ID",
        )?;
    }
    Ok(rows)
}
fn known30(value: &Value) -> Result<(), Error> {
    let actual: BTreeSet<_> = value
        .as_object()
        .ok_or(Error("Attachment WRITE cipher object missing"))?
        .keys()
        .map(String::as_str)
        .collect();
    let known:BTreeSet<_>="archivedDate attachments bankAccount card collectionIds creationDate deletedDate driversLicense edit favorite fields folderId id identity key login name notes object organizationId organizationUseTotp passport passwordHistory permissions reprompt revisionDate secureNote sshKey type viewPassword".split_whitespace().collect();
    require(
        actual == known,
        "Attachment WRITE known30 cipher shape differed",
    )
}
fn state(
    http: &mut Http,
    people: &[Account; 3],
    folders: &[String; 3],
    id: Option<&str>,
) -> Result<Value, Error> {
    let mut all = Vec::new();
    for (actor, folder) in people.iter().zip(folders) {
        let sync = http.json(Method::GET, "/api/sync", &actor.token, None)?;
        let key_id = sync
            .get("userDecryption")
            .and_then(|v| v.get("userKeyId"))
            .cloned()
            .ok_or(Error("Attachment WRITE user key ID missing"))?;
        let cipher = if let Some(id) = id {
            normalized(read_cipher(http, actor, id)?)?
        } else {
            Value::Null
        };
        all.push(json!({"revision":http.revision(&actor.token)?,"keys":http.json(Method::GET,"/api/accounts/keys",&actor.token,None)?,"folder":http.json(Method::GET,&format!("/api/folders/{folder}"),&actor.token,None)?,"control":read_cipher(http,actor,&actor.cipher_id)?,"keyId":key_id,"cipher":cipher}));
    }
    Ok(json!(all))
}
fn sdk_id(v: &Value) -> bool {
    v.as_str().is_some_and(|v| {
        v.len() == 32
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn state_shape(v: &Value) -> bool {
    v.as_array().is_some_and(|a| {
        a.len() == 3
            && a.iter().all(|v| {
                v.as_object().is_some_and(|o| {
                    o.len() == 6
                        && ["revision", "keys", "folder", "control", "keyId", "cipher"]
                            .iter()
                            .all(|k| o.contains_key(*k))
                })
            })
    })
}
fn login_observation(before: &Value, after: &Value, actor: usize) -> Value {
    let shape = actor < 3 && state_shape(before) && state_shape(after);
    let protected = shape
        && (0..3).all(|i| {
            ["keys", "folder", "control", "cipher"]
                .iter()
                .all(|k| before[i][k] == after[i][k])
        });
    let peers = shape
        && (0..3).filter(|i| *i != actor).all(|i| {
            before[i]["revision"] == after[i]["revision"] && before[i]["keyId"] == after[i]["keyId"]
        });
    let migration = shape && before[actor]["keyId"].is_null() && sdk_id(&after[actor]["keyId"]);
    let unchanged = shape
        && before[actor]["keyId"] == after[actor]["keyId"]
        && (before[actor]["keyId"].is_null() || sdk_id(&before[actor]["keyId"]));
    let revision_changed = shape && before[actor]["revision"] != after[actor]["revision"];
    json!({"actor":LABELS.get(actor).copied().unwrap_or("invalid"),"snapshotShapeValid":shape,"protectedVaultKeysFoldersControlsUnchanged":protected,"peerRevisionsAndKeyIdsUnchanged":peers,"sdkKeyIdMigrationObserved":migration,"actorRevisionChanged":revision_changed,"sourceAttributionOnly":true,"keyIdBackfillRouteCaptured":false,"passed":shape&&protected&&peers&&(migration||unchanged)&&(!revision_changed||migration)})
}
fn mutation_observation(
    before: &Value,
    after: &Value,
    actor: usize,
    action: &str,
    file: Option<&str>,
    count: usize,
) -> Result<Value, Error> {
    require(
        state_shape(before) && state_shape(after) && actor < 2,
        "Attachment WRITE mutation snapshot shape invalid",
    )?;
    let mut changed = Vec::new();
    let mut common_new_id = None;
    for i in 0..3 {
        let mut old = before[i]["cipher"].clone();
        let mut new = after[i]["cipher"].clone();
        known30(&old)?;
        known30(&new)?;
        let old_files = attachment_map(&old)?;
        let new_files = attachment_map(&new)?;
        old.as_object_mut().unwrap().remove("attachments");
        new.as_object_mut().unwrap().remove("attachments");
        require(
            old == new,
            "Attachment WRITE changed common/private/archive or cipher revision",
        )?;
        require(
            ["keys", "folder", "control", "keyId"]
                .iter()
                .all(|k| before[i][k] == after[i][k]),
            "Attachment WRITE changed key/folder/control or SDK identifier",
        )?;
        if before[i]["revision"] != after[i]["revision"] {
            changed.push(i);
        }
        require(
            new_files.len() == count,
            "Attachment WRITE attachment count differed",
        )?;
        if action == "upload" {
            require(
                new_files.len() == old_files.len() + 1
                    && old_files
                        .iter()
                        .all(|(id, row)| new_files.get(id) == Some(row)),
                "Attachment WRITE upload changed an existing file",
            )?;
            let added: Vec<_> = new_files
                .keys()
                .filter(|id| !old_files.contains_key(*id))
                .collect();
            require(
                added.len() == 1,
                "Attachment WRITE upload did not add one unique file",
            )?;
            if let Some(id) = &common_new_id {
                require(
                    id == added[0],
                    "Attachment WRITE readers disagree about new file ID",
                )?;
            } else {
                common_new_id = Some(added[0].clone());
            }
        } else {
            let file = file.ok_or(Error("Attachment WRITE deleted file ID missing"))?;
            require(
                old_files.len() == new_files.len() + 1
                    && old_files.contains_key(file)
                    && !new_files.contains_key(file)
                    && new_files
                        .iter()
                        .all(|(id, row)| old_files.get(id) == Some(row)),
                "Attachment WRITE delete changed an unrelated file",
            )?;
        }
    }
    require(
        changed == [0, 1, 2],
        "Attachment WRITE must advance every current reader account revision",
    )?;
    Ok(
        json!({"actor":LABELS[actor],"action":action,"currentReaderAccountRevisionChanged":[0,1,2],"allCipherRevisionsPreserved":true,"allOpaqueCommonPrivateArchiveKeysFoldersControlsPreserved":true,"unrelatedAttachmentMetadataPreserved":true,"attachmentCount":count}),
    )
}
fn check_note(
    value: &Value,
    id: &str,
    org: &Organization,
    folder: &str,
    favorite: bool,
    files: &[FileFixture],
) -> Result<(), Error> {
    require(
        value["id"] == id
            && value["organizationId"] == org.id
            && value["collectionIds"] == json!([org.collection_id])
            && value["type"] == 2
            && value["secureNote"]["type"] == 0
            && value["name"] == NOTE_NAME
            && value["notes"] == NOTE_TEXT
            && value["folderId"] == folder
            && value["favorite"] == favorite,
        "Attachment WRITE actual CLI note decryption/private fields differed",
    )?;
    let rows = attachment_map(value)?;
    require(
        rows.len() == files.len(),
        "Attachment WRITE actual CLI attachment count differed",
    )?;
    for file in files {
        require(
            rows.get(file.id()?)
                .is_some_and(|r| r["fileName"] == file.name),
            "Attachment WRITE actual CLI filename or ID differed",
        )?;
    }
    Ok(())
}
fn sync_get(
    c: &mut Cli,
    authenticated: (&Path, &str),
    actor: usize,
    id: &str,
    org: &Organization,
    folders: &[String; 3],
    files: &[FileFixture],
) -> Result<(), Error> {
    let (cache, session) = authenticated;
    c.command(&["sync"], cache, Some(session), None)?;
    let note = c.json(&["get", "item", id], cache, session, None)?;
    check_note(&note, id, org, &folders[actor], actor != 1, files)?;
    let rows = c.json(&["list", "folders"], cache, session, None)?;
    let rows = rows
        .as_array()
        .ok_or(Error("Attachment WRITE CLI folders not an array"))?;
    require(
        rows.iter()
            .any(|r| r["id"] == folders[actor] && r["name"] == FOLDER_NAMES[actor])
            && (0..3)
                .filter(|i| *i != actor)
                .all(|i| !rows.iter().any(|r| r["id"] == folders[i])),
        "Attachment WRITE private folder decryption/isolation differed",
    )
}
fn personal_delete_control(http: &mut Http, actor: &Account) -> Result<(), Error> {
    let encrypted = fixture::encrypted_fixture_value(
        &actor.fixture,
        &actor.password,
        b"Personal DELETE control",
    )
    .map_err(|_| Error("Attachment WRITE control encryption failed"))?;
    let source=http.json(Method::POST,"/api/ciphers",&actor.token,Some(&json!({"type":2,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"encryptedFor":actor.user_id})))?;
    let id = text(&source["id"])?;
    let mut file_key = [0u8; 64];
    OsRng
        .try_fill_bytes(&mut file_key)
        .map_err(|_| Error("Attachment WRITE control randomness failed"))?;
    let file_bytes = fixture::encrypt_file(&[0x42; 193], &file_key)
        .map_err(|_| Error("Attachment WRITE control byte encryption failed"))?;
    require(
        file_bytes.len() == 257,
        "Attachment WRITE control encrypted size differed",
    )?;
    let key = fixture::encrypted_fixture_value(&actor.fixture, &actor.password, &file_key)
        .map_err(|_| Error("Attachment WRITE control key wrap failed"))?;
    let reserved = http.json(
        Method::POST,
        &format!("/api/ciphers/{id}/attachment/v2"),
        &actor.token,
        Some(&json!({"fileName":encrypted,"key":key,"fileSize":257})),
    )?;
    let file = text(&reserved["attachmentId"])?;
    let boundary = format!("private-write-{}", uuid::Uuid::new_v4());
    let mut body=format!("--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"opaque\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    body.extend_from_slice(&file_bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    http.requests += 1;
    let r = http_client()?
        .post(format!(
            "{}/api/ciphers/{id}/attachment/{file}",
            http.server
        ))
        .bearer_auth(&actor.token)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .map_err(|_| Error("Attachment WRITE personal upload control failed"))?;
    require(
        r.status().as_u16() == 200 && r.headers().get("content-type").is_none(),
        "Attachment WRITE personal upload reply differed",
    )?;
    let mut bytes = Vec::new();
    r.take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("Attachment WRITE control response read failed"))?;
    require(
        bytes.is_empty(),
        "Attachment WRITE personal upload was not empty",
    )?;
    http.requests += 1;
    let r = http_client()?
        .delete(format!(
            "{}/api/ciphers/{id}/attachment/{file}",
            http.server
        ))
        .bearer_auth(&actor.token)
        .send()
        .map_err(|_| Error("Attachment WRITE personal DELETE failed"))?;
    require(
        r.status().as_u16() == 200
            && r.headers()
                .get("content-type")
                .is_some_and(|v| v == "application/json"),
        "Attachment WRITE personal DELETE status/media differed",
    )?;
    let mut bytes = Vec::new();
    r.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("Attachment WRITE personal DELETE response failed"))?;
    require(
        !bytes.is_empty() && bytes.len() <= 1024 * 1024,
        "Attachment WRITE personal DELETE response bound exceeded",
    )?;
    let reply: Value = serde_json::from_slice(&bytes)
        .map_err(|_| Error("Attachment WRITE personal DELETE JSON invalid"))?;
    require(
        reply
            .as_object()
            .is_some_and(|r| r.len() == 1 && r.contains_key("cipher")),
        "Attachment WRITE personal DELETE must return only cipher",
    )?;
    known30(&reply["cipher"])?;
    let after = read_cipher(http, actor, id)?;
    require(
        normalized(reply["cipher"].clone())? == normalized(after.clone())?
            && attachment_map(&after)?.is_empty(),
        "Attachment WRITE personal DELETE nested cipher differed from GET",
    )?;
    http.requests += 1;
    let r = http_client()?
        .delete(format!("{}/api/ciphers/{id}", http.server))
        .bearer_auth(&actor.token)
        .send()
        .map_err(|_| Error("Attachment WRITE personal source cleanup failed"))?;
    require(
        r.status().as_u16() == 200,
        "Attachment WRITE personal source cleanup rejected",
    )
}
pub fn run() -> Result<(), Error> {
    let work = private_dir("no-warden-attachment-write-cli-")?;
    let caches = [
        subdir(work.path(), "owner")?,
        subdir(work.path(), "writer")?,
        subdir(work.path(), "readonly")?,
    ];
    let inputs = subdir(work.path(), "inputs")?;
    let outputs = subdir(work.path(), "outputs")?;
    let tls = subdir(work.path(), "tls")?;
    let capture_dir = subdir(work.path(), "capture")?;
    // One unmodified OwnerHttp per account keeps its two-login ceiling intact.
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let mut writer_http = Http::new()?;
    let writer = organization_owner::seed(&mut writer_http)?;
    http.requests += writer_http.requests;
    http.logins += writer_http.logins;
    let mut readonly_http = Http::new()?;
    let readonly = organization_owner::seed(&mut readonly_http)?;
    http.requests += readonly_http.requests;
    http.logins += readonly_http.logins;
    let people = [owner, writer, readonly];
    let org = create_organization(&mut http, &people[0])?;
    confirm(&mut http, &people[0], &people[1], &org, false)?;
    confirm(&mut http, &people[0], &people[2], &org, true)?;
    let mut folders = Vec::new();
    for (actor, name) in people.iter().zip(FOLDER_NAMES) {
        let premium = http.json(Method::GET, "/api/accounts/profile", &actor.token, None)?;
        require(
            premium["premium"] == true,
            "Attachment WRITE actual client premium guard unavailable",
        )?;
        let name =
            fixture::encrypted_fixture_value(&actor.fixture, &actor.password, name.as_bytes())
                .map_err(|_| Error("Attachment WRITE folder encryption failed"))?;
        let folder = http.json(
            Method::POST,
            "/api/folders",
            &actor.token,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&folder["id"])?.to_owned());
    }
    let folders: [String; 3] = folders
        .try_into()
        .map_err(|_| Error("Attachment WRITE folder fixture count differed"))?;
    require(
        folders.iter().collect::<BTreeSet<_>>().len() == 3,
        "Attachment WRITE private folders must differ",
    )?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, &tls)
                .map_err(|_| Error("Attachment WRITE CLI TLS setup failed"))?,
        )
    } else {
        None
    };
    let server = proxy
        .as_ref()
        .map_or(http.server.as_str(), TlsProxy::url)
        .to_owned();
    let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/node_modules/.bin/bw");
    let binary = std::env::var_os("BW_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| if local.exists() { local } else { "bw".into() });
    let binary =
        fs::canonicalize(binary).map_err(|_| Error("Attachment WRITE actual CLI unavailable"))?;
    pin(&binary)?;
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
        "PWDEBUG",
        "NODE_DEBUG",
        "NODE_DEBUG_NATIVE",
        "BW_ATTACHMENT_CLI",
        "BW_ATTACHMENT_INPUT",
    ] {
        environment.remove(&OsString::from(key));
    }
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    for (actor, key) in people.iter().zip(PASSWORD_ENVS) {
        environment.insert(key.into(), actor.password.clone().into());
    }
    if let Some(proxy) = &proxy {
        environment.insert(
            "NODE_EXTRA_CA_CERTS".into(),
            proxy.certificate().as_os_str().to_owned(),
        );
    }
    let mut c = Cli {
        binary,
        environment,
        private: capture_dir,
        commands: 0,
        successful_commands: 0,
        logins: 0,
        downloads: 0,
        direct: None,
        receipt: receipt_file("BW_ORGANIZATION_ATTACHMENT_WRITE_CLI_RECEIPT")?,
        finished: false,
        premium: true,
        personal_delete_control: false,
        empty_move: false,
        login_observations: Vec::new(),
        mutation_observations: Vec::new(),
        readonly_read_preserved: false,
        final_decryption: false,
    };
    c.receipt("running")?;
    require(
        c.string(&["--version"], &caches[0], None, None)? == "2026.10.0",
        "Attachment WRITE actual CLI version differed",
    )?;
    let mut sessions = Vec::new();
    for i in 0..3 {
        let before = state(&mut http, &people, &folders, None)?;
        let session = c.login(&people[i], &caches[i], &server, PASSWORD_ENVS[i])?;
        let after = state(&mut http, &people, &folders, None)?;
        let observation = login_observation(&before, &after, i);
        let passed = observation["passed"] == true;
        c.login_observations.push(observation);
        c.receipt("running")?;
        require(
            passed,
            "Attachment WRITE login changed protected state or an unattributed revision/key ID",
        )?;
        sessions.push(session);
    }
    personal_delete_control(&mut http, &people[0])?;
    c.personal_delete_control = true;
    let created=c.json(&["create","item"],&caches[0],&sessions[0],Some(&json!({"type":2,"name":NOTE_NAME,"notes":NOTE_TEXT,"secureNote":{"type":0},"favorite":true,"folderId":folders[0]})))?;
    let id = text(&created["id"])?.to_owned();
    require(
        created["organizationId"].is_null() && attachment_map(&created)?.is_empty(),
        "Attachment WRITE new personal note must have no attachments",
    )?;
    let moved = c.json(
        &["move", &id, &org.id],
        &caches[0],
        &sessions[0],
        Some(&json!([org.collection_id])),
    )?;
    check_note(&moved, &id, &org, &folders[0], true, &[])?;
    c.empty_move = true;
    for i in 0..3 {
        if i != 0 {
            http.json(
                Method::PUT,
                &format!("/api/ciphers/{id}/partial"),
                &people[i].token,
                Some(&json!({"favorite":i!=1,"folderId":folders[i]})),
            )?;
        }
        http.json(
            Method::PUT,
            &format!("/api/ciphers/{id}/archive"),
            &people[i].token,
            None,
        )?;
        sync_get(
            &mut c,
            (&caches[i], &sessions[i]),
            i,
            &id,
            &org,
            &folders,
            &[],
        )?;
    }
    let readonly_view = read_cipher(&mut http, &people[2], &id)?;
    require(
        readonly_view["edit"] == false && readonly_view["permissions"]["delete"] == false,
        "Attachment WRITE recipient must be ordinary readonly",
    )?;
    let mut files = files(&inputs)?;
    for index in 0..files.len() {
        let actor = if index == 2 { 1 } else { 0 };
        let before = state(&mut http, &people, &folders, Some(&id))?;
        c.command(
            &[
                "create",
                "attachment",
                "--file",
                path_text(&files[index].path)?,
                "--itemid",
                &id,
            ],
            &caches[actor],
            Some(&sessions[actor]),
            None,
        )?;
        let after = state(&mut http, &people, &folders, Some(&id))?;
        let observation = mutation_observation(&before, &after, actor, "upload", None, index + 1)?;
        c.mutation_observations.push(observation);
        c.receipt("running")?;
        let note = c.json(
            &["get", "item", &id],
            &caches[actor],
            &sessions[actor],
            None,
        )?;
        let matches: Vec<_> = note["attachments"]
            .as_array()
            .ok_or(Error("Attachment WRITE created file list missing"))?
            .iter()
            .filter(|r| r["fileName"] == files[index].name)
            .collect();
        require(
            matches.len() == 1,
            "Attachment WRITE uploaded plaintext filename was not unique",
        )?;
        let file_id = text(&matches[0]["id"])?.to_owned();
        let before_files = attachment_map(&before[0]["cipher"])?;
        let after_files = attachment_map(&after[0]["cipher"])?;
        require(
            !before_files.contains_key(&file_id) && after_files.contains_key(&file_id),
            "Attachment WRITE actual CLI and raw GET disagree about new file ID",
        )?;
        files[index].attachment = Some(file_id);
        check_note(
            &note,
            &id,
            &org,
            &folders[actor],
            actor != 1,
            &files[..index + 1],
        )?;
    }
    let before = state(&mut http, &people, &folders, Some(&id))?;
    sync_get(
        &mut c,
        (&caches[2], &sessions[2]),
        2,
        &id,
        &org,
        &folders,
        &files,
    )?;
    for file in &files {
        c.download(
            &caches[2],
            &sessions[2],
            &id,
            file,
            &outputs.join(file.label),
        )?;
    }
    require(
        state(&mut http, &people, &folders, Some(&id))? == before,
        "Attachment WRITE readonly sync/decryption/download changed protected state",
    )?;
    c.readonly_read_preserved = true;
    for (index, file) in files.iter().enumerate() {
        let actor = if index == 2 { 1 } else { 0 };
        let before = state(&mut http, &people, &folders, Some(&id))?;
        c.command(
            &["delete", "attachment", file.id()?, "--itemid", &id],
            &caches[actor],
            Some(&sessions[actor]),
            None,
        )?;
        let after = state(&mut http, &people, &folders, Some(&id))?;
        let observation = mutation_observation(
            &before,
            &after,
            actor,
            "delete",
            Some(file.id()?),
            files.len() - index - 1,
        )?;
        c.mutation_observations.push(observation);
        c.receipt("running")?;
    }
    let before = state(&mut http, &people, &folders, Some(&id))?;
    for i in 0..3 {
        sync_get(
            &mut c,
            (&caches[i], &sessions[i]),
            i,
            &id,
            &org,
            &folders,
            &[],
        )?;
    }
    require(
        state(&mut http, &people, &folders, Some(&id))? == before,
        "Attachment WRITE final sync/decryption changed protected state",
    )?;
    c.final_decryption = true;
    for i in 0..3 {
        c.command(&["logout"], &caches[i], Some(&sessions[i]), None)?;
    }
    c.direct = Some(http.requests);
    c.receipt("running")?;
    require(
        c.logins == 3 && http.logins == 3 && c.downloads == 3 && c.mutation_observations.len() == 6,
        "Attachment WRITE actual operation counts differed",
    )?;
    pin(&c.binary)?;
    if c.commands != COMMAND_COUNT || http.requests != DIRECT_HTTP_REQUEST_COUNT {
        eprintln!(
            "Attachment WRITE CLI measured budgets expected commands {COMMAND_COUNT} direct {DIRECT_HTTP_REQUEST_COUNT}; actual commands {} direct {}",
            c.commands, http.requests
        );
    }
    require(
        c.commands == COMMAND_COUNT && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Attachment WRITE CLI literal measured counters differ",
    )?;
    drop(proxy);
    work.close()
        .map_err(|_| Error("Attachment WRITE private files/cache cleanup failed"))?;
    c.finished = true;
    c.receipt("passed")?;
    println!("PASS organization-attachment-write CLI: {COMMAND_COUNT} commands");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn before() -> Value {
        json!((0..3).map(|i|json!({"revision":i,"keys":{"opaque":true},"folder":{"private":i},"control":{"personal":i},"keyId":null,"cipher":null})).collect::<Vec<_>>())
    }
    #[test]
    fn login_setup_rejects_peer_changes_and_revision_without_observed_sdk_initialization() {
        let before = before();
        let mut after = before.clone();
        after[1]["keyId"] = json!("a".repeat(32));
        after[1]["revision"] = json!(7);
        assert!(login_observation(&before, &after, 1)["passed"] == true);
        let mut peer = after.clone();
        peer[0]["keyId"] = json!("b".repeat(32));
        assert!(login_observation(&before, &peer, 1)["passed"] == false);
        let mut changed = before.clone();
        changed[1]["revision"] = json!(8);
        assert!(login_observation(&before, &changed, 1)["passed"] == false);
        changed = after.clone();
        changed[2]["control"] = json!({"different":true});
        assert!(login_observation(&before, &changed, 1)["passed"] == false);
    }
    #[test]
    fn attachment_absence_accepts_native_null_and_empty_but_rejects_wrong_shapes_or_duplicate_ids()
    {
        assert!(
            attachment_map(&json!({"attachments":null}))
                .unwrap()
                .is_empty()
        );
        assert!(
            attachment_map(&json!({"attachments":[]}))
                .unwrap()
                .is_empty()
        );
        assert!(attachment_map(&json!({"attachments":{}})).is_err());
        assert!(attachment_map(&json!({"attachments":[{"id":"same"},{"id":"same"}]})).is_err());
    }
}
