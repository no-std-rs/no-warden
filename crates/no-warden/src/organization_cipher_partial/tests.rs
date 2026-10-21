use super::*;
use crate::{
    organization_cipher_sharing::CipherSharingCollection,
    service::ItemMetadata,
    wire::{CipherPartialRequest, CipherRequest, FolderRequest, RegisterRequest},
};
use std::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

// Deliberately neither Clone, Debug nor Serialize: no provider cache is borrowed.
struct Id(String);
impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
fn id(value: &str) -> Id {
    Id(value.to_string())
}
#[derive(Clone, Copy)]
struct Row {
    user: &'static str,
    canonical: &'static str,
    actual_org: &'static str,
    assigned: bool,
    readonly: bool,
    hide: bool,
    manage: bool,
}
struct Facts {
    rows: Vec<Row>,
    hole: bool,
}
impl CipherCollectionAccessData for Facts {
    fn len(&self) -> usize {
        self.rows.len()
    }
    fn get(&self, i: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        if self.hole {
            return None;
        }
        self.rows.get(i).map(|r| CipherCollectionAccessRecord {
            cipher_organization_id: Some(r.canonical),
            collection: CipherSharingCollection {
                id: "linked-collection",
                user_id: r.user,
                organization_id: r.actual_org,
                assigned: r.assigned,
                read_only: r.readonly,
                hide_passwords: r.hide,
                manage: r.manage,
            },
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Persistent {
    favorite: bool,
    folder: Option<&'static str>,
    account_revision: usize,
    other_favorite: bool,
    other_folder: &'static str,
    other_revision: usize,
    common_payload: &'static str,
    key: &'static str,
    cipher_revision: &'static str,
    created: &'static str,
    collection: &'static str,
}
#[derive(Clone, Copy)]
enum Live {
    Same,
    Revision,
    Ownership,
    Revoke,
    RemoveGrant,
    ForeignFolder,
    WrongFolderId,
    RevokeAndFolder,
}
struct Probe {
    state: Persistent,
    source_id: &'static str,
    owner: Option<&'static str>,
    organization: Option<&'static str>,
    source_revision: &'static str,
    source_present: bool,
    member_present: bool,
    member_user: &'static str,
    member_org: &'static str,
    role: i32,
    status: i32,
    full: bool,
    rows: Vec<Row>,
    hole: bool,
    folder_id: Option<&'static str>,
    folder_owner: &'static str,
    fail: Option<&'static str>,
    live: Live,
    calls: Vec<&'static str>,
    cache: String,
    commits: usize,
    live_error: Option<ApiError>,
}
impl Probe {
    fn new() -> Self {
        Self {
            state: Persistent {
                favorite: true,
                folder: Some("old-folder"),
                account_revision: 10,
                other_favorite: true,
                other_folder: "other-private",
                other_revision: 20,
                common_payload: "opaque encrypted bytes and unknown nested extension",
                key: "opaque wrapped key",
                cipher_revision: "cipher-revision",
                created: "creation-date",
                collection: "linked-collection",
            },
            source_id: "cipher",
            owner: None,
            organization: Some("org"),
            source_revision: "cipher-revision",
            source_present: true,
            member_present: true,
            member_user: "actor",
            member_org: "org",
            role: 2,
            status: 2,
            full: false,
            rows: vec![Row {
                user: "actor",
                canonical: "org",
                actual_org: "org",
                assigned: true,
                readonly: true,
                hide: false,
                manage: false,
            }],
            hole: false,
            folder_id: Some("own-folder"),
            folder_owner: "actor",
            fail: None,
            live: Live::Same,
            calls: Vec::new(),
            cache: String::new(),
            commits: 0,
            live_error: None,
        }
    }
    fn source(&self) -> CipherSharingSource<Id> {
        CipherSharingSource {
            id: id(self.source_id),
            owner_id: self.owner.map(id),
            organization_id: self.organization.map(id),
            revision: id(self.source_revision),
        }
    }
    fn member(&self) -> Option<CipherSharingMembership<Id>> {
        self.member_present.then(|| CipherSharingMembership {
            user_id: id(self.member_user),
            organization_id: id(self.member_org),
            role: self.role,
            status: self.status,
            access_all: self.full,
        })
    }
    fn facts(&self) -> Facts {
        Facts {
            rows: self.rows.clone(),
            hole: self.hole,
        }
    }
    fn folder(&self) -> Option<CipherPartialFolder<Id>> {
        self.folder_id.map(|name| CipherPartialFolder {
            id: id(name),
            owner_id: id(self.folder_owner),
        })
    }
    fn touch(&mut self, call: &'static str) -> Result<(), ()> {
        self.calls.push(call);
        self.cache = format!("overwritten cache {}", self.calls.len());
        if self.fail == Some(call) {
            Err(())
        } else {
            Ok(())
        }
    }
    fn apply(&mut self, folder: Option<&str>) -> Result<(), ApiError> {
        VaultService::new(&mut *self).update_cipher_private_annotations(
            "actor",
            "cipher",
            CipherPartialView {
                folder_id: folder,
                favorite: false,
            },
        )
    }
}
impl Storage for Probe {
    type Error = ();
    fn account_exists(&mut self, _: &str) -> Result<bool, ()> {
        panic!("unrelated account lookup")
    }
    fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), ()> {
        panic!("account mutation")
    }
    fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
        panic!("partial requires owned, identity-bound folder facts")
    }
    fn save_folder(&mut self, _: &str, _: &str, _: &FolderRequest<'_>) -> Result<(), ()> {
        panic!("folder mutation")
    }
    fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), ()> {
        panic!("folder deletion")
    }
    fn cipher_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
        panic!("canonical source needed")
    }
    fn save_cipher(&mut self, _: &str, _: &str, _: &CipherRequest<'_>) -> Result<(), ()> {
        panic!("partial must not replace a cipher")
    }
    fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), ()> {
        panic!("lifecycle mutation")
    }
    fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), ()> {
        panic!("cipher deletion")
    }
}
impl CipherPartialStorage for Probe {
    type PartialId = Id;
    type PartialAccess = Facts;
    fn cipher_partial_source(
        &mut self,
        wanted: &str,
    ) -> Result<Option<CipherSharingSource<Id>>, ()> {
        assert_eq!(wanted, "cipher");
        self.touch("source")?;
        Ok(self.source_present.then(|| self.source()))
    }
    fn cipher_partial_membership(
        &mut self,
        actor: &str,
        org: &str,
    ) -> Result<Option<CipherSharingMembership<Id>>, ()> {
        assert_eq!((actor, org), ("actor", "org"));
        self.touch("member")?;
        Ok(self.member())
    }
    fn cipher_partial_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<Id>,
    ) -> Result<Facts, ()> {
        assert_eq!(actor, "actor");
        assert_eq!(source.id.as_ref(), "cipher");
        self.touch("access")?;
        Ok(self.facts())
    }
    fn cipher_partial_folder(
        &mut self,
        wanted: &str,
    ) -> Result<Option<CipherPartialFolder<Id>>, ()> {
        assert_eq!(wanted, "own-folder");
        self.touch("folder")?;
        Ok(self.folder())
    }
    fn commit_cipher_partial(&mut self, plan: &ValidatedCipherPartial<'_>) -> Result<(), ()> {
        self.touch("commit")?;
        self.commits += 1;
        assert_eq!(
            (plan.actor(), plan.cipher_id(), plan.source_revision()),
            ("actor", "cipher", "cipher-revision")
        );
        assert_eq!(plan.personal_owner_id(), self.owner);
        assert_eq!(plan.organization_id(), self.organization);
        assert_eq!(format!("{plan:?}"), "ValidatedCipherPartial([REDACTED])");
        let mut source = self.source();
        let mut member = self.member();
        let mut access = self.facts();
        let mut folder = if plan.folder_id().is_some() {
            self.folder()
        } else {
            None
        };
        match self.live {
            Live::Same => {}
            Live::Revision => source.revision = id("new-revision"),
            Live::Ownership => {
                source.owner_id = Some(id("other"));
                source.organization_id = None;
            }
            Live::Revoke => member.as_mut().unwrap().status = -1,
            Live::RemoveGrant => access.rows.iter_mut().for_each(|r| r.assigned = false),
            Live::ForeignFolder => folder.as_mut().unwrap().owner_id = id("other"),
            Live::WrongFolderId => folder.as_mut().unwrap().id = id("other-folder"),
            Live::RevokeAndFolder => {
                member.as_mut().unwrap().status = -1;
                folder.as_mut().unwrap().owner_id = id("other");
            }
        }
        if let Err(e) = plan.validate_live(
            &source,
            member.as_ref().map(CipherSharingMembership::view),
            &access,
            folder.as_ref().map(CipherPartialFolder::view),
        ) {
            self.live_error = Some(e);
            return Err(());
        }
        // Model an atomic transaction: only this private staged value is applied.
        let mut next = self.state;
        next.favorite = plan.favorite();
        next.folder = plan.folder_id().map(|f| {
            assert_eq!(f, "own-folder");
            "own-folder"
        });
        next.account_revision += 1;
        if self.fail == Some("after-staging") {
            return Err(());
        }
        self.state = next;
        Ok(())
    }
}
fn assert_private_only(before: Persistent, after: Persistent, folder: Option<&'static str>) {
    let mut expected = before;
    expected.favorite = false;
    expected.folder = folder;
    expected.account_revision += 1;
    assert_eq!(after, expected);
}

#[test]
fn readonly_member_changes_only_actor_annotations_without_cipher_revision() {
    let mut p = Probe::new();
    let before = p.state;
    p.apply(Some("own-folder")).unwrap();
    assert_private_only(before, p.state, Some("own-folder"));
    assert_eq!(p.calls, ["source", "member", "access", "folder", "commit"]);
}
#[test]
fn admitted_full_and_direct_read_grants_do_not_require_write_or_manage() {
    for (role, full, assigned, readonly, manage) in [
        (0, false, false, true, false),
        (1, false, false, true, false),
        (4, true, false, true, false),
        (2, false, true, false, false),
        (2, false, true, true, false),
        (2, false, true, true, true),
    ] {
        let mut p = Probe::new();
        p.role = role;
        p.full = full;
        p.rows[0].assigned = assigned;
        p.rows[0].readonly = readonly;
        p.rows[0].manage = manage;
        p.apply(None).unwrap();
        assert_eq!(p.state.account_revision, 11);
    }
}
#[test]
fn missing_unconfirmed_revoked_and_unassigned_canonical_access_deny_before_folder() {
    for state in [0, 1, -1] {
        let mut p = Probe::new();
        p.status = state;
        let before = p.state;
        let e = p.apply(Some("own-folder")).unwrap_err();
        assert_eq!(e.field, Some("cipher"));
        assert!(!p.calls.contains(&"folder"));
        assert_eq!(p.state, before);
    }
    for missing in [false, true] {
        let mut p = Probe::new();
        p.member_present = !missing;
        p.rows[0].assigned = false;
        let before = p.state;
        assert!(p.apply(Some("own-folder")).is_err());
        assert_eq!(p.state, before);
        assert_eq!(p.commits, 0);
    }
}
#[test]
fn personal_owner_uses_no_organization_lookups_and_nonowner_is_denied() {
    let mut p = Probe::new();
    p.owner = Some("actor");
    p.organization = None;
    p.rows.clear();
    let before = p.state;
    p.apply(Some("own-folder")).unwrap();
    assert_private_only(before, p.state, Some("own-folder"));
    assert_eq!(p.calls, ["source", "folder", "commit"]);
    let mut p = Probe::new();
    p.owner = Some("other");
    p.organization = None;
    let before = p.state;
    assert_eq!(
        p.apply(Some("own-folder")).unwrap_err().field,
        Some("cipher")
    );
    assert_eq!(p.calls, ["source"]);
    assert_eq!(p.state, before);
}
#[test]
fn omitted_null_and_empty_folder_clear_without_any_folder_lookup() {
    for folder in [None, Some("")] {
        let mut p = Probe::new();
        let before = p.state;
        p.apply(folder).unwrap();
        assert_private_only(before, p.state, None);
        assert!(!p.calls.contains(&"folder"));
    }
}
#[test]
fn folders_require_exact_requested_identity_and_actor_owner() {
    for (folder, owner) in [
        (None, "actor"),
        (Some("own-folder"), "other"),
        (Some("different-id"), "actor"),
    ] {
        let mut p = Probe::new();
        p.folder_id = folder;
        p.folder_owner = owner;
        let before = p.state;
        assert_eq!(
            p.apply(Some("own-folder")).unwrap_err().field,
            Some("folderId")
        );
        assert_eq!(p.commits, 0);
        assert_eq!(p.state, before);
    }
}
#[test]
fn provider_source_identity_revision_and_canonical_owner_are_validated() {
    for case in 0..5 {
        let mut p = Probe::new();
        match case {
            0 => p.source_id = "wrong",
            1 => p.source_revision = "",
            2 => p.owner = Some("actor"),
            3 => p.organization = None,
            _ => p.source_id = "",
        };
        let before = p.state;
        assert_eq!(p.apply(None).unwrap_err().kind, ErrorKind::Storage);
        assert_eq!(p.state, before);
        assert_eq!(p.commits, 0);
    }
    let mut p = Probe::new();
    p.source_present = false;
    assert_eq!(p.apply(None).unwrap_err().field, Some("cipher"));
}
#[test]
fn wrong_membership_or_association_scope_and_missing_index_fail_closed() {
    for case in 0..6 {
        let mut p = Probe::new();
        match case {
            0 => p.member_user = "other",
            1 => p.member_org = "other-org",
            2 => p.rows[0].user = "other",
            3 => p.rows[0].canonical = "other-org",
            4 => p.rows[0].actual_org = "",
            _ => p.hole = true,
        };
        let before = p.state;
        assert_eq!(p.apply(None).unwrap_err().kind, ErrorKind::Storage);
        assert_eq!(p.state, before);
        assert_eq!(p.commits, 0);
    }
}
#[test]
fn historical_readonly_grants_require_confirmed_canonical_membership() {
    // Separate actual native companion: 8 trials/104 HTTP, canonical confirmed
    // membership plus a retained historical readonly grant admits partial edits.
    let mut p = Probe::new();
    p.rows[0].actual_org = "historical-org";
    p.apply(None).unwrap();
    for revoked in [false, true] {
        let mut p = Probe::new();
        p.rows[0].actual_org = "historical-org";
        if revoked {
            p.status = -1;
        } else {
            p.member_present = false;
        }
        let before = p.state;
        assert!(p.apply(None).is_err());
        assert_eq!(p.state, before);
    }
}
#[test]
fn identical_annotations_still_advance_only_actor_account_revision() {
    let mut p = Probe::new();
    p.apply(Some("own-folder")).unwrap();
    let before = p.state;
    p.apply(Some("own-folder")).unwrap();
    assert_private_only(before, p.state, Some("own-folder"));
}
#[test]
fn hidden_read_grant_uses_read_admission_without_native_hide_partial_claim() {
    // A local resolver consistency check; this partial-route variation has no
    // actual native companion measurement and makes no client parity claim.
    let mut p = Probe::new();
    p.rows[0].hide = true;
    p.apply(None).unwrap();
}
#[test]
fn owned_handles_survive_cache_reuse_without_clone_or_debug_bounds() {
    let mut p = Probe::new();
    p.apply(Some("own-folder")).unwrap();
    assert_eq!(p.cache, "overwritten cache 5");
    assert_eq!(p.commits, 1);
    assert_eq!(p.state.folder, Some("own-folder"));
}
#[test]
fn lookup_commit_and_staged_mutation_failures_preserve_all_persistent_state() {
    for failure in [
        "source",
        "member",
        "access",
        "folder",
        "commit",
        "after-staging",
    ] {
        let mut p = Probe::new();
        p.fail = Some(failure);
        let before = p.state;
        assert_eq!(
            p.apply(Some("own-folder")).unwrap_err().kind,
            ErrorKind::Storage
        );
        assert_eq!(p.state, before);
    }
}
#[test]
fn live_source_authority_and_folder_changes_reject_atomic_commit() {
    for change in [
        Live::Revision,
        Live::Ownership,
        Live::Revoke,
        Live::RemoveGrant,
        Live::ForeignFolder,
        Live::WrongFolderId,
    ] {
        let mut p = Probe::new();
        p.live = change;
        let before = p.state;
        assert!(p.apply(Some("own-folder")).is_err());
        assert_eq!(p.commits, 1);
        assert!(p.live_error.is_some());
        assert_eq!(p.state, before);
    }
    let mut p = Probe::new();
    p.live = Live::RevokeAndFolder;
    assert!(p.apply(Some("own-folder")).is_err());
    assert_eq!(p.live_error.unwrap().field, Some("cipher"));
}
#[test]
fn empty_authenticated_actor_never_reaches_provider() {
    let mut p = Probe::new();
    assert!(
        VaultService::new(&mut p)
            .update_cipher_private_annotations(
                "",
                "cipher",
                CipherPartialView {
                    folder_id: None,
                    favorite: false
                }
            )
            .is_err()
    );
    assert!(p.calls.is_empty());
}
#[test]
fn borrowed_wire_requires_boolean_and_accepts_only_measured_tuple_shape() {
    for bytes in [
        br#"{"favorite":false}"#.as_slice(),
        br#"{"folderId":null,"favorite":false}"#,
        br#"[null,false]"#,
        br#"["own-folder",false]"#,
    ] {
        let request = serde_json::from_slice::<CipherPartialRequest<'_>>(bytes).unwrap();
        assert!(!request.favorite);
    }
    for bytes in [
        br#"{}"#.as_slice(),
        br#"{"favorite":null}"#,
        br#"{"favorite":0}"#,
        br#"{"favorite":"false"}"#,
        br#"{"Favorite":false,"FolderId":null}"#,
        br#"{"favorite":false,"folderId":0}"#,
        br#"[false,"own-folder"]"#,
        br#"[null,false,0]"#,
        b"null",
        br#""body""#,
    ] {
        assert!(serde_json::from_slice::<CipherPartialRequest<'_>>(bytes).is_err());
    }
    let request = serde_json::from_slice::<CipherPartialRequest<'_>>(
        br#"{"favorite":false,"folder_id":"ignored","organizationId":"forged","name":"ignored"}"#,
    )
    .unwrap();
    assert_eq!(request.folder_id, None);
    let request = serde_json::from_slice::<CipherPartialRequest<'_>>(
        br#"{"favorite":false,"FolderId":"ignored-uppercase"}"#,
    )
    .unwrap();
    assert_eq!(request.folder_id, None);
}
#[test]
fn folder_is_borrowed_and_debug_does_not_reveal_private_values() {
    let bytes = br#"{"folderId":"private-folder-marker","favorite":true}"#;
    let request = serde_json::from_slice::<CipherPartialRequest<'_>>(bytes).unwrap();
    let value = request.folder_id.unwrap();
    let start = bytes.as_ptr() as usize;
    assert!((start..start + bytes.len()).contains(&(value.as_ptr() as usize)));
    assert_eq!(format!("{request:?}"), "CipherPartialRequest([REDACTED])");
    assert_eq!(
        format!("{:?}", request.view()),
        "CipherPartialView([REDACTED])"
    );
}
