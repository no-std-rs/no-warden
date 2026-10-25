use super::*;
use crate::{
    Storage,
    organization_collections::{
        CollectionAccessData, CollectionAccessEntry, CollectionCreateData,
        OrganizationCollectionMembership, ValidatedCollectionCreate,
    },
    organizations::{
        CollectionRecord, OrganizationCreationPolicy, OrganizationMembership,
        OrganizationProfileRecord, OrganizationRecord, OrganizationStorage, UserCollectionRecord,
        ValidatedOrganizationCreate,
    },
    service::ItemMetadata,
    wire::{CipherRequest, FolderRequest, OrganizationMemberUpdateRequest, RegisterRequest},
};
use std::{format, string::String, vec, vec::Vec};
struct Id(String);
impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Copy)]
struct Target {
    member: &'static str,
    org: &'static str,
    user: &'static str,
    role: i32,
    status: i32,
    access_all: bool,
    groups: bool,
}
struct Memory {
    actor: Option<OrganizationCollectionMembership<'static>>,
    target: Option<Target>,
    owners: u64,
    calls: Vec<&'static str>,
    cache: String,
    grants: Vec<(String, bool, bool, bool)>,
    revision: u64,
    preserved: [u64; 8],
    fail: Option<&'static str>,
    fail_append: Option<usize>,
    append_count: usize,
    bad_collection: Option<&'static str>,
    stale_at: Option<&'static str>,
}
impl Memory {
    fn new() -> Self {
        Self {
            actor: Some(OrganizationCollectionMembership {
                membership: OrganizationMembership {
                    user_id: "actor",
                    organization_id: "org",
                    role: 0,
                    status: 2,
                },
                access_all: false,
            }),
            target: Some(Target {
                member: "member",
                org: "org",
                user: "recipient",
                role: 2,
                status: 2,
                access_all: false,
                groups: false,
            }),
            owners: 2,
            calls: vec![],
            cache: String::new(),
            grants: vec![("old".into(), false, false, false)],
            revision: 7,
            preserved: [11, 22, 33, 44, 55, 66, 77, 88],
            fail: None,
            fail_append: None,
            append_count: 0,
            bad_collection: None,
            stale_at: None,
        }
    }
    fn step(&mut self, name: &'static str) -> Result<(), ()> {
        self.calls.push(name);
        self.cache.clear();
        self.cache.push_str(name);
        if self.stale_at == Some(name) {
            self.actor.as_mut().unwrap().membership.status = -126;
        }
        if self.fail == Some(name) {
            Err(())
        } else {
            Ok(())
        }
    }
    fn live(&self, p: &ValidatedOrganizationMemberUpdateStart<'_, Id>) -> Result<(), ()> {
        let a = self.actor.ok_or(())?.membership;
        let t = self.target.ok_or(())?;
        if a.user_id != p.owner()
            || a.organization_id != p.organization()
            || a.status != 2
            || !matches!(a.role, 0 | 1)
            || a.role != p.actor_role()
            || t.member != p.membership_id()
            || t.org != p.organization()
            || t.user != p.user_id()
            || t.role != p.previous_role()
            || t.status != p.status()
            || t.access_all != p.previous_access_all()
            || t.groups
            || (p.requires_other_confirmed_owner() && self.owners <= 1)
        {
            Err(())
        } else {
            Ok(())
        }
    }
}
impl Storage for Memory {
    type Error = ();
    fn map_error(_: ()) -> ApiError {
        ApiError::new(ErrorKind::Conflict, "Member update provider conflict")
    }
    fn account_exists(&mut self, _: &str) -> Result<bool, ()> {
        unreachable!()
    }
    fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), ()> {
        unreachable!()
    }
    fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
        unreachable!()
    }
    fn save_folder(&mut self, _: &str, _: &str, _: &FolderRequest<'_>) -> Result<(), ()> {
        unreachable!()
    }
    fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), ()> {
        unreachable!()
    }
    fn cipher_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
        unreachable!()
    }
    fn save_cipher(&mut self, _: &str, _: &str, _: &CipherRequest<'_>) -> Result<(), ()> {
        unreachable!()
    }
    fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), ()> {
        unreachable!()
    }
    fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), ()> {
        unreachable!()
    }
}
impl OrganizationStorage for Memory {
    type Collections<'a> = &'a [UserCollectionRecord<'static>];
    type Profiles<'a> = &'a [OrganizationProfileRecord<'static>];
    fn creation_policy(&mut self, _: &str, _: &str) -> Result<OrganizationCreationPolicy, ()> {
        unreachable!()
    }
    fn create_organization(
        &mut self,
        _: &str,
        _: &ValidatedOrganizationCreate<'_, '_>,
    ) -> Result<OrganizationRecord<'_>, ()> {
        unreachable!()
    }
    fn organization_membership(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<Option<OrganizationMembership<'_>>, ()> {
        unreachable!()
    }
    fn organization(&mut self, _: &str) -> Result<Option<OrganizationRecord<'_>>, ()> {
        unreachable!()
    }
    fn user_collections(&mut self, _: &str) -> Result<Self::Collections<'_>, ()> {
        unreachable!()
    }
    fn profile_organizations(&mut self, _: &str) -> Result<Self::Profiles<'_>, ()> {
        unreachable!()
    }
}
struct Unused;
impl CollectionAccessData for Unused {
    fn collection(&self) -> UserCollectionRecord<'_> {
        unreachable!()
    }
    fn assigned(&self) -> bool {
        unreachable!()
    }
    fn users_len(&self) -> usize {
        unreachable!()
    }
    fn user(&self, _: usize) -> Option<CollectionAccessEntry<'_>> {
        unreachable!()
    }
    fn groups_enabled(&self) -> bool {
        unreachable!()
    }
    fn groups_len(&self) -> usize {
        unreachable!()
    }
    fn group(&self, _: usize) -> Option<CollectionAccessEntry<'_>> {
        unreachable!()
    }
}
impl OrganizationCollectionStorage for Memory {
    type OrgCollections<'a> = &'a [CollectionRecord<'static>];
    type AccessDetails<'a> = Unused;
    fn collection_membership(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<Option<OrganizationCollectionMembership<'_>>, ()> {
        self.step("actor")?;
        Ok(self.actor)
    }
    fn org_collections(&mut self, _: &str) -> Result<Self::OrgCollections<'_>, ()> {
        unreachable!()
    }
    fn can_manage_collection(&mut self, _: &str, _: &str) -> Result<bool, ()> {
        unreachable!()
    }
    fn collection_access_details(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<Option<Self::AccessDetails<'_>>, ()> {
        unreachable!()
    }
    fn collection_group_exists(&mut self, _: &str, _: &str) -> Result<bool, ()> {
        unreachable!()
    }
    fn collection_member_exists(&mut self, _: &str, _: &str) -> Result<bool, ()> {
        unreachable!()
    }
    fn create_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        _: &str,
        _: &str,
        _: &ValidatedCollectionCreate<'_, D>,
    ) -> Result<UserCollectionRecord<'_>, ()> {
        unreachable!()
    }
}

impl OrganizationMemberUpdateStorage for Memory {
    type UpdateId = Id;
    fn update_member(
        &mut self,
        org: &str,
        member: &str,
    ) -> Result<Option<OrganizationMemberUpdateRecord<Id>>, ()> {
        assert_eq!((org, member), ("org", "member"));
        self.step("target")?;
        Ok(self.target.map(|t| OrganizationMemberUpdateRecord {
            membership_id: Id(t.member.into()),
            organization_id: Id(t.org.into()),
            user_id: Id(t.user.into()),
            role: t.role,
            status: t.status,
            access_all: t.access_all,
            groups_configured: t.groups,
        }))
    }
    fn update_confirmed_owner_count(&mut self, org: &str) -> Result<u64, ()> {
        assert_eq!(org, "org");
        self.step("owners")?;
        Ok(self.owners)
    }
    fn update_collection(
        &mut self,
        org: &str,
        id: &str,
    ) -> Result<Option<OrganizationMemberUpdateCollection<Id>>, ()> {
        assert_eq!(org, "org");
        self.step("collection")?;
        Ok(
            matches!(id, "valid" | "second").then(|| OrganizationMemberUpdateCollection {
                id: Id(if self.bad_collection == Some("id") {
                    "foreign"
                } else {
                    id
                }
                .into()),
                organization_id: Id(if self.bad_collection == Some("org") {
                    "foreign"
                } else {
                    org
                }
                .into()),
            }),
        )
    }
    fn begin_member_update(
        &mut self,
        p: &ValidatedOrganizationMemberUpdateStart<'_, Id>,
    ) -> Result<(), ()> {
        self.step("begin")?;
        self.live(p)?;
        self.grants.clear();
        self.revision += 1;
        Ok(())
    }
    fn append_member_update_grant(
        &mut self,
        p: &ValidatedOrganizationMemberUpdateGrant<'_, '_, Id>,
    ) -> Result<(), ()> {
        self.step("append")?;
        self.live(p.start())?;
        self.append_count += 1;
        if self.fail_append == Some(self.append_count) {
            return Err(());
        }
        let s = p.selection();
        self.grants.retain(|g| g.0 != s.id);
        self.grants
            .push((s.id.into(), s.read_only, s.hide_passwords, s.manage));
        Ok(())
    }
    fn finish_member_update(
        &mut self,
        p: &ValidatedOrganizationMemberUpdate<'_, '_, Id>,
    ) -> Result<(), ()> {
        self.step("finish")?;
        self.live(p.start())?;
        let t = self.target.as_mut().unwrap();
        t.role = p.start().new_role();
        t.access_all = p.start().new_access_all();
        Ok(())
    }
}
struct Input<'a> {
    role: OrganizationInviteRole<'a>,
    permissions: OrganizationInvitePermissions,
    collections: &'a [OrganizationInviteCollection<'a>],
    groups: &'a [&'a str],
}
impl OrganizationMemberUpdateData for Input<'_> {
    fn role(&self) -> OrganizationInviteRole<'_> {
        self.role
    }
    fn permissions(&self) -> OrganizationInvitePermissions {
        self.permissions
    }
    fn collections_len(&self) -> usize {
        self.collections.len()
    }
    fn collection(&self, i: usize) -> Option<OrganizationInviteCollection<'_>> {
        self.collections.get(i).copied()
    }
    fn groups_len(&self) -> usize {
        self.groups.len()
    }
    fn group(&self, i: usize) -> Option<&str> {
        self.groups.get(i).copied()
    }
}
fn input<'a>(collections: &'a [OrganizationInviteCollection<'a>]) -> Input<'a> {
    Input {
        role: OrganizationInviteRole::Integer(2),
        permissions: OrganizationInvitePermissions::default(),
        collections,
        groups: &[],
    }
}
fn selection(id: &str) -> OrganizationInviteCollection<'_> {
    OrganizationInviteCollection {
        id,
        read_only: false,
        hide_passwords: false,
        manage: false,
    }
}
fn run(s: &mut Memory, d: &impl OrganizationMemberUpdateData) -> Result<(), ApiError> {
    VaultService::new(s).update_org_member("actor", "org", "member", d)
}
fn request(json: &str) -> OrganizationMemberUpdateRequest<'_, 4, 4> {
    serde_json::from_str(json).unwrap()
}

#[test]
fn native_member_update_schema_has_exact_case_required_flags_and_three_or_four_positional_slots() {
    for json in [
        r#"{"type":2}"#,
        r#"{"type":"User","collections":null,"groups":null}"#,
        "[2,null,null]",
        "[2,[],[],{}]",
        r#"{"type":2,"accessAll":"ignored","name":"opaque","ignored":true}"#,
    ] {
        let d = request(json);
        assert_eq!(d.collections_len(), 0);
        assert_eq!(d.groups_len(), 0);
    }
    for json in [
        "{}",
        r#"{"Type":2}"#,
        r#"{"type":null}"#,
        r#"{"type":true}"#,
        r#"{"type":2,"type":1}"#,
        r#"{"type":2,"permissions":null}"#,
        r#"{"type":2,"groups":"bad"}"#,
        r#"{"type":2,"collections":"bad"}"#,
        r#"{"type":2,"collections":[{"id":"c","readOnly":false,"hidePasswords":false}]}"#,
        r#"{"type":2,"collections":[{"Id":"c","ReadOnly":false,"HidePasswords":false,"Manage":false}]}"#,
        r#"{"type":2,"collections":[{"id":"c","readOnly":"false","hidePasswords":false,"manage":false}]}"#,
        "[2]",
        "[2,null]",
        "[2,null,null,null]",
    ] {
        assert!(
            serde_json::from_str::<OrganizationMemberUpdateRequest<'_, 4, 4>>(json).is_err(),
            "{json}"
        );
    }
    assert!(
        serde_json::from_str::<OrganizationMemberUpdateRequest<'_, 4, 4>>("[2,null,null,{},false]")
            .unwrap_err()
            .is_syntax()
    );
    let d = request(r#"{"type":2,"Collections":[{"id":"ignored"}]}"#);
    assert!(d.collections.is_none());
    let json = r#"{"type":2,"collections":[{"id":"opaque 雪","readOnly":true,"hidePasswords":false,"manage":true}]}"#;
    let d = request(json);
    let s = d.collection(0).unwrap();
    assert_eq!(s.id, "opaque 雪");
    assert!(s.read_only && s.manage && !s.hide_passwords);
    assert!(s.id.as_ptr() >= json.as_ptr());
    assert!(serde_json::from_str::<OrganizationMemberUpdateRequest<'_, 0, 0>>(json).is_err());
}

#[test]
fn member_update_owned_target_survives_reused_provider_cache_and_duplicate_grants_keep_last_flags()
{
    let mut s = Memory::new();
    let preserved = s.preserved;
    let selections = [
        selection("valid"),
        OrganizationInviteCollection {
            id: "valid",
            read_only: true,
            hide_passwords: true,
            manage: false,
        },
        selection("second"),
    ];
    run(&mut s, &input(&selections)).unwrap();
    assert_eq!(
        s.grants,
        [
            ("valid".into(), true, true, false),
            ("second".into(), false, false, false)
        ]
    );
    assert_eq!(s.revision, 8);
    assert_eq!(s.preserved, preserved);
    assert_eq!(s.target.unwrap().status, 2);
    assert_eq!(
        s.calls,
        [
            "actor",
            "target",
            "begin",
            "collection",
            "append",
            "collection",
            "append",
            "collection",
            "append",
            "finish"
        ]
    );
}

#[test]
fn missing_collection_and_group_errors_retain_reset_revision_and_valid_prefix_without_committing_new_role()
 {
    for (ids, expected) in [
        (
            ["valid", "missing"],
            vec![("valid".into(), false, false, false)],
        ),
        (["missing", "valid"], vec![]),
    ] {
        let mut s = Memory::new();
        let selected = ids.map(selection);
        let mut d = input(&selected);
        d.role = OrganizationInviteRole::Integer(3);
        let e = run(&mut s, &d).unwrap_err();
        assert_eq!(e.message, "Collection not found in Organization");
        assert_eq!(s.grants, expected);
        assert_eq!(s.revision, 8);
        assert_eq!(s.target.unwrap().role, 2);
        assert!(!s.calls.contains(&"finish"));
    }
    let mut s = Memory::new();
    let selected = [selection("valid")];
    let mut d = input(&selected);
    d.role = OrganizationInviteRole::Integer(3);
    d.groups = &["absent-group"];
    assert_eq!(
        run(&mut s, &d).unwrap_err().message,
        "Group not found in Organization"
    );
    assert_eq!(s.grants, [("valid".into(), false, false, false)]);
    assert_eq!(s.target.unwrap().role, 2);
    assert_eq!(s.revision, 8);
}

#[test]
fn full_new_roles_skip_invalid_collections_but_never_skip_requested_group_validation() {
    for role in [0, 1, 4] {
        let selected = [selection("missing")];
        let mut d = input(&selected);
        d.role = OrganizationInviteRole::Integer(role);
        d.permissions = OrganizationInvitePermissions {
            create_new_collections: true,
            edit_any_collection: true,
            delete_any_collection: true,
        };
        let mut s = Memory::new();
        run(&mut s, &d).unwrap();
        assert!(s.grants.is_empty());
        assert!(!s.calls.contains(&"collection"));
        assert!(s.target.unwrap().access_all);
        assert_eq!(
            s.target.unwrap().role,
            if role == 4 { 3 } else { role as i32 }
        );
        let mut s = Memory::new();
        d.groups = &["missing"];
        assert_eq!(
            run(&mut s, &d).unwrap_err().message,
            "Group not found in Organization"
        );
        assert_eq!(s.target.unwrap().role, 2);
        assert!(s.grants.is_empty());
        assert_eq!(s.revision, 8);
        assert!(!s.calls.contains(&"finish"));
    }
}

#[test]
fn member_update_custom_permission_truth_table_keeps_numeric_four_provenance_and_preserves_requested_flags()
 {
    for role in [
        OrganizationInviteRole::Integer(4),
        OrganizationInviteRole::String("4"),
        OrganizationInviteRole::Integer(3),
        OrganizationInviteRole::String("Manager"),
        OrganizationInviteRole::String("Custom"),
        OrganizationInviteRole::Integer(2),
    ] {
        for mask in 0..8 {
            let selected = [OrganizationInviteCollection {
                id: "valid",
                read_only: true,
                hide_passwords: true,
                manage: false,
            }];
            let mut d = input(&selected);
            d.role = role;
            d.permissions = OrganizationInvitePermissions {
                create_new_collections: mask & 1 != 0,
                edit_any_collection: mask & 2 != 0,
                delete_any_collection: mask & 4 != 0,
            };
            let custom = matches!(
                role,
                OrganizationInviteRole::Integer(4) | OrganizationInviteRole::String("4")
            );
            let full = custom && mask == 7;
            let mut s = Memory::new();
            run(&mut s, &d).unwrap();
            assert_eq!(s.target.unwrap().access_all, full);
            assert_eq!(s.grants.is_empty(), full);
            if !full {
                assert_eq!(s.grants, [("valid".into(), true, true, false)]);
            }
        }
    }
    let d = request(
        r#"{"type":4,"permissions":{"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":"true","manageUsers":true}}"#,
    );
    let mut s = Memory::new();
    run(&mut s, &d).unwrap();
    assert!(!s.target.unwrap().access_all);
}

#[test]
fn member_update_admin_hierarchy_has_distinct_unchanged_owner_and_privilege_change_errors() {
    for (before, after, expected) in [
        (0, 0, Some("Only Owners can edit Owner users")),
        (
            0,
            2,
            Some("Only Owners can grant and remove Admin or Owner privileges"),
        ),
        (
            2,
            1,
            Some("Only Owners can grant and remove Admin or Owner privileges"),
        ),
        (
            1,
            2,
            Some("Only Owners can grant and remove Admin or Owner privileges"),
        ),
        (1, 1, None),
        (2, 3, None),
        (3, 2, None),
        (2, 2, None),
    ] {
        let mut s = Memory::new();
        s.actor.as_mut().unwrap().membership.role = 1;
        s.target.as_mut().unwrap().role = before;
        let mut d = input(&[]);
        d.role = OrganizationInviteRole::Integer(after);
        let r = run(&mut s, &d);
        if let Some(message) = expected {
            assert_eq!(r.unwrap_err().message, message);
            assert_eq!(s.revision, 7);
            assert!(!s.calls.contains(&"begin"));
        } else {
            r.unwrap();
            assert_eq!(s.revision, 8);
        }
    }
}

#[test]
fn only_confirmed_owner_demotion_counts_other_confirmed_owners_and_edit_preserves_every_target_status()
 {
    for status in [0, 1, 2, -126, -128] {
        for owners in [0, 1, 2] {
            let mut s = Memory::new();
            s.target.as_mut().unwrap().role = 0;
            s.target.as_mut().unwrap().status = status;
            s.owners = owners;
            let d = input(&[]);
            let r = run(&mut s, &d);
            if status == 2 && owners <= 1 {
                assert_eq!(r.unwrap_err().message, "Can't delete the last owner");
                assert_eq!(s.revision, 7);
            } else {
                r.unwrap();
                assert_eq!(s.target.unwrap().status, status);
                assert_eq!(s.target.unwrap().role, 2);
                assert_eq!(s.calls.contains(&"owners"), status == 2);
            }
        }
    }
    let mut s = Memory::new();
    s.target.as_mut().unwrap().role = 0;
    s.target.as_mut().unwrap().user = "actor";
    s.owners = 2;
    run(&mut s, &input(&[])).unwrap();
    assert_eq!(s.target.unwrap().role, 2);
}

#[test]
fn unauthorized_actors_and_incomplete_views_never_reach_destructive_member_update_phases() {
    for (role, status) in [(0, 1), (1, -126), (2, 2), (3, 2), (4, 2)] {
        let mut s = Memory::new();
        let a = &mut s.actor.as_mut().unwrap().membership;
        a.role = role;
        a.status = status;
        assert_eq!(run(&mut s, &input(&[])).unwrap_err().status_code(), 401);
        assert_eq!(s.calls, ["actor"]);
        assert_eq!(s.revision, 7);
    }
    struct Hole(bool);
    impl OrganizationMemberUpdateData for Hole {
        fn role(&self) -> OrganizationInviteRole<'_> {
            OrganizationInviteRole::Integer(2)
        }
        fn permissions(&self) -> OrganizationInvitePermissions {
            OrganizationInvitePermissions::default()
        }
        fn collections_len(&self) -> usize {
            usize::from(!self.0)
        }
        fn collection(&self, _: usize) -> Option<OrganizationInviteCollection<'_>> {
            None
        }
        fn groups_len(&self) -> usize {
            usize::from(self.0)
        }
        fn group(&self, _: usize) -> Option<&str> {
            None
        }
    }
    for hole in [Hole(false), Hole(true)] {
        let mut s = Memory::new();
        assert_eq!(run(&mut s, &hole).unwrap_err().kind, ErrorKind::Storage);
        assert_eq!(s.calls, ["actor"]);
        assert_eq!(s.revision, 7);
    }
    let mut s = Memory::new();
    assert_eq!(
        VaultService::new(&mut s)
            .update_org_member("", "org", "member", &Hole(true))
            .unwrap_err()
            .status_code(),
        401
    );
    assert!(s.calls.is_empty());
}

#[test]
fn scoped_owned_provider_facts_missing_targets_and_configured_groups_fail_closed_at_their_phase() {
    for field in ["member", "org", "user"] {
        let mut s = Memory::new();
        let t = s.target.as_mut().unwrap();
        match field {
            "member" => t.member = "foreign",
            "org" => t.org = "foreign",
            _ => t.user = "",
        };
        assert_eq!(
            run(&mut s, &input(&[])).unwrap_err().kind,
            ErrorKind::Storage
        );
        assert_eq!(s.revision, 7);
    }
    let mut s = Memory::new();
    s.target = None;
    assert_eq!(
        run(&mut s, &input(&[])).unwrap_err().message,
        "The specified user isn't member of the organization"
    );
    assert_eq!(s.revision, 7);
    let mut s = Memory::new();
    s.target.as_mut().unwrap().groups = true;
    assert_eq!(
        run(&mut s, &input(&[])).unwrap_err().message,
        "Configured organization member group updates are not supported"
    );
    assert_eq!(s.revision, 7);
    assert!(!s.calls.contains(&"begin"));
    for bad in ["id", "org"] {
        let mut s = Memory::new();
        s.bad_collection = Some(bad);
        let selected = [selection("valid")];
        assert_eq!(
            run(&mut s, &input(&selected)).unwrap_err().kind,
            ErrorKind::Storage
        );
        assert!(s.grants.is_empty());
        assert_eq!(s.revision, 8);
        assert!(!s.calls.contains(&"finish"));
    }
}

#[test]
fn member_update_provider_failures_and_live_authority_rechecks_preserve_prior_phase_effects() {
    for fail in ["actor", "target", "begin", "collection", "append", "finish"] {
        let mut s = Memory::new();
        s.fail = Some(fail);
        let selected = [selection("valid")];
        let mut d = input(&selected);
        d.role = OrganizationInviteRole::Integer(3);
        assert_eq!(run(&mut s, &d).unwrap_err().kind, ErrorKind::Conflict);
        let started = matches!(fail, "collection" | "append" | "finish");
        assert_eq!(s.revision, if started { 8 } else { 7 });
        assert_eq!(s.target.unwrap().role, 2);
        if fail == "finish" {
            assert_eq!(s.grants, [("valid".into(), false, false, false)]);
        } else if started {
            assert!(s.grants.is_empty());
        } else {
            assert_eq!(s.grants[0].0, "old");
        }
    }
    let mut s = Memory::new();
    s.fail_append = Some(2);
    let selected = [selection("valid"), selection("second")];
    assert!(run(&mut s, &input(&selected)).is_err());
    assert_eq!(s.grants, [("valid".into(), false, false, false)]);
    for stale in ["begin", "append", "finish"] {
        let mut s = Memory::new();
        s.stale_at = Some(stale);
        let selected = [selection("valid")];
        assert!(run(&mut s, &input(&selected)).is_err());
        assert_eq!(s.target.unwrap().role, 2);
        assert_eq!(s.revision, if stale == "begin" { 7 } else { 8 });
    }
}

#[test]
fn indexed_member_update_has_no_intrinsic_fixed_capacity_or_duplicate_deduplication() {
    let selections = [selection("valid"); 1025];
    let mut s = Memory::new();
    run(&mut s, &input(&selections)).unwrap();
    assert_eq!(s.append_count, 1025);
    assert_eq!(s.grants.len(), 1);
    assert_eq!(s.revision, 8);
}

#[test]
fn member_update_debug_redacts_owned_provider_handles_selections_and_sealed_authority() {
    let mut s = Memory::new();
    let target = s.update_member("org", "member").unwrap().unwrap();
    assert_eq!(
        format!("{target:?}"),
        "OrganizationMemberUpdateRecord([REDACTED])"
    );
    let start = ValidatedOrganizationMemberUpdateStart {
        owner: "secret-owner",
        target: &target,
        actor_role: 0,
        new_role: 3,
        new_access_all: false,
    };
    let grant = ValidatedOrganizationMemberUpdateGrant {
        start: &start,
        selection: selection("secret-collection"),
    };
    let final_plan = ValidatedOrganizationMemberUpdate { start: &start };
    for value in [
        format!("{start:?}"),
        format!("{grant:?}"),
        format!("{final_plan:?}"),
        format!(
            "{:?}",
            request(
                r#"{"type":"User","collections":[{"id":"secret","readOnly":false,"hidePasswords":false,"manage":false}]}"#
            )
        ),
    ] {
        assert!(!value.contains("secret"));
        assert!(value.contains("[REDACTED]"));
    }
}
