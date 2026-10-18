//! Equivalent-domain settings over caller-owned data and an adapter-supplied global catalog.
//!
//! Strings and signed IDs are opaque. Order, duplicate IDs, duplicate strings and empty
//! groups are retained; these services do not perform domain-name validation or normalization.

use crate::{
    ApiError, Storage, VaultService,
    service::require_owner,
    wire::{DomainSettingsRequest, DomainSettingsResponse, DomainSettingsUpdateResponse},
};

/// Indexed data with no intrinsic batch/string limit. Every index below its count must
/// exist, and counts/entries must stay unchanged for a service call and provider commit.
pub trait DomainSettingsData {
    fn excluded_global_count(&self) -> usize;
    fn excluded_global(&self, index: usize) -> Option<i32>;
    fn equivalent_group_count(&self) -> usize;
    fn equivalent_domain_count(&self, group: usize) -> Option<usize>;
    fn equivalent_domain(&self, group: usize, index: usize) -> Option<&str>;
}

impl<T: DomainSettingsData + ?Sized> DomainSettingsData for &T {
    fn excluded_global_count(&self) -> usize {
        (**self).excluded_global_count()
    }
    fn excluded_global(&self, index: usize) -> Option<i32> {
        (**self).excluded_global(index)
    }
    fn equivalent_group_count(&self) -> usize {
        (**self).equivalent_group_count()
    }
    fn equivalent_domain_count(&self, group: usize) -> Option<usize> {
        (**self).equivalent_domain_count(group)
    }
    fn equivalent_domain(&self, group: usize, index: usize) -> Option<&str> {
        (**self).equivalent_domain(group, index)
    }
}

/// An allocation-free view over caller-owned slices; hosts with owned vectors can
/// implement `DomainSettingsData` directly instead of converting their storage.
#[derive(Clone, Copy)]
pub struct DomainSettingsView<'a> {
    pub excluded_globals: &'a [i32],
    pub equivalent_domains: &'a [&'a [&'a str]],
}
impl core::fmt::Debug for DomainSettingsView<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DomainSettingsView")
            .field("excluded_global_count", &self.excluded_globals.len())
            .field("equivalent_group_count", &self.equivalent_domains.len())
            .finish_non_exhaustive()
    }
}
impl DomainSettingsData for DomainSettingsView<'_> {
    fn excluded_global_count(&self) -> usize {
        self.excluded_globals.len()
    }
    fn excluded_global(&self, index: usize) -> Option<i32> {
        self.excluded_globals.get(index).copied()
    }
    fn equivalent_group_count(&self) -> usize {
        self.equivalent_domains.len()
    }
    fn equivalent_domain_count(&self, group: usize) -> Option<usize> {
        self.equivalent_domains.get(group).map(|g| g.len())
    }
    fn equivalent_domain(&self, group: usize, index: usize) -> Option<&str> {
        self.equivalent_domains.get(group)?.get(index).copied()
    }
}
impl<const E: usize, const G: usize, const D: usize> DomainSettingsData
    for DomainSettingsRequest<'_, E, G, D>
{
    fn excluded_global_count(&self) -> usize {
        self.excluded_global_equivalent_domains
            .as_ref()
            .map_or(0, |v| v.len())
    }
    fn excluded_global(&self, index: usize) -> Option<i32> {
        self.excluded_global_equivalent_domains
            .as_ref()?
            .get(index)
            .copied()
    }
    fn equivalent_group_count(&self) -> usize {
        self.equivalent_domains.as_ref().map_or(0, |v| v.len())
    }
    fn equivalent_domain_count(&self, group: usize) -> Option<usize> {
        self.equivalent_domains
            .as_ref()?
            .get(group)
            .map(|g| g.len())
    }
    fn equivalent_domain(&self, group: usize, index: usize) -> Option<&str> {
        self.equivalent_domains
            .as_ref()?
            .get(group)?
            .get(index)
            .copied()
    }
}

/// The global catalog is adapter input, never mutable account state in the core.
/// Its indexed entries must remain complete and stable while a response is serialized.
pub trait GlobalDomainCatalog {
    fn group_count(&self) -> usize;
    fn kind(&self, group: usize) -> Option<i32>;
    fn domain_count(&self, group: usize) -> Option<usize>;
    fn domain(&self, group: usize, index: usize) -> Option<&str>;
}
impl<T: GlobalDomainCatalog + ?Sized> GlobalDomainCatalog for &T {
    fn group_count(&self) -> usize {
        (**self).group_count()
    }
    fn kind(&self, group: usize) -> Option<i32> {
        (**self).kind(group)
    }
    fn domain_count(&self, group: usize) -> Option<usize> {
        (**self).domain_count(group)
    }
    fn domain(&self, group: usize, index: usize) -> Option<&str> {
        (**self).domain(group, index)
    }
}

/// Convenient static/caller-owned catalog entry. No catalog is hardcoded in the core.
#[derive(Clone, Copy)]
pub struct GlobalDomain<'a> {
    pub kind: i32,
    pub domains: &'a [&'a str],
}
impl core::fmt::Debug for GlobalDomain<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GlobalDomain")
            .field("kind", &self.kind)
            .field("domain_count", &self.domains.len())
            .finish_non_exhaustive()
    }
}
impl GlobalDomainCatalog for [GlobalDomain<'_>] {
    fn group_count(&self) -> usize {
        self.len()
    }
    fn kind(&self, group: usize) -> Option<i32> {
        self.get(group).map(|g| g.kind)
    }
    fn domain_count(&self, group: usize) -> Option<usize> {
        self.get(group).map(|g| g.domains.len())
    }
    fn domain(&self, group: usize, index: usize) -> Option<&str> {
        self.get(group)?.domains.get(index).copied()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainProjection {
    /// GET settings includes every catalog group and its computed exclusion flag.
    All,
    /// Sync omits excluded catalog groups, preserving the order of retained groups.
    Sync,
}

/// Opt-in persistence. Hold the application's authenticated operation lock/transaction.
/// Read views must belong only to the verified owner and keep their storage alive.
/// Updating replaces both arrays exactly (absent/null fields are empty in the view) and
/// advances the account revision even for identical values. Commit both arrays/revision
/// atomically; any error preserves all prior settings/revisions and unrelated keys,
/// credentials, sessions, vault payloads and foreign state. Notifications belong to the
/// adapter after commit and are not implemented by this interface.
pub trait DomainSettingsStorage: Storage {
    type Settings<'a>: DomainSettingsData
    where
        Self: 'a;
    fn domain_settings(&mut self, owner: &str) -> Result<Self::Settings<'_>, Self::Error>;
    fn update_domain_settings<D: DomainSettingsData + ?Sized>(
        &mut self,
        owner: &str,
        data: &D,
    ) -> Result<(), Self::Error>;
}
impl<T: DomainSettingsStorage + ?Sized> DomainSettingsStorage for &mut T {
    type Settings<'a>
        = T::Settings<'a>
    where
        Self: 'a;
    fn domain_settings(&mut self, owner: &str) -> Result<Self::Settings<'_>, Self::Error> {
        (**self).domain_settings(owner)
    }
    fn update_domain_settings<D: DomainSettingsData + ?Sized>(
        &mut self,
        owner: &str,
        data: &D,
    ) -> Result<(), Self::Error> {
        (**self).update_domain_settings(owner, data)
    }
}

fn validate_data<D: DomainSettingsData + ?Sized>(data: &D) -> Result<(), ApiError> {
    let missing = || ApiError::invalid("domains", "The domain settings view is incomplete.");
    for i in 0..data.excluded_global_count() {
        data.excluded_global(i).ok_or_else(missing)?;
    }
    for g in 0..data.equivalent_group_count() {
        for i in 0..data.equivalent_domain_count(g).ok_or_else(missing)? {
            data.equivalent_domain(g, i).ok_or_else(missing)?;
        }
    }
    Ok(())
}
fn validate_catalog<C: GlobalDomainCatalog + ?Sized>(catalog: &C) -> Result<(), ApiError> {
    let missing = || {
        ApiError::invalid(
            "globalEquivalentDomains",
            "The global catalog view is incomplete.",
        )
    };
    for g in 0..catalog.group_count() {
        catalog.kind(g).ok_or_else(missing)?;
        for i in 0..catalog.domain_count(g).ok_or_else(missing)? {
            catalog.domain(g, i).ok_or_else(missing)?;
        }
    }
    Ok(())
}
impl<S: DomainSettingsStorage> VaultService<S> {
    pub fn domain_settings<'a, C: GlobalDomainCatalog + ?Sized>(
        &'a mut self,
        owner: &str,
        catalog: &'a C,
        projection: DomainProjection,
    ) -> Result<DomainSettingsResponse<'a, S::Settings<'a>, C>, ApiError> {
        require_owner(owner)?;
        validate_catalog(catalog)?;
        let settings = self
            .storage_mut()
            .domain_settings(owner)
            .map_err(S::map_error)?;
        validate_data(&settings)?;
        Ok(DomainSettingsResponse::new(settings, catalog, projection))
    }
    pub fn update_domain_settings<D: DomainSettingsData + ?Sized>(
        &mut self,
        owner: &str,
        data: &D,
    ) -> Result<DomainSettingsUpdateResponse, ApiError> {
        require_owner(owner)?;
        validate_data(data)?;
        self.storage_mut()
            .update_domain_settings(owner, data)
            .map_err(S::map_error)?;
        Ok(DomainSettingsUpdateResponse {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorKind,
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use std::{
        collections::BTreeMap,
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    #[derive(Clone, Eq, PartialEq)]
    struct Settings {
        excluded: Vec<i32>,
        groups: Vec<Vec<String>>,
    }
    impl core::fmt::Debug for Settings {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Settings")
                .field("group_count", &self.groups.len())
                .finish_non_exhaustive()
        }
    }
    impl DomainSettingsData for Settings {
        fn excluded_global_count(&self) -> usize {
            self.excluded.len()
        }
        fn excluded_global(&self, i: usize) -> Option<i32> {
            self.excluded.get(i).copied()
        }
        fn equivalent_group_count(&self) -> usize {
            self.groups.len()
        }
        fn equivalent_domain_count(&self, g: usize) -> Option<usize> {
            self.groups.get(g).map(Vec::len)
        }
        fn equivalent_domain(&self, g: usize, i: usize) -> Option<&str> {
            self.groups.get(g)?.get(i).map(String::as_str)
        }
    }
    #[derive(Clone, Eq, PartialEq)]
    struct Account {
        settings: Settings,
        revision: usize,
        authority: &'static str,
        vault: &'static str,
    }
    impl core::fmt::Debug for Account {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Account")
                .field("revision", &self.revision)
                .finish_non_exhaustive()
        }
    }
    #[derive(Clone, Copy, Debug)]
    enum Failure {
        Backend,
        Conflict,
        Missing,
    }
    struct Memory {
        accounts: BTreeMap<String, Account>,
        calls: Vec<&'static str>,
        fail_at: Option<&'static str>,
        failure: Failure,
    }
    impl core::fmt::Debug for Memory {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Memory")
                .field("calls", &self.calls)
                .finish_non_exhaustive()
        }
    }
    impl Memory {
        fn new() -> Self {
            let alice = Account {
                settings: Settings {
                    excluded: vec![-2, -2, i32::MIN, 999],
                    groups: vec![
                        vec![
                            "  Mixed.Case  ".into(),
                            "".into(),
                            "雪\0\"\n".into(),
                            "".into(),
                        ],
                        vec![],
                    ],
                },
                revision: 4,
                authority: "preserved credentials and sessions",
                vault: "preserved encrypted items",
            };
            let mut bob = alice.clone();
            bob.settings = Settings {
                excluded: vec![],
                groups: vec![vec!["foreign-only".into()]],
            };
            Self {
                accounts: BTreeMap::from([("alice".into(), alice), ("bob".into(), bob)]),
                calls: Vec::new(),
                fail_at: None,
                failure: Failure::Backend,
            }
        }
        fn fail(&self, call: &str) -> Result<(), Failure> {
            if self.fail_at == Some(call) {
                Err(self.failure)
            } else {
                Ok(())
            }
        }
    }
    impl Storage for Memory {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            match error {
                Failure::Backend => ApiError::new(ErrorKind::Storage, "Domain provider failed."),
                Failure::Conflict => {
                    ApiError::new(ErrorKind::Conflict, "Retry the domain operation.")
                }
                Failure::Missing => ApiError::new(ErrorKind::NotFound, "Account unavailable."),
            }
        }
        fn account_exists(&mut self, _: &str) -> Result<bool, Failure> {
            unreachable!()
        }
        fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), Failure> {
            unreachable!()
        }
        fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
            unreachable!()
        }
        fn save_folder(&mut self, _: &str, _: &str, _: &FolderRequest<'_>) -> Result<(), Failure> {
            unreachable!()
        }
        fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), Failure> {
            unreachable!()
        }
        fn cipher_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
            unreachable!()
        }
        fn save_cipher(&mut self, _: &str, _: &str, _: &CipherRequest<'_>) -> Result<(), Failure> {
            unreachable!()
        }
        fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), Failure> {
            unreachable!()
        }
        fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), Failure> {
            unreachable!()
        }
    }
    impl DomainSettingsStorage for Memory {
        type Settings<'a> = &'a Settings;
        fn domain_settings(&mut self, owner: &str) -> Result<Self::Settings<'_>, Failure> {
            self.calls.push("read");
            self.fail("read")?;
            Ok(&self.accounts.get(owner).ok_or(Failure::Missing)?.settings)
        }
        fn update_domain_settings<D: DomainSettingsData + ?Sized>(
            &mut self,
            owner: &str,
            data: &D,
        ) -> Result<(), Failure> {
            self.calls.push("update");
            let mut staged = self.accounts.clone();
            let account = staged.get_mut(owner).ok_or(Failure::Missing)?;
            account.settings.excluded = (0..data.excluded_global_count())
                .map(|i| data.excluded_global(i).unwrap())
                .collect();
            account.settings.groups = (0..data.equivalent_group_count())
                .map(|g| {
                    (0..data.equivalent_domain_count(g).unwrap())
                        .map(|i| data.equivalent_domain(g, i).unwrap().to_string())
                        .collect()
                })
                .collect();
            account.revision += 1;
            self.fail("update")?;
            self.accounts = staged;
            Ok(())
        }
    }
    fn catalog() -> [GlobalDomain<'static>; 3] {
        [
            GlobalDomain {
                kind: 1,
                domains: &["one", "one"],
            },
            GlobalDomain {
                kind: -2,
                domains: &["excluded"],
            },
            GlobalDomain {
                kind: 3,
                domains: &["three"],
            },
        ]
    }

    #[test]
    fn get_and_sync_project_catalog_flags_without_normalizing_or_reordering_settings() {
        let catalog = catalog();
        let mut service = VaultService::new(Memory::new());
        let before = service.storage().accounts.clone();
        let all = serde_json::to_value(
            service
                .domain_settings("alice", &catalog[..], DomainProjection::All)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            all,
            serde_json::json!({"equivalentDomains":[["  Mixed.Case  ","","雪\0\"\n",""],[]],"globalEquivalentDomains":[{"type":1,"domains":["one","one"],"excluded":false},{"type":-2,"domains":["excluded"],"excluded":true},{"type":3,"domains":["three"],"excluded":false}],"object":"domains"})
        );
        let sync = serde_json::to_value(
            service
                .domain_settings("alice", &catalog[..], DomainProjection::Sync)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sync["equivalentDomains"], all["equivalentDomains"]);
        assert_eq!(
            sync["globalEquivalentDomains"],
            serde_json::json!([
                all["globalEquivalentDomains"][0],
                all["globalEquivalentDomains"][2]
            ])
        );
        let foreign = serde_json::to_value(
            service
                .domain_settings("bob", &catalog[..], DomainProjection::All)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            foreign["equivalentDomains"],
            serde_json::json!([["foreign-only"]])
        );
        assert_eq!(service.storage().accounts, before);
    }

    #[test]
    fn host_owned_views_have_no_fixed_capacity_and_commit_exact_duplicates_and_opaque_strings() {
        let settings = Settings {
            excluded: (0..1000).map(|_| i32::MIN).collect(),
            groups: (0..129)
                .map(|_| vec!["".into(), "Unicode雪\0".into(), "Unicode雪\0".into()])
                .collect(),
        };
        let mut storage = Memory::new();
        let mut expected = storage.accounts.clone();
        expected.get_mut("alice").unwrap().settings = settings.clone();
        expected.get_mut("alice").unwrap().revision += 2;
        let mut service = VaultService::new(&mut storage);
        for _ in 0..2 {
            let response = service.update_domain_settings("alice", &settings).unwrap();
            assert_eq!(
                serde_json::to_value(response).unwrap(),
                serde_json::json!({})
            );
        }
        assert_eq!(service.storage().accounts, expected);
        assert_eq!(service.storage().calls, ["update", "update"]);
    }

    #[test]
    fn omitted_or_null_fields_replace_each_array_with_empty_instead_of_retaining_old_values() {
        for input in [
            "{}",
            "[null,null]",
            r#"{"equivalentDomains":null}"#,
            r#"{"excludedGlobalEquivalentDomains":null}"#,
        ] {
            let request: DomainSettingsRequest<'_, 0, 0, 0> = serde_json::from_str(input).unwrap();
            let mut service = VaultService::new(Memory::new());
            service.update_domain_settings("alice", &request).unwrap();
            let stored = &service.storage().accounts["alice"];
            assert!(stored.settings.excluded.is_empty());
            assert!(stored.settings.groups.is_empty());
            assert_eq!(stored.revision, 5);
        }
    }

    #[test]
    fn authentication_precedes_all_provider_and_view_access() {
        let mut service = VaultService::new(Memory::new());
        assert_eq!(
            service
                .update_domain_settings("", &Incomplete)
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
        assert_eq!(
            service
                .domain_settings("", &Incomplete, DomainProjection::All)
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
        assert!(service.storage().calls.is_empty());
    }

    struct Incomplete;
    impl DomainSettingsData for Incomplete {
        fn excluded_global_count(&self) -> usize {
            1
        }
        fn excluded_global(&self, _: usize) -> Option<i32> {
            None
        }
        fn equivalent_group_count(&self) -> usize {
            0
        }
        fn equivalent_domain_count(&self, _: usize) -> Option<usize> {
            None
        }
        fn equivalent_domain(&self, _: usize, _: usize) -> Option<&str> {
            None
        }
    }
    impl GlobalDomainCatalog for Incomplete {
        fn group_count(&self) -> usize {
            1
        }
        fn kind(&self, _: usize) -> Option<i32> {
            None
        }
        fn domain_count(&self, _: usize) -> Option<usize> {
            None
        }
        fn domain(&self, _: usize, _: usize) -> Option<&str> {
            None
        }
    }
    #[test]
    fn incomplete_views_fail_before_mutation_or_catalog_provider_reads() {
        let mut service = VaultService::new(Memory::new());
        let before = service.storage().accounts.clone();
        assert_eq!(
            service
                .update_domain_settings("alice", &Incomplete)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidRequest
        );
        assert_eq!(
            service
                .domain_settings("alice", &Incomplete, DomainProjection::All)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidRequest
        );
        assert!(service.storage().calls.is_empty());
        assert_eq!(service.storage().accounts, before);
    }

    #[test]
    fn provider_errors_preserve_both_arrays_revisions_and_existing_error_mapping() {
        let catalog = catalog();
        let empty = DomainSettingsView {
            excluded_globals: &[],
            equivalent_domains: &[],
        };
        for (failure, kind) in [
            (Failure::Backend, ErrorKind::Storage),
            (Failure::Conflict, ErrorKind::Conflict),
        ] {
            for operation in ["read", "update"] {
                let mut storage = Memory::new();
                storage.failure = failure;
                storage.fail_at = Some(operation);
                let before = storage.accounts.clone();
                let mut service = VaultService::new(&mut storage);
                let error = if operation == "read" {
                    service
                        .domain_settings("alice", &catalog[..], DomainProjection::All)
                        .unwrap_err()
                } else {
                    service.update_domain_settings("alice", &empty).unwrap_err()
                };
                assert_eq!(error.kind, kind);
                assert_eq!(service.storage().accounts, before);
                assert_eq!(service.storage().calls, [operation]);
            }
        }
    }
}
