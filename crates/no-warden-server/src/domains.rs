//! Host decoding and catalog for equivalent-domain protocol settings.
//!
//! Catalog facts are pinned to Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91:
//! <https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/static/global_domains.json>.
//! The exact source SHA-256 is
//! `3f2c8a39c8c1a8dd9a8c9f4c6b14201afd7113d4fea2b22a27e1847e95e7933a`.

use no_warden::domains::{DomainSettingsData, GlobalDomainCatalog};
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Default)]
pub struct Settings {
    pub excluded_globals: Vec<i32>,
    pub equivalent_domains: Vec<Vec<String>>,
}

impl Settings {
    pub fn from_data<D: DomainSettingsData + ?Sized>(data: &D) -> rusqlite::Result<Self> {
        let excluded_globals = (0..data.excluded_global_count())
            .map(|index| {
                data.excluded_global(index)
                    .ok_or(rusqlite::Error::InvalidQuery)
            })
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let equivalent_domains = (0..data.equivalent_group_count())
            .map(|group| {
                let count = data
                    .equivalent_domain_count(group)
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                (0..count)
                    .map(|index| {
                        data.equivalent_domain(group, index)
                            .map(str::to_owned)
                            .ok_or(rusqlite::Error::InvalidQuery)
                    })
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Self {
            excluded_globals,
            equivalent_domains,
        })
    }
}

impl DomainSettingsData for Settings {
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
        self.equivalent_domains.get(group).map(Vec::len)
    }
    fn equivalent_domain(&self, group: usize, index: usize) -> Option<&str> {
        self.equivalent_domains
            .get(group)?
            .get(index)
            .map(String::as_str)
    }
}

// The declaration order and lack of explicit defaults match upstream
// EquivDomainData: missing map fields are absent, while positional sequences
// must include both slots (which can each be null).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Input {
    excluded_global_equivalent_domains: Option<Vec<i32>>,
    equivalent_domains: Option<Vec<Vec<String>>>,
}

impl DomainSettingsData for Input {
    fn excluded_global_count(&self) -> usize {
        self.excluded_global_equivalent_domains
            .as_ref()
            .map_or(0, Vec::len)
    }
    fn excluded_global(&self, index: usize) -> Option<i32> {
        self.excluded_global_equivalent_domains
            .as_ref()?
            .get(index)
            .copied()
    }
    fn equivalent_group_count(&self) -> usize {
        self.equivalent_domains.as_ref().map_or(0, Vec::len)
    }
    fn equivalent_domain_count(&self, group: usize) -> Option<usize> {
        self.equivalent_domains.as_ref()?.get(group).map(Vec::len)
    }
    fn equivalent_domain(&self, group: usize, index: usize) -> Option<&str> {
        self.equivalent_domains
            .as_ref()?
            .get(group)?
            .get(index)
            .map(String::as_str)
    }
}

pub(crate) fn parse_input(body: &[u8]) -> Result<Input, crate::Failure> {
    serde_json::from_slice(body).map_err(crate::json_guard_error)
}

#[derive(Deserialize)]
struct CatalogGroup {
    #[serde(rename = "type")]
    kind: i32,
    domains: Vec<String>,
}

pub(crate) struct Catalog(Vec<CatalogGroup>);

impl GlobalDomainCatalog for Catalog {
    fn group_count(&self) -> usize {
        self.0.len()
    }
    fn kind(&self, group: usize) -> Option<i32> {
        self.0.get(group).map(|entry| entry.kind)
    }
    fn domain_count(&self, group: usize) -> Option<usize> {
        self.0.get(group).map(|entry| entry.domains.len())
    }
    fn domain(&self, group: usize, index: usize) -> Option<&str> {
        self.0.get(group)?.domains.get(index).map(String::as_str)
    }
}

pub(crate) fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        Catalog(
            serde_json::from_str(include_str!("global_domains.json"))
                .expect("Bundled domain catalog must be valid JSON"),
        )
    })
}

// The first key follows Rocket 0.5.1 NameView::shift/key_lossy, including a
// leading dot, bracketed key, or unfinished bracket at the end of the name.
// <https://github.com/rwf2/Rocket/blob/v0.5.1/core/lib/src/form/name/view.rs#L152-L175>
fn query_root(name: &str) -> &str {
    if name.starts_with('=') {
        return "";
    }
    if let Some(bracketed) = name.strip_prefix('[') {
        return bracketed.split(']').next().unwrap_or_default();
    }
    name.strip_prefix('.')
        .unwrap_or(name)
        .split(['.', '['])
        .next()
        .unwrap_or_default()
}

pub(crate) fn sync_excludes(query: Option<&str>) -> Result<bool, crate::Failure> {
    let pairs: Vec<(String, String)> = serde_urlencoded::from_str(query.unwrap_or_default())
        .map_err(|_| {
            crate::Failure(
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid sync query",
            )
        })?;
    // Rocket's derived form matches the first name segment. Its lenient scalar
    // parser accepts a remaining dotted/bracketed suffix after that match.
    let Some((_, value)) = pairs
        .iter()
        .find(|(name, _)| query_root(name) == "excludeDomains")
    else {
        return Ok(false);
    };
    if ["", "on", "yes", "true"]
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
    {
        return Ok(true);
    }
    if ["off", "no", "false"]
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
    {
        return Ok(false);
    }
    Err(crate::Failure(
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        "Invalid sync query",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use no_warden::{domains::DomainProjection, wire::DomainSettingsResponse};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    #[test]
    fn bundled_catalog_matches_the_pinned_source_facts_and_hash() {
        let digest = Sha256::digest(include_bytes!("global_domains.json"));
        assert_eq!(
            format!("{digest:x}"),
            "3f2c8a39c8c1a8dd9a8c9f4c6b14201afd7113d4fea2b22a27e1847e95e7933a"
        );
        assert_eq!(catalog().group_count(), 91);
        assert_eq!(catalog().kind(0), Some(2));
        assert_eq!(catalog().domain(0, 0), Some("ameritrade.com"));
        assert_eq!(catalog().domain(0, 1), Some("tdameritrade.com"));
        assert!(catalog().kind(91).is_none());
        assert!(catalog().domain(0, 2).is_none());
    }

    #[test]
    fn domain_input_preserves_opaque_values_and_has_no_core_decoder_capacity_limit() {
        for body in [
            b"{}".as_slice(),
            br#"{"equivalentDomains":null,"excludedGlobalEquivalentDomains":null,"ignored":true}"#
                .as_slice(),
            b"[null,null]".as_slice(),
        ] {
            let input =
                parse_input(body).unwrap_or_else(|_| panic!("Valid empty settings were rejected."));
            assert_eq!(input.excluded_global_count(), 0);
            assert_eq!(input.equivalent_group_count(), 0);
        }
        let body=br#"{"excludedGlobalEquivalentDomains":[-2147483648,2,2,2147483647],"equivalentDomains":[[],["","\u0000","caf\u00e9","quoted \"","same","same"]]}"#;
        let input =
            parse_input(body).unwrap_or_else(|_| panic!("Opaque domain settings were rejected."));
        let settings = Settings::from_data(&input).unwrap();
        assert!(settings.excluded_globals == [i32::MIN, 2, 2, i32::MAX]);
        assert!(
            settings.equivalent_domains
                == vec![vec![], vec!["", "\0", "café", "quoted \"", "same", "same"]]
        );
        let sequence = parse_input(br#"[[2,-1],[[],["one","two"]]]"#)
            .unwrap_or_else(|_| panic!("Valid positional domain settings were rejected."));
        assert_eq!(sequence.excluded_global(0), Some(2));
        assert_eq!(sequence.equivalent_domain(1, 1), Some("two"));
        let large=json!({"excludedGlobalEquivalentDomains":vec![2;257],"equivalentDomains":vec![vec!["opaque";257];129]}).to_string();
        let input = parse_input(large.as_bytes())
            .unwrap_or_else(|_| panic!("Host imposed an unsupported decoder capacity."));
        assert_eq!(input.excluded_global_count(), 257);
        assert_eq!(input.equivalent_group_count(), 129);
        assert_eq!(input.equivalent_domain_count(128), Some(257));
    }

    #[test]
    fn domain_input_preserves_schema_syntax_and_duplicate_known_field_errors() {
        for (body,status) in [
            (b"{".as_slice(),StatusCode::BAD_REQUEST),
            (br#"[null,null,null]"#.as_slice(),StatusCode::BAD_REQUEST),
            (b"[]".as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (b"[null]".as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (b"null".as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"excludedGlobalEquivalentDomains":[2147483648]}"#.as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"excludedGlobalEquivalentDomains":[-2147483649]}"#.as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"excludedGlobalEquivalentDomains":[1.0]}"#.as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"excludedGlobalEquivalentDomains":["2"]}"#.as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"equivalentDomains":[null]}"#.as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"equivalentDomains":[[null]]}"#.as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"equivalentDomains":[[7]]}"#.as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"equivalentDomains":"not-an-array"}"#.as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"equivalentDomains":null,"equivalentDomains":null}"#.as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"excludedGlobalEquivalentDomains":[],"excludedGlobalEquivalent\u0044omains":[]}"#.as_slice(),StatusCode::UNPROCESSABLE_ENTITY),
        ] {
            let error=parse_input(body).err().expect("Invalid domain settings were accepted.");
            assert_eq!(error.0,status);
            assert_eq!(error.1,"Invalid request");
        }
    }

    #[test]
    fn domain_projection_sets_exclusion_flags_and_filters_only_sync_globals() {
        let settings = Settings {
            excluded_globals: vec![2, 2, -1, i32::MAX],
            equivalent_domains: vec![vec![], vec!["opaque\0café".into(), "".into()]],
        };
        let all = serde_json::to_value(DomainSettingsResponse::new(
            &settings,
            catalog(),
            DomainProjection::All,
        ))
        .unwrap();
        let sync = serde_json::to_value(DomainSettingsResponse::new(
            &settings,
            catalog(),
            DomainProjection::Sync,
        ))
        .unwrap();
        assert_eq!(all.as_object().unwrap().len(), 3);
        assert_eq!(all["object"], "domains");
        assert!(all["equivalentDomains"] == json!(settings.equivalent_domains));
        assert!(sync["equivalentDomains"] == all["equivalentDomains"]);
        let globals = all["globalEquivalentDomains"].as_array().unwrap();
        assert_eq!(globals.len(), 91);
        assert_eq!(
            globals
                .iter()
                .filter(|entry| entry["excluded"] == true)
                .count(),
            1
        );
        assert_eq!(globals[0]["type"], 2);
        assert_eq!(globals[0]["excluded"], true);
        let filtered = sync["globalEquivalentDomains"].as_array().unwrap();
        assert_eq!(filtered.len(), 90);
        assert!(
            filtered
                .iter()
                .all(|entry| entry["type"] != 2 && entry["excluded"] == false)
        );
        assert!(
            filtered
                .iter()
                .all(|entry| entry.as_object().unwrap().len() == 3)
        );
        assert!(filtered.iter().all(|entry| {
            entry["domains"]
                .as_array()
                .is_some_and(|domains| domains.iter().all(Value::is_string))
        }));
    }

    #[test]
    fn sync_query_accepts_rocket_leading_name_delimiters() {
        let accepted = [
            "[excludeDomains]=true",
            ".excludeDomains=true",
            "[excludeDomains=true",
            "[excludeDomains]junk=true",
            ".excludeDomains[foo]=true",
        ]
        .map(|query| {
            sync_excludes(Some(query))
                .unwrap_or_else(|_| panic!("Valid leading-delimiter query was rejected."))
        });
        assert_eq!(accepted, [true; 5]);
        for query in [
            "[excludeDomains.foo]=true",
            "[excludeDomains.foo=true",
            "..excludeDomains=true",
            "[]excludeDomains=true",
        ] {
            assert!(
                !sync_excludes(Some(query))
                    .unwrap_or_else(|_| panic!("Ignored form name caused an error."))
            );
        }
    }

    #[test]
    fn sync_query_uses_rocket_boolean_aliases_case_sensitive_names_and_first_value() {
        for query in [
            None,
            Some(""),
            Some("excludeDomains=false"),
            Some("excludeDomains=FALSE"),
            Some("excludeDomains=off"),
            Some("excludeDomains=nO"),
            Some("ExcludeDomains=true"),
            Some("excludeDomains=false&excludeDomains=true"),
            Some("[excludeDomains]=false&excludeDomains=true"),
        ] {
            assert!(
                !sync_excludes(query).unwrap_or_else(|_| panic!("Valid false query was rejected."))
            );
        }
        for query in [
            "excludeDomains",
            "excludeDomains=",
            "excludeDomains=true",
            "excludeDomains=TrUe",
            "excludeDomains=yes",
            "excludeDomains=ON",
            "exclude%44omains=yes",
            "excludeDomains.foo=true",
            "excludeDomains%5Bfoo%5D=true",
            "excludeDomains=true&excludeDomains=false",
        ] {
            assert!(
                sync_excludes(Some(query))
                    .unwrap_or_else(|_| panic!("Valid true query was rejected."))
            );
        }
        for query in [
            "excludeDomains=1",
            "excludeDomains=0",
            "excludeDomains=unexpected",
            "excludeDomains=bad&excludeDomains=true",
            "[excludeDomains]=bad&excludeDomains=true",
        ] {
            let Err(error) = sync_excludes(Some(query)) else {
                panic!("Invalid Boolean query was accepted.");
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
    }
}
