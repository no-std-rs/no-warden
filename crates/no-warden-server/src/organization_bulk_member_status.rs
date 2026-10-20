//! Owned HTTP decoding for ordered member status transitions.
//! Revoke accepts absent/null IDs; restore requires the complete string list.
use crate::Failure;
use no_warden::organization_bulk_member_status::OrganizationBulkMemberStatusData;
use serde::Deserialize;

pub struct Input {
    ids: Vec<String>,
}
impl Input {
    pub fn parse(body: &[u8], revoke: bool) -> Result<Self, Failure> {
        #[derive(Deserialize)]
        struct Revoke {
            ids: Option<Vec<String>>,
        }
        #[derive(Deserialize)]
        struct Restore {
            ids: Vec<String>,
        }
        let body = std::str::from_utf8(body).map_err(|_| crate::invalid())?;
        let ids = if revoke {
            serde_json::from_str::<Revoke>(body)
                .map_err(crate::json_guard_error)?
                .ids
                .unwrap_or_default()
        } else {
            serde_json::from_str::<Restore>(body)
                .map_err(crate::json_guard_error)?
                .ids
        };
        Ok(Self { ids })
    }
}
impl OrganizationBulkMemberStatusData for Input {
    fn len(&self) -> usize {
        self.ids.len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        self.ids.get(index).map(String::as_str)
    }
}

#[cfg(test)]
mod tests;
