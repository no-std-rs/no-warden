//! Independently authored ordered bulk confirmation adapter.
//! JSON is decoded in full before the allocation-free service can commit an item.
use crate::{Failure, organization_confirmations};
use no_warden::{
    organization_confirmations::OrganizationBulkConfirmData, wire::OrganizationConfirmRequest,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    keys: Option<Vec<organization_confirmations::Input>>,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        let body = std::str::from_utf8(body).map_err(|_| crate::invalid())?;
        serde_json::from_str(body).map_err(crate::json_guard_error)
    }
}
impl OrganizationBulkConfirmData for Input {
    fn len(&self) -> usize {
        self.keys.as_ref().map_or(0, Vec::len)
    }
    fn get(&self, index: usize) -> Option<OrganizationConfirmRequest<'_>> {
        self.keys
            .as_ref()?
            .get(index)
            .map(organization_confirmations::Input::request)
    }
}

#[cfg(test)]
mod tests;
