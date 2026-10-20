//! Independently authored official CLI observation of direct HTTP bulk revoke/restore.
//! The CLI has no bulk status command; shared observer orchestration verifies
//! live and fresh cache sync, retained decryption, and live member discovery.
use crate::{organization_member_status_cli as observer, text_sends::TextSendsError};
pub const COMMAND_COUNT: usize = observer::COMMAND_COUNT;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = observer::DIRECT_HTTP_REQUEST_COUNT;
pub fn run() -> Result<(), TextSendsError> {
    observer::run_mode(observer::StatusMode::Bulk)
}
