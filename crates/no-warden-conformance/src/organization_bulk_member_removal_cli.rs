//! Independently authored official CLI observation after direct HTTP bulk removal.
//! The shipped CLI has no bulk member-delete command; shared observer orchestration
//! verifies member discovery, sync revocation and retained decryption identically.
use crate::{organization_member_removal_cli as observer, text_sends::TextSendsError};
pub const COMMAND_COUNT: usize = observer::COMMAND_COUNT;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = observer::DIRECT_HTTP_REQUEST_COUNT;
pub fn run() -> Result<(), TextSendsError> {
    observer::run_mode(observer::RemovalMode::Bulk)
}
