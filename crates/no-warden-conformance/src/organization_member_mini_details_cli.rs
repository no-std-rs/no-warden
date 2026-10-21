//! Actual CLI observation of independently queried seven-field mini metadata.
//! The shipped CLI uses full member discovery; it has no proven mini caller.
use crate::{organization_members_cli as observer, text_sends::TextSendsError};
pub const COMMAND_COUNT: usize = observer::COMMAND_COUNT;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = observer::DIRECT_HTTP_REQUEST_COUNT + 3;
pub fn run() -> Result<(), TextSendsError> {
    observer::run_mode(observer::MemberObservation::Mini)
}
