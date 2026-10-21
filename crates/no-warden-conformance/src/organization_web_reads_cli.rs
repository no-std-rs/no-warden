//! Actual CLI cache/decryption observer beside three explicit HTTP reads.
//! The CLI is not claimed to call the new web routes; no browser trace is captured.
use crate::{organization_collections_cli as observer, text_sends::TextSendsError};
pub const COMMAND_COUNT: usize = observer::WEB_COMMAND_COUNT;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = observer::WEB_DIRECT_HTTP_REQUEST_COUNT;
pub fn run() -> Result<(), TextSendsError> {
    observer::run_web_reads()
}
