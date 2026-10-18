use std::{ffi::OsStr, fmt::Display};

#[derive(Clone, Copy, PartialEq)]
enum Suite {
    All,
    Personal,
    Folders,
    AccountKeys,
    Profile,
    Domains,
    Devices,
    DeviceTokens,
    AuthRequests,
}

impl Suite {
    fn parse(value: &OsStr) -> Option<Self> {
        Some(match value.to_str()? {
            "all" => Self::All,
            "personal" => Self::Personal,
            "folders" => Self::Folders,
            "account-keys" => Self::AccountKeys,
            "profile" => Self::Profile,
            "domains" => Self::Domains,
            "devices" => Self::Devices,
            "device-tokens" => Self::DeviceTokens,
            "auth-requests" => Self::AuthRequests,
            _ => return None,
        })
    }

    fn includes(self, group: Self) -> bool {
        self == Self::All
            || self == group
            || (self == Self::Personal
                && matches!(
                    group,
                    Self::Folders | Self::AccountKeys | Self::Profile | Self::Domains
                ))
    }
}

fn check<E: Display>(result: Result<(), E>) {
    if let Err(error) = result {
        eprintln!("HTTP conformance failed: {error}");
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!(
        "Usage: no-warden-http-conformance [--suite all|personal|folders|account-keys|profile|domains|devices|device-tokens|auth-requests]"
    );
}

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let suite = match (arguments.next(), arguments.next(), arguments.next()) {
        (None, None, None) => Some(Suite::All),
        (Some(flag), None, None) if flag == "--help" => {
            usage();
            return;
        }
        (Some(flag), Some(value), None) if flag == "--suite" => Suite::parse(&value),
        _ => None,
    };
    let Some(suite) = suite else {
        usage();
        std::process::exit(2);
    };
    if suite.includes(Suite::Folders) {
        check(no_warden_conformance::folders::run());
    }
    if suite.includes(Suite::AccountKeys) {
        check(no_warden_conformance::account_keys::run());
    }
    if suite.includes(Suite::Profile) {
        check(no_warden_conformance::account_profile::run());
    }
    if suite.includes(Suite::Domains) {
        check(no_warden_conformance::domains::run());
    }
    if suite.includes(Suite::Devices) {
        check(no_warden_conformance::devices::run());
    }
    if suite.includes(Suite::DeviceTokens) {
        check(no_warden_conformance::device_tokens::run());
    }
    if suite.includes(Suite::AuthRequests) {
        check(no_warden_conformance::auth_requests::run());
    }
}
