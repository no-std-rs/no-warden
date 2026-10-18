fn main() {
    if let Err(error) = no_warden_conformance::folders::run() {
        eprintln!("HTTP conformance failed: {error}");
        std::process::exit(1);
    }
    if let Err(error) = no_warden_conformance::account_keys::run() {
        eprintln!("HTTP conformance failed: {error}");
        std::process::exit(1);
    }
}
