fn main() {
    if let Err(error) = no_warden_conformance::folders::run() {
        eprintln!("HTTP conformance failed: {error}");
        std::process::exit(1);
    }
}
