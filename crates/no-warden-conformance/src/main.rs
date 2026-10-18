fn main() {
    if let Err(error) = no_warden_conformance::cli::run() {
        eprintln!("Conformance failed: {error}");
        std::process::exit(1);
    }
}
