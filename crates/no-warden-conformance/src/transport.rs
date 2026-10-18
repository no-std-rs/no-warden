//! Disposable loopback TLS termination for unmodified HTTPS-only clients.
//!
//! This adapter never includes upstream URLs, headers or payloads in errors.

use std::{
    fmt,
    fs::{self, OpenOptions},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread::{self, JoinHandle},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use reqwest::{Client, Url};

const BODY_LIMIT: usize = 16 * 1024 * 1024;

/// A redacted transport failure that never retains an underlying request error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportError(&'static str);

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for TransportError {}

/// An HTTPS listener that forwards only to its configured loopback HTTP origin.
#[derive(Debug)]
pub struct TlsProxy {
    url: String,
    certificate: PathBuf,
    handle: Handle,
    finished: Receiver<()>,
    thread: Option<JoinHandle<()>>,
}

impl TlsProxy {
    /// Start a disposable TLS proxy, creating certificate files in a private directory.
    ///
    /// The caller owns the directory and its cleanup. Certificate and key names must
    /// not already exist; refusing to overwrite them also prevents following symlinks.
    pub fn start(upstream: &str, directory: &Path) -> Result<Self, TransportError> {
        let upstream = loopback_upstream(upstream)?;
        private_directory(directory)?;
        let certificate = directory.join("localhost.crt");
        let key = directory.join("localhost.key");
        generate_certificate(&certificate, &key)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| TransportError("Could not bind the test TLS listener"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| TransportError("Could not configure the test TLS listener"))?;
        let address = listener
            .local_addr()
            .map_err(|_| TransportError("Could not inspect the test TLS listener"))?;
        let handle = Handle::new();
        let thread_handle = handle.clone();
        let thread_certificate = certificate.clone();
        let (ready_sender, ready) = mpsc::channel();
        let (finished_sender, finished) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("no-warden-test-tls".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build();
                match runtime {
                    Ok(runtime) => {
                        let result = runtime.block_on(serve(
                            upstream,
                            listener,
                            &thread_certificate,
                            &key,
                            thread_handle,
                            &ready_sender,
                        ));
                        if let Err(error) = result {
                            let _ = ready_sender.send(Err(error));
                        }
                        runtime.shutdown_timeout(Duration::from_millis(500));
                    }
                    Err(_) => {
                        let _ = ready_sender
                            .send(Err(TransportError("Could not start the test TLS runtime")));
                    }
                }
                let _ = finished_sender.send(());
            })
            .map_err(|_| TransportError("Could not start the test TLS thread"))?;
        let mut proxy = Self {
            url: format!("https://{address}"),
            certificate,
            handle,
            finished,
            thread: Some(thread),
        };
        match ready.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(proxy),
            Ok(Err(error)) => {
                proxy.stop();
                Err(error)
            }
            Err(_) => {
                proxy.stop();
                Err(TransportError("The test TLS listener did not become ready"))
            }
        }
    }

    /// The HTTPS origin to configure on the client under test.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The PEM certificate to trust, for example via `NODE_EXTRA_CA_CERTS`.
    pub fn certificate(&self) -> &Path {
        &self.certificate
    }

    fn stop(&mut self) {
        if self.thread.is_none() {
            return;
        }
        self.handle
            .graceful_shutdown(Some(Duration::from_millis(500)));
        let mut finished = self.finished.recv_timeout(Duration::from_secs(2)).is_ok();
        if !finished {
            self.handle.shutdown();
            finished = self.finished.recv_timeout(Duration::from_secs(1)).is_ok();
        }
        if let Some(thread) = self.thread.take()
            && (finished || thread.is_finished())
        {
            let _ = thread.join();
        }
        // Do not allow a failed runtime to block the synchronous caller forever.
    }
}

impl Drop for TlsProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

fn loopback_upstream(value: &str) -> Result<Url, TransportError> {
    let upstream =
        Url::parse(value).map_err(|_| TransportError("The test TLS upstream URL is invalid"))?;
    if upstream.scheme() != "http"
        || !matches!(
            upstream.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]")
        )
        || !upstream.username().is_empty()
        || upstream.password().is_some()
        || upstream.fragment().is_some()
    {
        return Err(TransportError(
            "The test TLS proxy requires a loopback HTTP upstream",
        ));
    }
    Ok(upstream)
}

fn private_directory(directory: &Path) -> Result<(), TransportError> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| TransportError("The test TLS directory is unavailable"))?;
    if !metadata.is_dir() {
        return Err(TransportError("The test TLS directory is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(TransportError("The test TLS directory must be private"));
        }
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<(), TransportError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| TransportError("Could not create a private test TLS certificate file"))?;
    Ok(())
}

fn generate_certificate(certificate: &Path, key: &Path) -> Result<(), TransportError> {
    create_private_file(key)?;
    create_private_file(certificate)?;
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=no-warden disposable compatibility test",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
        ])
        .arg(key)
        .arg("-out")
        .arg(certificate)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| TransportError("Could not generate the disposable test TLS certificate"))?;
    if !status.success() {
        return Err(TransportError(
            "Could not generate the disposable test TLS certificate",
        ));
    }
    Ok(())
}

#[derive(Clone)]
struct ProxyState {
    upstream: Url,
    client: Client,
}

async fn serve(
    upstream: Url,
    listener: TcpListener,
    certificate: &Path,
    key: &Path,
    handle: Handle,
    ready: &Sender<Result<(), TransportError>>,
) -> Result<(), TransportError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = RustlsConfig::from_pem_file(certificate, key)
        .await
        .map_err(|_| TransportError("Could not load the disposable test TLS certificate"))?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30));
    // A modified hosts file must not turn the permitted localhost name into a
    // non-loopback destination. Literal IPv4/IPv6 loopback needs no DNS lookup.
    if upstream.host_str() == Some("localhost") {
        builder = builder.resolve(
            "localhost",
            SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                upstream.port_or_known_default().unwrap_or(80),
            )),
        );
    }
    let client = builder
        .build()
        .map_err(|_| TransportError("Could not create the test TLS forwarding client"))?;
    let router = Router::new()
        .fallback(forward)
        .with_state(ProxyState { upstream, client });
    let server = axum_server::from_tcp_rustls(listener, config)
        .handle(handle.clone())
        .serve(router.into_make_service());
    tokio::pin!(server);
    tokio::select! {
        _ = &mut server => return Err(TransportError("The test TLS listener stopped before readiness")),
        address = handle.listening() => {
            if address.is_none() {
                return Err(TransportError("Could not start the test TLS listener"));
            }
        }
    }
    let _ = ready.send(Ok(()));
    server
        .await
        .map_err(|_| TransportError("The test TLS listener stopped unexpectedly"))
}

fn destination(upstream: &Url, uri: &Uri) -> Result<Url, TransportError> {
    let mut destination = if uri.scheme().is_some() || uri.authority().is_some() {
        Url::parse(&uri.to_string())
            .map_err(|_| TransportError("Invalid test proxy destination"))?
    } else {
        let path = uri.path();
        if !path.starts_with('/') || path.starts_with("//") {
            return Err(TransportError("Invalid test proxy destination"));
        }
        let mut destination = upstream.clone();
        destination.set_path(path);
        destination.set_query(uri.query());
        destination
    };
    if destination.origin() != upstream.origin()
        || !destination.username().is_empty()
        || destination.password().is_some()
    {
        return Err(TransportError("Invalid test proxy destination"));
    }
    destination.set_fragment(None);
    Ok(destination)
}

fn remove_hop_headers(headers: &mut HeaderMap) {
    let connection_headers: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| header::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in connection_headers {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn failure(status: StatusCode, message: &'static str) -> Response {
    let mut response = Response::new(Body::from(message));
    *response.status_mut() = status;
    response
}

async fn forward(State(state): State<ProxyState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let destination = match destination(&state.upstream, &parts.uri) {
        Ok(destination) => destination,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "Invalid test proxy destination"),
    };
    let body = match to_bytes(body, BODY_LIMIT).await {
        Ok(body) => body,
        Err(_) => {
            return failure(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Test proxy request is too large",
            );
        }
    };
    let mut headers = parts.headers;
    remove_hop_headers(&mut headers);
    headers.remove(header::HOST);
    let mut upstream = match state
        .client
        .request(parts.method, destination)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return failure(StatusCode::BAD_GATEWAY, "Test upstream is unavailable"),
    };
    let status = upstream.status();
    let mut headers = upstream.headers().clone();
    remove_hop_headers(&mut headers);
    let mut body = Vec::new();
    loop {
        match upstream.chunk().await {
            Ok(Some(chunk)) if chunk.len() <= BODY_LIMIT.saturating_sub(body.len()) => {
                body.extend_from_slice(&chunk);
            }
            Ok(Some(_)) => {
                return failure(
                    StatusCode::BAD_GATEWAY,
                    "Test upstream response is too large",
                );
            }
            Ok(None) => break,
            Err(_) => return failure(StatusCode::BAD_GATEWAY, "Test upstream is unavailable"),
        }
    }
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn success<T, E>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|_| panic!("test operation failed"))
    }

    fn private_tempdir() -> tempfile::TempDir {
        let mut builder = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        success(builder.tempdir())
    }

    #[test]
    fn only_loopback_http_origins_are_accepted_and_errors_are_redacted() {
        for value in [
            "http://127.0.0.1:8080/",
            "http://localhost:8080/base",
            "http://[::1]:8080/",
        ] {
            assert!(loopback_upstream(value).is_ok());
        }
        for value in [
            "https://127.0.0.1/",
            "http://192.0.2.1/",
            "http://example.com/",
            "http://127.0.0.1.example.com/",
            "http://client:secret@127.0.0.1/?token=secret",
            "http://127.0.0.1/#secret",
            "secret",
        ] {
            let error = match loopback_upstream(value) {
                Err(error) => error,
                Ok(_) => panic!("must reject upstream"),
            };
            assert!(!error.to_string().contains("secret"));
            assert!(!format!("{error:?}").contains("secret"));
        }
    }

    #[test]
    fn absolute_request_uris_cannot_escape_the_configured_origin() {
        let upstream = success(loopback_upstream("http://127.0.0.1:8080/base"));
        for value in [
            "http://example.com/secret?token=hidden",
            "http://127.0.0.1:8081/secret",
            "https://127.0.0.1:8080/secret",
            "//example.com/secret",
            "*",
        ] {
            let uri: Uri = success(value.parse());
            assert!(destination(&upstream, &uri).is_err());
        }
        for value in [
            "/root/download?token=hidden%2Bvalue&name=a%2Fb",
            "http://127.0.0.1:8080/root/download?token=hidden%2Bvalue&name=a%2Fb",
        ] {
            let uri: Uri = success(value.parse());
            let destination = success(destination(&upstream, &uri));
            assert!(destination.path() == "/root/download");
            assert!(destination.query() == Some("token=hidden%2Bvalue&name=a%2Fb"));
        }
    }

    #[test]
    fn existing_certificate_files_are_never_overwritten() {
        let directory = private_tempdir();
        let key = directory.path().join("localhost.key");
        success(fs::write(&key, b"private existing material"));
        assert!(TlsProxy::start("http://127.0.0.1:8080/", directory.path()).is_err());
        assert!(success(fs::read(key)) == b"private existing material");
        assert!(!directory.path().join("localhost.crt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn shared_certificate_directories_are_rejected_before_creating_files() {
        use std::os::unix::fs::PermissionsExt;
        let directory = private_tempdir();
        success(fs::set_permissions(
            directory.path(),
            fs::Permissions::from_mode(0o755),
        ));
        assert!(TlsProxy::start("http://127.0.0.1:8080/", directory.path()).is_err());
        assert!(!directory.path().join("localhost.key").exists());
    }

    struct Upstream {
        url: String,
        requests: Receiver<(Uri, HeaderMap, Vec<u8>)>,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<JoinHandle<()>>,
    }

    impl Upstream {
        fn start() -> Self {
            let listener = success(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
            let address = success(listener.local_addr());
            success(listener.set_nonblocking(true));
            let (sender, requests) = mpsc::channel();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let thread = thread::spawn(move || {
                let runtime = success(
                    tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(1)
                        .enable_all()
                        .build(),
                );
                runtime.block_on(async move {
                    let listener = success(tokio::net::TcpListener::from_std(listener));
                    let app = Router::new()
                        .fallback(
                            |State(sender): State<Sender<_>>, request: Request| async move {
                                let (parts, body) = request.into_parts();
                                let body = success(to_bytes(body, BODY_LIMIT + 1).await);
                                let redirect = parts.uri.path() == "/redirect";
                                let oversized = parts.uri.path() == "/oversized";
                                success(sender.send((parts.uri, parts.headers, body.to_vec())));
                                let mut response = Response::new(if oversized {
                                    Body::from(vec![1; BODY_LIMIT + 1])
                                } else {
                                    Body::from(body)
                                });
                                *response.status_mut() = if redirect {
                                    StatusCode::FOUND
                                } else {
                                    StatusCode::CREATED
                                };
                                response
                                    .headers_mut()
                                    .insert("x-roundtrip", "preserved".parse().unwrap());
                                response
                                    .headers_mut()
                                    .insert("connection", "x-remove".parse().unwrap());
                                response
                                    .headers_mut()
                                    .insert("x-remove", "private-hop".parse().unwrap());
                                response
                                    .headers_mut()
                                    .append("set-cookie", "one=opaque; HttpOnly".parse().unwrap());
                                response
                                    .headers_mut()
                                    .append("set-cookie", "two=opaque; HttpOnly".parse().unwrap());
                                if redirect {
                                    response.headers_mut().insert(
                                        "location",
                                        "http://192.0.2.1/private".parse().unwrap(),
                                    );
                                }
                                response
                            },
                        )
                        .with_state(sender);
                    success(
                        axum::serve(listener, app)
                            .with_graceful_shutdown(async {
                                let _ = stopped.await;
                            })
                            .await,
                    );
                });
            });
            Self {
                url: format!("http://{address}/base"),
                requests,
                stop: Some(stop),
                thread: Some(thread),
            }
        }
    }

    impl Drop for Upstream {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                success(thread.join());
            }
        }
    }

    fn client(proxy: &TlsProxy) -> reqwest::blocking::Client {
        let certificate = success(fs::read(proxy.certificate()));
        let certificate = success(reqwest::Certificate::from_pem(&certificate));
        success(
            reqwest::blocking::Client::builder()
                .add_root_certificate(certificate)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build(),
        )
    }

    #[test]
    fn tls_preserves_json_binary_multipart_root_paths_and_queries_without_redirects() {
        let upstream = Upstream::start();
        let directory = private_tempdir();
        let proxy = TlsProxy::start(&upstream.url, directory.path())
            .unwrap_or_else(|error| panic!("{error}"));
        let client = client(&proxy);
        let bodies = [
            ("application/json", b"{\"encrypted\":\"opaque\"}".as_slice()),
            ("application/octet-stream", &[0, 255, 1, 128, b'\n']),
            ("multipart/form-data; boundary=test-boundary", b"--test-boundary\r\nContent-Disposition: form-data; name=\"data\"; filename=\"opaque.bin\"\r\n\r\n\x00\xff\r\n--test-boundary--\r\n".as_slice()),
        ];
        for (content_type, body) in bodies {
            let response = success(
                client
                    .post(format!(
                        "{}/root/download?token=hidden%2Bvalue",
                        proxy.url()
                    ))
                    .header("content-type", content_type)
                    .header("authorization", "Bearer hidden")
                    .header("host", "untrusted.example")
                    .header("connection", "x-private-hop")
                    .header("x-private-hop", "hidden")
                    .body(body.to_vec())
                    .send(),
            );
            assert_eq!(response.status(), StatusCode::CREATED);
            assert!(response.headers().get("x-roundtrip").is_some());
            assert!(response.headers().get("x-remove").is_none());
            assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
            assert!(success(response.bytes()).as_ref() == body);
            let (uri, headers, received) =
                success(upstream.requests.recv_timeout(Duration::from_secs(2)));
            assert!(uri.path() == "/root/download");
            assert!(uri.query() == Some("token=hidden%2Bvalue"));
            assert!(
                headers
                    .get("authorization")
                    .is_some_and(|value| value == "Bearer hidden")
            );
            assert!(
                headers
                    .get("content-type")
                    .is_some_and(|value| value == content_type)
            );
            assert!(headers.get("x-private-hop").is_none());
            assert!(
                headers
                    .get("host")
                    .is_some_and(|value| value != "untrusted.example")
            );
            assert!(received == body);
        }
        let response = success(client.get(format!("{}/redirect", proxy.url())).send());
        assert_eq!(response.status(), StatusCode::FOUND);
        assert!(response.headers().get("location").is_some());
        assert!(
            upstream
                .requests
                .recv_timeout(Duration::from_secs(2))
                .is_ok()
        );
        assert!(upstream.requests.try_recv().is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key = directory.path().join("localhost.key");
            assert_eq!(
                success(fs::metadata(key)).permissions().mode() & 0o777,
                0o600
            );
        }
        let address = success(Url::parse(proxy.url()));
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, address.port().expect("port")));
        // A peer that never starts its TLS handshake must not hold Drop open.
        let _unfinished_handshake = success(std::net::TcpStream::connect_timeout(
            &address,
            Duration::from_secs(1),
        ));
        let stopped = Instant::now();
        drop(proxy);
        assert!(stopped.elapsed() < Duration::from_secs(4));
        assert!(
            std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err()
        );
    }

    #[test]
    fn bodies_are_bounded_and_unavailable_upstream_errors_are_redacted() {
        let upstream = Upstream::start();
        let directory = private_tempdir();
        let proxy = TlsProxy::start(&upstream.url, directory.path())
            .unwrap_or_else(|error| panic!("{error}"));
        let client = client(&proxy);
        let response = success(
            client
                .post(format!("{}/too-large?token=hidden", proxy.url()))
                .body(vec![1; BODY_LIMIT + 1])
                .send(),
        );
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(upstream.requests.try_recv().is_err());
        let response = success(
            client
                .get(format!("{}/oversized?token=hidden", proxy.url()))
                .send(),
        );
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(success(response.text()) == "Test upstream response is too large");
        drop(upstream);
        let response = success(
            client
                .get(format!("{}/private?token=hidden", proxy.url()))
                .send(),
        );
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = success(response.text());
        assert!(body == "Test upstream is unavailable");
        assert!(!body.contains("hidden"));
    }
}
