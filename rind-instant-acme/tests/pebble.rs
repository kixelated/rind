//! Issues a certificate from Pebble, Let's Encrypt's test ACME server, with
//! every cryptographic operation on rind: the account and External Account
//! Binding signatures, the http-01 key authorization's thumbprint, the CSR,
//! and the TLS to the server.
//!
//! Pebble comes from the Nix dev shell. Without it the test is skipped, except
//! under `just ci`, which sets `CI_STRICT`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use instant_acme::{
    Account, ChallengeType, DefaultClient, ExternalAccountKey, Identifier, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, PublicKeyData, SerialNumber};
use rind_instant_acme::DEFAULT_PROVIDER;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const EAB_KID: &str = "rind";
const EAB_KEY: &[u8] = b"an external account binding key for rind-instant-acme";

#[tokio::test]
async fn issue_certificate() {
    let Some(pebble) = find_pebble() else {
        return;
    };

    // Pebble validates http-01 against this port on the identifier's address.
    let challenges = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("pebble-{}", std::process::id()));
    let (directory, _pebble) =
        start_pebble(&pebble, &dir, challenges.local_addr().unwrap().port()).await;
    let root = dir.join("cert.pem");
    let http = || {
        let provider = Arc::new(rind_rustls::default_provider());
        Box::new(DefaultClient::with_pem_root(&root, provider).unwrap())
    };

    // Creating the account generates its key and signs the EAB with HS256.
    let eab = ExternalAccountKey::new(EAB_KID.to_string(), DEFAULT_PROVIDER.hmac.load_key(EAB_KEY));
    let new_account = NewAccount {
        contact: &[],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (_, credentials) = Account::builder(http(), &DEFAULT_PROVIDER)
        .unwrap()
        .create(&new_account, directory, Some(&eab))
        .await
        .unwrap();

    // Ordering from stored credentials loads the PKCS#8 key back.
    let account = Account::builder(http(), &DEFAULT_PROVIDER)
        .unwrap()
        .from_credentials(credentials)
        .await
        .unwrap();
    let identifiers = [Identifier::Ip(LOCALHOST)];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .unwrap();

    // One identifier, so one authorization.
    let mut authorizations = order.authorizations();
    let mut authorization = authorizations.next().await.unwrap().unwrap();
    let mut challenge = authorization.challenge(ChallengeType::Http01).unwrap();
    let path = format!("/.well-known/acme-challenge/{}", challenge.token);
    let key_authorization = challenge.key_authorization().unwrap();
    tokio::spawn(serve_challenge(
        challenges,
        path,
        key_authorization.as_str().to_string(),
    ));
    challenge.set_ready().await.unwrap();

    let retries = RetryPolicy::new().initial_delay(Duration::from_millis(10));
    assert_eq!(
        order.poll_ready(&retries).await.unwrap(),
        OrderStatus::Ready
    );

    let key = rind_rcgen::KeyPair::generate().unwrap();
    let csr = CertificateParams::new([LOCALHOST.to_string()])
        .unwrap()
        .serialize_request(&key)
        .unwrap();
    order.finalize_csr(csr.der()).await.unwrap();
    let chain = order.poll_certificate(&retries).await.unwrap();

    let leaf = CertificateDer::pem_slice_iter(chain.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let public_key = key.der_bytes();
    assert!(
        leaf.windows(public_key.len()).any(|w| w == public_key),
        "the certificate is for the CSR's key"
    );
}

/// Pebble on `PATH`, or `None` to skip when outside `just ci`.
fn find_pebble() -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path)
        .map(|dir| dir.join("pebble"))
        .find(|candidate| candidate.is_file());
    if found.is_none() {
        assert!(
            std::env::var_os("CI_STRICT").is_none(),
            "pebble is not on PATH; run inside the Nix dev shell"
        );
        eprintln!("skipping: pebble is not on PATH; run inside the Nix dev shell");
    }
    found
}

/// Starts Pebble with a TLS certificate for 127.0.0.1 written to `dir`, and
/// returns its directory URL once it accepts connections.
async fn start_pebble(pebble: &Path, dir: &Path, http_port: u16) -> (String, Child) {
    std::fs::create_dir_all(dir).unwrap();

    let key = rind_rcgen::KeyPair::generate().unwrap();
    let mut params = CertificateParams::new([LOCALHOST.to_string()]).unwrap();
    params.serial_number = Some(SerialNumber::from_slice(&[1]));
    let cert = params.self_signed(&key).unwrap();
    let key = STANDARD.encode(key.to_pkcs8_der().unwrap().secret_pkcs8_der());
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(
        dir.join("key.pem"),
        format!("-----BEGIN PRIVATE KEY-----\n{key}\n-----END PRIVATE KEY-----\n"),
    )
    .unwrap();

    let listen = free_port();
    let config = serde_json::json!({
        "pebble": {
            "listenAddress": listen.to_string(),
            "managementListenAddress": "",
            "certificate": dir.join("cert.pem"),
            "privateKey": dir.join("key.pem"),
            "httpPort": http_port,
            "tlsPort": 0,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": true,
            "externalAccountMACKeys": { EAB_KID: URL_SAFE_NO_PAD.encode(EAB_KEY) },
            // No Retry-After, so polling follows the test's short RetryPolicy.
            "retryAfter": { "authz": 0, "order": 0 },
        }
    });
    let config_path = dir.join("config.json");
    std::fs::write(&config_path, config.to_string()).unwrap();

    let mut child = Command::new(pebble)
        .arg("-config")
        .arg(&config_path)
        // Validate at once, and never reject a good nonce.
        .env("PEBBLE_VA_NOSLEEP", "1")
        .env("PEBBLE_WFE_NONCEREJECT", "0")
        // Its log is a line per request; a failure to start goes to stderr.
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    // Pebble signals nothing once it listens, so connect until it accepts.
    while TcpStream::connect(listen).await.is_err() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "pebble exited before listening"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    (format!("https://{listen}/dir"), child)
}

/// An unused local address for Pebble to bind.
fn free_port() -> SocketAddr {
    StdListener::bind((LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Answers Pebble's http-01 requests with the key authorization.
async fn serve_challenge(listener: TcpListener, path: String, key_authorization: String) {
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if stream.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            request.push(byte[0]);
        }
        let request = String::from_utf8_lossy(&request);
        let (status, body) = match request.split(' ').nth(1) == Some(path.as_str()) {
            true => ("200 OK", key_authorization.as_str()),
            false => ("404 Not Found", ""),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }
}
