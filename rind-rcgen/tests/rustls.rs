//! Certificates signed by rind-rcgen verify under rind-rustls and under
//! rustls on aws-lc-rs, and each key loads and matches its certificate.

use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, SerialNumber};
use rind_rcgen::KeyPair;
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;

#[test]
fn self_signed() {
    let key = KeyPair::generate().unwrap();
    let cert = params(1).self_signed(&key).unwrap();

    for provider in providers() {
        verify(&provider, cert.der(), cert.der()).unwrap();
        load(&provider, cert.der(), &key);
    }
}

#[test]
fn signed_by_ca() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = params(1);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let cert = params(2)
        .signed_by(&key, &Issuer::new(ca_params, &ca_key))
        .unwrap();

    for provider in providers() {
        verify(&provider, ca.der(), cert.der()).unwrap();
        load(&provider, cert.der(), &key);
    }
}

fn providers() -> [Arc<CryptoProvider>; 2] {
    [
        Arc::new(rind_rustls::default_provider()),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    ]
}

fn params(serial: u64) -> CertificateParams {
    let mut params = CertificateParams::new(["localhost".to_string()]).unwrap();
    params.serial_number = Some(SerialNumber::from(serial));
    params
}

fn verify(
    provider: &Arc<CryptoProvider>,
    root: &CertificateDer<'_>,
    cert: &CertificateDer<'_>,
) -> Result<(), rustls::Error> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone().into_owned()).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(roots.into(), provider.clone())
        .build()
        .unwrap();

    // Inside rcgen's default validity, without reading the wall clock.
    let now = UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000));
    let name = ServerName::try_from("localhost").unwrap();
    verifier
        .verify_server_cert(cert, &[], &name, &[], now)
        .map(|_| ())
}

fn load(provider: &CryptoProvider, cert: &CertificateDer<'_>, key: &KeyPair) {
    let key = PrivateKeyDer::Pkcs8(key.to_pkcs8_der().unwrap());
    CertifiedKey::from_der(vec![cert.clone().into_owned()], key, provider).unwrap();
}
