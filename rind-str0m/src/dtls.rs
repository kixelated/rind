use std::sync::Arc;
use std::time::Instant;

use rcgen::{CertificateParams, DistinguishedName, DnType, SerialNumber};
use str0m_proto::crypto::dtls::{
    DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider, ProtocolVersion,
};
use str0m_proto::crypto::{CryptoError, DtlsVersion};
use time::{Duration, OffsetDateTime};

pub(crate) static DTLS: RindDtls = RindDtls;

#[derive(Debug)]
pub(crate) struct RindDtls;

impl DtlsProvider for RindDtls {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        generate_certificate()
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
        mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        // ICE checks return routability before DTLS starts, so a server cookie
        // adds a round trip without protecting anything.
        let mut builder = dimpl::Config::builder()
            .with_crypto_provider(rind_dimpl::default_provider())
            .use_server_cookie(false);
        if let Some(mtu) = mtu {
            builder = builder.mtu(mtu);
        }
        let config = Arc::new(
            builder
                .build()
                .map_err(|e| CryptoError::Other(e.to_string()))?,
        );

        let cert = cert.clone();
        let dtls = match dtls_version {
            DtlsVersion::Dtls12 => dimpl::Dtls::new_12(config, cert, now),
            DtlsVersion::Dtls13 => dimpl::Dtls::new_13(config, cert, now),
            DtlsVersion::Auto => dimpl::Dtls::new_auto(config, cert, now),
            other => {
                return Err(CryptoError::Other(format!(
                    "unsupported DTLS version: {other}"
                )));
            }
        };
        Ok(Box::new(Dtls(dtls)))
    }
}

/// A self-signed ECDSA P-256 certificate, valid for a year, as dimpl's own generator makes.
///
/// Only a failing system RNG returns `None`, on which str0m panics.
fn generate_certificate() -> Option<DtlsCert> {
    let key = rind_rcgen::KeyPair::generate().ok()?;

    // Firefox rejects a peer reusing another certificate's issuer and serial,
    // so the serial must be unique across processes, not only within one.
    let mut serial = [0u8; 16];
    rind::random::fill(&mut serial).ok()?;

    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "DTLS");
    name.push(DnType::CommonName, "DTLS Peer");

    let mut params = CertificateParams::default();
    params.distinguished_name = name;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = params.not_before + Duration::days(365);

    let certificate = params.self_signed(&key).ok()?;
    Some(DtlsCert {
        certificate: certificate.der().to_vec(),
        private_key: key.to_pkcs8_der().ok()?.secret_pkcs8_der().to_vec(),
    })
}

/// A dimpl connection, forwarded as is.
struct Dtls(dimpl::Dtls);

impl std::fmt::Debug for Dtls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dtls").finish_non_exhaustive()
    }
}

impl DtlsInstance for Dtls {
    fn set_active(&mut self, active: bool) {
        self.0.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.0.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        self.0.poll_output(buf)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.0.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<usize, DtlsImplError> {
        self.0.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.0.is_active()
    }

    fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.0.protocol_version()
    }

    fn is_closing(&self) -> bool {
        self.0.is_closing()
    }

    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }

    fn close(&mut self) -> Result<(), DtlsImplError> {
        self.0.close()
    }
}
