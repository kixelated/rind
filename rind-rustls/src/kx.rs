use crypto::SupportedKxGroup;
use rind::agreement;
use rustls::crypto;
use rustls::ffdhe_groups::FfdheGroup;

mod hybrid;
mod mlkem;

/// All key exchange algorithms, in order of preference.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    X25519MLKEM768,
    &X25519 as &dyn SupportedKxGroup,
    &P256 as &dyn SupportedKxGroup,
    &P384 as &dyn SupportedKxGroup,
];

/// Key exchange using X25519.
#[derive(Debug)]
pub struct X25519;

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Active::start(&agreement::X25519, self.name())
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

/// Key exchange using P256.
///
/// Also known as secp256r1 or NISTP256.
#[derive(Debug)]
pub struct P256;

impl SupportedKxGroup for P256 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Active::start(&agreement::ECDH_P256, self.name())
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}

/// Key exchange using P384.
///
/// Also known as secp384r1 or NISTP384.
#[derive(Debug)]
pub struct P384;

impl SupportedKxGroup for P384 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Active::start(&agreement::ECDH_P384, self.name())
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp384r1
    }
}

struct Active {
    algorithm: &'static agreement::Algorithm,
    group: rustls::NamedGroup,
    priv_key: agreement::EphemeralPrivateKey,
    pub_key: agreement::PublicKey,
}

impl Active {
    fn start(
        algorithm: &'static agreement::Algorithm,
        group: rustls::NamedGroup,
    ) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let priv_key = agreement::EphemeralPrivateKey::generate(algorithm)
            .map_err(|_| rustls::Error::from(crypto::GetRandomFailed))?;
        let pub_key = priv_key.compute_public_key();
        Ok(Box::new(Self {
            algorithm,
            group,
            priv_key,
            pub_key,
        }))
    }
}

impl crypto::ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<crypto::SharedSecret, rustls::Error> {
        let peer = agreement::UnparsedPublicKey::new(self.algorithm, peer);
        let shared_secret = agreement::agree_ephemeral(self.priv_key, &peer)
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(crypto::SharedSecret::from(shared_secret.as_ref()))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> rustls::NamedGroup {
        self.group
    }
}

/// Hybrid key exchange using X25519 and ML-KEM-768.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: &X25519,
    post_quantum: &mlkem::MlKem768,
    layout: hybrid::Layout {
        classical_share_len: 32,
        post_quantum_first: true,
        post_quantum_client_share_len: mlkem::MlKem768::ENCAPS_LEN,
        post_quantum_server_share_len: mlkem::MlKem768::CIPHERTEXT_LEN,
    },
    name: rustls::NamedGroup::X25519MLKEM768,
};

#[cfg(test)]
mod tests {
    use rustls::NamedGroup;
    use rustls::ProtocolVersion;

    use super::*;

    #[test]
    fn test_kx_x25519() {
        // Create a private key and verify its metadata.
        let key = X25519;
        assert_eq!(key.name(), NamedGroup::X25519);
        assert_eq!(key.ffdhe_group(), None);
        assert!(key.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(key.usable_for_version(ProtocolVersion::TLSv1_3));

        // A key exchange with an invalid peer public key should fail.
        let active = key.start().unwrap();
        assert!(active.complete(&[0u8]).is_err());

        // A key exchange with a valid peer public key should succeed.
        let active = key.start().unwrap();
        assert_eq!(active.ffdhe_group(), None);
        let peer = agreement::EphemeralPrivateKey::generate(&agreement::X25519).unwrap();
        assert!(active.complete(peer.compute_public_key().as_ref()).is_ok());
    }

    #[test]
    fn test_kx_p256() {
        // Create a private key and verify its metadata.
        let key = P256;
        assert_eq!(key.name(), NamedGroup::secp256r1);
        assert_eq!(key.ffdhe_group(), None);
        assert!(key.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(key.usable_for_version(ProtocolVersion::TLSv1_3));

        // A key exchange with an invalid peer public key should fail.
        let active = key.start().unwrap();
        assert!(active.complete(&[0u8]).is_err());

        // A key exchange with a valid peer public key should succeed.
        let active = key.start().unwrap();
        assert_eq!(active.ffdhe_group(), None);
        let peer = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256).unwrap();
        assert!(active.complete(peer.compute_public_key().as_ref()).is_ok());
    }

    #[test]
    fn test_kx_p384() {
        // Create a private key and verify its metadata.
        let key = P384;
        assert_eq!(key.name(), NamedGroup::secp384r1);
        assert_eq!(key.ffdhe_group(), None);
        assert!(key.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(key.usable_for_version(ProtocolVersion::TLSv1_3));

        // A key exchange with an invalid peer public key should fail.
        let active = key.start().unwrap();
        assert!(active.complete(&[0u8]).is_err());

        // A key exchange with a valid peer public key should succeed.
        let active = key.start().unwrap();
        assert_eq!(active.ffdhe_group(), None);
        let peer = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P384).unwrap();
        assert!(active.complete(peer.compute_public_key().as_ref()).is_ok());
    }
}
