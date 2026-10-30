use std::fmt;

use dimpl::crypto::{ActiveKeyExchange, Buf, NamedGroup, SupportedKxGroup};
use dimpl::{CryptoError, CryptoOperation};
use rind::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};

#[derive(Debug)]
struct Group(NamedGroup);

/// Key exchange groups, in order of preference.
pub(crate) static ALL: &[&dyn SupportedKxGroup] = &[
    &Group(NamedGroup::X25519),
    &Group(NamedGroup::Secp256r1),
    &Group(NamedGroup::Secp384r1),
];

impl SupportedKxGroup for Group {
    fn name(&self) -> NamedGroup {
        self.0
    }

    fn start_exchange(&self, mut pub_key: Buf) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        let algorithm = match self.0 {
            NamedGroup::X25519 => &agreement::X25519,
            NamedGroup::Secp256r1 => &agreement::ECDH_P256,
            NamedGroup::Secp384r1 => &agreement::ECDH_P384,
            group => return Err(CryptoError::UnsupportedKeyExchangeGroup(group)),
        };
        let key = EphemeralPrivateKey::generate(algorithm)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::GenerateEphemeralKey))?;
        pub_key.clear();
        pub_key.extend_from_slice(key.compute_public_key().as_ref());
        Ok(Box::new(Exchange {
            group: self.0,
            algorithm,
            key,
            pub_key,
        }))
    }
}

struct Exchange {
    group: NamedGroup,
    algorithm: &'static agreement::Algorithm,
    key: EphemeralPrivateKey,
    pub_key: Buf,
}

impl fmt::Debug for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchange")
            .field("group", &self.group())
            .finish_non_exhaustive()
    }
}

impl ActiveKeyExchange for Exchange {
    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), CryptoError> {
        // Covers a malformed or off-curve point, and X25519's all-zero output
        // from a low-order point (RFC 7748 section 6.1).
        let peer = UnparsedPublicKey::new(self.algorithm, peer_pub);
        let secret = agreement::agree_ephemeral(self.key, &peer)
            .map_err(|_| CryptoError::InvalidPublicKey(self.group))?;
        out.clear();
        out.extend_from_slice(secret.as_ref());
        Ok(())
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}
