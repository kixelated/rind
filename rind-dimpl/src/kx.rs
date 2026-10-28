use std::fmt;

use dimpl::crypto::{ActiveKeyExchange, Buf, NamedGroup, SupportedKxGroup};
use dimpl::{CryptoError, CryptoOperation};
use rind::key_agreement::{p256, p384, x25519};

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
        let failed = |_| CryptoError::OperationFailed(CryptoOperation::GenerateEphemeralKey);
        pub_key.clear();
        let key = match self.0 {
            NamedGroup::X25519 => {
                let key = x25519::PrivateKey::new_random().map_err(failed)?;
                pub_key.extend_from_slice(&key.public_key().as_bytes());
                Private::X25519(key)
            }
            NamedGroup::Secp256r1 => {
                let key = p256::PrivateKey::new_random().map_err(failed)?;
                pub_key.extend_from_slice(&key.public_key_uncompressed());
                Private::P256(key)
            }
            NamedGroup::Secp384r1 => {
                let key = p384::PrivateKey::new_random().map_err(failed)?;
                pub_key.extend_from_slice(&key.public_key_uncompressed());
                Private::P384(key)
            }
            group => return Err(CryptoError::UnsupportedKeyExchangeGroup(group)),
        };
        Ok(Box::new(Exchange { key, pub_key }))
    }
}

enum Private {
    X25519(x25519::PrivateKey),
    P256(p256::PrivateKey),
    P384(p384::PrivateKey),
}

struct Exchange {
    key: Private,
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
        let group = self.group();
        let invalid = |_| CryptoError::InvalidPublicKey(group);
        out.clear();
        match self.key {
            Private::X25519(key) => {
                let peer = x25519::PublicKey::try_from_slice(peer_pub).map_err(invalid)?;
                out.extend_from_slice(&key.diffie_hellman(&peer).map_err(invalid)?.0);
            }
            Private::P256(key) => {
                let peer = p256::PublicKey::from_x962_uncompressed(peer_pub).map_err(invalid)?;
                out.extend_from_slice(&key.diffie_hellman(&peer).map_err(invalid)?.0);
            }
            Private::P384(key) => {
                let peer = p384::PublicKey::from_x962_uncompressed(peer_pub).map_err(invalid)?;
                out.extend_from_slice(&key.diffie_hellman(&peer).map_err(invalid)?.0);
            }
        }
        Ok(())
    }

    fn group(&self) -> NamedGroup {
        match self.key {
            Private::X25519(_) => NamedGroup::X25519,
            Private::P256(_) => NamedGroup::Secp256r1,
            Private::P384(_) => NamedGroup::Secp384r1,
        }
    }
}
