//! Guardian key management and VAA signing utilities.

use libsecp256k1::{PublicKey, SecretKey};
use sha3::{Digest, Keccak256};

/// Well-known test guardian secret key (from Wormhole test fixtures).
pub const DEFAULT_GUARDIAN_SECRET_KEY: [u8; 32] = [
    0xcf, 0xb1, 0x23, 0x03, 0xa1, 0x9c, 0xde, 0x58, 0x0b, 0xb4, 0xdd, 0x77, 0x16, 0x39, 0xb0, 0xd2,
    0x6b, 0xc6, 0x83, 0x53, 0x64, 0x55, 0x71, 0xa8, 0xcf, 0xf5, 0x16, 0xab, 0x2e, 0xe1, 0x13, 0xa0,
];

/// A test guardian with signing capabilities.
#[derive(Clone)]
pub struct TestGuardian {
    secret_key: SecretKey,
    /// The guardian's public key.
    pub public_key: PublicKey,
    /// The guardian's Ethereum address (last 20 bytes of keccak256(pubkey)).
    pub eth_address: [u8; 20],
    /// The guardian's index within the guardian set.
    pub index: u8,
}

impl TestGuardian {
    /// Create a new test guardian with the given secret key and index.
    pub fn new(secret_key: [u8; 32], index: u8) -> Self {
        let secret_key = SecretKey::parse(&secret_key).expect("Invalid secret key");
        let public_key = PublicKey::from_secret_key(&secret_key);

        // Derive Ethereum address from public key (last 20 bytes of keccak256(pubkey[1..]))
        let pubkey_bytes = public_key.serialize();
        let hash = Keccak256::digest(&pubkey_bytes[1..]); // Skip the 0x04 prefix
        let eth_address: [u8; 20] = hash[12..32].try_into().unwrap();

        Self {
            secret_key,
            public_key,
            eth_address,
            index,
        }
    }

    /// Create a test guardian from a hex-encoded secret key.
    pub fn from_hex(hex_key: &str, index: u8) -> Result<Self, hex::FromHexError> {
        let bytes: [u8; 32] = hex::decode(hex_key)?
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self::new(bytes, index))
    }

    /// Sign a 32-byte digest and return the 65-byte signature [r, s, v].
    pub fn sign(&self, digest: &[u8; 32]) -> [u8; 65] {
        let message = libsecp256k1::Message::parse(digest);
        let (signature, recovery_id) = libsecp256k1::sign(&message, &self.secret_key);

        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&signature.serialize());
        sig_bytes[64] = recovery_id.serialize();
        sig_bytes
    }

    /// Sign a VAA body and return a 66-byte guardian signature.
    ///
    /// Format: [guardian_index (1 byte), signature (65 bytes)]
    ///
    /// The VAA body is double-hashed with keccak256 per Wormhole protocol.
    pub fn sign_vaa_body(&self, vaa_body: &[u8]) -> [u8; 66] {
        let message_hash = Keccak256::digest(vaa_body);
        let digest: [u8; 32] = Keccak256::digest(message_hash).into();

        let signature = self.sign(&digest);

        let mut result = [0u8; 66];
        result[0] = self.index;
        result[1..66].copy_from_slice(&signature);
        result
    }
}

impl Default for TestGuardian {
    fn default() -> Self {
        Self::new(DEFAULT_GUARDIAN_SECRET_KEY, 0)
    }
}

/// A set of test guardians for quorum testing.
#[derive(Clone)]
pub struct TestGuardianSet {
    guardians: Vec<TestGuardian>,
}

impl TestGuardianSet {
    /// Create a guardian set from a list of guardians.
    pub fn new(guardians: Vec<TestGuardian>) -> Self {
        Self { guardians }
    }

    /// Create a guardian set with a single guardian.
    pub fn single(guardian: TestGuardian) -> Self {
        Self::new(vec![guardian])
    }

    /// Generate N guardians deterministically from a seed.
    ///
    /// Uses keccak256(seed || index) as the secret key for each guardian.
    pub fn generate(count: usize, seed: u64) -> Self {
        let guardians = (0..count)
            .map(|i| {
                let mut input = [0u8; 40];
                input[..8].copy_from_slice(&seed.to_le_bytes());
                input[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                let secret: [u8; 32] = Keccak256::digest(input).into();
                TestGuardian::new(secret, i as u8)
            })
            .collect();
        Self { guardians }
    }

    /// Sign a VAA body with all guardians in the set.
    pub fn sign_vaa_body(&self, vaa_body: &[u8]) -> Vec<[u8; 66]> {
        self.guardians
            .iter()
            .map(|g| g.sign_vaa_body(vaa_body))
            .collect()
    }

    /// Sign a VAA body with specific guardians (by index).
    pub fn sign_vaa_body_with(&self, vaa_body: &[u8], indices: &[u8]) -> Vec<[u8; 66]> {
        indices
            .iter()
            .filter_map(|&i| self.guardians.get(i as usize))
            .map(|g| g.sign_vaa_body(vaa_body))
            .collect()
    }

    /// Get the Ethereum addresses of all guardians.
    pub fn eth_addresses(&self) -> Vec<[u8; 20]> {
        self.guardians.iter().map(|g| g.eth_address).collect()
    }

    /// Get the number of guardians in the set.
    pub fn len(&self) -> usize {
        self.guardians.len()
    }

    /// Check if the guardian set is empty.
    pub fn is_empty(&self) -> bool {
        self.guardians.is_empty()
    }

    /// Get a guardian by index.
    pub fn get(&self, index: usize) -> Option<&TestGuardian> {
        self.guardians.get(index)
    }

    /// Iterate over guardians.
    pub fn iter(&self) -> impl Iterator<Item = &TestGuardian> {
        self.guardians.iter()
    }
}

impl Default for TestGuardianSet {
    fn default() -> Self {
        Self::single(TestGuardian::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_guardian_eth_address() {
        let guardian = TestGuardian::default();
        // Just verify it's 20 bytes and deterministic
        assert_eq!(guardian.eth_address.len(), 20);

        let guardian2 = TestGuardian::default();
        assert_eq!(guardian.eth_address, guardian2.eth_address);
    }

    #[test]
    fn test_sign_vaa_body() {
        let guardian = TestGuardian::default();
        let body = b"test vaa body";

        let sig = guardian.sign_vaa_body(body);

        assert_eq!(sig.len(), 66);
        assert_eq!(sig[0], 0); // guardian index
    }

    #[test]
    fn test_guardian_set_generate() {
        let set = TestGuardianSet::generate(13, 12345);

        assert_eq!(set.len(), 13);

        // Indices should be correct
        for (i, g) in set.iter().enumerate() {
            assert_eq!(g.index, i as u8);
        }

        // All addresses should be unique
        let addrs = set.eth_addresses();
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(addrs[i], addrs[j]);
            }
        }
    }

    #[test]
    fn test_sign_with_subset() {
        let set = TestGuardianSet::generate(5, 999);
        let body = b"test";

        let sigs = set.sign_vaa_body_with(body, &[0, 2, 4]);

        assert_eq!(sigs.len(), 3);
        assert_eq!(sigs[0][0], 0); // index 0
        assert_eq!(sigs[1][0], 2); // index 2
        assert_eq!(sigs[2][0], 4); // index 4
    }
}
