#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::error::Error as StdError;
use std::fmt;
use std::ptr;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
mod hex_bytes {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(s).map_err(Error::custom)
    }
}

#[allow(dead_code)]
pub(crate) mod bindings_include;
use bindings_include::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum PqcError {
    BadArgument,
    InsufficientData,
    BadKey,
    BadSignature,
    NotImplemented,
    SigningLimitExceeded,
    Other(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignWithStatsError {
    pub error: PqcError,
    pub stats: Option<SigningStats>,
}

impl fmt::Display for PqcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PqcError::BadArgument => write!(f, "Invalid arguments provided"),
            PqcError::InsufficientData => write!(f, "Not enough data provided"),
            PqcError::BadKey => write!(f, "Invalid key provided or invalid format"),
            PqcError::BadSignature => write!(f, "Invalid signature provided or invalid format"),
            PqcError::NotImplemented => write!(f, "Operation not implemented"),
            PqcError::SigningLimitExceeded => write!(f, "Signing attempt limit exceeded"),
            PqcError::Other(code) => write!(f, "Unexpected error code: {code}"),
        }
    }
}

impl StdError for PqcError {}

impl fmt::Display for SignWithStatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl StdError for SignWithStatsError {}

impl From<SignWithStatsError> for PqcError {
    fn from(error: SignWithStatsError) -> Self {
        error.error
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
    #[cfg_attr(feature = "serde", serde(with = "hex_bytes"))]
    pub bytes: Vec<u8>,
}

impl PublicKey {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != public_key_size() {
            return Err(PqcError::BadKey);
        }

        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, PqcError> {
        let bytes = hex::decode(s).map_err(|_| PqcError::BadArgument)?;
        Self::try_from_slice(&bytes)
    }
}

/// SLH-DSA secret key material.
///
/// Secret key bytes are intentionally private to avoid accidental logging or
/// serialization. Use [`SecretKey::as_secret_bytes`] only for explicit export
/// or interoperability paths that must handle raw secret material.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "secret-key-serde", derive(Serialize, Deserialize))]
pub struct SecretKey {
    #[cfg_attr(feature = "secret-key-serde", serde(with = "hex_bytes"))]
    bytes: Vec<u8>,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("bytes", &RedactedBytes(self.bytes.len()))
            .finish()
    }
}

impl SecretKey {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != secret_key_size() {
            return Err(PqcError::BadKey);
        }

        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, PqcError> {
        let bytes = hex::decode(s).map_err(|_| PqcError::BadArgument)?;
        Self::try_from_slice(&bytes)
    }

    /// Return the raw secret key bytes.
    ///
    /// This intentionally exposes secret key material. Do not log, serialize,
    /// or retain copies of this data unless the calling protocol explicitly
    /// requires it; zeroize any owned copies when they are no longer needed.
    pub fn as_secret_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

struct RedactedBytes(usize);

impl fmt::Debug for RedactedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted> ({} bytes)", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    #[cfg_attr(feature = "serde", serde(with = "hex_bytes"))]
    pub bytes: Vec<u8>,
}

impl Signature {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != signature_size() {
            return Err(PqcError::BadSignature);
        }

        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, PqcError> {
        let bytes = hex::decode(s).map_err(|_| PqcError::BadArgument)?;
        Self::try_from_slice(&bytes)
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "secret-key-serde", derive(Serialize, Deserialize))]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &self.secret_key)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningStats {
    pub forsc_attempts: u32,
    pub forsc_max_attempts: u32,
    pub wotsc_attempts: Vec<u32>,
    pub wotsc_max_attempts: u32,
    pub wotsc_max_observed_attempts: u32,
    pub cap_exceeded: u32,
}

impl SigningStats {
    fn from_raw(raw: &bitcoin_pqc_sign_stats_t) -> Self {
        let layer_count = (raw.wotsc_layer_count as usize).min(raw.wotsc_attempts.len());
        Self {
            forsc_attempts: raw.forsc_attempts,
            forsc_max_attempts: raw.forsc_max_attempts,
            wotsc_attempts: raw.wotsc_attempts[..layer_count].to_vec(),
            wotsc_max_attempts: raw.wotsc_max_attempts,
            wotsc_max_observed_attempts: raw.wotsc_max_observed_attempts,
            cap_exceeded: raw.cap_exceeded,
        }
    }

    pub fn limit_exceeded(&self) -> bool {
        self.cap_exceeded != 0
    }
}

fn pqc_error_from_code(error: bitcoin_pqc_error_t) -> PqcError {
    match error {
        bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_BAD_ARG => PqcError::BadArgument,
        bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_BAD_KEY => PqcError::BadKey,
        bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_BAD_SIGNATURE => PqcError::BadSignature,
        bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_NOT_IMPLEMENTED => PqcError::NotImplemented,
        bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_SIGNING_LIMIT => PqcError::SigningLimitExceeded,
        _ => PqcError::Other(error),
    }
}

fn map_error(error: bitcoin_pqc_error_t) -> Result<(), PqcError> {
    match error {
        bitcoin_pqc_error_t_BITCOIN_PQC_OK => Ok(()),
        _ => Err(pqc_error_from_code(error)),
    }
}

/// Generate a keypair from caller-provided entropy.
///
/// The library borrows `random_data` and cannot clear caller-owned memory.
/// Treat keygen entropy as sensitive seed material when applicable, and
/// zeroize the caller's buffer after this call if it must not remain in memory.
pub fn generate_keypair(random_data: &[u8]) -> Result<KeyPair, PqcError> {
    if random_data.len() < 128 {
        return Err(PqcError::InsufficientData);
    }

    unsafe {
        let mut keypair = bitcoin_pqc_keypair_t {
            public_key: ptr::null_mut(),
            secret_key: ptr::null_mut(),
            public_key_size: 0,
            secret_key_size: 0,
        };

        let result = bitcoin_pqc_keygen(&mut keypair, random_data.as_ptr(), random_data.len());
        if result != bitcoin_pqc_error_t_BITCOIN_PQC_OK {
            bitcoin_pqc_keypair_free(&mut keypair);
            map_error(result)?;
            return Err(PqcError::Other(result));
        }

        let pk_slice =
            std::slice::from_raw_parts(keypair.public_key as *const u8, keypair.public_key_size);
        let sk_slice =
            std::slice::from_raw_parts(keypair.secret_key as *const u8, keypair.secret_key_size);

        let public_key = PublicKey {
            bytes: pk_slice.to_vec(),
        };
        let secret_key = SecretKey {
            bytes: sk_slice.to_vec(),
        };

        bitcoin_pqc_keypair_free(&mut keypair);

        Ok(KeyPair {
            public_key,
            secret_key,
        })
    }
}

pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Signature, PqcError> {
    sign_inner(secret_key, message, None)
        .map(|(signature, _)| signature)
        .map_err(|error| error.error)
}

pub fn sign_with_stats(
    secret_key: &SecretKey,
    message: &[u8],
) -> Result<(Signature, SigningStats), SignWithStatsError> {
    let mut stats = bitcoin_pqc_sign_stats_t {
        forsc_attempts: 0,
        forsc_max_attempts: 0,
        wotsc_attempts: [0; BITCOIN_PQC_SIGN_WOTSC_LAYERS as usize],
        wotsc_layer_count: 0,
        wotsc_max_attempts: 0,
        wotsc_max_observed_attempts: 0,
        cap_exceeded: 0,
    };
    match sign_inner(secret_key, message, Some(&mut stats)) {
        Ok((signature, stats)) => Ok((
            signature,
            stats.expect("sign_inner should return stats when requested"),
        )),
        Err(error) => Err(SignWithStatsError {
            error: error.error,
            stats: error.stats,
        }),
    }
}

#[derive(Debug)]
struct SignInnerError {
    error: PqcError,
    stats: Option<SigningStats>,
}

fn sign_inner(
    secret_key: &SecretKey,
    message: &[u8],
    mut stats: Option<&mut bitcoin_pqc_sign_stats_t>,
) -> Result<(Signature, Option<SigningStats>), SignInnerError> {
    let secret_key_bytes = secret_key.as_secret_bytes();
    if secret_key_bytes.len() != secret_key_size() {
        return Err(SignInnerError {
            error: PqcError::BadKey,
            stats: None,
        });
    }

    unsafe {
        let mut signature = bitcoin_pqc_signature_t {
            signature: ptr::null_mut(),
            signature_size: 0,
        };

        let stats_ptr = match stats.as_deref_mut() {
            Some(stats) => stats as *mut bitcoin_pqc_sign_stats_t,
            None => ptr::null_mut(),
        };

        let result = if stats_ptr.is_null() {
            bitcoin_pqc_sign(
                secret_key_bytes.as_ptr(),
                secret_key_bytes.len(),
                message.as_ptr(),
                message.len(),
                &mut signature,
            )
        } else {
            bitcoin_pqc_sign_with_stats(
                secret_key_bytes.as_ptr(),
                secret_key_bytes.len(),
                message.as_ptr(),
                message.len(),
                &mut signature,
                stats_ptr,
            )
        };

        if result != bitcoin_pqc_error_t_BITCOIN_PQC_OK {
            let mapped_stats = stats.as_ref().map(|stats| SigningStats::from_raw(stats));
            bitcoin_pqc_signature_free(&mut signature);
            return Err(SignInnerError {
                error: pqc_error_from_code(result),
                stats: mapped_stats,
            });
        }

        let sig_slice =
            std::slice::from_raw_parts(signature.signature as *const u8, signature.signature_size);
        let sig = Signature {
            bytes: sig_slice.to_vec(),
        };
        let mapped_stats = stats.as_ref().map(|stats| SigningStats::from_raw(stats));

        bitcoin_pqc_signature_free(&mut signature);

        Ok((sig, mapped_stats))
    }
}

pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), PqcError> {
    if public_key.bytes.len() != public_key_size() {
        return Err(PqcError::BadKey);
    }

    if signature.bytes.len() != signature_size() {
        return Err(PqcError::BadSignature);
    }

    unsafe {
        let result = bitcoin_pqc_verify(
            public_key.bytes.as_ptr(),
            public_key.bytes.len(),
            message.as_ptr(),
            message.len(),
            signature.bytes.as_ptr(),
            signature.bytes.len(),
        );
        map_error(result)
    }
}

pub fn public_key_size() -> usize {
    unsafe { bitcoin_pqc_public_key_size() }
}

pub fn secret_key_size() -> usize {
    unsafe { bitcoin_pqc_secret_key_size() }
}

pub fn signature_size() -> usize {
    unsafe { bitcoin_pqc_signature_size() }
}

/// Test-only WOTS+C parameter snapshot for the compiled bounded30 profile.
#[cfg(feature = "test-helpers")]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WotscParams {
    pub n: u32,
    pub w: u32,
    pub logw: u32,
    pub len1: u32,
    pub len2: u32,
    pub len: u32,
    pub target: u32,
    pub wots_bytes: u32,
    pub wots_pk_bytes: u32,
    pub fors_bytes: u32,
    pub d: u32,
    pub tree_height: u32,
    pub auth_path_bytes: u32,
    pub signature_bytes: u32,
}

/// Test-only WOTS+C derivation details from the C implementation.
#[cfg(feature = "test-helpers")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotscDerivation {
    pub compressed_message: Vec<u8>,
    pub chain_lengths: Vec<u32>,
    pub counter: u32,
    pub checksum: u32,
}

/// Test-only WOTS+C hash-at-counter result from the C implementation.
#[cfg(feature = "test-helpers")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WotscCounterHash {
    pub compressed_message: Vec<u8>,
    pub checksum: u32,
}

#[cfg(feature = "test-helpers")]
extern "C" {
    fn bitcoin_pqc_test_message_to_indices(
        indices_out: *mut u32,
        mhash: *const u8,
        mhash_len: usize,
    ) -> i32;

    fn bitcoin_pqc_test_forsc_compressed_index(mhash: *const u8, mhash_len: usize) -> u32;

    fn bitcoin_pqc_test_compressed_index(
        sig: *const u8,
        sig_len: usize,
        pk: *const u8,
        pk_len: usize,
        msg: *const u8,
        msg_len: usize,
    ) -> u32;

    fn bitcoin_pqc_test_wotsc_params(params: *mut WotscParams) -> i32;

    fn bitcoin_pqc_test_wotsc_hash_counter(
        compressed_msg: *mut u8,
        compressed_msg_len: usize,
        checksum_out: *mut u32,
        msg: *const u8,
        msg_len: usize,
        counter: u32,
    ) -> i32;

    fn bitcoin_pqc_test_wotsc_derive(
        compressed_msg: *mut u8,
        compressed_msg_len: usize,
        lengths_out: *mut u32,
        lengths_len: usize,
        counter_out: *mut u32,
        checksum_out: *mut u32,
        msg: *const u8,
        msg_len: usize,
    ) -> i32;

    fn bitcoin_pqc_test_wotsc_derive_with_limit(
        compressed_msg: *mut u8,
        compressed_msg_len: usize,
        lengths_out: *mut u32,
        lengths_len: usize,
        counter_out: *mut u32,
        checksum_out: *mut u32,
        msg: *const u8,
        msg_len: usize,
        max_counter: u32,
    ) -> i32;

    fn bitcoin_pqc_test_seed_keypair_with_prefilled_root_tail(
        pk: *mut u8,
        pk_len: usize,
        sk: *mut u8,
        sk_len: usize,
        root_tail_prefill: u8,
        stats: *mut bitcoin_pqc_sign_stats_t,
    ) -> i32;
}

/// Test helper: extract FORS tree indices from a message hash via the C implementation.
/// Returns `None` on invalid input, or `Some(indices)` with 7 u32 values.
#[cfg(feature = "test-helpers")]
pub fn test_message_to_indices(mhash: &[u8]) -> Option<Vec<u32>> {
    if mhash.len() < 16 {
        return None;
    }
    let mut indices = vec![0u32; 7];
    let rc = unsafe {
        bitcoin_pqc_test_message_to_indices(indices.as_mut_ptr(), mhash.as_ptr(), mhash.len())
    };
    if rc == 0 {
        Some(indices)
    } else {
        None
    }
}

/// Test helper: extract the compressed FORS tree index from a message hash.
/// Returns `None` on invalid input.
#[cfg(feature = "test-helpers")]
pub fn test_forsc_compressed_index(mhash: &[u8]) -> Option<u32> {
    if mhash.len() < 16 {
        return None;
    }
    let idx = unsafe { bitcoin_pqc_test_forsc_compressed_index(mhash.as_ptr(), mhash.len()) };
    if idx == u32::MAX {
        None
    } else {
        Some(idx)
    }
}

/// Test helper: run the hash_message -> compressed index pipeline for a signature tuple.
/// Returns `None` on invalid input.
#[cfg(feature = "test-helpers")]
pub fn test_compressed_index(sig: &[u8], pk: &[u8], msg: &[u8]) -> Option<u32> {
    let idx = unsafe {
        bitcoin_pqc_test_compressed_index(
            sig.as_ptr(),
            sig.len(),
            pk.as_ptr(),
            pk.len(),
            msg.as_ptr(),
            msg.len(),
        )
    };
    if idx == u32::MAX {
        None
    } else {
        Some(idx)
    }
}

/// Test helper: return WOTS+C constants from the compiled C parameter set.
#[cfg(feature = "test-helpers")]
pub fn test_wotsc_params() -> Option<WotscParams> {
    let mut params = WotscParams::default();
    let rc = unsafe { bitcoin_pqc_test_wotsc_params(&mut params) };
    if rc == 0 {
        Some(params)
    } else {
        None
    }
}

/// Test helper: hash a WOTS+C message with an explicit two-byte counter.
#[cfg(feature = "test-helpers")]
pub fn test_wotsc_hash_counter(msg: &[u8], counter: u32) -> Option<WotscCounterHash> {
    let params = test_wotsc_params()?;
    if msg.len() != params.n as usize {
        return None;
    }

    let mut compressed_message = vec![0u8; params.n as usize];
    let mut checksum = 0u32;
    let rc = unsafe {
        bitcoin_pqc_test_wotsc_hash_counter(
            compressed_message.as_mut_ptr(),
            compressed_message.len(),
            &mut checksum,
            msg.as_ptr(),
            msg.len(),
            counter,
        )
    };

    if rc == 0 {
        Some(WotscCounterHash {
            compressed_message,
            checksum,
        })
    } else {
        None
    }
}

/// Test helper: run WOTS+C counter search and return the derived chain lengths.
#[cfg(feature = "test-helpers")]
pub fn test_wotsc_derive(msg: &[u8]) -> Option<WotscDerivation> {
    let params = test_wotsc_params()?;
    if msg.len() != params.n as usize {
        return None;
    }

    let mut compressed_message = vec![0u8; params.n as usize];
    let mut chain_lengths = vec![0u32; params.len1 as usize];
    let mut counter = 0u32;
    let mut checksum = 0u32;
    let rc = unsafe {
        bitcoin_pqc_test_wotsc_derive(
            compressed_message.as_mut_ptr(),
            compressed_message.len(),
            chain_lengths.as_mut_ptr(),
            chain_lengths.len(),
            &mut counter,
            &mut checksum,
            msg.as_ptr(),
            msg.len(),
        )
    };

    if rc == 0 {
        Some(WotscDerivation {
            compressed_message,
            chain_lengths,
            counter,
            checksum,
        })
    } else {
        None
    }
}

/// Test helper: run WOTS+C counter search with an inclusive counter limit.
#[cfg(feature = "test-helpers")]
pub fn test_wotsc_derive_with_limit(msg: &[u8], max_counter: u32) -> Option<WotscDerivation> {
    let params = test_wotsc_params()?;
    if msg.len() != params.n as usize || max_counter > 0xFFFF {
        return None;
    }

    let mut compressed_message = vec![0u8; params.n as usize];
    let mut chain_lengths = vec![0u32; params.len1 as usize];
    let mut counter = 0u32;
    let mut checksum = 0u32;
    let rc = unsafe {
        bitcoin_pqc_test_wotsc_derive_with_limit(
            compressed_message.as_mut_ptr(),
            compressed_message.len(),
            chain_lengths.as_mut_ptr(),
            chain_lengths.len(),
            &mut counter,
            &mut checksum,
            msg.as_ptr(),
            msg.len(),
            max_counter,
        )
    };

    if rc == 0 {
        Some(WotscDerivation {
            compressed_message,
            chain_lengths,
            counter,
            checksum,
        })
    } else {
        None
    }
}

/// Test helper: run deterministic seed keygen after pre-filling the secret-key root slot.
#[cfg(feature = "test-helpers")]
pub fn test_seed_keypair_with_prefilled_root_tail(
    root_tail_prefill: u8,
) -> Option<(PublicKey, SecretKey, SigningStats)> {
    let mut pk = vec![0u8; public_key_size()];
    let mut sk = vec![0u8; secret_key_size()];
    let mut stats = bitcoin_pqc_sign_stats_t {
        forsc_attempts: 0,
        forsc_max_attempts: 0,
        wotsc_attempts: [0; BITCOIN_PQC_SIGN_WOTSC_LAYERS as usize],
        wotsc_layer_count: 0,
        wotsc_max_attempts: 0,
        wotsc_max_observed_attempts: 0,
        cap_exceeded: 0,
    };

    let rc = unsafe {
        bitcoin_pqc_test_seed_keypair_with_prefilled_root_tail(
            pk.as_mut_ptr(),
            pk.len(),
            sk.as_mut_ptr(),
            sk.len(),
            root_tail_prefill,
            &mut stats,
        )
    };

    if rc == 0 {
        Some((
            PublicKey { bytes: pk },
            SecretKey::try_from_slice(&sk).ok()?,
            SigningStats::from_raw(&stats),
        ))
    } else {
        None
    }
}
