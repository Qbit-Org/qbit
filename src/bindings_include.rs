// This file exists to solve the problem with OUT_DIR not being
// available in the IDE but required for builds.
// The build script always generates bindings.rs in the OUT_DIR.

#[cfg(all(not(feature = "ide"), not(doc)))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(doc)]
pub mod doc_bindings {
    pub type bitcoin_pqc_error_t = ::std::os::raw::c_int;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_OK: bitcoin_pqc_error_t = 0;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_BAD_ARG: bitcoin_pqc_error_t = -1;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_BAD_KEY: bitcoin_pqc_error_t = -2;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_BAD_SIGNATURE: bitcoin_pqc_error_t = -3;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_NOT_IMPLEMENTED: bitcoin_pqc_error_t = -4;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_SIGNING_LIMIT: bitcoin_pqc_error_t = -5;
    pub const BITCOIN_PQC_SIGN_WOTSC_LAYERS: u32 = 5;

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bitcoin_pqc_sign_stats_t {
        pub forsc_attempts: u32,
        pub forsc_max_attempts: u32,
        pub wotsc_attempts: [u32; BITCOIN_PQC_SIGN_WOTSC_LAYERS as usize],
        pub wotsc_layer_count: u32,
        pub wotsc_max_attempts: u32,
        pub wotsc_max_observed_attempts: u32,
        pub cap_exceeded: u32,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bitcoin_pqc_keypair_t {
        pub public_key: *mut ::std::os::raw::c_void,
        pub secret_key: *mut ::std::os::raw::c_void,
        pub public_key_size: usize,
        pub secret_key_size: usize,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bitcoin_pqc_signature_t {
        pub signature: *mut ::std::os::raw::c_uchar,
        pub signature_size: usize,
    }

    pub unsafe fn bitcoin_pqc_keygen(
        _keypair: *mut bitcoin_pqc_keypair_t,
        _random_data: *const ::std::os::raw::c_uchar,
        _random_data_len: usize,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is a doc stub")
    }

    pub unsafe fn bitcoin_pqc_keypair_free(_keypair: *mut bitcoin_pqc_keypair_t) {}

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn bitcoin_pqc_sign(
        _secret_key: *const ::std::os::raw::c_uchar,
        _secret_key_len: usize,
        _message: *const ::std::os::raw::c_uchar,
        _message_len: usize,
        _signature: *mut bitcoin_pqc_signature_t,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is a doc stub")
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn bitcoin_pqc_sign_with_stats(
        _secret_key: *const ::std::os::raw::c_uchar,
        _secret_key_len: usize,
        _message: *const ::std::os::raw::c_uchar,
        _message_len: usize,
        _signature: *mut bitcoin_pqc_signature_t,
        _stats: *mut bitcoin_pqc_sign_stats_t,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is a doc stub")
    }

    pub unsafe fn bitcoin_pqc_verify(
        _public_key: *const ::std::os::raw::c_uchar,
        _public_key_len: usize,
        _message: *const ::std::os::raw::c_uchar,
        _message_len: usize,
        _signature: *const ::std::os::raw::c_uchar,
        _signature_len: usize,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is a doc stub")
    }

    pub unsafe fn bitcoin_pqc_signature_free(_signature: *mut bitcoin_pqc_signature_t) {}

    pub unsafe fn bitcoin_pqc_public_key_size() -> usize {
        0
    }

    pub unsafe fn bitcoin_pqc_secret_key_size() -> usize {
        0
    }

    pub unsafe fn bitcoin_pqc_signature_size() -> usize {
        0
    }
}

#[cfg(feature = "ide")]
pub mod ide_bindings {
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bitcoin_pqc_keypair_t {
        pub public_key: *mut ::std::os::raw::c_void,
        pub secret_key: *mut ::std::os::raw::c_void,
        pub public_key_size: usize,
        pub secret_key_size: usize,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bitcoin_pqc_signature_t {
        pub signature: *mut ::std::os::raw::c_uchar,
        pub signature_size: usize,
    }

    pub type bitcoin_pqc_error_t = ::std::os::raw::c_int;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_OK: bitcoin_pqc_error_t = 0;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_BAD_ARG: bitcoin_pqc_error_t = -1;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_BAD_KEY: bitcoin_pqc_error_t = -2;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_BAD_SIGNATURE: bitcoin_pqc_error_t = -3;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_NOT_IMPLEMENTED: bitcoin_pqc_error_t = -4;
    pub const bitcoin_pqc_error_t_BITCOIN_PQC_ERROR_SIGNING_LIMIT: bitcoin_pqc_error_t = -5;
    pub const BITCOIN_PQC_SIGN_WOTSC_LAYERS: u32 = 5;

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bitcoin_pqc_sign_stats_t {
        pub forsc_attempts: u32,
        pub forsc_max_attempts: u32,
        pub wotsc_attempts: [u32; BITCOIN_PQC_SIGN_WOTSC_LAYERS as usize],
        pub wotsc_layer_count: u32,
        pub wotsc_max_attempts: u32,
        pub wotsc_max_observed_attempts: u32,
        pub cap_exceeded: u32,
    }

    pub unsafe fn bitcoin_pqc_keygen(
        _keypair: *mut bitcoin_pqc_keypair_t,
        _random_data: *const ::std::os::raw::c_uchar,
        _random_data_len: usize,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is an IDE stub")
    }

    pub unsafe fn bitcoin_pqc_keypair_free(_keypair: *mut bitcoin_pqc_keypair_t) {}

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn bitcoin_pqc_sign(
        _secret_key: *const ::std::os::raw::c_uchar,
        _secret_key_len: usize,
        _message: *const ::std::os::raw::c_uchar,
        _message_len: usize,
        _signature: *mut bitcoin_pqc_signature_t,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is an IDE stub")
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn bitcoin_pqc_sign_with_stats(
        _secret_key: *const ::std::os::raw::c_uchar,
        _secret_key_len: usize,
        _message: *const ::std::os::raw::c_uchar,
        _message_len: usize,
        _signature: *mut bitcoin_pqc_signature_t,
        _stats: *mut bitcoin_pqc_sign_stats_t,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is an IDE stub")
    }

    pub unsafe fn bitcoin_pqc_verify(
        _public_key: *const ::std::os::raw::c_uchar,
        _public_key_len: usize,
        _message: *const ::std::os::raw::c_uchar,
        _message_len: usize,
        _signature: *const ::std::os::raw::c_uchar,
        _signature_len: usize,
    ) -> bitcoin_pqc_error_t {
        unimplemented!("This is an IDE stub")
    }

    pub unsafe fn bitcoin_pqc_signature_free(_signature: *mut bitcoin_pqc_signature_t) {}

    pub unsafe fn bitcoin_pqc_public_key_size() -> usize {
        0
    }

    pub unsafe fn bitcoin_pqc_secret_key_size() -> usize {
        0
    }

    pub unsafe fn bitcoin_pqc_signature_size() -> usize {
        0
    }
}

#[cfg(doc)]
pub use doc_bindings::*;

#[cfg(feature = "ide")]
pub use ide_bindings::*;
