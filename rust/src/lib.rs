use std::ffi::{CStr, CString, c_char};
use std::ptr;
use age::x25519;
use secrecy::ExposeSecret;

#[repr(C)]
pub struct CKeyPair {
    pub public_key: *mut c_char,
    pub private_key: *mut c_char,
}

#[no_mangle]
pub extern "C" fn age_keygen_c() -> CKeyPair {
    let identity = x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let private_key = identity.to_string();
    
    CKeyPair {
        public_key: CString::new(public_key).unwrap().into_raw(),
        private_key: CString::new(private_key.expose_secret()).unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn free_c_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}