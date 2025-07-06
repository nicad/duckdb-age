use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::io::Write;
use age::x25519;
use secrecy::ExposeSecret;

#[repr(C)]
pub struct CKeyPair {
    pub public_key: *mut c_char,
    pub private_key: *mut c_char,
}

#[repr(C)]
pub struct CBytes {
    pub data: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct CResult {
    pub success: bool,
    pub data: *mut u8,
    pub len: usize,
    pub error_message: *mut c_char,
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
pub extern "C" fn age_encrypt_c(
    data: *const u8,
    data_len: usize,
    recipient: *const c_char,
) -> CResult {
    // Convert inputs from C to Rust
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    let recipient_str = unsafe {
        match CStr::from_ptr(recipient).to_str() {
            Ok(s) => s,
            Err(_) => return CResult { 
                success: false, 
                data: ptr::null_mut(), 
                len: 0,
                error_message: CString::new("Invalid UTF-8 in recipient key").unwrap().into_raw()
            },
        }
    };
    
    // Check for empty recipient
    if recipient_str.is_empty() {
        return CResult {
            success: false,
            data: ptr::null_mut(),
            len: 0,
            error_message: CString::new("Invalid age recipient key: (empty)").unwrap().into_raw()
        };
    }
    
    // Perform encryption
    match age_encrypt_impl(data_slice, recipient_str) {
        Ok(encrypted) => {
            let len = encrypted.len();
            let data_ptr = encrypted.as_ptr() as *mut u8;
            std::mem::forget(encrypted); // Prevent Rust from freeing the memory
            CResult { 
                success: true, 
                data: data_ptr, 
                len,
                error_message: ptr::null_mut()
            }
        }
        Err(e) => {
            let error_msg = format!("Invalid age recipient key: {}", recipient_str);
            CResult { 
                success: false, 
                data: ptr::null_mut(), 
                len: 0,
                error_message: CString::new(error_msg).unwrap().into_raw()
            }
        }
    }
}

fn age_encrypt_impl(data: &[u8], recipient_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Parse recipient public key
    let recipient: x25519::Recipient = recipient_str.parse()?;
    
    // Create encryptor with single recipient
    let recipients = vec![&recipient as &dyn age::Recipient];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
        .expect("we provided a recipient");
    
    // Encrypt the data
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(data)?;
    writer.finish()?;
    
    Ok(encrypted)
}

#[no_mangle]
pub extern "C" fn free_c_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[no_mangle]
pub extern "C" fn free_c_bytes(bytes: CBytes) {
    if !bytes.data.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(bytes.data, bytes.len, bytes.len);
        }
    }
}

#[no_mangle]
pub extern "C" fn free_c_result(result: CResult) {
    if !result.data.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(result.data, result.len, result.len);
        }
    }
    if !result.error_message.is_null() {
        unsafe {
            let _ = CString::from_raw(result.error_message);
        }
    }
}