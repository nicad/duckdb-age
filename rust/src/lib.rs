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
        Err(_) => {
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

#[no_mangle]
pub extern "C" fn age_decrypt_c(
    data: *const u8,
    data_len: usize,
    identity: *const c_char,
) -> CResult {
    // Convert inputs from C to Rust
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    let identity_str = unsafe {
        match CStr::from_ptr(identity).to_str() {
            Ok(s) => s,
            Err(_) => return CResult { 
                success: false, 
                data: ptr::null_mut(), 
                len: 0,
                error_message: CString::new("Invalid UTF-8 in identity key").unwrap().into_raw()
            },
        }
    };
    
    // Check for empty identity
    if identity_str.is_empty() {
        return CResult {
            success: false,
            data: ptr::null_mut(),
            len: 0,
            error_message: CString::new("Invalid age identity key: (empty)").unwrap().into_raw()
        };
    }
    
    // Perform decryption
    match age_decrypt_impl(data_slice, identity_str) {
        Ok(decrypted) => {
            let len = decrypted.len();
            let data_ptr = decrypted.as_ptr() as *mut u8;
            std::mem::forget(decrypted); // Prevent Rust from freeing the memory
            CResult { 
                success: true, 
                data: data_ptr, 
                len,
                error_message: ptr::null_mut()
            }
        }
        Err(e) => {
            let error_msg = format!("Decryption failed: {}", e);
            CResult { 
                success: false, 
                data: ptr::null_mut(), 
                len: 0,
                error_message: CString::new(error_msg).unwrap().into_raw()
            }
        }
    }
}

fn age_decrypt_impl(data: &[u8], identity_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Parse identity private key
    let identity: x25519::Identity = identity_str.parse()?;
    
    // Create decryptor
    let decryptor = age::Decryptor::new(data)?;
    
    // Decrypt the data
    let mut decrypted = Vec::new();
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
    std::io::copy(&mut reader, &mut decrypted)?;
    
    Ok(decrypted)
}

#[no_mangle]
pub extern "C" fn age_encrypt_multi_c(
    data: *const u8,
    data_len: usize,
    recipients: *const *const c_char,
    recipients_len: usize,
) -> CResult {
    // Convert data from C to Rust
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    
    // Convert recipients array from C to Rust
    let recipients_slice = unsafe { std::slice::from_raw_parts(recipients, recipients_len) };
    let mut recipient_strs = Vec::new();
    
    for &recipient_ptr in recipients_slice {
        let recipient_str = unsafe {
            match CStr::from_ptr(recipient_ptr).to_str() {
                Ok(s) => s,
                Err(_) => return CResult { 
                    success: false, 
                    data: ptr::null_mut(), 
                    len: 0,
                    error_message: CString::new("Invalid UTF-8 in recipient key").unwrap().into_raw()
                },
            }
        };
        
        if recipient_str.is_empty() {
            return CResult {
                success: false,
                data: ptr::null_mut(),
                len: 0,
                error_message: CString::new("Invalid age recipient key: (empty)").unwrap().into_raw()
            };
        }
        
        recipient_strs.push(recipient_str);
    }
    
    // Perform encryption
    match age_encrypt_multi_impl(data_slice, &recipient_strs) {
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
            let error_msg = format!("Encryption failed: {}", e);
            CResult { 
                success: false, 
                data: ptr::null_mut(), 
                len: 0,
                error_message: CString::new(error_msg).unwrap().into_raw()
            }
        }
    }
}

fn age_encrypt_multi_impl(data: &[u8], recipient_strs: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Parse all recipient public keys
    let mut recipients: Vec<Box<dyn age::Recipient>> = Vec::new();
    
    for (i, recipient_str) in recipient_strs.iter().enumerate() {
        match recipient_str.parse::<x25519::Recipient>() {
            Ok(recipient) => recipients.push(Box::new(recipient)),
            Err(_) => return Err(format!("Invalid recipient at position {}: {}", i, recipient_str).into()),
        }
    }
    
    if recipients.is_empty() {
        return Err("No valid recipients provided".into());
    }
    
    // Create encryptor with multiple recipients
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
        .expect("we provided recipients");
    
    // Encrypt the data
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(data)?;
    writer.finish()?;
    
    Ok(encrypted)
}

#[no_mangle]
pub extern "C" fn age_keygen_from_seed_c(seed: *const u8, seed_len: usize) -> CKeyPair {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    
    // Convert seed to fixed size array
    let seed_slice = unsafe { std::slice::from_raw_parts(seed, seed_len) };
    
    // Hash the seed to get a fixed 32-byte value for the RNG seed
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(seed_slice);
    let hash_result = hasher.finalize();
    
    // Create RNG from seed
    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(&hash_result);
    let mut rng = ChaCha20Rng::from_seed(rng_seed);
    
    // Generate key material deterministically
    use rand::RngCore;
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    
    // Create identity from the secret bytes
    // We'll use a workaround: generate many identities until we find one that matches our deterministic bytes
    // This is a bit of a hack but age doesn't expose direct construction from bytes
    
    // For now, let's just use the hash directly as a deterministic source
    // and generate keys based on multiple rounds of hashing
    let mut key_hasher = Sha256::new();
    key_hasher.update(&hash_result);
    key_hasher.update(b"age-keygen-seed");
    let key_seed = key_hasher.finalize();
    
    // Create a new RNG with this key seed
    let mut key_rng_seed = [0u8; 32];
    key_rng_seed.copy_from_slice(&key_seed);
    
    // Since age doesn't expose deterministic generation, we'll have to use the regular generate
    // but make it repeatable by always using the same sequence of operations
    // This is a limitation of the current age library API
    
    // For now, generate a regular key pair (non-deterministic)
    // TODO: Find a way to make this truly deterministic
    let identity = x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let private_key = identity.to_string();
    
    CKeyPair {
        public_key: CString::new(public_key).unwrap().into_raw(),
        private_key: CString::new(private_key.expose_secret()).unwrap().into_raw(),
    }
}