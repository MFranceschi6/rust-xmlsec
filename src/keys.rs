//!
//! Wrapper for XmlSec Key and Certificate management Context
//!
use crate::bindings;

use crate::XmlSecError;
use crate::XmlSecResult;

use std::ptr::null;
use std::ptr::null_mut;

use std::os::raw::c_char;
use std::os::raw::c_uchar;

use std::ffi::CStr;
use std::ffi::CString;


/// x509 key format.
#[allow(missing_docs)]
#[repr(u32)]
pub enum XmlSecKeyFormat
{
    Unknown  = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatUnknown,
    Binary   = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatBinary,
    Pem      = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
    Der      = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatDer,
    Pkcs8Pem = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPkcs8Pem,
    Pkcs8Der = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPkcs8Der,
    Pkcs12   = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPkcs12,
    CertPem  = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatCertPem,
    CertDer  = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatCertDer,
}


/// Key with which we sign/verify signatures or encrypt data. Used by [`XmlSecSignatureContext`][sigctx].
///
/// [sigctx]: struct.XmlSecSignatureContext.html
#[derive(Debug)]
pub struct XmlSecKey(*mut bindings::xmlSecKey);

#[cfg(feature = "dynamic")]
fn load_key_from_path(cpath: *const c_char, format: XmlSecKeyFormat, cpassword: *const i8) -> bindings::xmlSecKeyPtr {
    unsafe { bindings::xmlSecCryptoAppKeyLoad(
        cpath,
        format as u32,
        cpassword,
        null_mut(),
        null_mut()
    ) }
}

#[cfg(feature = "nss")]
fn load_key_from_path(cpath: *const c_char, format: XmlSecKeyFormat, cpassword: *const i8) -> bindings::xmlSecKeyPtr {
    unsafe { bindings::xmlSecNssAppKeyLoad(
        cpath,
        format as u32,
        cpassword,
        null_mut(),
        null_mut()
    ) }
}

#[cfg(feature = "gnutls")]
fn load_key_from_path(cpath: *const c_char, format: XmlSecKeyFormat, cpassword: *const i8) -> bindings::xmlSecKeyPtr {
    unsafe { bindings::xmlSecGnuTLSAppKeyLoad(
        cpath,
        format as u32,
        cpassword,
        null_mut(),
        null_mut()
    ) }
}

#[cfg(feature = "openssl")]
fn load_key_from_path(cpath: *const c_char, format: XmlSecKeyFormat, cpassword: *const i8) -> bindings::xmlSecKeyPtr {
    unsafe { bindings::xmlSecGnuTLSAppKeyLoad(
        cpath,
        format as u32,
        cpassword,
        null_mut(),
        null_mut()
    ) }
}


#[cfg(feature = "dynamic")]
fn load_key_from_memory(buffer: &[u8], format: XmlSecKeyFormat, cpassword: *const i8) -> bindings::xmlSecKeyPtr {
    unsafe { bindings::xmlSecCryptoAppKeyLoadMemory(
        buffer.as_ptr(),
        buffer.len() as u32,
        format as u32,
        cpassword,
        null_mut(),
        null_mut()) }
}

#[cfg(feature = "nss")]
fn load_key_from_memory(buffer: &[u8], format: XmlSecKeyFormat, cpassword: *const i8) -> bindings::xmlSecKeyPtr {
    unsafe { bindings::xmlSecNssAppKeyLoadMemory(
        buffer.as_ptr(),
        buffer.len() as u32,
        format as u32,
        cpassword,
        null_mut(),
        null_mut()) }
}

#[cfg(feature = "gnutls")]
fn load_key_from_memory(buffer: &[u8], format: XmlSecKeyFormat, cpassword: *const i8) -> bindings::xmlSecKeyPtr {
    unsafe { bindings::xmlSecGnuTLSAppKeyLoadMemory(
        buffer.as_ptr(),
        buffer.len() as u32,
        format as u32,
        cpassword,
        null_mut(),
        null_mut()) }
}

#[cfg(feature = "openssl")]
fn load_key_from_memory(buffer: &[u8], format: XmlSecKeyFormat, cpassword: *const i8) -> bindings::xmlSecKeyPtr {
    unsafe { bindings::xmlSecOpenSSLAppKeyLoadMemory(
        buffer.as_ptr(),
        buffer.len() as u32,
        format as u32,
        cpassword,
        null_mut(),
        null_mut()) }
}

#[cfg(feature = "dynamic")]
fn load_cert_from_path(key: bindings::xmlSecKeyPtr, cpath: *const c_char, format: XmlSecKeyFormat) -> i32 {
    unsafe { bindings::xmlSecCryptoAppKeyCertLoad(key, cpath, format as u32) }
}

#[cfg(feature = "nss")]
fn load_cert_from_path(key: bindings::xmlSecKeyPtr, cpath: *const c_char, format: XmlSecKeyFormat) -> i32 {
    unsafe { bindings::xmlSecNssAppKeyCertLoad(key, cpath, format as u32) }
}

#[cfg(feature = "gnutls")]
fn load_cert_from_path(key: bindings::xmlSecKeyPtr, cpath: *const c_char, format: XmlSecKeyFormat) -> i32 {
    unsafe { bindings::xmlSecGnuTLSAppKeyCertLoad(key, cpath, format as u32) }
}

#[cfg(feature = "openssl")]
fn load_cert_from_path(key: bindings::xmlSecKeyPtr, cpath: *const c_char, format: XmlSecKeyFormat) -> i32 {
    unsafe { bindings::xmlSecOpenSSLAppKeyCertLoad(key, cpath, format as u32) }
}

#[cfg(feature = "dynamic")]
fn load_cert_from_memory(key: bindings::xmlSecKeyPtr, buffer: &[u8], format: XmlSecKeyFormat) -> i32 {
    unsafe { bindings::xmlSecCryptoAppKeyCertLoadMemory(key, buffer.as_ptr(), buffer.len() as u32, format as u32) }
}

#[cfg(feature = "nss")]
fn load_cert_from_memory(key: bindings::xmlSecKeyPtr, buffer: &[u8], format: XmlSecKeyFormat) -> i32 {
    unsafe { bindings::xmlSecNssAppKeyCertLoadMemory(key, buffer.as_ptr(), buffer.len() as u32, format as u32) }
}

#[cfg(feature = "gnutls")]
fn load_cert_from_memory(key: bindings::xmlSecKeyPtr, buffer: &[u8], format: XmlSecKeyFormat) -> i32 {
    unsafe { bindings::xmlSecGnuTLSAppKeyCertLoadMemory(key, buffer.as_ptr(), buffer.len() as u32, format as u32) }
}

#[cfg(feature = "openssl")]
fn load_cert_from_memory(key: bindings::xmlSecKeyPtr, buffer: &[u8], format: XmlSecKeyFormat) -> i32 {
    unsafe { bindings::xmlSecOpenSSLAppKeyCertLoadMemory(key, buffer.as_ptr(), buffer.len() as u32, format as u32) }
}

impl XmlSecKey
{
    /// Load key from file by specifying path, its format in the file, and optionally the password required to
    /// decrypt/unlock.
    pub fn from_file(path: &str, format: XmlSecKeyFormat, password: Option<&str>) -> XmlSecResult<Self>
    {
        // TODO deprecate internals for Rust read-from-file and then loading with `from_memory`

        crate::xmlsec::guarantee_xmlsec_init();

        // TODO proper sanitization/error handling of input
        let cpath   = CString::new(path).unwrap();
        let cpasswd = password.map(|p| CString::new(p).unwrap());

        let cpasswd_ptr = cpasswd.map(|cstr| cstr.as_ptr())
            .unwrap_or(null());

        // Load key from file
        // #[cfg(feature = "dynamic")]
        let key = load_key_from_path(cpath.as_ptr(), format, cpasswd_ptr);

        if key.is_null() {
            return Err(XmlSecError::KeyLoadError);
        }

        Ok(Self {0: key})
    }

    /// Load key from buffer in memory, specifying format and optionally the password required to decrypt/unlock.
    pub fn from_memory(buffer: &[u8], format: XmlSecKeyFormat, password: Option<&str>) -> XmlSecResult<Self>
    {
        crate::xmlsec::guarantee_xmlsec_init();

        // TODO proper sanitization/error handling of input
        let cpasswd = password.map(|p| CString::new(p).unwrap());

        let cpasswd_ptr = cpasswd.map(|cstr| cstr.as_ptr())
            .unwrap_or(null());

        // Load key from buffer
        let key = load_key_from_memory(buffer, format, cpasswd_ptr);

        if key.is_null() {
            return Err(XmlSecError::KeyLoadError);
        }

        Ok(Self {0: key})
    }

    /// Load certificate into key by specifying path and ints format.
    pub fn load_cert_from_file(&self, path: &str, format: XmlSecKeyFormat) -> XmlSecResult<()>
    {
        let cpath = CString::new(path).unwrap();

        let rc = load_cert_from_path(self.0, cpath.as_ptr(), format);

        if rc != 0 {
            return Err(XmlSecError::CertLoadError);
        }

        Ok(())
    }

    /// Load certificate into key by specifying buffer to its contents.
    pub fn load_cert_from_memory(&self, buff: &[u8], format: XmlSecKeyFormat) -> XmlSecResult<()>
    {
        let rc = load_cert_from_memory(self.0, buff, format);

        if rc != 0 {
            return Err(XmlSecError::CertLoadError);
        }

        Ok(())
    }

    /// Set name of the key.
    pub fn set_name(&mut self, name: &str)
    {
        let cname = CString::new(name).unwrap();

        let rc = unsafe { bindings::xmlSecKeySetName(
            self.0,
            cname.as_ptr() as *const c_uchar
        ) };

        if rc < 0 {
            panic!("Failed to set name for key");   // TODO proper error handling
        }
    }

    /// Get the name currently set for the key.
    pub fn get_name(&self) -> &str
    {
        let raw   = unsafe { bindings::xmlSecKeyGetName(self.0) };
        let cname = unsafe { CStr::from_ptr(raw as *const c_char) };

        cname.to_str().unwrap()  // TODO proper error handling
    }

    /// # Safety
    ///
    /// Create from raw pointer to an underlying xmlsec key structure. Henceforth its lifetime will be managed by this
    /// object.
    pub unsafe fn from_ptr(ptr: *mut bindings::xmlSecKey) -> Self
    {
        Self {0: ptr}
    }

    /// # Safety
    ///
    /// Returns a raw pointer to the underlying xmlsec structure.
    pub unsafe fn as_ptr(&self) -> *mut bindings::xmlSecKey
    {
        self.0
    }

    /// # Safety
    ///
    /// Leak the internal resource. This is needed by [`XmlSecSignatureContext`][sigctx], since xmlsec takes over the
    /// lifetime management of the underlying resource when setting it as the active key for signature signing or
    /// verification.
    ///
    /// [sigctx]: struct.XmlSecSignatureContext.html
    pub unsafe fn leak(key: Self) -> *mut bindings::xmlSecKey
    {
        let ptr = key.0;

        std::mem::forget(key);

        ptr
    }
}


impl PartialEq for XmlSecKey
{
    fn eq(&self, other: &Self) -> bool
    {
        self.0 == other.0  // compare pointer addresses
    }
}


impl Eq for XmlSecKey {}


impl Clone for XmlSecKey
{
    fn clone(&self) -> Self
    {
        let new = unsafe { bindings::xmlSecKeyDuplicate(self.0) };

        Self {0: new}
    }
}


impl Drop for XmlSecKey
{
    fn drop(&mut self)
    {
        unsafe { bindings::xmlSecKeyDestroy(self.0) };
    }
}
