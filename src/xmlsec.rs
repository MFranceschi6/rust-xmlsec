//!
//! Central XmlSec1 Context
//!
use crate::bindings;

use crate::lazy_static;

use std::ptr::null;
use std::sync::Mutex;


lazy_static! {
    static ref XMLSEC: Mutex<Option<XmlSecContext>> = Mutex::new(None);
}


pub fn guarantee_xmlsec_init()
{
    let mut inner = XMLSEC.lock()
        .expect("Unable to lock global xmlsec initalization wrapper");

    if inner.is_none() {
        *inner = Some(XmlSecContext::new());
    }
}


/// XmlSec Global Context
///
/// This object initializes the underlying xmlsec global state and cleans it
/// up once gone out of scope. It is checked by all objects in the library that
/// require the context to be initialized. See [`globals`][globals].
///
/// [globals]: globals
struct XmlSecContext {}


impl XmlSecContext
{
    /// Runs xmlsec initialization and returns instance of itself.
    pub fn new() -> Self
    {
        init_xmlsec();
        init_crypto_app();
        init_crypto();

        Self {}
    }
}


impl Drop for XmlSecContext
{
    fn drop(&mut self)
    {
        cleanup_crypto();
        cleanup_crypto_app();
        cleanup_xmlsec();
    }
}


/// Init xmlsec library
fn init_xmlsec()
{
    let rc = unsafe { bindings::xmlSecInit() };

    if rc < 0 {
        panic!("XmlSec failed initialization");
    }
}


/// Load default crypto engine if we are supporting dynamic loading for
/// xmlsec-crypto libraries. Use the crypto library name ("openssl",
/// "nss", etc.) to load corresponding xmlsec-crypto library.
fn init_crypto_app()
{
    // if bindings::XMLSEC_CRYPTO_DYNAMIC_LOADING
    // {
    //     let rc = unsafe { bindings::xmlSecCryptoDLLoadLibrary(0) };

    //     if rc < 0 {
    //         panic!("XmlSec failed while loading default crypto backend. \
    //                 Make sure that you have it installed and check shread libraries path");
    //     }
    // }
    #[cfg(feature = "dynamic")]
    let rc = {   
        let rc = unsafe { bindings::xmlSecCryptoDLLoadLibrary(null()) };
        if rc < 0 {
            panic!("XmlSec failed while loading default crypto backend. \
                    Make sure that you have it installed and check shread libraries path");
        }
        unsafe { bindings::xmlSecCryptoAppInit(null()) }
    };
    #[cfg(feature = "nss")]
    let rc = unsafe { bindings::xmlSecNssAppInit(null()) };
    #[cfg(feature = "gnutls")]
    let rc = unsafe { bindings::xmlSecGnuTLSAppInit(null()) };
    #[cfg(feature = "openssl")]
    let rc = unsafe { bindings::xmlSecOpenSSLAppInit(null()) };
    

    if rc < 0 {
        panic!("XmlSec failed to init crypto backend")
    }
}


/// Init xmlsec-crypto library
fn init_crypto()
{
    #[cfg(feature = "dynamic")]
    let rc = unsafe { bindings::xmlSecCryptoInit() };
    #[cfg(feature = "nss")]
    let rc = unsafe { bindings::xmlSecNssInit() };
    #[cfg(feature = "gnutls")]
    let rc = unsafe { bindings::xmlSecGnuTLSInit() };
    #[cfg(feature = "openssl")]
    let rc = unsafe { bindings::xmlSecOpenSSLInit() };

    if rc < 0 {
        panic!("XmlSec failed while loading default crypto backend. \
               Make sure that you have it installed and check shread libraries path");
    }
}


/// Shutdown xmlsec-crypto library
fn cleanup_crypto()
{
    #[cfg(feature = "dynamic")]
    unsafe { bindings::xmlSecCryptoShutdown() };
    #[cfg(feature = "nss")]
    unsafe { bindings::xmlSecNssShutdown() };
    #[cfg(feature = "gnutls")]
    unsafe { bindings::xmlSecGnuTLSShutdown() };
    #[cfg(feature = "openssl")]
    unsafe { bindings::xmlSecOpenSSLShutdown() };
}


/// Shutdown crypto library
fn cleanup_crypto_app()
{
    #[cfg(feature = "dynamic")]
    unsafe { bindings::xmlSecCryptoAppShutdown() };
    #[cfg(feature = "nss")]
    unsafe { bindings::xmlSecNssAppShutdown() };
    #[cfg(feature = "gnutls")]
    unsafe { bindings::xmlSecGnuTLSAppShutdown() };
    #[cfg(feature = "openssl")]
    unsafe { bindings::xmlSecOpenSSLAppShutdown() };
}


/// Shutdown xmlsec library
fn cleanup_xmlsec()
{
    unsafe { bindings::xmlSecShutdown() };
}
