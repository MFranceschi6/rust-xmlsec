//!
//! Crypto Backend Wrappings
//!

#[cfg(feature = "dynamic")]
mod dynamic;
#[cfg(feature = "dynamic")]
pub use dynamic::XmlSecSignatureMethod;

#[cfg(feature = "nss")]
mod nss;
#[cfg(feature = "nss")]
pub use nss::XmlSecSignatureMethod;

#[cfg(feature = "gcrypt")]
mod gcrypt;
#[cfg(feature = "gcrypt")]
pub use gcrypt::XmlSecSignatureMethod;

#[cfg(feature = "gnutls")]
mod gnutls;
#[cfg(feature = "gnutls")]
pub use gnutls::XmlSecSignatureMethod;

#[cfg(feature = "openssl")]
mod openssl;
#[cfg(feature = "openssl")]
pub use openssl::XmlSecSignatureMethod;
