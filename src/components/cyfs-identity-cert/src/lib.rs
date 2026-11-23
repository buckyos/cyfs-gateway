//! Checking a server certificate and installing it at its identity path,
//! shared by cyfs-acme (issued) and node_daemon (uploaded).

mod inspect;
mod install;
mod parse;
mod x509;

#[cfg(test)]
mod test_ca;

pub use inspect::*;
pub use install::*;
pub use x509::{CertificateSummary, TrustRoots, certificate_summary};
