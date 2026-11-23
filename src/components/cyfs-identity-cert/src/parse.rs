use std::sync::Mutex;

use openssl::base64::decode_block;
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::pkcs12::{ParsedPkcs12_2, Pkcs12};
use openssl::pkey::{PKey, Private};
use openssl::provider::Provider;
use openssl::x509::X509;

use crate::inspect::{CertificateInput, CheckReason};
use crate::x509::same_certificate;

/// Everything found in the uploaded files, duplicates removed.
#[derive(Default)]
pub(crate) struct ParsedInput {
    pub certificates: Vec<X509>,
    pub keys: Vec<PKey<Private>>,
    /// The first reason the input is not usable as given.
    pub problem: Option<(CheckReason, Option<String>)>,
}

impl ParsedInput {
    fn add_certificate(&mut self, cert: X509) {
        if !self
            .certificates
            .iter()
            .any(|known| same_certificate(known, &cert))
        {
            self.certificates.push(cert);
        }
    }

    fn add_key(&mut self, key: PKey<Private>) {
        let key = with_public_part(&key).unwrap_or(key);
        if !self.keys.iter().any(|known| known.public_eq(&key)) {
            self.keys.push(key);
        }
    }

    fn set_problem(&mut self, reason: CheckReason, detail: Option<String>) {
        if self.problem.is_none() {
            self.problem = Some((reason, detail));
        }
    }
}

pub(crate) fn parse_input(input: &CertificateInput) -> ParsedInput {
    let mut parsed = ParsedInput::default();
    let files = input
        .files
        .iter()
        .filter(|file| !file.iter().all(u8::is_ascii_whitespace))
        .collect::<Vec<_>>();
    if files.is_empty() {
        parsed.set_problem(CheckReason::Empty, None);
        return parsed;
    }
    for (index, file) in files.iter().enumerate() {
        if let Err(reason) = parse_file(file, input.pfx_password.as_deref(), &mut parsed) {
            parsed.set_problem(reason, Some(format!("file {}", index + 1)));
        }
    }
    if parsed.keys.is_empty() {
        parsed.set_problem(CheckReason::KeyMissing, None);
    } else if parsed.certificates.is_empty() {
        parsed.set_problem(CheckReason::Unparsable, None);
    }
    parsed
}

fn parse_file(
    data: &[u8],
    pfx_password: Option<&str>,
    parsed: &mut ParsedInput,
) -> Result<(), CheckReason> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN ")
    {
        return parse_pem(text, parsed);
    }
    if let Ok(cert) = X509::from_der(data) {
        parsed.add_certificate(cert);
        return Ok(());
    }
    if let Ok(pfx) = Pkcs12::from_der(data) {
        let contents = open_pfx(&pfx, pfx_password.unwrap_or(""))?;
        if let Some(cert) = contents.cert {
            parsed.add_certificate(cert);
        }
        for cert in contents.ca.into_iter().flatten() {
            parsed.add_certificate(cert);
        }
        if let Some(key) = contents.pkey {
            parsed.add_key(key);
        }
        return Ok(());
    }
    let _ = ErrorStack::get();
    parsed.add_key(PKey::private_key_from_der(data).map_err(|_| CheckReason::Unparsable)?);
    Ok(())
}

/// Decodes the blocks itself: text pasted from a mail often lost its line
/// breaks, and OpenSSL's PEM reader would ask the terminal for the passphrase of
/// an encrypted key.
fn parse_pem(text: &str, parsed: &mut ParsedInput) -> Result<(), CheckReason> {
    const BEGIN: &str = "-----BEGIN ";
    const DASHES: &str = "-----";

    let mut found = false;
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        rest = &rest[start + BEGIN.len()..];
        let label_end = rest.find(DASHES).ok_or(CheckReason::Unparsable)?;
        let label = &rest[..label_end];
        rest = &rest[label_end + DASHES.len()..];
        let end_marker = format!("-----END {label}-----");
        let body_end = rest.find(&end_marker).ok_or(CheckReason::Unparsable)?;
        let body = &rest[..body_end];
        rest = &rest[body_end + end_marker.len()..];

        match label {
            "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => {
                let der = decode_body(body)?;
                // A trusted certificate carries OpenSSL's own data behind the certificate.
                parsed.add_certificate(X509::from_der(&der).map_err(|_| CheckReason::Unparsable)?);
                found = true;
            }
            "ENCRYPTED PRIVATE KEY" => return Err(CheckReason::KeyEncrypted),
            "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                if body.contains("ENCRYPTED") {
                    return Err(CheckReason::KeyEncrypted);
                }
                let der = decode_body(body)?;
                parsed.add_key(
                    PKey::private_key_from_der(&der).map_err(|_| CheckReason::Unparsable)?,
                );
                found = true;
            }
            _ => {}
        }
    }
    if found {
        Ok(())
    } else {
        Err(CheckReason::Unparsable)
    }
}

/// An EC key file may leave out the public point or hold it compressed; the
/// gateway's TLS library needs it in full.
fn with_public_part(key: &PKey<Private>) -> Option<PKey<Private>> {
    let key = key.ec_key().ok()?;
    let group = EcGroup::from_curve_name(key.group().curve_name()?).ok()?;
    let key = EcKey::from_private_components(&group, key.private_key(), key.public_key()).ok()?;
    PKey::from_ec_key(key).ok()
}

fn decode_body(body: &str) -> Result<Vec<u8>, CheckReason> {
    let compact = body.split_whitespace().collect::<String>();
    decode_block(&compact).map_err(|_| CheckReason::Unparsable)
}

/// PFX files from older tools use RC2, which OpenSSL 3 only has in its legacy
/// provider. It is loaded for the second try only.
fn open_pfx(pfx: &Pkcs12, password: &str) -> Result<ParsedPkcs12_2, CheckReason> {
    static LEGACY: Mutex<()> = Mutex::new(());

    if password.contains('\0') {
        return Err(CheckReason::PfxPasswordWrong);
    }
    match pfx.parse2(password) {
        Ok(contents) => return Ok(contents),
        Err(error) if is_password_error(&error) => return Err(CheckReason::PfxPasswordWrong),
        Err(_) => {}
    }
    let _guard = LEGACY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _legacy = Provider::try_load(None, "legacy", true).map_err(|error| {
        log::warn!("OpenSSL legacy provider is not available: {}", error);
        CheckReason::Unparsable
    })?;
    pfx.parse2(password).map_err(|error| {
        if is_password_error(&error) {
            CheckReason::PfxPasswordWrong
        } else {
            CheckReason::Unparsable
        }
    })
}

fn is_password_error(error: &ErrorStack) -> bool {
    error.errors().iter().any(|error| {
        matches!(
            error.reason(),
            Some("mac verify failure" | "bad decrypt" | "pkcs12 cipherfinal error")
        )
    })
}
