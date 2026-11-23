use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use name_client::{
    IdentityMaterial, IdentityRoots, IdentityUsage, X509_METADATA_SCHEMA, X509CertificateMetadata,
    X509MatchMetadata, X509Metadata, X509PathMetadata, X509Paths, X509SanMetadata,
};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::inspect::PreparedCertificate;
use crate::x509::{
    asn1_time_to_utc, cert_dns_names, cert_fingerprint_sha256, cert_uri_names, dns_san_matches,
    public_key_fingerprint, summarize, x509_name_to_string,
};

/// `renewal.manager` in `server.meta.json`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CertManager {
    Acme,
    /// Uploaded by the user: never renewed or replaced by the system.
    Manual,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InstalledCertificate {
    pub host: String,
    pub manager: Option<CertManager>,
    pub not_before: u64,
    pub not_after: u64,
    pub issuer: Option<String>,
    pub dns_names: Vec<String>,
    pub fingerprint: String,
}

/// Installs the uploaded certificates with `renewal.manager = manual`. Every
/// file is staged before the first rename, so a failure leaves no half set.
pub fn install_manual_certificates(
    roots: &IdentityRoots,
    certificates: &[PreparedCertificate],
) -> Result<()> {
    let installs = certificates
        .iter()
        .map(|certificate| {
            let renewal = serde_json::json!({
                "manager": CertManager::Manual,
                "last_renewed_at": chrono::Utc::now().to_rfc3339(),
            });
            prepare_identity_certificate(
                roots,
                &certificate.host,
                &certificate.host,
                &certificate.fullchain_pem,
                &certificate.key_pem,
                renewal,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    install_prepared(&installs)
}

/// Installs a certificate issued through ACME (`renewal.manager = acme`).
pub fn install_acme_certificate(
    roots: &IdentityRoots,
    identity: &str,
    domain: &str,
    work_dir: &Path,
    fullchain_pem: &[u8],
    key_pem: &[u8],
    renew_before_expiry: chrono::Duration,
) -> Result<()> {
    std::fs::create_dir_all(work_dir).map_err(|e| {
        anyhow::anyhow!("create acme work dir {} failed: {}", work_dir.display(), e)
    })?;
    let renewal = serde_json::json!({
        "manager": CertManager::Acme,
        "renew_before": format!("PT{}S", renew_before_expiry.num_seconds()),
        "last_renewed_at": chrono::Utc::now().to_rfc3339(),
        "state_ref": work_dir.to_string_lossy()
    });
    let prepared =
        prepare_identity_certificate(roots, identity, domain, fullchain_pem, key_pem, renewal)?;
    install_prepared(&[prepared])
}

/// The certificate installed for exactly `host` (no wildcard fallback).
pub fn installed_certificate(
    roots: &IdentityRoots,
    host: &str,
) -> Result<Option<InstalledCertificate>> {
    let paths = server_paths(roots, host)?;
    let fullchain = match std::fs::read(&paths.fullchain) {
        Ok(fullchain) => fullchain,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "read {} failed: {}",
                paths.fullchain.display(),
                e
            ));
        }
    };
    let leaf = X509::stack_from_pem(&fullchain)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("{} has no certificate", paths.fullchain.display()))?;
    let summary = summarize(&leaf)?;
    Ok(Some(InstalledCertificate {
        host: host.to_string(),
        manager: certificate_manager(roots, host),
        not_before: summary.not_before,
        not_after: summary.not_after,
        issuer: Some(summary.issuer),
        dns_names: summary.dns_names,
        fingerprint: summary.fingerprint,
    }))
}

/// `renewal.manager` of exactly `identity` (no wildcard fallback).
pub fn certificate_manager(roots: &IdentityRoots, identity: &str) -> Option<CertManager> {
    manager_of(&read_renewal(
        &server_paths(roots, identity).ok()?.metadata,
    )?)
}

/// `renewal.manager` of the certificate a TLS listener finds for `identity`, which
/// may be the wildcard certificate of its parent name.
pub fn served_certificate_manager(roots: &IdentityRoots, identity: &str) -> Option<CertManager> {
    let found = roots
        .find_public_file(identity, IdentityUsage::Server, IdentityMaterial::Fullchain)
        .ok()?;
    manager_of(&read_renewal(
        &found.path.with_file_name("server.meta.json"),
    )?)
}

/// The certificate is usable but ACME has to replace it now (see [`clear_manual_mark`]).
pub fn reissue_requested(roots: &IdentityRoots, identity: &str) -> bool {
    server_paths(roots, identity)
        .ok()
        .and_then(|paths| read_renewal(&paths.metadata)?.get("reissue")?.as_bool())
        .unwrap_or(false)
}

/// Back to automatic issuing: drops the manual mark so ACME takes over. The
/// uploaded certificate stays in use until ACME has installed its own.
pub fn clear_manual_mark(roots: &IdentityRoots, host: &str) -> Result<()> {
    if certificate_manager(roots, host) != Some(CertManager::Manual) {
        return Ok(());
    }
    let path = server_paths(roots, host)?.metadata;
    let mut metadata: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    metadata["renewal"] = serde_json::json!({
        "manager": CertManager::Acme,
        "reissue": true,
    });
    let staged = stage_file(&path, &serde_json::to_vec_pretty(&metadata)?, false)?;
    commit_staged_files(&[staged])
}

pub fn validate_identity_certificate(
    roots: &IdentityRoots,
    identity: &str,
    domain: &str,
    cert: &X509,
    private_key: &PKey<Private>,
) -> Result<()> {
    let now = chrono::Utc::now();
    let not_before = asn1_time_to_utc(cert.not_before())?;
    let not_after = asn1_time_to_utc(cert.not_after())?;
    if now < not_before {
        return Err(anyhow::anyhow!(
            "certificate is not valid yet: {}",
            not_before
        ));
    }
    if now >= not_after {
        return Err(anyhow::anyhow!("certificate is expired: {}", not_after));
    }

    let cert_public_key = cert.public_key()?;
    if !cert_public_key.public_eq(private_key) {
        return Err(anyhow::anyhow!(
            "certificate public key does not match private key"
        ));
    }

    let dns_names = cert_dns_names(cert);
    let expected_dns = roots
        .did_web_dns_san(identity)
        .unwrap_or_else(|_| domain.to_string());
    if !dns_names
        .iter()
        .any(|dns_name| dns_san_matches(dns_name, &expected_dns))
    {
        return Err(anyhow::anyhow!(
            "certificate DNS SAN does not cover identity host: expected {}, got {:?}",
            expected_dns,
            dns_names
        ));
    }

    Ok(())
}

struct PreparedIdentityCertificate {
    paths: X509Paths,
    cert_pem: Vec<u8>,
    chain_pem: Vec<u8>,
    fullchain_pem: Vec<u8>,
    key_pem: Vec<u8>,
    metadata_json: Vec<u8>,
}

struct StagedFile {
    tmp_path: PathBuf,
    final_path: PathBuf,
}

fn server_paths(roots: &IdentityRoots, identity: &str) -> Result<X509Paths> {
    roots
        .x509_paths(identity, IdentityUsage::Server)
        .map_err(|e| anyhow::anyhow!("calculate identity x509 paths failed: {}", e))
}

fn read_renewal(metadata: &Path) -> Option<Value> {
    let content = std::fs::read(metadata).ok()?;
    match serde_json::from_slice::<Value>(&content) {
        Ok(metadata) => metadata.get("renewal").cloned(),
        Err(e) => {
            log::warn!(
                "parse certificate metadata {} failed: {}",
                metadata.display(),
                e
            );
            None
        }
    }
}

fn manager_of(renewal: &Value) -> Option<CertManager> {
    serde_json::from_value(renewal.get("manager")?.clone()).ok()
}

fn prepare_identity_certificate(
    roots: &IdentityRoots,
    identity: &str,
    domain: &str,
    fullchain_pem: &[u8],
    key_pem: &[u8],
    renewal: Value,
) -> Result<PreparedIdentityCertificate> {
    let certificates = X509::stack_from_pem(fullchain_pem)
        .map_err(|e| anyhow::anyhow!("parse certificate chain failed: {}", e))?;
    let leaf = certificates
        .first()
        .ok_or_else(|| anyhow::anyhow!("certificate chain is empty"))?;
    let private_key = PKey::private_key_from_pem(key_pem)
        .map_err(|e| anyhow::anyhow!("parse private key failed: {}", e))?;
    validate_identity_certificate(roots, identity, domain, leaf, &private_key)?;

    let cert_pem = leaf.to_pem()?;
    let mut chain_pem = Vec::new();
    for cert in certificates.iter().skip(1) {
        chain_pem.extend(cert.to_pem()?);
    }
    let mut normalized_fullchain = cert_pem.clone();
    normalized_fullchain.extend(chain_pem.iter());

    let metadata = build_x509_metadata(roots, identity, domain, leaf, renewal)?;

    Ok(PreparedIdentityCertificate {
        paths: server_paths(roots, identity)?,
        cert_pem,
        chain_pem,
        fullchain_pem: normalized_fullchain,
        key_pem: key_pem.to_vec(),
        metadata_json: serde_json::to_vec_pretty(&metadata)?,
    })
}

fn build_x509_metadata(
    roots: &IdentityRoots,
    identity: &str,
    domain: &str,
    cert: &X509,
    renewal: Value,
) -> Result<X509Metadata> {
    let raw_host_uri = roots
        .raw_host_uri(identity)
        .map_err(|e| anyhow::anyhow!("calculate raw host uri failed: {}", e))?;
    let dir_name = roots
        .dir_name(identity)
        .map_err(|e| anyhow::anyhow!("calculate identity dir name failed: {}", e))?;
    let did = canonical_did(identity, &raw_host_uri);
    let not_before = asn1_time_to_utc(cert.not_before())?.to_rfc3339();
    let not_after = asn1_time_to_utc(cert.not_after())?.to_rfc3339();
    let serial_number = cert
        .serial_number()
        .to_bn()
        .and_then(|bn| bn.to_hex_str())
        .map(|s| s.to_string())
        .ok();
    let match_info = if domain.starts_with("*.") {
        X509MatchMetadata::Wildcard {
            host_pattern: domain.to_string(),
        }
    } else {
        X509MatchMetadata::Exact {
            host: domain.to_string(),
        }
    };
    let generation = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
        cert_fingerprint_sha256(cert)?
    );

    Ok(X509Metadata {
        schema: Some(X509_METADATA_SCHEMA.to_string()),
        raw_host_uri,
        dir_name,
        usage: IdentityUsage::Server,
        match_info: Some(match_info),
        certificate: Some(X509CertificateMetadata {
            serial_number,
            issuer: Some(x509_name_to_string(cert.issuer_name())),
            subject: Some(x509_name_to_string(cert.subject_name())),
            not_before: Some(not_before),
            not_after,
            fingerprint_sha256: Some(cert_fingerprint_sha256(cert)?),
            public_key_fingerprint: Some(public_key_fingerprint(cert)?),
        }),
        san: Some(X509SanMetadata {
            dns: cert_dns_names(cert),
            uri: cert_uri_names(cert),
        }),
        paths: Some(X509PathMetadata {
            cert: Some("server.cert.pem".to_string()),
            chain: Some("server.chain.pem".to_string()),
            fullchain: Some("server.fullchain.pem".to_string()),
            ca: None,
            key_ref: None,
        }),
        did_binding: roots
            .did_web_document_url(identity)
            .ok()
            .map(|did_document_url| {
                serde_json::json!({
                    "type": "did-web-domain",
                    "did": did,
                    "web_origin": format!("https://{}", domain.trim_start_matches("*.")),
                    "did_document_url": did_document_url
                })
            }),
        did,
        renewal: Some(renewal),
        updated_at: Some(chrono::Utc::now().to_rfc3339()),
        generation: Some(generation),
    })
}

fn canonical_did(identity: &str, raw_host_uri: &str) -> String {
    if identity.trim().starts_with("did:") {
        identity.trim().to_string()
    } else {
        let host_uri = raw_host_uri.replace('/', ":");
        format!("did:web:{host_uri}")
    }
}

fn install_prepared(installs: &[PreparedIdentityCertificate]) -> Result<()> {
    let mut staged = Vec::new();
    let stage_result = (|| -> Result<()> {
        for install in installs {
            let paths = &install.paths;
            staged.push(stage_file(&paths.cert, &install.cert_pem, false)?);
            staged.push(stage_file(&paths.chain, &install.chain_pem, false)?);
            staged.push(stage_file(&paths.fullchain, &install.fullchain_pem, false)?);
            staged.push(stage_file(&paths.metadata, &install.metadata_json, false)?);
            staged.push(stage_file(&paths.private_key, &install.key_pem, true)?);
        }
        Ok(())
    })();
    if let Err(err) = stage_result {
        cleanup_staged_files(&staged);
        return Err(err);
    }

    commit_staged_files(&staged)?;

    for install in installs {
        if let Some(keyref_path) = install.paths.keyref.as_deref() {
            remove_legacy_keyref(keyref_path)?;
        }
        sync_parent_dir(&install.paths.fullchain)?;
        sync_parent_dir(&install.paths.private_key)?;
    }
    Ok(())
}

fn stage_file(path: &Path, data: &[u8], private: bool) -> Result<StagedFile> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("identity file path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| anyhow::anyhow!("create identity dir {} failed: {}", parent.display(), e))?;

    let tmp_path = sibling_path(path, "tmp")?;
    let staged = StagedFile {
        tmp_path: tmp_path.clone(),
        final_path: path.to_path_buf(),
    };

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(&tmp_path).map_err(|e| {
        anyhow::anyhow!(
            "create temp identity file {} failed: {}",
            tmp_path.display(),
            e
        )
    })?;
    if let Err(e) = file.write_all(data).and_then(|()| file.sync_all()) {
        cleanup_staged_files(&[staged]);
        return Err(anyhow::anyhow!(
            "write temp identity file {} failed: {}",
            tmp_path.display(),
            e
        ));
    }
    Ok(staged)
}

fn sibling_path(path: &Path, suffix: &str) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("identity file path has no file name: {}", path.display()))?
        .to_string_lossy();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok(path.with_file_name(format!(".{file_name}.{unique}.{suffix}")))
}

fn cleanup_staged_files(staged: &[StagedFile]) {
    for staged_file in staged {
        let _ = std::fs::remove_file(&staged_file.tmp_path);
    }
}

/// Each file is replaced atomically. When one cannot be, the ones already
/// replaced get their former contents back.
fn commit_staged_files(staged: &[StagedFile]) -> Result<()> {
    let mut replaced: Vec<(&Path, Option<PathBuf>)> = Vec::new();
    for (index, staged_file) in staged.iter().enumerate() {
        match replace_file(staged_file) {
            Ok(backup) => replaced.push((&staged_file.final_path, backup)),
            Err(error) => {
                for (path, backup) in replaced.into_iter().rev() {
                    let restored = match &backup {
                        Some(backup) => std::fs::rename(backup, path),
                        None => std::fs::remove_file(path),
                    };
                    if let Err(e) = restored {
                        log::error!("restore identity file {} failed: {}", path.display(), e);
                    }
                }
                cleanup_staged_files(&staged[index..]);
                return Err(error);
            }
        }
    }
    for (_, backup) in replaced {
        if let Some(backup) = backup {
            let _ = std::fs::remove_file(backup);
        }
    }
    Ok(())
}

/// Returns where the former contents are kept, if there were any.
fn replace_file(staged: &StagedFile) -> Result<Option<PathBuf>> {
    let backup = if staged.final_path.exists() {
        let backup = sibling_path(&staged.final_path, "bak")?;
        std::fs::hard_link(&staged.final_path, &backup)
            .or_else(|_| std::fs::copy(&staged.final_path, &backup).map(|_| ()))
            .map_err(|e| {
                let _ = std::fs::remove_file(&backup);
                anyhow::anyhow!(
                    "keep former identity file {} failed: {}",
                    staged.final_path.display(),
                    e
                )
            })?;
        Some(backup)
    } else {
        None
    };
    if let Err(e) = std::fs::rename(&staged.tmp_path, &staged.final_path) {
        if let Some(backup) = backup {
            let _ = std::fs::remove_file(backup);
        }
        return Err(anyhow::anyhow!(
            "rename staged identity file {} to {} failed: {}",
            staged.tmp_path.display(),
            staged.final_path.display(),
            e
        ));
    }
    Ok(backup)
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dir = std::fs::File::open(parent)
            .map_err(|e| anyhow::anyhow!("open identity dir {} failed: {}", parent.display(), e))?;
        dir.sync_all()
            .map_err(|e| anyhow::anyhow!("sync identity dir {} failed: {}", parent.display(), e))?;
    }
    Ok(())
}

/// Windows cannot open a directory as a file.
#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

fn remove_legacy_keyref(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            log::info!("removed legacy identity keyref {}", path.display());
            sync_parent_dir(path)?;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "remove legacy identity keyref {} failed: {}",
                path.display(),
                e
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_ca::*;

    const DOMAIN: &str = "home.example.com";
    const WILDCARD: &str = "*.home.example.com";

    fn roots(temp: &Path) -> IdentityRoots {
        IdentityRoots::new(temp.join("identity"), temp.join("security"))
    }

    fn prepared(host: &str, issued: &Issued) -> PreparedCertificate {
        PreparedCertificate {
            host: host.to_string(),
            fullchain_pem: issued.pem(),
            key_pem: issued.key_pem(),
        }
    }

    fn both(issued: &Issued) -> Vec<PreparedCertificate> {
        vec![prepared(DOMAIN, issued), prepared(WILDCARD, issued)]
    }

    fn self_signed(days: i64) -> Issued {
        Spec {
            not_after: now() + days * DAY,
            ..Spec::leaf(&[DOMAIN, WILDCARD])
        }
        .self_signed()
    }

    fn files(dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                found.extend(files(&path));
            } else {
                found.push(path);
            }
        }
        found.sort();
        found
    }

    fn leftovers(temp: &Path) -> Vec<PathBuf> {
        files(temp)
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'))
            })
            .collect()
    }

    #[test]
    fn manual_certificate_is_installed_for_both_hosts() {
        let temp = tempfile::tempdir().unwrap();
        let roots = roots(temp.path());
        let issued = self_signed(90);
        install_manual_certificates(&roots, &both(&issued)).unwrap();

        for host in [DOMAIN, WILDCARD] {
            let installed = installed_certificate(&roots, host).unwrap().unwrap();
            assert_eq!(installed.host, host);
            assert_eq!(installed.manager, Some(CertManager::Manual));
            assert_eq!(
                installed.not_after,
                summarize(&issued.cert).unwrap().not_after
            );
            assert_eq!(installed.dns_names, vec![DOMAIN, WILDCARD]);
            let paths = server_paths(&roots, host).unwrap();
            assert_eq!(std::fs::read(&paths.private_key).unwrap(), issued.key_pem());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&paths.private_key)
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            let metadata: X509Metadata =
                serde_json::from_slice(&std::fs::read(&paths.metadata).unwrap()).unwrap();
            assert_eq!(metadata.renewal.unwrap()["manager"], "manual");
        }
        assert_eq!(
            server_paths(&roots, WILDCARD).unwrap().fullchain,
            temp.path()
                .join("identity/_.home.example.com/server.fullchain.pem")
        );
        assert!(leftovers(temp.path()).is_empty());
    }

    #[test]
    fn nothing_is_installed_when_one_certificate_does_not_fit() {
        let temp = tempfile::tempdir().unwrap();
        let roots = roots(temp.path());
        let good = self_signed(90);
        let other = Spec::leaf(&["other.example"]).self_signed();
        let expired = self_signed(-1);
        for bad in [&other, &expired] {
            assert!(
                install_manual_certificates(
                    &roots,
                    &[prepared(DOMAIN, &good), prepared(WILDCARD, bad)]
                )
                .is_err()
            );
        }
        let mut wrong_key = prepared(WILDCARD, &good);
        wrong_key.key_pem = other.key_pem();
        assert!(
            install_manual_certificates(&roots, &[prepared(DOMAIN, &good), wrong_key]).is_err()
        );
        assert!(installed_certificate(&roots, DOMAIN).unwrap().is_none());
        assert!(!temp.path().join("identity").exists());
    }

    #[test]
    fn a_failure_while_replacing_restores_the_former_set() {
        let temp = tempfile::tempdir().unwrap();
        let roots = roots(temp.path());
        let former = self_signed(90);
        install_manual_certificates(&roots, &[prepared(DOMAIN, &former)]).unwrap();
        // The last file of the second host cannot be replaced.
        let blocked = server_paths(&roots, WILDCARD).unwrap().private_key;
        std::fs::create_dir_all(blocked.join("in the way")).unwrap();
        let before = files(temp.path());

        assert!(install_manual_certificates(&roots, &both(&self_signed(60))).is_err());

        assert_eq!(files(temp.path()), before, "no new and no temporary files");
        let installed = installed_certificate(&roots, DOMAIN).unwrap().unwrap();
        assert_eq!(
            installed.fingerprint,
            summarize(&former.cert).unwrap().fingerprint
        );
        assert_eq!(
            std::fs::read(server_paths(&roots, DOMAIN).unwrap().private_key).unwrap(),
            former.key_pem()
        );
    }

    #[test]
    fn a_failure_while_staging_leaves_the_former_set() {
        let temp = tempfile::tempdir().unwrap();
        let roots = roots(temp.path());
        let former = self_signed(90);
        install_manual_certificates(&roots, &[prepared(DOMAIN, &former)]).unwrap();
        // A file where the wildcard's directory belongs.
        std::fs::write(temp.path().join("security/_.home.example.com"), "blocked").unwrap();
        let before = files(temp.path());

        assert!(install_manual_certificates(&roots, &both(&self_signed(60))).is_err());

        assert_eq!(files(temp.path()), before);
        assert_eq!(
            installed_certificate(&roots, DOMAIN)
                .unwrap()
                .unwrap()
                .fingerprint,
            summarize(&former.cert).unwrap().fingerprint
        );
    }

    #[test]
    fn clearing_the_mark_hands_the_certificate_to_acme() {
        let temp = tempfile::tempdir().unwrap();
        let roots = roots(temp.path());
        clear_manual_mark(&roots, DOMAIN).unwrap();
        install_manual_certificates(&roots, &both(&self_signed(90))).unwrap();
        assert!(!reissue_requested(&roots, DOMAIN));

        clear_manual_mark(&roots, DOMAIN).unwrap();

        assert_eq!(certificate_manager(&roots, DOMAIN), Some(CertManager::Acme));
        assert!(reissue_requested(&roots, DOMAIN));
        assert_eq!(
            certificate_manager(&roots, WILDCARD),
            Some(CertManager::Manual)
        );
        let metadata: X509Metadata = serde_json::from_slice(
            &std::fs::read(server_paths(&roots, DOMAIN).unwrap().metadata).unwrap(),
        )
        .unwrap();
        assert!(metadata.certificate.is_some());
        assert!(leftovers(temp.path()).is_empty());

        let issued = self_signed(80);
        install_acme_certificate(
            &roots,
            DOMAIN,
            DOMAIN,
            &temp.path().join("work"),
            &issued.pem(),
            &issued.key_pem(),
            chrono::Duration::days(7),
        )
        .unwrap();
        assert_eq!(certificate_manager(&roots, DOMAIN), Some(CertManager::Acme));
        assert!(!reissue_requested(&roots, DOMAIN));
    }

    #[test]
    fn a_wildcard_certificate_is_not_the_exact_one() {
        let temp = tempfile::tempdir().unwrap();
        let roots = roots(temp.path());
        install_manual_certificates(&roots, &[prepared(WILDCARD, &self_signed(90))]).unwrap();
        assert!(
            installed_certificate(&roots, "notes.home.example.com")
                .unwrap()
                .is_none()
        );
        assert_eq!(certificate_manager(&roots, DOMAIN), None);
        assert_eq!(
            served_certificate_manager(&roots, "notes.home.example.com"),
            Some(CertManager::Manual)
        );
        assert_eq!(served_certificate_manager(&roots, DOMAIN), None);
    }
}
