use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::crypto::{hex, random_bytes};
use crate::provider::{DnsProviderError, DnsProviderResult};
use crate::table::provider_info;

const DIRECTORY: &str = "dns_credentials";

/// What the user gave for one DNS service. The file form is
/// `$BUCKYOS_ROOT/security/dns_credentials/<id>.json` (0600).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsCredential {
    /// Provider id from the table.
    pub provider: String,
    /// Field id -> value.
    pub fields: BTreeMap<String, String>,
    /// Overrides the service's API address (official sandboxes, tests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl Debug for DnsCredential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsCredential")
            .field("provider", &self.provider)
            .field("fields", &self.fields.keys().collect::<Vec<_>>())
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

fn invalid(text: impl Into<String>) -> DnsProviderError {
    DnsProviderError::InvalidCredential(text.into())
}

impl DnsCredential {
    /// Known provider, every required field present and non-empty, no unknown field.
    pub fn validate(&self) -> DnsProviderResult<()> {
        let provider = provider_info(&self.provider)
            .ok_or_else(|| invalid(format!("unknown DNS service: {}", self.provider)))?;
        for id in self.fields.keys() {
            if !provider.fields.iter().any(|field| field.id == id) {
                return Err(invalid(format!("{} has no field {id}", provider.id)));
            }
        }
        for field in provider.fields {
            let Some(value) = self.field(field.id) else {
                if field.optional {
                    continue;
                }
                return Err(invalid(format!("{} is missing", field.id)));
            };
            let options = field.options;
            if !options.is_empty() && !options.iter().any(|(option, _)| *option == value) {
                return Err(invalid(format!("{} is not one of the choices", field.id)));
            }
            if !field.multiline && value.chars().any(char::is_control) {
                return Err(invalid(format!("{} has to be a single line", field.id)));
            }
        }
        if self.provider == "netcup"
            && self.field("customer_number").is_some() != self.field("api_password").is_some()
        {
            return Err(invalid(
                "customer_number and api_password are given together or not at all",
            ));
        }
        if let Some(endpoint) = &self.endpoint {
            let valid = url::Url::parse(endpoint).is_ok_and(|url| {
                matches!(url.scheme(), "https" | "http")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
            });
            if !valid {
                return Err(invalid("invalid API address"));
            }
        }
        Ok(())
    }

    /// The value without surrounding whitespace, `None` when empty.
    pub(crate) fn field(&self, id: &str) -> Option<&str> {
        self.fields
            .get(id)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    }

    /// Everything that must not show up in an error.
    pub(crate) fn secrets(&self) -> Vec<String> {
        let Some(provider) = provider_info(&self.provider) else {
            return Vec::new();
        };
        let mut secrets = Vec::new();
        for field in provider.fields.iter().filter(|field| field.secret) {
            let Some(value) = self.field(field.id) else {
                continue;
            };
            secrets.push(value.to_string());
            if field.multiline {
                secrets.extend(
                    value
                        .split('\n')
                        .flat_map(|line| line.split("\\n"))
                        .map(str::trim)
                        .filter(|line| line.len() >= 24)
                        .map(str::to_string),
                );
            }
        }
        secrets
    }
}

/// `<security_root>/dns_credentials/<id>.json`; `id` must be `[a-z0-9-]{1,64}`.
pub fn credential_path(security_root: &Path, id: &str) -> DnsProviderResult<PathBuf> {
    let valid = (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'));
    if !valid {
        return Err(invalid("invalid credential id"));
    }
    Ok(security_root.join(DIRECTORY).join(format!("{id}.json")))
}

pub fn load_credential(path: &Path) -> DnsProviderResult<DnsCredential> {
    let text = fs::read_to_string(path)
        .map_err(|error| invalid(format!("{}: {error}", path.display())))?;
    // The parser's message can quote the content.
    let credential: DnsCredential = serde_json::from_str(&text).map_err(|error| {
        invalid(format!(
            "{}: invalid at line {} column {}",
            path.display(),
            error.line(),
            error.column()
        ))
    })?;
    credential.validate()?;
    Ok(credential)
}

/// Atomic, 0600, parent created 0700.
pub fn save_credential(path: &Path, credential: &DnsCredential) -> DnsProviderResult<()> {
    credential.validate()?;
    let failed = |error: std::io::Error| invalid(format!("{}: {error}", path.display()));
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| invalid("credential path has no directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("credential path has no file name"))?;
    create_private_directory(directory).map_err(failed)?;
    let text = serde_json::to_string_pretty(credential)
        .map_err(|_| invalid("cannot encode the credential"))?;
    let temporary = directory.join(format!(
        ".{}.{}",
        name.to_string_lossy(),
        hex(&random_bytes::<8>())
    ));
    let written = create_private_file(&temporary)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&temporary, path));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written.map_err(failed)
}

#[cfg(unix)]
fn create_private_directory(directory: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_directory(directory: &Path) -> std::io::Result<()> {
    fs::create_dir_all(directory)
}

fn create_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::provider_table;

    fn credential(provider: &str, fields: &[(&str, &str)]) -> DnsCredential {
        DnsCredential {
            provider: provider.to_string(),
            fields: fields
                .iter()
                .map(|(id, value)| (id.to_string(), value.to_string()))
                .collect(),
            endpoint: None,
        }
    }

    #[test]
    fn validation() {
        assert!(
            credential("cloudflare", &[("api_token", "t")])
                .validate()
                .is_ok()
        );
        for bad in [
            credential("nobody", &[]),
            credential("cloudflare", &[]),
            credential("cloudflare", &[("api_token", "  ")]),
            credential("cloudflare", &[("api_token", "t"), ("extra", "x")]),
            credential("cloudflare", &[("api_token", "a\nb")]),
            credential(
                "ovh",
                &[
                    ("region", "mars"),
                    ("application_key", "a"),
                    ("application_secret", "b"),
                    ("consumer_key", "c"),
                ],
            ),
            credential("netcup", &[("api_key", "k"), ("customer_number", "1")]),
        ] {
            assert!(matches!(
                bad.validate(),
                Err(DnsProviderError::InvalidCredential(_))
            ));
        }
        assert!(credential("netcup", &[("api_key", "k")]).validate().is_ok());
        let mut endpoint = credential("cloudflare", &[("api_token", "t")]);
        endpoint.endpoint = Some("file:///etc/passwd".to_string());
        assert!(endpoint.validate().is_err());
        endpoint.endpoint = Some("https://api.example.com/v4".to_string());
        assert!(endpoint.validate().is_ok());
    }

    #[test]
    fn ids_are_file_names() {
        let root = Path::new("/security");
        assert_eq!(
            credential_path(root, "home-example-com-1a2b").unwrap(),
            Path::new("/security/dns_credentials/home-example-com-1a2b.json")
        );
        for id in ["", "../x", "A", "a.b", &"a".repeat(65)] {
            assert!(credential_path(root, id).is_err(), "{id}");
        }
    }

    #[test]
    fn save_and_load() {
        let root = tempfile::tempdir().unwrap();
        let path = credential_path(root.path(), "one").unwrap();
        let first = credential("cloudflare", &[("api_token", "first")]);
        let second = credential("cloudflare", &[("api_token", "second")]);
        save_credential(&path, &first).unwrap();
        save_credential(&path, &second).unwrap();
        assert_eq!(load_credential(&path).unwrap(), second);
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["one.json"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
    }

    #[test]
    fn secrets_stay_out_of_text() {
        let root = tempfile::tempdir().unwrap();
        let path = credential_path(root.path(), "bad").unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            r#"{"provider":"cloudflare","fields":["top-secret-token"]}"#,
        )
        .unwrap();
        let error = load_credential(&path).unwrap_err().to_string();
        assert!(!error.contains("top-secret-token"), "{error}");
        let credential = credential("cloudflare", &[("api_token", "top-secret-token")]);
        assert!(!format!("{credential:?}").contains("top-secret-token"));
    }

    #[test]
    fn every_provider_can_be_created() {
        let key = String::from_utf8(
            openssl::rsa::Rsa::generate(2048)
                .unwrap()
                .private_key_to_pem()
                .unwrap(),
        )
        .unwrap();
        for provider in provider_table() {
            let fields = provider
                .fields
                .iter()
                .filter(|field| !field.optional)
                .map(|field| {
                    let value = match field.id {
                        "service_account_json" => serde_json::json!({
                            "client_email": "a@b",
                            "private_key": key,
                            "token_uri": "https://oauth2.googleapis.com/token",
                            "project_id": "p",
                        })
                        .to_string(),
                        _ => field
                            .options
                            .first()
                            .map_or("value", |(value, _)| value)
                            .to_string(),
                    };
                    (field.id.to_string(), value)
                })
                .collect();
            let credential = DnsCredential {
                provider: provider.id.to_string(),
                fields,
                endpoint: None,
            };
            if let Err(error) = crate::create_provider(&credential, "Example.com.") {
                panic!("{}: {error}", provider.id);
            }
        }
    }
}
