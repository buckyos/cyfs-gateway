use serde::Serialize;

use crate::values::host;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ProviderField {
    pub id: &'static str,
    /// English label, the service's own wording; shown when no translation exists.
    pub label: &'static str,
    pub secret: bool,
    pub optional: bool,
    pub multiline: bool,
    /// A closed choice (value, label), e.g. OVHcloud's EU / US / CA entry.
    pub options: &'static [(&'static str, &'static str)],
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    /// Can be limited to one domain.
    Domain,
    /// Reaches a whole project or account: the page says so.
    Account,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ProviderInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub fields: &'static [ProviderField],
    /// Where the user creates the token.
    pub token_url: &'static str,
    /// Suffixes of the service's name servers, for detection (lower case, no
    /// trailing dot). `*` stands for any part of one label, as in
    /// `awsdns-*.com`; use [`detect_provider`] instead of comparing.
    pub ns_suffixes: &'static [&'static str],
    pub token_scope: TokenScope,
    /// The service answers a CNAME at the zone apex by flattening it.
    pub apex_cname: bool,
    /// Tried against the live service with a real account.
    pub tested: bool,
    /// Official test environment, if any.
    pub sandbox_url: Option<&'static str>,
}

const fn text(id: &'static str, label: &'static str) -> ProviderField {
    ProviderField {
        id,
        label,
        secret: false,
        optional: false,
        multiline: false,
        options: &[],
    }
}

const fn secret(id: &'static str, label: &'static str) -> ProviderField {
    ProviderField {
        secret: true,
        ..text(id, label)
    }
}

const fn multiline(id: &'static str, label: &'static str) -> ProviderField {
    ProviderField {
        multiline: true,
        ..secret(id, label)
    }
}

const fn optional(field: ProviderField) -> ProviderField {
    ProviderField {
        optional: true,
        ..field
    }
}

const fn choice(
    id: &'static str,
    label: &'static str,
    options: &'static [(&'static str, &'static str)],
) -> ProviderField {
    ProviderField {
        options,
        ..text(id, label)
    }
}

static PROVIDERS: [ProviderInfo; 20] = [
    ProviderInfo {
        id: "cloudflare",
        name: "Cloudflare",
        fields: &[secret("api_token", "API Token")],
        // Zone read is needed to find the zone by its name.
        token_url: "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%5D&accountId=%2A&zoneId=all&name=BuckyOS%20DNS",
        ns_suffixes: &[
            "ns.cloudflare.com",
            "foundationdns.com",
            "foundationdns.net",
            "foundationdns.org",
        ],
        token_scope: TokenScope::Domain,
        apex_cname: true,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "godaddy",
        name: "GoDaddy",
        fields: &[secret("access_token", "Personal Access Token")],
        token_url: "https://developer.godaddy.com/personal-access-token",
        ns_suffixes: &["domaincontrol.com"],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "route53",
        name: "Amazon Route 53",
        fields: &[
            text("access_key_id", "Access key ID"),
            secret("secret_access_key", "Secret access key"),
            optional(text("hosted_zone_id", "Hosted zone ID")),
        ],
        token_url: "https://console.aws.amazon.com/iam",
        ns_suffixes: &[
            "awsdns-*.com",
            "awsdns-*.net",
            "awsdns-*.org",
            "awsdns-*.co.uk",
        ],
        token_scope: TokenScope::Domain,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "porkbun",
        name: "Porkbun",
        fields: &[
            secret("api_key", "API Key"),
            secret("secret_api_key", "Secret Key"),
        ],
        token_url: "https://porkbun.com/account/api",
        ns_suffixes: &["ns.porkbun.com", "ns*.porkbun.com"],
        token_scope: TokenScope::Domain,
        apex_cname: false,
        tested: false,
        sandbox_url: Some("https://api.porkbun.com/api/json/v3"),
    },
    ProviderInfo {
        id: "ionos",
        name: "IONOS",
        fields: &[secret("api_key", "API Key (prefix.secret)")],
        token_url: "https://developer.hosting.ionos.com/keys",
        ns_suffixes: &["ui-dns.com", "ui-dns.de", "ui-dns.org", "ui-dns.biz"],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "ovh",
        name: "OVHcloud",
        fields: &[
            choice(
                "region",
                "Region",
                &[
                    ("eu", "Europe"),
                    ("us", "United States"),
                    ("ca", "Canada / Asia-Pacific"),
                ],
            ),
            text("application_key", "Application Key"),
            secret("application_secret", "Application Secret"),
            secret("consumer_key", "Consumer Key"),
        ],
        token_url: "https://auth.eu.ovhcloud.com/api/createToken",
        ns_suffixes: &[
            "ns*.ovh.net",
            "dns*.ovh.net",
            "ns*.ovh.ca",
            "dns*.ovh.ca",
            "anycast.me",
        ],
        token_scope: TokenScope::Domain,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "hetzner",
        name: "Hetzner",
        fields: &[secret("api_token", "API Token")],
        token_url: "https://console.hetzner.com/",
        ns_suffixes: &["ns.hetzner.com", "ns.hetzner.de"],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "gandi",
        name: "Gandi",
        fields: &[secret("personal_access_token", "Personal Access Token")],
        token_url: "https://admin.gandi.net/organizations/account/pat",
        ns_suffixes: &["ns-*.gandi.net"],
        token_scope: TokenScope::Domain,
        apex_cname: false,
        tested: false,
        sandbox_url: Some("https://api.sandbox.gandi.net/v5"),
    },
    ProviderInfo {
        id: "digitalocean",
        name: "DigitalOcean",
        fields: &[secret("api_token", "Personal Access Token")],
        token_url: "https://cloud.digitalocean.com/account/api/tokens",
        ns_suffixes: &["digitalocean.com"],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "google_cloud",
        name: "Google Cloud DNS",
        fields: &[
            multiline("service_account_json", "Service account key (JSON)"),
            optional(text("project_id", "Project ID")),
        ],
        token_url: "https://console.cloud.google.com/iam-admin/serviceaccounts",
        ns_suffixes: &["ns-cloud-*.googledomains.com"],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "azure",
        name: "Azure DNS",
        fields: &[
            text("tenant_id", "Directory (tenant) ID"),
            text("client_id", "Application (client) ID"),
            secret("client_secret", "Client secret value"),
            text("subscription_id", "Subscription ID"),
            text("resource_group", "Resource group"),
        ],
        token_url: "https://entra.microsoft.com/",
        ns_suffixes: &[
            "azure-dns.com",
            "azure-dns.net",
            "azure-dns.org",
            "azure-dns.info",
        ],
        token_scope: TokenScope::Domain,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "namecom",
        name: "Name.com",
        fields: &[
            text("username", "Username"),
            secret("api_token", "API Token"),
        ],
        token_url: "https://www.name.com/account/settings/api",
        ns_suffixes: &["name.com"],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: Some("https://api.dev.name.com"),
    },
    ProviderInfo {
        id: "hostinger",
        name: "Hostinger",
        fields: &[secret("api_token", "API Token")],
        token_url: "https://hpanel.hostinger.com/profile/api",
        ns_suffixes: &["dns-parking.com", "ns.hostinger.com"],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "desec",
        name: "deSEC",
        fields: &[secret("api_token", "API Token")],
        token_url: "https://desec.io/tokens",
        ns_suffixes: &["desec.io", "desec.org"],
        token_scope: TokenScope::Domain,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "inwx",
        name: "INWX",
        fields: &[
            text("username", "Username"),
            secret("password", "Password"),
            optional(secret("shared_secret", "Two-factor secret")),
        ],
        token_url: "https://www.inwx.com/",
        ns_suffixes: &[
            "inwx.com",
            "inwx.de",
            "inwx.eu",
            "inwx.net",
            "domrobot.com",
            "domrobot.net",
            "domrobot.org",
        ],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: Some("https://api.ote.domrobot.com/jsonrpc/"),
    },
    ProviderInfo {
        id: "netcup",
        name: "netcup",
        // A key alone is for CloudDNS; the legacy API takes all three.
        fields: &[
            optional(text("customer_number", "Customer number (Legacy API only)")),
            secret("api_key", "API Key"),
            optional(secret(
                "api_password",
                "Legacy API Password (Legacy API only)",
            )),
        ],
        token_url: "https://www.customercontrolpanel.de/",
        ns_suffixes: &["netcup.net"],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "transip",
        name: "TransIP",
        fields: &[
            text("login", "Username"),
            multiline("private_key", "Private key"),
        ],
        token_url: "https://www.transip.nl/cp/account/api",
        ns_suffixes: &["transip.net", "transip.nl", "transip.eu"],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: Some("https://api.transip.nl/v6"),
    },
    ProviderInfo {
        id: "alidns",
        name: "Alibaba Cloud DNS",
        fields: &[
            text("access_key_id", "AccessKey ID"),
            secret("access_key_secret", "AccessKey Secret"),
        ],
        token_url: "https://ram.console.aliyun.com/",
        ns_suffixes: &["alidns.com", "hichina.com"],
        token_scope: TokenScope::Domain,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "dnspod",
        name: "Tencent Cloud DNSPod",
        fields: &[
            text("secret_id", "SecretId"),
            secret("secret_key", "SecretKey"),
        ],
        token_url: "https://console.cloud.tencent.com/cam/capi",
        ns_suffixes: &[
            "dnspod.net",
            "dnsv2.com",
            "dnsv3.com",
            "dnsv4.com",
            "dnsv5.com",
        ],
        token_scope: TokenScope::Domain,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
    ProviderInfo {
        id: "sakura",
        name: "さくらのクラウド",
        fields: &[
            text("access_token", "Access Token"),
            secret("access_token_secret", "Access Token Secret"),
        ],
        token_url: "https://secure.sakura.ad.jp/cloud/#/apikeys",
        ns_suffixes: &["gslb*.sakura.ne.jp"],
        token_scope: TokenScope::Account,
        apex_cname: false,
        tested: false,
        sandbox_url: None,
    },
];

/// The 20 services, in display order.
pub fn provider_table() -> &'static [ProviderInfo] {
    &PROVIDERS
}

pub fn provider_info(id: &str) -> Option<&'static ProviderInfo> {
    provider_table().iter().find(|provider| provider.id == id)
}

fn label_matches(pattern: &str, label: &str) -> bool {
    match pattern.split_once('*') {
        Some((before, after)) => {
            label.len() > before.len() + after.len()
                && label.starts_with(before)
                && label.ends_with(after)
        }
        None => pattern == label,
    }
}

fn suffix_matches(pattern: &str, host: &str) -> bool {
    let mut labels = host.rsplit('.');
    pattern.rsplit('.').all(|part| {
        labels
            .next()
            .is_some_and(|label| label_matches(part, label))
    })
}

/// The service whose name servers these are. All names must belong to it.
pub fn detect_provider(ns_names: &[String]) -> Option<&'static ProviderInfo> {
    if ns_names.is_empty() {
        return None;
    }
    let names: Vec<String> = ns_names.iter().map(|name| host(name)).collect();
    provider_table().iter().find(|provider| {
        names.iter().all(|name| {
            provider
                .ns_suffixes
                .iter()
                .any(|suffix| suffix_matches(suffix, name))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn detected(names: &[&str]) -> Option<&'static str> {
        let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
        detect_provider(&names).map(|provider| provider.id)
    }

    #[test]
    fn name_servers() {
        for (names, id) in [
            (
                &["amy.ns.cloudflare.com", "bob.ns.cloudflare.com."][..],
                "cloudflare",
            ),
            (
                &["blue.foundationdns.com", "blue.foundationdns.org"],
                "cloudflare",
            ),
            (
                &["ns01.domaincontrol.com", "NS02.DOMAINCONTROL.COM"],
                "godaddy",
            ),
            (
                &[
                    "ns-2048.awsdns-64.com",
                    "ns-2049.awsdns-65.net",
                    "ns-2050.awsdns-66.org",
                    "ns-2051.awsdns-67.co.uk",
                ],
                "route53",
            ),
            (
                &["curitiba.ns.porkbun.com", "salvador.ns.porkbun.com"],
                "porkbun",
            ),
            (&["ns1045.ui-dns.de", "ns1045.ui-dns.biz"], "ionos"),
            (&["dns103.ovh.net", "ns103.ovh.net"], "ovh"),
            (&["dns200.anycast.me", "ns200.anycast.me"], "ovh"),
            (
                &["hydrogen.ns.hetzner.com", "helium.ns.hetzner.de"],
                "hetzner",
            ),
            (&["ns-154-a.gandi.net", "ns-9-b.gandi.net"], "gandi"),
            (&["ns1.digitalocean.com"], "digitalocean"),
            (
                &[
                    "ns-cloud-a1.googledomains.com",
                    "ns-cloud-a2.googledomains.com",
                ],
                "google_cloud",
            ),
            (&["ns1-01.azure-dns.com", "ns4-01.azure-dns.info"], "azure"),
            (&["ns1.name.com", "ns2abc.name.com"], "namecom"),
            (&["ns1.dns-parking.com", "ns2.dns-parking.com"], "hostinger"),
            (&["ns1.desec.io", "ns2.desec.org"], "desec"),
            (&["ns.inwx.de", "ns2.inwx.de", "ns3.inwx.eu"], "inwx"),
            (&["root-dns.netcup.net", "third-dns.netcup.net"], "netcup"),
            (
                &["ns0.transip.net", "ns1.transip.nl", "ns2.transip.eu"],
                "transip",
            ),
            (&["dns17.hichina.com", "dns18.hichina.com"], "alidns"),
            (&["f1g1ns1.dnspod.net", "f1g1ns2.dnspod.net"], "dnspod"),
            (&["ns3.dnsv5.com", "ns4.dnsv5.com"], "dnspod"),
            (
                &["ns1.gslb2.sakura.ne.jp", "ns2.gslb2.sakura.ne.jp"],
                "sakura",
            ),
        ] {
            assert_eq!(detected(names), Some(id), "{names:?}");
        }
        for names in [
            &[][..],
            &["ns1.example.com"],
            &["amy.ns.cloudflare.com", "ns1.digitalocean.com"],
            &["evilns.cloudflare.com.example"],
            &["ns1.notname.com"],
            &["secondary.cloudflare.com"],
            &["ns1.googledomains.com"],
            &["ns1.sakura.ne.jp"],
            &["ns1.dns.ne.jp"],
            &["vps123.ovh.net"],
            &["awsdns-.com"],
        ] {
            assert_eq!(detected(names), None, "{names:?}");
        }
    }

    #[test]
    fn table_is_consistent() {
        let ids: HashSet<_> = provider_table()
            .iter()
            .map(|provider| provider.id)
            .collect();
        assert_eq!(ids.len(), 20);
        for provider in provider_table() {
            assert!(
                provider.token_url.starts_with("https://"),
                "{}",
                provider.id
            );
            assert!(!provider.ns_suffixes.is_empty(), "{}", provider.id);
            assert!(
                provider.fields.iter().any(|field| field.secret),
                "{}",
                provider.id
            );
            let fields: HashSet<_> = provider.fields.iter().map(|field| field.id).collect();
            assert_eq!(fields.len(), provider.fields.len(), "{}", provider.id);
        }
    }
}
