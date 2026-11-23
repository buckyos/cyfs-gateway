use openssl::hash::MessageDigest;
use reqwest::{Method, Url};
use serde_json::{Value, json};
use tokio::sync::OnceCell;

use crate::crypto::{hex, hmac, sha256};
use crate::engine::{Backend, Change, Stored};
use crate::http::{Http, now, snippet, url};
use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};
use crate::values::{fqdn, host, quote_txt, stored_value, type_name};

const ENDPOINT: &str = "https://route53.amazonaws.com";
const API: &str = "2013-04-01";
const XMLNS: &str = "https://route53.amazonaws.com/doc/2013-04-01/";
const REGION: &str = "us-east-1";

pub(crate) struct Route53 {
    http: Http,
    base: String,
    access_key_id: String,
    secret_access_key: String,
    origin: String,
    zone: OnceCell<String>,
}

/// `YYYYMMDD`, `YYYYMMDDTHHMMSSZ`
fn amz_date(seconds: u64) -> (String, String) {
    let days = seconds / 86400;
    let time = seconds % 86400;
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    let date = format!("{year:04}{month:02}{day:02}");
    let moment = format!(
        "{date}T{:02}{:02}{:02}Z",
        time / 3600,
        time / 60 % 60,
        time % 60
    );
    (date, moment)
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn unescape_xml(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn elements<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        rest = &rest[start + open.len()..];
        let Some(end) = rest.find(&close) else { break };
        found.push(&rest[..end]);
        rest = &rest[end + close.len()..];
    }
    found
}

fn element(xml: &str, tag: &str) -> Option<String> {
    elements(xml, tag).first().map(|text| unescape_xml(text))
}

/// Names come back with everything but letters, digits, `-` and `_` as `\ooo`.
fn unescape_name(name: &str) -> String {
    let mut out = String::new();
    let mut rest = name;
    while let Some(start) = rest.find('\\') {
        out.push_str(&rest[..start]);
        let code = rest
            .get(start + 1..start + 4)
            .and_then(|digits| u8::from_str_radix(digits, 8).ok());
        match code {
            Some(code) => {
                out.push(char::from(code));
                rest = &rest[start + 4..];
            }
            None => {
                out.push('\\');
                rest = &rest[start + 1..];
            }
        }
    }
    out.push_str(rest);
    host(&out)
}

/// Signature Version 4 over the host and the date.
struct Signer<'a> {
    access_key_id: &'a str,
    secret_access_key: &'a str,
    service: &'a str,
}

impl Signer<'_> {
    fn authorization(
        &self,
        method: &Method,
        url: &Url,
        body: &str,
        date: &str,
        moment: &str,
    ) -> DnsProviderResult<String> {
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        };
        let request = format!(
            "{method}\n{}\n{}\nhost:{host}\nx-amz-date:{moment}\n\nhost;x-amz-date\n{}",
            url.path(),
            url.query().unwrap_or_default(),
            hex(&sha256(body.as_bytes())?),
        );
        let scope = format!("{date}/{REGION}/{}/aws4_request", self.service);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{moment}\n{scope}\n{}",
            hex(&sha256(request.as_bytes())?)
        );
        let mut key = format!("AWS4{}", self.secret_access_key).into_bytes();
        for part in [date, REGION, self.service, "aws4_request"] {
            key = hmac(MessageDigest::sha256(), &key, part.as_bytes())?;
        }
        let signature = hex(&hmac(MessageDigest::sha256(), &key, to_sign.as_bytes())?);
        Ok(format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders=host;x-amz-date, Signature={signature}",
            self.access_key_id
        ))
    }
}

impl Route53 {
    pub(crate) fn new(
        access_key_id: &str,
        secret_access_key: &str,
        hosted_zone_id: Option<&str>,
        origin: &str,
        endpoint: Option<&str>,
    ) -> DnsProviderResult<Self> {
        let zone =
            hosted_zone_id.map(|id| id.trim().trim_start_matches("/hostedzone/").to_string());
        Ok(Self {
            http: Http::new()?,
            base: endpoint.unwrap_or(ENDPOINT).to_string(),
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_access_key.to_string(),
            origin: origin.to_string(),
            zone: OnceCell::new_with(zone),
        })
    }

    async fn call(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, &str)],
        body: String,
    ) -> DnsProviderResult<String> {
        let mut url = url(&self.base, &[&[API], path].concat(), &[])?;
        let mut pairs: Vec<String> = query
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect();
        pairs.sort();
        if !pairs.is_empty() {
            url.set_query(Some(&pairs.join("&")));
        }
        let (date, moment) = amz_date(now());
        let signer = Signer {
            access_key_id: &self.access_key_id,
            secret_access_key: &self.secret_access_key,
            service: "route53",
        };
        let authorization = signer.authorization(&method, &url, &body, &date, &moment)?;
        let request = self
            .http
            .request(method, url)
            .header("x-amz-date", moment)
            .header("authorization", authorization)
            .header("content-type", "application/xml")
            .body(body);
        let reply = self.http.send(request).await?;
        if reply.is_ok() {
            return Ok(reply.body);
        }
        let code = element(&reply.body, "Code").unwrap_or_default();
        let message = format!(
            "{code}: {}",
            element(&reply.body, "Message").unwrap_or_else(|| snippet(&reply.body).to_string())
        );
        Err(match code.as_str() {
            "Throttling"
            | "ThrottlingException"
            | "PriorRequestNotComplete"
            | "RequestLimitExceeded"
            | "SlowDown" => DnsProviderError::RateLimited {
                message,
                retry_after: reply.retry_after(),
            },
            "InvalidClientTokenId"
            | "SignatureDoesNotMatch"
            | "AccessDenied"
            | "AccessDeniedException"
            | "UnrecognizedClientException"
            | "IncompleteSignature"
            | "ExpiredToken"
            | "ExpiredTokenException"
            | "NotAuthorized"
            | "OptInRequired" => DnsProviderError::Unauthorized(message),
            "NoSuchHostedZone" => DnsProviderError::ZoneNotFound(message),
            _ => reply.error(),
        })
    }

    async fn zone(&self) -> DnsProviderResult<&str> {
        self.zone
            .get_or_try_init(|| async {
                let body = self
                    .call(
                        Method::GET,
                        &["hostedzonesbyname"],
                        &[("dnsname", &fqdn(&self.origin)), ("maxitems", "100")],
                        String::new(),
                    )
                    .await?;
                elements(&body, "HostedZone")
                    .into_iter()
                    .filter(|zone| {
                        element(zone, "Name")
                            .is_some_and(|name| unescape_name(&name) == self.origin)
                            && element(zone, "PrivateZone").as_deref() != Some("true")
                    })
                    .find_map(|zone| element(zone, "Id"))
                    .map(|id| id.trim_start_matches("/hostedzone/").to_string())
                    .ok_or_else(|| DnsProviderError::ZoneNotFound(self.origin.clone()))
            })
            .await
            .map(String::as_str)
    }

    fn rrset(&self, name: &str, ty: RecordType, ttl: u32, values: &[String]) -> String {
        let values: String = values
            .iter()
            .map(|value| {
                format!(
                    "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                    escape_xml(value)
                )
            })
            .collect();
        format!(
            "<ResourceRecordSet><Name>{}</Name><Type>{}</Type><TTL>{ttl}</TTL>\
             <ResourceRecords>{values}</ResourceRecords></ResourceRecordSet>",
            fqdn(name),
            type_name(ty)
        )
    }
}

#[async_trait::async_trait]
impl Backend for Route53 {
    fn ttl_range(&self) -> (u32, u32) {
        (1, 172_800)
    }

    async fn list(&self, name: &str, ty: RecordType) -> DnsProviderResult<Vec<Stored>> {
        let zone = self.zone().await?;
        let body = self
            .call(
                Method::GET,
                &["hostedzone", zone, "rrset"],
                &[("name", &fqdn(name)), ("type", type_name(ty))],
                String::new(),
            )
            .await?;
        let mut records = Vec::new();
        for rrset in elements(&body, "ResourceRecordSet") {
            if element(rrset, "Type").as_deref() != Some(type_name(ty))
                || element(rrset, "Name").is_none_or(|found| unescape_name(&found) != name)
            {
                continue;
            }
            if rrset.contains("<SetIdentifier>") || rrset.contains("<AliasTarget>") {
                records.push(Stored {
                    raw: json!({ "managed": true }),
                    ..Default::default()
                });
                continue;
            }
            let ttl = element(rrset, "TTL")
                .and_then(|ttl| ttl.parse().ok())
                .unwrap_or_default();
            for value in elements(rrset, "Value") {
                let raw = unescape_xml(value);
                records.push(Stored {
                    value: stored_value(ty, &raw),
                    ttl,
                    raw: Value::from(raw),
                    ..Default::default()
                });
            }
        }
        Ok(records)
    }

    async fn apply(&self, name: &str, ty: RecordType, change: Change) -> DnsProviderResult<()> {
        let managed = |records: &[Stored]| records.iter().any(|record| record.raw.is_object());
        if managed(&change.keep) || (managed(&change.remove) && change.add.is_empty()) {
            return Err(DnsProviderError::Unsupported(format!(
                "{name} is an alias or uses a routing policy"
            )));
        }
        let raw = |records: &[Stored]| -> Vec<String> {
            records
                .iter()
                .filter_map(|record| record.raw.as_str().map(str::to_string))
                .collect()
        };
        let mut values = raw(&change.keep);
        values.extend(change.add.iter().map(|value| match ty {
            RecordType::TXT => quote_txt(value),
            RecordType::CNAME | RecordType::NS => fqdn(value),
            _ => value.clone(),
        }));
        let (action, rrset) = if values.is_empty() {
            let ttl = change.remove[0].ttl;
            ("DELETE", self.rrset(name, ty, ttl, &raw(&change.remove)))
        } else {
            ("UPSERT", self.rrset(name, ty, change.ttl, &values))
        };
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ChangeResourceRecordSetsRequest xmlns=\"{XMLNS}\"><ChangeBatch><Changes><Change>\
             <Action>{action}</Action>{rrset}</Change></Changes></ChangeBatch>\
             </ChangeResourceRecordSetsRequest>"
        );
        let zone = self.zone().await?;
        self.call(Method::POST, &["hostedzone", zone, "rrset"], &[], body)
            .await
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(amz_date(0).1, "19700101T000000Z");
        assert_eq!(amz_date(951_782_400).0, "20000229");
        assert_eq!(amz_date(1_795_392_000).1, "20261123T000000Z");
    }

    #[test]
    fn names_are_unescaped() {
        assert_eq!(
            unescape_name("\\052.home.example.com."),
            "*.home.example.com"
        );
        assert_eq!(unescape_name("plain.example.com."), "plain.example.com");
    }

    /// "get-vanilla" of the AWS Signature Version 4 test suite.
    #[test]
    fn signature() {
        let signer = Signer {
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            service: "service",
        };
        let url = Url::parse("https://example.amazonaws.com/").unwrap();
        assert_eq!(
            signer
                .authorization(&Method::GET, &url, "", "20150830", "20150830T123600Z")
                .unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }
}
