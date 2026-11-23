//! The services implemented in this crate.

use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use openssl::hash::{MessageDigest, hash};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use serde_json::{Value, json};

use cyfs_dns_provider::{DnsProviderError, RecordType};

use crate::mocks::too_many;
use crate::net::{Request, Response};
use crate::zone::{
    Harness, ORIGIN, Service, Zone, absolute, check, from_bare, from_dotted, from_zone_file, start,
    undotted, unquoted,
};

static RSA_KEY: LazyLock<PKey<Private>> =
    LazyLock::new(|| PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap());

fn rsa_pem() -> String {
    String::from_utf8(RSA_KEY.private_key_to_pem_pkcs8().unwrap()).unwrap()
}

fn cloudflare(zone: &mut Zone, request: &Request) -> Response {
    let failed = |status: u16, code: u64, message: &str| {
        Response::new(
            status,
            json!({ "success": false, "errors": [{ "code": code, "message": message }],
                    "messages": [], "result": null }),
        )
    };
    let success = |result: Value| {
        Response::new(
            200,
            json!({ "success": true, "errors": [], "messages": [], "result": result,
                    "result_info": { "page": 1, "total_pages": 1 } }),
        )
    };
    if zone.revoked || request.bearer() != "cf-secret-token" {
        // Some services echo what they were given.
        return failed(
            403,
            9109,
            &format!("Invalid access token {}", request.bearer()),
        );
    }
    let path = request.path.strip_prefix("/client/v4/zones").unwrap();
    let store = |zone: &mut Zone, id: Option<&str>, body: &Value| {
        let old = id.map(|id| zone.by_id(id).unwrap().clone());
        let (name, ty) = match &old {
            Some(old) => (old.name.clone(), old.ty.clone()),
            None => (
                body["name"].as_str().unwrap().to_string(),
                body["type"].as_str().unwrap().to_string(),
            ),
        };
        let content = body["content"].as_str().unwrap();
        let value = match ty.as_str() {
            "TXT" => unquoted(content),
            _ => from_bare(&ty, content),
        };
        if matches!(ty.as_str(), "A" | "AAAA" | "CNAME") {
            assert_eq!(body["proxied"], false);
        }
        if let Some(old) = old {
            zone.delete_id(&old.id.to_string());
        }
        zone.add(&name, &ty, &value, body["ttl"].as_u64().unwrap());
    };
    match (request.method.as_str(), path) {
        ("GET", "") if request.query("name") == ORIGIN => success(json!([
            { "id": "old", "name": ORIGIN, "status": "moved" },
            { "id": "z1", "name": ORIGIN, "status": "active" },
        ])),
        ("GET", "") => success(json!([])),
        ("GET", "/z1/dns_records") => {
            let records: Vec<Value> = zone
                .at(request.query("name"), request.query("type"))
                .iter()
                .map(|rec| {
                    // Records made in the dashboard can come back without quotes.
                    let content = match rec.ty.as_str() {
                        "TXT" if rec.ttl < 3600 => rec.zone_file(),
                        _ => rec.value.clone(),
                    };
                    json!({ "id": rec.id.to_string(), "name": rec.name, "type": rec.ty,
                            "content": content, "ttl": rec.ttl,
                            "proxied": rec.mark == "proxied" })
                })
                .collect();
            success(json!(records))
        }
        ("POST", "/z1/dns_records") => {
            zone.writes += 1;
            store(zone, None, &request.json());
            success(json!({}))
        }
        ("PATCH", path) => {
            zone.writes += 1;
            let id = path.strip_prefix("/z1/dns_records/").unwrap();
            store(zone, Some(id), &request.json());
            success(json!({}))
        }
        ("DELETE", path) => {
            zone.writes += 1;
            assert!(zone.delete_id(path.strip_prefix("/z1/dns_records/").unwrap()));
            success(json!({}))
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn cloudflare_records() {
    let harness = check(Service {
        id: "cloudflare",
        fields: vec![("api_token", "cf-secret-token".to_string())],
        hosts: &["api.cloudflare.com"],
        mock: cloudflare,
        limited: too_many,
        missing_zone: true,
    })
    .await;

    // A record that is already right but goes through the proxy.
    let provider = harness.provider();
    let name = "home.example.com";
    let target = vec!["203.0.113.7".to_string()];
    provider
        .set_rrset(name, RecordType::A, 300, target.clone())
        .await
        .unwrap();
    for adding in [true, false] {
        {
            let mut zone = harness.zone.lock().unwrap();
            let rec = zone
                .records
                .iter_mut()
                .find(|rec| rec.name == name && rec.ty == "A");
            rec.unwrap().mark = "proxied".to_string();
        }
        if adding {
            provider
                .add_values(name, RecordType::A, 300, target.clone())
                .await
                .unwrap();
        } else {
            provider
                .set_rrset(name, RecordType::A, 300, target.clone())
                .await
                .unwrap();
        }
        let records = harness.zone.lock().unwrap().at(name, "A");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].mark, "");
    }
}

fn godaddy(zone: &mut Zone, request: &Request) -> Response {
    if zone.revoked || request.bearer() != "gd-secret-pat" {
        return Response::new(401, "");
    }
    let path: Vec<&str> = request
        .path
        .strip_prefix("/v3/domains/zones/")
        .unwrap()
        .split('/')
        .collect();
    if path[0] != ORIGIN {
        return Response::new(
            404,
            json!({ "name": "NOT_FOUND", "message": "no such zone" }),
        );
    }
    assert_eq!(path[1], "dns-records");
    let parse = |body: &Value| {
        let ty = body["type"].as_str().unwrap().to_string();
        let ttl = body["ttl"].as_u64().unwrap();
        assert!((600..=86400).contains(&ttl));
        let value = from_dotted(&ty, body["data"].as_str().unwrap());
        (absolute(body["name"].as_str().unwrap()), ty, value, ttl)
    };
    match request.method.as_str() {
        "GET" => {
            let name = absolute(request.query("name"));
            let items: Vec<Value> = zone
                .at(&name, request.query("type"))
                .iter()
                .map(|rec| {
                    json!({ "recordId": rec.id.to_string(), "name": rec.label("@"),
                            "type": rec.ty, "data": rec.dotted(), "ttl": rec.ttl })
                })
                .collect();
            Response::new(200, json!({ "items": items, "links": [] }))
        }
        "POST" => {
            zone.writes += 1;
            let (name, ty, value, ttl) = parse(&request.json());
            zone.add(&name, &ty, &value, ttl);
            Response::new(201, json!({}))
        }
        "PUT" => {
            zone.writes += 1;
            let (name, ty, value, ttl) = parse(&request.json());
            assert!(zone.delete_id(path[2]));
            zone.add(&name, &ty, &value, ttl);
            Response::new(200, json!({}))
        }
        "DELETE" => {
            zone.writes += 1;
            assert!(zone.delete_id(path[2]));
            Response::new(204, "")
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn godaddy_records() {
    check(Service {
        id: "godaddy",
        fields: vec![("access_token", "gd-secret-pat".to_string())],
        hosts: &["api.godaddy.com"],
        mock: godaddy,
        limited: || Response::new(429, "").header("RateLimit-Reset", 1),
        missing_zone: true,
    })
    .await;
}

fn route53(zone: &mut Zone, request: &Request) -> Response {
    let failed = |status: u16, code: &str| {
        Response::new(
            status,
            format!(
                "<?xml version=\"1.0\"?><ErrorResponse><Error><Type>Sender</Type>\
                 <Code>{code}</Code><Message>refused</Message></Error></ErrorResponse>"
            ),
        )
    };
    let authorization = request.header("authorization");
    assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDTEST/"));
    assert!(request.header("x-amz-date").ends_with('Z'));
    if zone.revoked {
        return failed(403, "InvalidClientTokenId");
    }
    let escaped = |name: &str| format!("{}.", name.replace('*', "\\052"));
    let inner = |xml: &str, tag: &str| -> String {
        let start = xml.find(&format!("<{tag}>")).unwrap() + tag.len() + 2;
        xml[start..start + xml[start..].find(&format!("</{tag}>")).unwrap()].to_string()
    };
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/2013-04-01/hostedzonesbyname") => {
            let hosted = |id: &str, name: &str, private: bool| {
                format!(
                    "<HostedZone><Id>/hostedzone/{id}</Id><Name>{name}.</Name>\
                     <CallerReference>c</CallerReference><Config><PrivateZone>{private}\
                     </PrivateZone></Config></HostedZone>"
                )
            };
            Response::new(
                200,
                format!(
                    "<ListHostedZonesByNameResponse><HostedZones>{}{}{}</HostedZones>\
                     <IsTruncated>false</IsTruncated></ListHostedZonesByNameResponse>",
                    hosted("ZPRIVATE", ORIGIN, true),
                    hosted("ZPUBLIC", ORIGIN, false),
                    hosted("ZOTHER", "zexample.com", false),
                ),
            )
        }
        ("GET", "/2013-04-01/hostedzone/ZPUBLIC/rrset") => {
            let first = (
                undotted(request.query("name")),
                request.query("type").to_string(),
            );
            let mut sets = vec![first.clone()];
            sets.extend(zone.names().into_iter().filter(|set| *set != first));
            let mut body = String::new();
            for (name, ty) in sets {
                let records = zone.at(&name, &ty);
                let Some(one) = records.first() else { continue };
                let content = if one.mark == "alias" {
                    "<AliasTarget><HostedZoneId>Z9</HostedZoneId><DNSName>lb.example.net.\
                     </DNSName><EvaluateTargetHealth>false</EvaluateTargetHealth></AliasTarget>"
                        .to_string()
                } else {
                    let values: String = records
                        .iter()
                        .map(|rec| {
                            format!(
                                "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                                rec.zone_file().replace('"', "&quot;")
                            )
                        })
                        .collect();
                    format!(
                        "<TTL>{}</TTL><ResourceRecords>{values}</ResourceRecords>",
                        one.ttl
                    )
                };
                body += &format!(
                    "<ResourceRecordSet><Name>{}</Name><Type>{ty}</Type>{content}</ResourceRecordSet>",
                    escaped(&name)
                );
            }
            Response::new(
                200,
                format!(
                    "<?xml version=\"1.0\"?><ListResourceRecordSetsResponse><ResourceRecordSets>\
                     {body}</ResourceRecordSets><IsTruncated>false</IsTruncated>\
                     <MaxItems>300</MaxItems></ListResourceRecordSetsResponse>"
                ),
            )
        }
        ("POST", "/2013-04-01/hostedzone/ZPUBLIC/rrset") => {
            let body = &request.body;
            let name = undotted(&inner(body, "Name"));
            let ty = inner(body, "Type");
            let ttl: u64 = inner(body, "TTL").parse().unwrap();
            let values: Vec<String> = body
                .split("<Value>")
                .skip(1)
                .map(|part| from_zone_file(&ty, part.split("</Value>").next().unwrap()))
                .collect();
            match inner(body, "Action").as_str() {
                "UPSERT" => zone.set(&name, &ty, ttl, &values),
                "DELETE" => {
                    let records = zone.at(&name, &ty);
                    let current: Vec<_> = records.iter().map(|rec| rec.value.clone()).collect();
                    if current != values || records[0].ttl != ttl {
                        return failed(400, "InvalidChangeBatch");
                    }
                    zone.set(&name, &ty, 0, &[]);
                }
                other => panic!("{other}"),
            }
            zone.writes += 1;
            Response::new(200, "<ChangeResourceRecordSetsResponse/>")
        }
        other => panic!("{other:?}"),
    }
}

fn route53_service(zone_id: Option<&str>) -> Service {
    let mut fields = vec![
        ("access_key_id", "AKIDTEST".to_string()),
        ("secret_access_key", "aws-secret-value".to_string()),
    ];
    fields.extend(zone_id.map(|id| ("hosted_zone_id", id.to_string())));
    Service {
        id: "route53",
        fields,
        hosts: &["route53.amazonaws.com"],
        mock: route53,
        limited: || {
            Response::new(
                400,
                "<ErrorResponse><Error><Code>Throttling</Code><Message>Rate exceeded</Message>\
                 </Error></ErrorResponse>",
            )
        },
        missing_zone: true,
    }
}

#[tokio::test]
async fn route53_record_sets() {
    check(route53_service(None)).await;
    let harness = start(&route53_service(Some("/hostedzone/ZPUBLIC")));
    let provider = harness.provider();
    let name = "lb.example.com";
    {
        let mut zone = harness.zone.lock().unwrap();
        zone.add(name, "A", "alias", 0);
        zone.by_id("1013").unwrap().mark = "alias".to_string();
    }
    // Alias records cannot be changed value by value, only replaced.
    let values = vec!["192.0.2.1".to_string()];
    for result in [
        provider
            .add_values(name, RecordType::A, 60, values.clone())
            .await,
        provider.set_rrset(name, RecordType::A, 60, vec![]).await,
    ] {
        assert!(
            matches!(result, Err(DnsProviderError::Unsupported(_))),
            "{result:?}"
        );
    }
    provider
        .remove_values(name, RecordType::A, values.clone())
        .await
        .unwrap();
    provider
        .set_rrset(name, RecordType::A, 60, values)
        .await
        .unwrap();
    assert_eq!(harness.values(name, "A"), ["192.0.2.1"]);
}

fn ovh(zone: &mut Zone, request: &Request) -> Response {
    const SKEW: u64 = 5000;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + SKEW;
    if request.path == "/1.0/auth/time" {
        return Response::new(200, now);
    }
    let failed = |status: u16, class: &str, message: &str| {
        Response::new(
            status,
            json!({ "class": format!("Client::{class}"), "message": message }),
        )
    };
    let sent: u64 = request.header("x-ovh-timestamp").parse().unwrap();
    if sent.abs_diff(now) > 30 {
        return failed(400, "BadRequest", "Query out of time");
    }
    let query = match request.raw_query.as_str() {
        "" => String::new(),
        query => format!("?{query}"),
    };
    let signed = format!(
        "ovh-app-secret+ovh-consumer+{}+https://{}{}{query}+{}+{sent}",
        request.method, request.host, request.path, request.body
    );
    let digest = hash(MessageDigest::sha1(), signed.as_bytes()).unwrap();
    let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    if zone.revoked
        || request.header("x-ovh-application") != "ovh-app"
        || request.header("x-ovh-consumer") != "ovh-consumer"
        || request.header("x-ovh-signature") != format!("$1${digest}")
    {
        return failed(403, "Forbidden", "This application key is invalid");
    }
    let path = request.path.strip_prefix("/1.0/domain/zone/").unwrap();
    let Some(path) = path.strip_prefix(ORIGIN) else {
        return failed(404, "NotFound", "This service does not exist");
    };
    let describe = |rec: &crate::zone::Rec| {
        json!({ "id": rec.id, "zone": ORIGIN, "subDomain": rec.label(""),
                "fieldType": rec.ty, "target": rec.zone_file(), "ttl": rec.ttl })
    };
    match (request.method.as_str(), path) {
        ("GET", "/record") => {
            // `fieldType` is LIKE, `subDomain` is ILIKE, so `_` matches anything.
            let wanted: Vec<char> = request.query("subDomain").chars().collect();
            let ids: Vec<u64> = zone
                .records
                .iter()
                .filter(|rec| {
                    let label: Vec<char> = rec.label("").chars().collect();
                    rec.ty == request.query("fieldType")
                        && (wanted.is_empty()
                            || label.len() == wanted.len()
                                && label.iter().zip(&wanted).all(|(a, b)| a == b || *b == '_'))
                })
                .map(|rec| rec.id)
                .collect();
            Response::new(200, json!(ids))
        }
        ("POST", "/record") => {
            zone.writes += 1;
            let body = request.json();
            let ty = body["fieldType"].as_str().unwrap();
            let value = from_dotted(ty, body["target"].as_str().unwrap());
            let name = absolute(body["subDomain"].as_str().unwrap());
            let rec = zone.add(&name, ty, &value, body["ttl"].as_u64().unwrap());
            zone.notes.insert("dirty".to_string(), 1);
            Response::new(200, describe(&rec))
        }
        ("POST", "/refresh") => {
            zone.notes.remove("dirty");
            Response::new(200, "null")
        }
        (method, path) => {
            let id = path.strip_prefix("/record/").unwrap();
            let Some(rec) = zone.by_id(id).cloned() else {
                return failed(404, "NotFound", "The requested object does not exist");
            };
            match method {
                "GET" => return Response::new(200, describe(&rec)),
                "PUT" => {
                    let body = request.json();
                    let value = from_dotted(&rec.ty, body["target"].as_str().unwrap());
                    zone.delete_id(id);
                    zone.add(&rec.name, &rec.ty, &value, body["ttl"].as_u64().unwrap());
                }
                "DELETE" => assert!(zone.delete_id(id)),
                other => panic!("{other}"),
            }
            zone.writes += 1;
            zone.notes.insert("dirty".to_string(), 1);
            Response::new(200, "null")
        }
    }
}

#[tokio::test]
async fn ovh_records() {
    let harness = check(Service {
        id: "ovh",
        fields: vec![
            ("region", "ca".to_string()),
            ("application_key", "ovh-app".to_string()),
            ("application_secret", "ovh-app-secret".to_string()),
            ("consumer_key", "ovh-consumer".to_string()),
        ],
        hosts: &["api.ca.ovhcloud.com"],
        mock: ovh,
        limited: too_many,
        missing_zone: true,
    })
    .await;
    assert!(
        !harness.zone.lock().unwrap().notes.contains_key("dirty"),
        "not refreshed"
    );
}

fn hetzner(zone: &mut Zone, request: &Request) -> Response {
    let failed = |status: u16, code: &str| {
        Response::new(
            status,
            json!({ "error": { "code": code, "message": "refused" } }),
        )
    };
    if zone.revoked || request.bearer() != "hz-secret-token" {
        return failed(401, "unauthorized");
    }
    // A change keeps running until it has been asked about.
    if request.path == "/v1/zones/actions/5" {
        zone.notes.remove("running");
        return Response::new(200, json!({ "action": { "id": 5, "status": "success" } }));
    }
    let path: Vec<&str> = request
        .path
        .strip_prefix("/v1/zones/")
        .unwrap()
        .split('/')
        .collect();
    if path[0] != ORIGIN {
        return failed(404, "not_found");
    }
    assert_eq!(path[1], "rrsets");
    if request.method == "GET" {
        let name = absolute(request.query("name"));
        let ty = request.query("type");
        let records = zone.at(&name, ty);
        let values: Vec<Value> = records
            .iter()
            .map(|rec| json!({ "value": rec.zone_file(), "comment": rec.mark }))
            .collect();
        let sets = match records.first() {
            Some(rec) => json!([{ "id": format!("{}/{ty}", rec.label("@")),
                                  "name": rec.label("@"), "type": ty, "ttl": rec.ttl,
                                  "records": values }]),
            None => json!([]),
        };
        return Response::new(200, json!({ "rrsets": sets }));
    }
    if zone.notes.contains_key("running") {
        return failed(423, "locked");
    }
    let done = |zone: &mut Zone| {
        zone.writes += 1;
        zone.notes.insert("running".to_string(), 1);
        Response::new(201, json!({ "action": { "id": 5, "status": "running" } }))
    };
    let values = |ty: &str, body: &Value| -> Vec<String> {
        body["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| from_zone_file(ty, record["value"].as_str().unwrap()))
            .collect()
    };
    match (request.method.as_str(), path.len()) {
        ("POST", 2) => {
            let body = request.json();
            let ty = body["type"].as_str().unwrap();
            let name = absolute(body["name"].as_str().unwrap());
            if !zone.at(&name, ty).is_empty() {
                return failed(409, "uniqueness_error");
            }
            let ttl = body["ttl"].as_u64().unwrap();
            zone.set(&name, ty, ttl, &values(ty, &body));
            done(zone)
        }
        ("DELETE", 4) => {
            zone.set(&absolute(path[2]), path[3], 0, &[]);
            done(zone)
        }
        ("POST", 6) => {
            let (name, ty) = (absolute(path[2]), path[3]);
            let existing = zone.at(&name, ty);
            if existing.is_empty() {
                return failed(404, "not_found");
            }
            let body = request.json();
            let ttl = existing[0].ttl;
            match path[5] {
                "add_records" => {
                    for value in values(ty, &body) {
                        zone.add(&name, ty, &value, ttl);
                    }
                }
                "set_records" => {
                    let comments: Vec<String> = body["records"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|record| record["comment"].as_str().unwrap_or_default().to_string())
                        .collect();
                    zone.set(&name, ty, ttl, &values(ty, &body));
                    for (rec, comment) in zone
                        .records
                        .iter_mut()
                        .filter(|rec| rec.name == name && rec.ty == ty)
                        .zip(comments)
                    {
                        rec.mark = comment;
                    }
                }
                other => panic!("{other}"),
            }
            done(zone)
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn hetzner_rrsets() {
    let harness = check(Service {
        id: "hetzner",
        fields: vec![("api_token", "hz-secret-token".to_string())],
        hosts: &["api.hetzner.cloud"],
        mock: hetzner,
        limited: || {
            Response::new(429, json!({ "error": { "code": "rate_limit_exceeded" } }))
                .header("RateLimit-Reset", 1_700_000_000)
        },
        missing_zone: true,
    })
    .await;
    // Comments of the values that stay are kept.
    let name = "_acme-challenge.home.example.com";
    for rec in harness
        .zone
        .lock()
        .unwrap()
        .records
        .iter_mut()
        .filter(|rec| rec.name == name)
    {
        rec.mark = "do not touch".to_string();
    }
    let provider = harness.provider();
    let value = vec!["x".to_string()];
    provider
        .add_values(name, RecordType::TXT, 60, value.clone())
        .await
        .unwrap();
    provider
        .remove_values(name, RecordType::TXT, value)
        .await
        .unwrap();
    assert_eq!(
        harness.zone.lock().unwrap().at(name, "TXT")[0].mark,
        "do not touch"
    );
}

fn gandi(zone: &mut Zone, request: &Request) -> Response {
    if zone.revoked || request.bearer() != "gandi-secret-pat" {
        return Response::new(
            403,
            json!({ "object": "HTTPForbidden", "cause": "Forbidden", "code": 403 }),
        );
    }
    let path: Vec<&str> = request
        .path
        .strip_prefix("/v5/livedns/domains/")
        .unwrap()
        .split('/')
        .collect();
    let not_found = || Response::new(404, json!({ "object": "HTTPNotFound", "code": 404 }));
    if path[0] != ORIGIN {
        return not_found();
    }
    let (name, ty) = (absolute(path[2]), path[3]);
    let records = zone.at(&name, ty);
    match request.method.as_str() {
        "GET" if records.is_empty() => not_found(),
        "GET" => {
            let values: Vec<_> = records.iter().map(|rec| rec.zone_file()).collect();
            Response::new(
                200,
                json!({ "rrset_name": path[2], "rrset_type": ty,
                        "rrset_ttl": records[0].ttl, "rrset_values": values }),
            )
        }
        "PUT" => {
            zone.writes += 1;
            let body = request.json();
            let ttl = body["rrset_ttl"].as_u64().unwrap();
            assert!(ttl >= 300);
            let values: Vec<String> = body["rrset_values"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| from_zone_file(ty, value.as_str().unwrap()))
                .collect();
            zone.set(&name, ty, ttl, &values);
            Response::new(201, json!({ "message": "DNS Record Created" }))
        }
        "DELETE" => {
            zone.writes += 1;
            zone.set(&name, ty, 0, &[]);
            Response::new(204, "")
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn gandi_rrsets() {
    check(Service {
        id: "gandi",
        fields: vec![("personal_access_token", "gandi-secret-pat".to_string())],
        hosts: &["api.gandi.net"],
        mock: gandi,
        limited: too_many,
        missing_zone: true,
    })
    .await;
}

fn digitalocean(zone: &mut Zone, request: &Request) -> Response {
    let failed = |status: u16, id: &str, message: &str| {
        Response::new(status, json!({ "id": id, "message": message }))
    };
    if zone.revoked || request.bearer() != "do-secret-token" {
        return failed(401, "Unauthorized", "Unable to authenticate you");
    }
    let path: Vec<&str> = request
        .path
        .strip_prefix("/v2/domains/")
        .unwrap()
        .split('/')
        .collect();
    if path[0] != ORIGIN {
        return failed(
            404,
            "not_found",
            "The resource you were accessing could not be found.",
        );
    }
    let parse = |body: &Value| {
        let ty = body["type"].as_str().unwrap().to_string();
        let data = body["data"].as_str().unwrap();
        (
            absolute(body["name"].as_str().unwrap()),
            from_dotted(&ty, data),
            ty,
            body["ttl"].as_u64().unwrap(),
        )
    };
    match request.method.as_str() {
        "GET" => {
            let items: Vec<Value> = zone
                .at(request.query("name"), request.query("type"))
                .iter()
                .map(|rec| {
                    json!({ "id": rec.id, "type": rec.ty, "name": rec.label("@"),
                            "data": rec.value, "ttl": rec.ttl, "priority": null })
                })
                .collect();
            Response::new(
                200,
                json!({ "domain_records": items, "links": {}, "meta": {} }),
            )
        }
        "POST" => {
            zone.writes += 1;
            let (name, value, ty, ttl) = parse(&request.json());
            zone.add(&name, &ty, &value, ttl);
            Response::new(201, json!({}))
        }
        "PUT" => {
            zone.writes += 1;
            let (name, value, ty, ttl) = parse(&request.json());
            assert!(zone.delete_id(path[2]));
            zone.add(&name, &ty, &value, ttl);
            Response::new(200, json!({}))
        }
        "DELETE" => {
            zone.writes += 1;
            assert!(zone.delete_id(path[2]));
            Response::new(204, "")
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn digitalocean_records() {
    check(Service {
        id: "digitalocean",
        fields: vec![("api_token", "do-secret-token".to_string())],
        hosts: &["api.digitalocean.com"],
        mock: digitalocean,
        limited: too_many,
        missing_zone: true,
    })
    .await;
}

fn google(zone: &mut Zone, request: &Request) -> Response {
    if request.host == "oauth2.googleapis.com" {
        let form: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(request.body.as_bytes())
                .into_owned()
                .collect();
        let assertion = &form["assertion"];
        let (signed, signature) = assertion.rsplit_once('.').unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &RSA_KEY).unwrap();
        let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
        if zone.revoked
            || !verifier
                .verify_oneshot(&signature, signed.as_bytes())
                .unwrap()
        {
            return Response::new(
                400,
                json!({ "error": "invalid_grant", "error_description": "Invalid JWT Signature." }),
            );
        }
        let claims = URL_SAFE_NO_PAD
            .decode(signed.split('.').nth(1).unwrap())
            .unwrap();
        let claims: Value = serde_json::from_slice(&claims).unwrap();
        assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
        assert_eq!(claims["iss"], "dns@project-1.iam");
        return Response::new(
            200,
            json!({ "access_token": "google-access", "expires_in": 3599 }),
        );
    }
    assert_eq!(request.bearer(), "google-access");
    let path = request
        .path
        .strip_prefix("/dns/v1/projects/project-1/managedZones")
        .unwrap();
    match (request.method.as_str(), path) {
        ("GET", "") => {
            let wanted = request.query("dnsName");
            let zones: Vec<Value> = [
                ("private", "example.com.", "private"),
                ("public", "example.com.", "public"),
                ("suffix", "ample.com.", "public"),
            ]
            .iter()
            .filter(|(_, name, _)| *name == wanted)
            .map(|(id, name, visibility)| {
                json!({ "name": id, "dnsName": name, "visibility": visibility })
            })
            .collect();
            Response::new(200, json!({ "managedZones": zones }))
        }
        ("GET", "/public/rrsets") => {
            let name = undotted(request.query("name"));
            let ty = request.query("type");
            let records = zone.at(&name, ty);
            let sets = match records.first() {
                Some(rec) => json!([{ "name": format!("{name}."), "type": ty, "ttl": rec.ttl,
                    "rrdatas": records.iter().map(|rec| rec.zone_file()).collect::<Vec<_>>() }]),
                None => json!([]),
            };
            Response::new(200, json!({ "rrsets": sets }))
        }
        ("POST", "/public/changes") => {
            let body = request.json();
            let sets = |key: &str| body[key].as_array().cloned().unwrap_or_default();
            for set in sets("deletions") {
                let name = undotted(set["name"].as_str().unwrap());
                let ty = set["type"].as_str().unwrap();
                let records = zone.at(&name, ty);
                let current: Vec<_> = records.iter().map(|rec| rec.zone_file()).collect();
                if set["rrdatas"] != json!(current) || set["ttl"] != records[0].ttl {
                    return Response::new(
                        412,
                        json!({ "error": { "errors": [{ "reason": "conditionNotMet" }] } }),
                    );
                }
                zone.set(&name, ty, 0, &[]);
            }
            for set in sets("additions") {
                let name = undotted(set["name"].as_str().unwrap());
                let ty = set["type"].as_str().unwrap();
                assert!(zone.at(&name, ty).is_empty());
                let values: Vec<String> = set["rrdatas"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| from_zone_file(ty, value.as_str().unwrap()))
                    .collect();
                zone.set(&name, ty, set["ttl"].as_u64().unwrap(), &values);
            }
            zone.writes += 1;
            Response::new(200, json!({ "status": "pending" }))
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn google_cloud_rrsets() {
    let account = json!({
        "type": "service_account",
        "project_id": "project-1",
        "client_email": "dns@project-1.iam",
        "private_key": rsa_pem(),
        "token_uri": "https://oauth2.googleapis.com/token",
    });
    check(Service {
        id: "google_cloud",
        fields: vec![("service_account_json", account.to_string())],
        hosts: &["oauth2.googleapis.com", "dns.googleapis.com"],
        mock: google,
        limited: || {
            Response::new(
                403,
                json!({ "error": { "code": 403, "errors": [{ "reason": "rateLimitExceeded" }] } }),
            )
        },
        missing_zone: true,
    })
    .await;
}

fn namecom(zone: &mut Zone, request: &Request) -> Response {
    let expected = format!("Basic {}", STANDARD.encode("alice:nc-secret-token"));
    if zone.revoked || request.header("authorization") != expected {
        return Response::new(401, json!({ "message": "Unauthorized" }));
    }
    let path: Vec<&str> = request
        .path
        .strip_prefix("/core/v1/domains/")
        .unwrap()
        .split('/')
        .collect();
    if path[0] != ORIGIN {
        return Response::new(404, json!({ "message": "Not Found" }));
    }
    let parse = |body: &Value| {
        let ty = body["type"].as_str().unwrap().to_string();
        let ttl = body["ttl"].as_u64().unwrap();
        assert!(ttl >= 300);
        (
            absolute(body["host"].as_str().unwrap()),
            from_bare(&ty, body["answer"].as_str().unwrap()),
            ty,
            ttl,
        )
    };
    match request.method.as_str() {
        "GET" => {
            // Two pages; the host of the apex is left out.
            let page: usize = request.query("page").parse().unwrap();
            let half = zone.records.len() / 2;
            let records = if page == 1 {
                &zone.records[..half]
            } else {
                &zone.records[half..]
            };
            let items: Vec<Value> = records
                .iter()
                .map(|rec| {
                    let mut item = json!({ "id": rec.id, "domainName": ORIGIN,
                        "fqdn": format!("{}.", rec.name), "type": rec.ty,
                        "answer": rec.value, "ttl": rec.ttl });
                    if rec.name != ORIGIN {
                        item["host"] = json!(rec.label(""));
                    }
                    item
                })
                .collect();
            let mut body = json!({ "records": items });
            if page == 1 {
                body["nextPage"] = json!(2);
            }
            Response::new(200, body)
        }
        "POST" => {
            zone.writes += 1;
            let (name, value, ty, ttl) = parse(&request.json());
            zone.add(&name, &ty, &value, ttl);
            Response::new(200, json!({}))
        }
        "PUT" => {
            zone.writes += 1;
            let (name, value, ty, ttl) = parse(&request.json());
            assert!(zone.delete_id(path[2]));
            zone.add(&name, &ty, &value, ttl);
            Response::new(200, json!({}))
        }
        "DELETE" => {
            zone.writes += 1;
            assert!(zone.delete_id(path[2]));
            Response::new(204, "")
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn namecom_records() {
    check(Service {
        id: "namecom",
        fields: vec![
            ("username", "alice".to_string()),
            ("api_token", "nc-secret-token".to_string()),
        ],
        hosts: &["api.name.com"],
        mock: namecom,
        limited: || Response::new(429, "").header("x-ratelimit-reset", 1_700_000_000),
        missing_zone: true,
    })
    .await;
}

fn hostinger(zone: &mut Zone, request: &Request) -> Response {
    if zone.revoked || request.bearer() != "hostinger-token" {
        return Response::new(401, json!({ "message": "Unauthenticated." }));
    }
    let domain = request.path.strip_prefix("/api/dns/v1/zones/").unwrap();
    if domain != ORIGIN {
        return Response::new(422, json!({ "message": "unknown domain" }));
    }
    match request.method.as_str() {
        "GET" => {
            let sets: Vec<Value> = zone
                .names()
                .into_iter()
                .map(|(name, ty)| {
                    let records = zone.at(&name, &ty);
                    let values: Vec<Value> = records
                        .iter()
                        .map(|rec| json!({ "content": rec.zone_file(), "is_disabled": false }))
                        .collect();
                    json!({ "name": records[0].label("@"), "type": ty,
                            "ttl": records[0].ttl, "records": values })
                })
                .collect();
            Response::new(200, json!(sets))
        }
        "PUT" => {
            zone.writes += 1;
            let body = request.json();
            for set in body["zone"].as_array().unwrap() {
                let ty = set["type"].as_str().unwrap();
                let values: Vec<String> = set["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|record| {
                        let content = record["content"].as_str().unwrap();
                        match ty {
                            // Both forms are taken.
                            "TXT" => content.trim_matches('"').to_string(),
                            _ => from_dotted(ty, content),
                        }
                    })
                    .collect();
                let name = absolute(set["name"].as_str().unwrap());
                let ttl = set["ttl"].as_u64().unwrap();
                if body["overwrite"] == true {
                    zone.set(&name, ty, ttl, &values);
                    continue;
                }
                for rec in zone.records.iter_mut() {
                    if rec.name == name && rec.ty == ty {
                        rec.ttl = ttl;
                    }
                }
                for value in values {
                    zone.add(&name, ty, &value, ttl);
                }
            }
            Response::new(200, json!({ "message": "Request accepted" }))
        }
        "DELETE" => {
            zone.writes += 1;
            for filter in request.json()["filters"].as_array().unwrap() {
                let name = absolute(filter["name"].as_str().unwrap());
                zone.set(&name, filter["type"].as_str().unwrap(), 0, &[]);
            }
            Response::new(200, json!({ "message": "Request accepted" }))
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn hostinger_rrsets() {
    check(Service {
        id: "hostinger",
        fields: vec![("api_token", "hostinger-token".to_string())],
        hosts: &["developers.hostinger.com"],
        mock: hostinger,
        limited: too_many,
        missing_zone: false,
    })
    .await;
}

fn inwx(zone: &mut Zone, request: &Request) -> Response {
    let body = request.json();
    let params = &body["params"];
    let reply = |code: u64, data: Value| {
        Response::new(
            200,
            json!({ "code": code, "msg": "message", "resData": data }),
        )
    };
    assert_eq!(request.path, "/jsonrpc/");
    let session = request.header("cookie");
    let method = body["method"].as_str().unwrap();
    match method {
        "account.login" => {
            zone.note("logins");
            if zone.revoked || params["pass"] != "inwx-password" {
                return reply(2200, Value::Null);
            }
            return reply(1000, json!({ "tfa": "GOOGLE-AUTH" }))
                .header("set-cookie", "domrobot=session-1; path=/; secure");
        }
        "account.unlock" => {
            assert_eq!(session, "domrobot=session-1");
            assert_eq!(params["tan"].as_str().unwrap().len(), 6);
            zone.note("unlocked");
            return reply(1000, Value::Null);
        }
        _ => {}
    }
    if zone.revoked {
        return reply(2200, Value::Null);
    }
    if session != "domrobot=session-1" || !zone.notes.contains_key("unlocked") {
        return reply(2002, Value::Null);
    }
    match method {
        "nameserver.info" => {
            if params["domain"] != ORIGIN {
                return reply(2303, Value::Null);
            }
            let name = params["name"].as_str().unwrap();
            let records: Vec<Value> = zone
                .at(name, params["type"].as_str().unwrap())
                .iter()
                .map(|rec| {
                    json!({ "id": rec.id.to_string(), "name": rec.name, "type": rec.ty,
                            "content": rec.value, "ttl": rec.ttl, "prio": 0 })
                })
                .collect();
            if records.is_empty() {
                return reply(1000, json!({ "domain": ORIGIN, "count": 0 }));
            }
            reply(1000, json!({ "domain": ORIGIN, "record": records }))
        }
        "nameserver.createRecord" => {
            zone.writes += 1;
            let ty = params["type"].as_str().unwrap();
            let ttl = params["ttl"].as_u64().unwrap();
            assert!(ttl >= 300);
            let value = from_bare(ty, params["content"].as_str().unwrap());
            zone.add(params["name"].as_str().unwrap(), ty, &value, ttl);
            reply(1000, json!({ "id": "1" }))
        }
        "nameserver.updateRecord" => {
            zone.writes += 1;
            let id = params["id"].as_str().unwrap();
            let old = zone.by_id(id).unwrap().clone();
            let value = from_bare(&old.ty, params["content"].as_str().unwrap());
            zone.delete_id(id);
            zone.add(&old.name, &old.ty, &value, params["ttl"].as_u64().unwrap());
            reply(1000, Value::Null)
        }
        "nameserver.deleteRecord" => {
            zone.writes += 1;
            assert!(zone.delete_id(params["id"].as_str().unwrap()));
            reply(1000, Value::Null)
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn inwx_records() {
    let service = Service {
        id: "inwx",
        fields: vec![
            ("username", "alice".to_string()),
            ("password", "inwx-password".to_string()),
            (
                "shared_secret",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            ),
        ],
        hosts: &["api.domrobot.com"],
        mock: inwx,
        limited: too_many,
        missing_zone: true,
    };
    let harness = check(service).await;
    // One-time codes work once, so every provider shares the session.
    assert_eq!(harness.zone.lock().unwrap().notes["logins"], 1);
}

fn netcup(zone: &mut Zone, request: &Request) -> Response {
    assert_eq!(request.path, "/run/webservice/servers/endpoint.php");
    assert_eq!(request.raw_query, "JSON");
    let body = request.json();
    let param = &body["param"];
    let failed = |code: u64, text: &str| {
        Response::new(
            200,
            json!({ "status": "error", "statuscode": code,
                    "shortmessage": "Validation Error.", "longmessage": text,
                    "responsedata": "" }),
        )
    };
    let success = |data: Value| {
        Response::new(
            200,
            json!({ "status": "success", "statuscode": 2000, "shortmessage": "ok",
                    "longmessage": "", "responsedata": data }),
        )
    };
    if zone.revoked || param["apikey"] != "nc-api-key" || param["customernumber"] != "12345" {
        return failed(4013, "Customer account not found. key nc-api-key");
    }
    if body["action"] == "login" {
        assert_eq!(param["apipassword"], "nc-api-password");
        zone.note("session");
        let id = format!("session-{}", zone.notes["session"]);
        return success(json!({ "apisessionid": id }));
    }
    let current = format!(
        "session-{}",
        zone.notes.get("session").copied().unwrap_or(0)
    );
    if param["apisessionid"] != current.as_str() {
        return failed(4001, "The session id is not in a valid format.");
    }
    if param["domainname"] != ORIGIN {
        return failed(5029, "Can not get DNS records for zone. Domain not found.");
    }
    match body["action"].as_str().unwrap() {
        "infoDnsRecords" => {
            let records: Vec<Value> = zone
                .records
                .iter()
                .map(|rec| {
                    json!({ "id": rec.id.to_string(), "hostname": rec.label("@"),
                            "type": rec.ty, "priority": "0", "destination": rec.value,
                            "deleterecord": false, "state": "yes" })
                })
                .collect();
            success(json!({ "dnsrecords": records }))
        }
        "updateDnsRecords" => {
            zone.writes += 1;
            for record in param["dnsrecordset"]["dnsrecords"].as_array().unwrap() {
                let ty = record["type"].as_str().unwrap();
                let name = absolute(record["hostname"].as_str().unwrap());
                let value = from_bare(ty, record["destination"].as_str().unwrap());
                let id = record["id"].as_str().unwrap_or_default();
                if !id.is_empty() {
                    let rec = zone.by_id(id).unwrap();
                    assert_eq!((rec.name.as_str(), rec.ty.as_str()), (name.as_str(), ty));
                    if record["deleterecord"] == true {
                        assert_eq!(rec.value, value);
                        zone.delete_id(id);
                    } else {
                        rec.value = value;
                    }
                } else {
                    zone.add(&name, ty, &value, 86400);
                }
            }
            success(json!({}))
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn netcup_legacy_records() {
    let harness = check(Service {
        id: "netcup",
        fields: vec![
            ("customer_number", "12345".to_string()),
            ("api_key", "nc-api-key".to_string()),
            ("api_password", "nc-api-password".to_string()),
        ],
        hosts: &["ccp.netcup.net"],
        mock: netcup,
        limited: || {
            Response::new(
                200,
                json!({ "status": "error", "statuscode": 4013,
                        "shortmessage": "Validation Error.",
                        "longmessage": "More than 180 requests per minute. Please wait and retry later." }),
            )
        },
        missing_zone: false,
    })
    .await;
    // A session that ended is replaced.
    let provider = harness.provider();
    let value = vec!["x".to_string()];
    let name = "s.example.com";
    provider
        .add_values(name, RecordType::TXT, 60, value.clone())
        .await
        .unwrap();
    harness.zone.lock().unwrap().note("session");
    provider
        .remove_values(name, RecordType::TXT, value)
        .await
        .unwrap();
    assert!(harness.values(name, "TXT").is_empty());
}

fn netcup_cloud(zone: &mut Zone, request: &Request) -> Response {
    let failed = |code: &str, message: &str| {
        Response::new(
            400,
            json!({ "success": false, "errors": [{ "code": code, "message": message }],
                    "messages": [], "meta": null, "result": null }),
        )
    };
    let success = |result: Value| {
        Response::new(
            200,
            json!({ "success": true, "errors": [], "messages": [],
                    "meta": { "pagination": { "page": 1, "lastPage": 1 } }, "result": result }),
        )
    };
    // The service does not see the header in lower case.
    if zone.revoked
        || request.bearer() != "netcup-cloud-key"
        || !request.names.iter().any(|name| name == "Authorization")
    {
        return failed("authenticationError", "Authentication failed");
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/v1/domain") if request.query("fqdn") == ORIGIN => {
            success(json!([{ "id": 7, "fqdn": ORIGIN, "isDnsManaged": true }]))
        }
        ("GET", "/v1/domain") => success(json!([])),
        ("GET", "/v1/domain/7/dns/revision") => success(json!([
            { "identifier": "r2", "state": "committed", "serial": 2 },
            { "identifier": "r1", "state": "committed", "serial": 1 },
            { "identifier": "r3", "state": "draft", "serial": null },
        ])),
        ("GET", "/v1/domain/7/dns/revision/r2/record") => {
            let records: Vec<Value> = zone
                .records
                .iter()
                .map(|rec| {
                    json!({ "identifier": rec.id.to_string(), "name": rec.label("@"),
                            "type": rec.ty, "rdata": rec.zone_file(), "ttl": rec.ttl,
                            "immutable": rec.ty == "NS" })
                })
                .collect();
            success(json!(records))
        }
        ("POST", "/v1/domain/7/changeset") => {
            zone.writes += 1;
            let body = request.json();
            assert_eq!(body["autoCommit"], true);
            for item in body["delete"].as_array().into_iter().flatten() {
                let ty = item["type"].as_str().unwrap();
                let name = absolute(item["name"].as_str().unwrap());
                let value = from_zone_file(ty, item["rdata"].as_str().unwrap());
                let before = zone.records.len();
                zone.records
                    .retain(|rec| !(rec.name == name && rec.ty == ty && rec.value == value));
                assert_eq!(zone.records.len(), before - 1);
            }
            for item in body["create"].as_array().into_iter().flatten() {
                let ty = item["type"].as_str().unwrap();
                let value = from_zone_file(ty, item["rdata"].as_str().unwrap());
                let name = absolute(item["name"].as_str().unwrap());
                zone.add(&name, ty, &value, item["ttl"].as_u64().unwrap());
            }
            success(json!({ "identifier": "r3", "state": "committed" }))
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn netcup_cloud_dns_records() {
    check(Service {
        id: "netcup",
        fields: vec![("api_key", "netcup-cloud-key".to_string())],
        hosts: &["api.netcup.com"],
        mock: netcup_cloud,
        limited: too_many,
        missing_zone: true,
    })
    .await;
}

fn transip(zone: &mut Zone, request: &Request) -> Response {
    let failed = |status: u16, text: &str| Response::new(status, json!({ "error": text }));
    if request.path == "/v6/auth" {
        let signature = STANDARD.decode(request.header("signature")).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha512(), &RSA_KEY).unwrap();
        if zone.revoked
            || !verifier
                .verify_oneshot(&signature, request.body.as_bytes())
                .unwrap()
        {
            return failed(401, "Invalid signature");
        }
        let body = request.json();
        assert_eq!(body["login"], "alice");
        assert!((6..=32).contains(&body["nonce"].as_str().unwrap().len()));
        return Response::new(201, json!({ "token": "transip-access" }));
    }
    if request.bearer() != "transip-access" {
        return failed(401, "Your access token is invalid.");
    }
    let Some(ORIGIN) = request
        .path
        .strip_prefix("/v6/domains/")
        .and_then(|path| path.strip_suffix("/dns"))
    else {
        return failed(404, "Domain with name 'missing.example' not found");
    };
    let busy = zone.notes.remove("saving").is_some();
    if busy && request.method != "GET" {
        return failed(409, "DNS Entries are currently being saved");
    }
    // Targets inside of the zone are relative.
    let content = |rec: &crate::zone::Rec| match rec.ty.as_str() {
        "CNAME" if rec.value == ORIGIN => "@".to_string(),
        _ => rec.dotted(),
    };
    if request.method == "GET" {
        let entries: Vec<Value> = zone
            .records
            .iter()
            .map(|rec| {
                json!({ "name": rec.label("@"), "expire": rec.ttl, "type": rec.ty,
                        "content": content(rec) })
            })
            .collect();
        return Response::new(200, json!({ "dnsEntries": entries }));
    }
    zone.writes += 1;
    zone.notes.insert("saving".to_string(), 1);
    let entry = request.json()["dnsEntry"].clone();
    let ty = entry["type"].as_str().unwrap();
    let name = absolute(entry["name"].as_str().unwrap());
    match request.method.as_str() {
        "POST" => {
            let value = from_dotted(ty, entry["content"].as_str().unwrap());
            zone.add(&name, ty, &value, entry["expire"].as_u64().unwrap());
            Response::new(201, "")
        }
        "DELETE" => {
            let before = zone.records.len();
            zone.records.retain(|rec| {
                !(rec.name == name
                    && rec.ty == ty
                    && entry["content"] == content(rec).as_str()
                    && entry["expire"] == rec.ttl)
            });
            assert_eq!(zone.records.len(), before - 1);
            Response::new(204, "")
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn transip_entries() {
    check(Service {
        id: "transip",
        fields: vec![("login", "alice".to_string()), ("private_key", rsa_pem())],
        hosts: &["api.transip.nl"],
        mock: transip,
        limited: || Response::new(429, "").header("X-Rate-Limit-Reset", 1_700_000_000),
        missing_zone: true,
    })
    .await;
}

fn sakura_hash(zone: &Zone) -> String {
    let text = format!("{:?}", zone.records);
    let digest = hash(MessageDigest::md5(), text.as_bytes()).unwrap();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sakura(zone: &mut Zone, request: &Request) -> Response {
    let expected = format!("Basic {}", STANDARD.encode("sk-token:sk-secret-value"));
    if zone.revoked || request.header("authorization") != expected {
        return Response::new(
            401,
            json!({ "is_fatal": true, "status": "401 Unauthorized",
                    "error_code": "unauthorized", "error_msg": "error-unauthorized" }),
        );
    }
    let path = request
        .path
        .strip_prefix("/cloud/zone/is1a/api/cloud/1.1/commonserviceitem")
        .unwrap();
    let item = |zone: &Zone| {
        let records: Vec<Value> = zone
            .records
            .iter()
            .map(|rec| {
                let mut record = json!({ "Name": rec.label("@"), "Type": rec.ty,
                                         "RData": rec.dotted(), "TTL": rec.ttl });
                if !rec.mark.is_empty() {
                    record["Extra"] = json!(rec.mark);
                }
                record
            })
            .collect();
        json!({ "ID": "112900000001", "Name": "label", "Status": { "Zone": ORIGIN },
                "Settings": { "DNS": { "ResourceRecordSets": records, "Other": { "keep": 1 } } },
                "SettingsHash": sakura_hash(zone), "ServiceClass": "cloud/dns" })
    };
    match (request.method.as_str(), path) {
        ("GET", "") => {
            let raw: String =
                url::form_urlencoded::parse(format!("q={}", request.raw_query).as_bytes())
                    .next()
                    .unwrap()
                    .1
                    .into_owned();
            let filter: Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(filter["Filter"]["Provider.Class"], "dns");
            // One item per page.
            let items = match filter["From"].as_u64().unwrap() {
                0 => json!([{ "ID": "1", "Status": { "Zone": "other.jp" } }]),
                1 => json!([item(zone)]),
                _ => json!([]),
            };
            Response::new(200, json!({ "Total": 2, "CommonServiceItems": items }))
        }
        ("GET", "/112900000001") => {
            // Somebody else writes between reading and writing.
            let body = json!({ "CommonServiceItem": item(zone), "is_ok": true });
            if zone.notes.remove("race").is_some() {
                let name = absolute(&format!("raced{}", zone.writes));
                zone.add(&name, "TXT", "somebody else", 3600);
            }
            Response::new(200, body)
        }
        ("PUT", "/112900000001") => {
            let body = request.json();
            if body["OriginalSettingsHash"] != sakura_hash(zone).as_str() {
                return Response::new(409, json!({ "error_code": "conflict" }));
            }
            let settings = &body["CommonServiceItem"]["Settings"]["DNS"];
            assert_eq!(settings["Other"], json!({ "keep": 1 }));
            let mut records = Vec::new();
            for record in settings["ResourceRecordSets"].as_array().unwrap() {
                let ty = record["Type"].as_str().unwrap();
                let name = absolute(record["Name"].as_str().unwrap());
                let value = from_dotted(ty, record["RData"].as_str().unwrap());
                let ttl = record["TTL"].as_u64().unwrap();
                let old = zone
                    .at(&name, ty)
                    .into_iter()
                    .find(|rec| rec.value == value);
                let mark = record["Extra"].as_str().unwrap_or_default().to_string();
                records.push((
                    old.map(|rec| rec.id),
                    name,
                    ty.to_string(),
                    value,
                    ttl,
                    mark,
                ));
            }
            for (_, name, _, _, ttl, _) in &records {
                assert!(
                    records
                        .iter()
                        .all(|other| other.1 != *name || other.4 == *ttl),
                    "the records of {name} have different TTLs"
                );
            }
            zone.writes += 1;
            zone.records.clear();
            for (id, name, ty, value, ttl, mark) in records {
                let mut rec = zone.add(&name, &ty, &value, ttl);
                let added = zone.records.last_mut().unwrap();
                added.id = id.unwrap_or(rec.id);
                added.mark = mark;
                rec.id = added.id;
            }
            if zone.notes.remove("drop").is_some() {
                zone.records.remove(0);
            }
            Response::new(200, json!({ "Success": true, "is_ok": true }))
        }
        other => panic!("{other:?}"),
    }
}

fn sakura_service() -> Service {
    Service {
        id: "sakura",
        fields: vec![
            ("access_token", "sk-token".to_string()),
            ("access_token_secret", "sk-secret-value".to_string()),
        ],
        hosts: &["secure.sakura.ad.jp"],
        mock: sakura,
        limited: || Response::new(503, "").header("retry-after", 0),
        missing_zone: true,
    }
}

#[tokio::test]
async fn sakura_zone() {
    let harness: Harness = check(sakura_service()).await;
    let name = "race.example.com";
    let provider = harness.provider();

    // A change made in between is kept, the write starts over.
    harness
        .zone
        .lock()
        .unwrap()
        .notes
        .insert("race".to_string(), 1);
    let value = vec!["one".to_string()];
    provider
        .add_values(name, RecordType::TXT, 60, value.clone())
        .await
        .unwrap();
    assert_eq!(harness.values(name, "TXT"), ["one"]);
    let raced = harness
        .zone
        .lock()
        .unwrap()
        .records
        .iter()
        .filter(|rec| rec.value == "somebody else")
        .count();
    assert_eq!(raced, 1);

    // Parallel writers of one zone do not lose each other's records.
    let names: Vec<String> = (0..6)
        .map(|index| format!("p{index}.example.com"))
        .collect();
    let writers: Vec<_> = names
        .iter()
        .map(|name| {
            let provider = harness.provider();
            let name = name.clone();
            tokio::spawn(async move {
                provider
                    .add_values(&name, RecordType::TXT, 60, vec![name.clone()])
                    .await
                    .unwrap();
            })
        })
        .collect();
    for writer in writers {
        writer.await.unwrap();
    }
    for name in &names {
        assert_eq!(harness.values(name, "TXT"), [name.as_str()]);
    }

    // Reading back notices that something got lost.
    harness
        .zone
        .lock()
        .unwrap()
        .notes
        .insert("drop".to_string(), 1);
    let error = provider
        .add_values("lost.example.com", RecordType::TXT, 60, value)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("read back"), "{error}");
}

#[tokio::test]
async fn endpoint_replaces_the_address() {
    let service = Service {
        id: "gandi",
        fields: vec![("personal_access_token", "gandi-secret-pat".to_string())],
        hosts: &["api.sandbox.gandi.net"],
        mock: gandi,
        limited: too_many,
        missing_zone: true,
    };
    let mut harness = start(&service);
    harness.credential.endpoint = Some("https://api.sandbox.gandi.net/v5/".to_string());
    let value = vec!["x".to_string()];
    harness
        .provider()
        .add_values("sandbox.example.com", RecordType::TXT, 300, value)
        .await
        .unwrap();
    assert_eq!(harness.values("sandbox.example.com", "TXT"), ["x"]);

    harness.credential.provider = "ionos".to_string();
    harness.credential.fields = [("api_key".to_string(), "k".to_string())].into();
    assert!(matches!(
        cyfs_dns_provider::create_provider(&harness.credential, ORIGIN).err(),
        Some(DnsProviderError::Unsupported(_))
    ));
}
