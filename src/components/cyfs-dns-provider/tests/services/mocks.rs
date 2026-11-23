//! The services `dns-update` handles. Each mock follows the vendor's API
//! reference and refuses what the service would refuse.

use serde_json::{Value, json};

use crate::net::{Request, Response};
use crate::zone::{
    ORIGIN, Service, Zone, absolute, check, from_bare, from_dotted, from_zone_file, unquoted,
};

pub fn too_many() -> Response {
    Response::new(429, json!({ "message": "slow down" })).header("retry-after", 0)
}

fn porkbun(zone: &mut Zone, request: &Request) -> Response {
    let body = request.json();
    let error = |code: &str, message: &str| {
        Response::new(
            400,
            json!({ "status": "ERROR", "code": code, "message": message }),
        )
    };
    if zone.revoked
        || body["apikey"] != "pk1-key-value"
        || body["secretapikey"] != "sk1-secret-value"
    {
        return error("INVALID_API_KEYS_001", "Invalid API key. (001)");
    }
    let path: Vec<&str> = request
        .path
        .strip_prefix("/api/json/v3/dns/")
        .unwrap()
        .split('/')
        .collect();
    if path[1] != ORIGIN {
        return error("INVALID_DOMAIN", "Invalid domain.");
    }
    let success = || Response::new(200, json!({ "status": "SUCCESS" }));
    match path[0] {
        "retrieveByNameType" => {
            let name = absolute(path.get(3).unwrap_or(&""));
            let records: Vec<Value> = zone
                .at(&name, path[2])
                .iter()
                .map(|rec| {
                    json!({
                        "id": rec.id.to_string(), "name": rec.name, "type": rec.ty,
                        "content": rec.value, "ttl": rec.ttl.to_string(), "prio": "0", "notes": "",
                    })
                })
                .collect();
            Response::new(200, json!({ "status": "SUCCESS", "records": records }))
        }
        "create" => {
            let ty = body["type"].as_str().unwrap();
            let ttl = body["ttl"].as_u64().unwrap();
            assert!(ttl >= 600);
            let value = from_bare(ty, body["content"].as_str().unwrap());
            let name = absolute(body["name"].as_str().unwrap());
            zone.writes += 1;
            let rec = zone.add(&name, ty, &value, ttl);
            Response::new(200, json!({ "status": "SUCCESS", "id": rec.id }))
        }
        "delete" => {
            zone.writes += 1;
            assert!(zone.delete_id(path[2]));
            success()
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn porkbun_records() {
    check(Service {
        id: "porkbun",
        fields: vec![
            ("api_key", "pk1-key-value".to_string()),
            ("secret_api_key", "sk1-secret-value".to_string()),
        ],
        hosts: &["api.porkbun.com"],
        mock: porkbun,
        limited: too_many,
        missing_zone: true,
    })
    .await;
}

fn ionos(zone: &mut Zone, request: &Request) -> Response {
    if zone.revoked || request.header("x-api-key") != "prefix.ionos-secret" {
        return Response::new(401, json!({ "message": "Missing or invalid API key." }));
    }
    let path = request.path.strip_prefix("/dns/v1/zones").unwrap();
    match (request.method.as_str(), path) {
        ("GET", "") => Response::new(
            200,
            json!([
                { "id": "z0", "name": "otherexample.com", "type": "NATIVE" },
                { "id": "z1", "name": ORIGIN, "type": "NATIVE" },
            ]),
        ),
        ("GET", "/z1") => {
            let records: Vec<Value> = zone
                .at(request.query("recordName"), request.query("recordType"))
                .iter()
                .map(|rec| {
                    let content = if rec.ty == "TXT" {
                        rec.zone_file()
                    } else {
                        rec.value.clone()
                    };
                    json!({
                        "id": rec.id.to_string(), "name": rec.name, "rootName": ORIGIN,
                        "type": rec.ty, "content": content, "ttl": rec.ttl, "prio": 0,
                        "disabled": false,
                    })
                })
                .collect();
            Response::new(
                200,
                json!({ "id": "z1", "name": ORIGIN, "records": records }),
            )
        }
        ("POST", "/z1/records") => {
            zone.writes += 1;
            for rec in request.json().as_array().unwrap() {
                let ty = rec["type"].as_str().unwrap();
                let content = rec["content"].as_str().unwrap();
                let value = match ty {
                    "TXT" => unquoted(content),
                    _ => from_bare(ty, content),
                };
                zone.add(
                    rec["name"].as_str().unwrap(),
                    ty,
                    &value,
                    rec["ttl"].as_u64().unwrap(),
                );
            }
            Response::new(201, json!([]))
        }
        ("DELETE", path) => {
            zone.writes += 1;
            assert!(zone.delete_id(path.strip_prefix("/z1/records/").unwrap()));
            Response::new(200, "")
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn ionos_records() {
    check(Service {
        id: "ionos",
        fields: vec![("api_key", "prefix.ionos-secret".to_string())],
        hosts: &["api.hosting.ionos.com"],
        mock: ionos,
        limited: || Response::new(429, json!({ "message": "API rate limit exceeded" })),
        missing_zone: true,
    })
    .await;
}

fn azure(zone: &mut Zone, request: &Request) -> Response {
    if request.host == "login.microsoftonline.com" {
        assert_eq!(request.path, "/tenant-1/oauth2/v2.0/token");
        if zone.revoked || !request.body.contains("client_secret=azure-secret-value") {
            return Response::new(
                401,
                json!({ "error": "invalid_client",
                        "error_description": "AADSTS7000215: Invalid client secret provided." }),
            );
        }
        return Response::new(
            200,
            json!({ "access_token": "azure-access", "expires_in": 3599, "token_type": "Bearer" }),
        );
    }
    assert_eq!(request.bearer(), "azure-access");
    let prefix =
        "/subscriptions/sub-1/resourceGroups/group-1/providers/Microsoft.Network/dnsZones/";
    let path: Vec<&str> = request
        .path
        .strip_prefix(prefix)
        .unwrap()
        .split('/')
        .collect();
    let not_found = |code: &str| Response::new(404, json!({ "error": { "code": code } }));
    if path[0] != ORIGIN {
        return not_found(if request.method == "PUT" {
            "ParentResourceNotFound"
        } else {
            "ResourceNotFound"
        });
    }
    let (ty, name) = (path[1], absolute(path[2]));
    let records = zone.at(&name, ty);
    let etag = format!("{:?}", records.iter().map(|rec| rec.id).collect::<Vec<_>>());
    if !request.header("if-match").is_empty() && request.header("if-match") != etag {
        return Response::new(412, json!({ "code": "PreconditionFailed" }));
    }
    let key = match ty {
        "CNAME" => "CNAMERecord".to_string(),
        ty => format!("{ty}Records"),
    };
    match request.method.as_str() {
        "GET" if records.is_empty() => Response::new(
            404,
            json!({ "code": "NotFound", "message": "no record set" }),
        ),
        "GET" => {
            let values: Vec<Value> = records
                .iter()
                .map(|rec| match ty {
                    "A" => json!({ "ipv4Address": rec.value }),
                    "AAAA" => json!({ "ipv6Address": rec.value }),
                    "CNAME" => json!({ "cname": rec.value }),
                    "TXT" => json!({ "value": [rec.value] }),
                    other => panic!("{other}"),
                })
                .collect();
            let mut properties = json!({ "TTL": records[0].ttl });
            properties[&key] = if ty == "CNAME" {
                values[0].clone()
            } else {
                json!(values)
            };
            Response::new(
                200,
                json!({ "name": path[2], "type": format!("Microsoft.Network/dnszones/{ty}"),
                        "etag": etag, "properties": properties }),
            )
        }
        "PUT" => {
            zone.writes += 1;
            let body = request.json();
            let properties = &body["properties"];
            let value = |item: &Value| match ty {
                "A" => item["ipv4Address"].as_str().unwrap().to_string(),
                "AAAA" => item["ipv6Address"].as_str().unwrap().to_string(),
                "CNAME" => item["cname"].as_str().unwrap().to_string(),
                "TXT" => item["value"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(Value::as_str)
                    .collect(),
                other => panic!("{other}"),
            };
            let values: Vec<String> = match &properties[&key] {
                Value::Array(items) => items.iter().map(value).collect(),
                item => vec![value(item)],
            };
            zone.set(&name, ty, properties["TTL"].as_u64().unwrap(), &values);
            Response::new(200, json!({}))
        }
        "DELETE" => {
            zone.writes += 1;
            zone.set(&name, ty, 0, &[]);
            Response::new(if records.is_empty() { 204 } else { 200 }, "")
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn azure_record_sets() {
    check(Service {
        id: "azure",
        fields: vec![
            ("tenant_id", "tenant-1".to_string()),
            ("client_id", "client-1".to_string()),
            ("client_secret", "azure-secret-value".to_string()),
            ("subscription_id", "sub-1".to_string()),
            ("resource_group", "group-1".to_string()),
        ],
        hosts: &["login.microsoftonline.com", "management.azure.com"],
        mock: azure,
        limited: too_many,
        missing_zone: true,
    })
    .await;
}

fn desec(zone: &mut Zone, request: &Request) -> Response {
    if zone.revoked || request.header("authorization") != "Token desec-secret-token" {
        return Response::new(
            401,
            json!({ "detail": "Invalid token.", "code": "authentication_failed" }),
        );
    }
    let not_found = || Response::new(404, json!({ "detail": "Not found." }));
    let path: Vec<&str> = request
        .path
        .strip_prefix("/api/v1/domains/")
        .unwrap()
        .trim_end_matches('/')
        .split('/')
        .collect();
    if path[0] != ORIGIN {
        return not_found();
    }
    let describe = |zone: &Zone, subname: &str, ty: &str| {
        let records = zone.at(&absolute(subname), ty);
        json!({
            "created": "2026-01-01T00:00:00Z", "touched": "2026-01-01T00:00:00Z",
            "domain": ORIGIN, "subname": subname, "name": format!("{}.", absolute(subname)),
            "type": ty, "ttl": records.first().map_or(3600, |rec| rec.ttl),
            "records": records.iter().map(|rec| rec.zone_file()).collect::<Vec<_>>(),
        })
    };
    let store = |zone: &mut Zone, item: &Value| {
        let ty = item["type"].as_str().unwrap();
        let ttl = item["ttl"].as_u64().unwrap();
        assert!(ttl >= 3600, "below the domain's minimum_ttl");
        let values: Vec<String> = item["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| from_zone_file(ty, value.as_str().unwrap()))
            .collect();
        let name = absolute(item["subname"].as_str().unwrap());
        zone.set(&name, ty, ttl, &values);
    };
    match (request.method.as_str(), path.len()) {
        ("GET", 1) => Response::new(200, json!({ "name": ORIGIN, "minimum_ttl": 3600 })),
        ("GET", 4) => {
            if zone.at(&absolute(path[2]), path[3]).is_empty() {
                return not_found();
            }
            Response::new(
                200,
                describe(zone, path[2].trim_start_matches('@'), path[3]),
            )
        }
        ("PUT", 2) => {
            zone.writes += 1;
            let body = request.json();
            for item in body.as_array().unwrap() {
                store(zone, item);
            }
            let item = &body[0];
            Response::new(
                200,
                json!([describe(
                    zone,
                    item["subname"].as_str().unwrap(),
                    item["type"].as_str().unwrap()
                )]),
            )
        }
        ("POST" | "PUT", _) => {
            zone.writes += 1;
            let item = request.json();
            store(zone, &item);
            Response::new(
                200,
                describe(
                    zone,
                    item["subname"].as_str().unwrap(),
                    item["type"].as_str().unwrap(),
                ),
            )
        }
        ("DELETE", 4) => {
            zone.writes += 1;
            zone.set(&absolute(path[2]), path[3], 0, &[]);
            Response::new(204, "")
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn desec_rrsets() {
    check(Service {
        id: "desec",
        fields: vec![("api_token", "desec-secret-token".to_string())],
        hosts: &["desec.io"],
        mock: desec,
        limited: too_many,
        missing_zone: true,
    })
    .await;
}

fn alidns(zone: &mut Zone, request: &Request) -> Response {
    let failed = |status: u16, code: &str| {
        Response::new(
            status,
            json!({ "RequestId": "r", "Code": code, "Message": "refused" }),
        )
    };
    let authorization = request.header("authorization");
    assert!(authorization.starts_with("ACS3-HMAC-SHA256 Credential=ali-id,SignedHeaders="));
    if zone.revoked {
        return failed(404, "InvalidAccessKeyId.NotFound");
    }
    match request.query("Action") {
        "DescribeDomains" => Response::new(
            200,
            json!({ "TotalCount": 1, "PageSize": 100, "PageNumber": 1,
                    "Domains": { "Domain": [{ "DomainName": ORIGIN, "PunyCode": ORIGIN }] } }),
        ),
        "DescribeDomainRecords" => {
            // The service ignores the label and type in this search mode.
            let records: Vec<Value> = zone
                .records
                .iter()
                .map(|rec| {
                    json!({ "RecordId": rec.id.to_string(), "RR": rec.label("@"),
                            "Type": rec.ty, "Value": rec.value, "TTL": rec.ttl, "Line": "default" })
                })
                .collect();
            Response::new(200, json!({ "DomainRecords": { "Record": records } }))
        }
        "AddDomainRecord" => {
            zone.writes += 1;
            let ttl: u64 = request.query("TTL").parse().unwrap();
            if ttl < 600 {
                return failed(400, "QuotaExceeded.TTL");
            }
            let ty = request.query("Type");
            let value = from_bare(ty, request.query("Value"));
            zone.add(&absolute(request.query("RR")), ty, &value, ttl);
            Response::new(200, json!({ "RecordId": "1" }))
        }
        "DeleteDomainRecord" => {
            zone.writes += 1;
            assert!(zone.delete_id(request.query("RecordId")));
            Response::new(200, json!({ "RecordId": "1" }))
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn alidns_records() {
    check(Service {
        id: "alidns",
        fields: vec![
            ("access_key_id", "ali-id".to_string()),
            ("access_key_secret", "ali-secret-value".to_string()),
        ],
        hosts: &["alidns.aliyuncs.com"],
        mock: alidns,
        limited: || Response::new(400, json!({ "Code": "Throttling.User", "Message": "busy" })),
        missing_zone: true,
    })
    .await;
}

fn dnspod(zone: &mut Zone, request: &Request) -> Response {
    let reply = |body: Value| Response::new(200, json!({ "Response": body }));
    let failed = |code: &str| reply(json!({ "Error": { "Code": code, "Message": "refused" } }));
    let authorization = request.header("authorization");
    assert!(authorization.starts_with("TC3-HMAC-SHA256 Credential=pod-id/"));
    if zone.revoked {
        return failed("AuthFailure.SecretIdNotFound");
    }
    let body = request.json();
    match request.header("x-tc-action") {
        "DescribeDomainList" => reply(json!({
            "DomainCountInfo": { "AllTotal": 2 },
            "DomainList": [
                { "DomainId": 1, "Name": "other.com", "Punycode": "" },
                { "DomainId": 2, "Name": ORIGIN, "Punycode": "" },
            ],
        })),
        "DescribeRecordList" => {
            let records: Vec<Value> = zone
                .at(
                    &absolute(body["Subdomain"].as_str().unwrap()),
                    body["RecordType"].as_str().unwrap(),
                )
                .iter()
                .map(|rec| {
                    json!({ "RecordId": rec.id, "Name": rec.label("@"), "Type": rec.ty,
                            "Value": rec.dotted(), "TTL": rec.ttl, "Line": "默认" })
                })
                .collect();
            if records.is_empty() {
                return failed("ResourceNotFound.NoDataOfRecord");
            }
            reply(json!({ "RecordList": records }))
        }
        "CreateRecord" => {
            zone.writes += 1;
            let ttl = body["TTL"].as_u64().unwrap();
            if ttl < 600 {
                return failed("LimitExceeded.RecordTtlLimit");
            }
            let ty = body["RecordType"].as_str().unwrap();
            let value = from_dotted(ty, body["Value"].as_str().unwrap());
            zone.add(
                &absolute(body["SubDomain"].as_str().unwrap()),
                ty,
                &value,
                ttl,
            );
            reply(json!({ "RecordId": 1 }))
        }
        "DeleteRecord" => {
            zone.writes += 1;
            assert_eq!(body["Domain"], ORIGIN);
            assert!(zone.delete_id(&body["RecordId"].to_string()));
            reply(json!({ "RequestId": "r" }))
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn dnspod_records() {
    check(Service {
        id: "dnspod",
        fields: vec![
            ("secret_id", "pod-id".to_string()),
            ("secret_key", "pod-secret-value".to_string()),
        ],
        hosts: &["dnspod.tencentcloudapi.com"],
        mock: dnspod,
        limited: || {
            Response::new(
                200,
                json!({ "Response": { "Error": {
                    "Code": "RequestLimitExceeded.UinLimitExceeded", "Message": "busy" } } }),
            )
        },
        missing_zone: true,
    })
    .await;
}
