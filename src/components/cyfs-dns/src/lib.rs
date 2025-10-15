#![allow(unused)]

mod dns_server;
mod resolve;
mod local_dns;

use std::net::IpAddr;
use std::sync::Arc;
use hickory_proto::rr::{Name, RData};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
use log::{debug, warn};
use name_client::NameInfo;
use name_lib::EncodedDocument;
use cyfs_gateway_lib::{into_server_err, server_err, ServerErrorCode, ServerResult};
use cyfs_process_chain::{CollectionValue, MapCollectionRef, MemoryMapCollection, MemorySetCollection};
use cyfs_process_chain::SetCollection;
pub use dns_server::*;
pub use local_dns::*;

pub(crate) async fn nameinfo_to_map_collection(record_type: &str, name_info: &NameInfo) -> ServerResult<MapCollectionRef> {
    let map = MemoryMapCollection::new_ref();
    map.insert("record_type", CollectionValue::String(record_type.to_string())).await
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add record_type {} err {}", record_type, e))?;
    if name_info.ttl.is_some() {
        map.insert("ttl", CollectionValue::String(name_info.ttl.unwrap().to_string())).await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add ttl {} err {}", name_info.ttl.unwrap(), e))?;
    }
    map.insert("name", CollectionValue::String(name_info.name.clone())).await
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add name {} err {}", name_info.name, e))?;
    match record_type {
        "A" => {
            if name_info.address.is_empty() {
                return Err(server_err!(ServerErrorCode::InvalidParam, "Address is none"));
            }

            let ip_set = MemorySetCollection::new();
            // Convert all IPv4 addresses to A records
            for addr in name_info.address.iter() {
                match addr {
                    IpAddr::V4(addr) => {
                        ip_set.insert(addr.to_string().as_str()).await
                            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add address {} err {}", addr, e))?;
                    }
                    _ => {
                        debug!("Skipping non-IPv4 address");
                        continue;
                    }
                }
            }

            if ip_set.len().await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "get ip_set len err {}", e))? == 0 {
                return Err(server_err!(ServerErrorCode::InvalidParam, "No valid IPv4 addresses found"));
            }
            map.insert("address", CollectionValue::Set(Arc::new(Box::new(ip_set)))).await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add address err {}", e))?;
            Ok(map)
        }
        "AAAA" => {
            if name_info.address.is_empty() {
                return Err(server_err!(ServerErrorCode::InvalidParam, "Address is none"));
            }
            let ip_set = MemorySetCollection::new();
            // Convert all IPv6 addresses to AAAA records
            for addr in name_info.address.iter() {
                match addr {
                    IpAddr::V6(addr) => {
                        ip_set.insert(addr.to_string().as_str()).await
                            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add address {} err {}", addr, e))?;
                    }
                    _ => {
                        debug!("Skipping non-IPv6 address");
                        continue;
                    }
                }
            }

            if ip_set.len().await.map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "get ip_set len err {}", e))? == 0 {
                return Err(server_err!(ServerErrorCode::InvalidParam, "No valid IPv6 addresses found"));
            }
            map.insert("address", CollectionValue::Set(Arc::new(Box::new(ip_set)))).await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add address err {}", e))?;
            Ok(map)
        }
        "CNAME" => {
            if name_info.cname.is_none() {
                return Err(server_err!(ServerErrorCode::InvalidParam, "CNAME is none"));
            }
            let cname = name_info.cname.clone().unwrap();
            map.insert("cname", CollectionValue::String(cname)).await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add cname {:?} err {}", name_info.cname, e))?;
            return Ok(map);
        }
        "TXT" => {
            if name_info.txt.is_some() {
                let txt = name_info.txt.clone().unwrap();
                map.insert("txt", CollectionValue::String(txt.clone())).await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add txt {} err {}", txt, e))?;
            }

            if name_info.did_document.is_some() {
                let did_string = name_info.did_document.as_ref().unwrap().to_string();
                map.insert("did_document", CollectionValue::String(did_string.clone())).await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add did_document {} err {}", did_string, e))?;
            }

            if name_info.pk_x_list.is_some() {
                let set = MemorySetCollection::new();
                let pk_x_list = name_info.pk_x_list.as_ref().unwrap();
                for pk_x in pk_x_list.iter() {
                    set.insert(pk_x).await
                        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add pk_x {} err {}", pk_x, e))?;
                }
                map.insert("pk_x_list", CollectionValue::Set(Arc::new(Box::new(set)))).await
                    .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add pk_x_list {:?} err {}", name_info.pk_x_list, e))?;
            }

            return Ok(map);
        }
        _ => {
            return Err(server_err!(ServerErrorCode::InvalidParam, "Unknown record type:{}", record_type));
        }
    }
}

pub(crate) async fn map_collection_to_nameinfo(map: &MapCollectionRef) -> ServerResult<NameInfo> {
    let record_type = map.get("record_type").await
        .map_err(|_e| server_err!(ServerErrorCode::ProcessChainError, "get record_type err"))?
        .ok_or_else(|| server_err!(ServerErrorCode::ProcessChainError, "record_type is none"))?;
    let record_type = match record_type {
        CollectionValue::String(s) => s,
        _ => return Err(server_err!(ServerErrorCode::ProcessChainError, "record_type is not string"))
    };
    let ttl = map.get("ttl").await
        .map_err(|_e| server_err!(ServerErrorCode::ProcessChainError, "get ttl err"))?;
    let ttl = if let Some(ttl) = ttl {
        match ttl {
            CollectionValue::String(n) => n.parse::<u32>().map_err(|_e| server_err!(ServerErrorCode::ProcessChainError, "ttl is not number"))?,
            _ => return Err(server_err!(ServerErrorCode::ProcessChainError, "ttl is not number")),
        }
    } else {
        600
    };

    let name = map.get("name").await
        .map_err(|_e| server_err!(ServerErrorCode::ProcessChainError, "get name err"))?
        .ok_or_else(|| server_err!(ServerErrorCode::ProcessChainError, "name is none"))?;
    let name = match name {
        CollectionValue::String(s) => s,
        _ => return Err(server_err!(ServerErrorCode::ProcessChainError, "name is not string"))
    };

    match record_type.as_str() {
        "A" => {
            let address = map.get("address").await
                .map_err(|_e| server_err!(ServerErrorCode::ProcessChainError, "get address err"))?
                .ok_or_else(|| server_err!(ServerErrorCode::ProcessChainError, "address is none"))?;
            match address {
                CollectionValue::Set(s) => {
                    let mut addresses = Vec::new();
                    let all = s.get_all().await
                        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "get address set all err {}", e))?;
                    for item in all.iter() {
                        addresses.push(item.parse::<IpAddr>().map_err(into_server_err!(ServerErrorCode::ProcessChainError, "parse ip err"))?);
                    }
                    let mut name_info = NameInfo::from_address_vec(name.as_str(), addresses);
                    name_info.ttl = Some(ttl);
                    Ok(name_info)
                },
                _ => Err(server_err!(ServerErrorCode::ProcessChainError, "address is not set"))
            }
        }
        "AAAA" => {
            let address = map.get("address").await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "get address err {}", e))?;
            if let Some(address) = address {
                match address {
                    CollectionValue::Set(s) => {
                        let mut addresses = Vec::new();
                        let all = s.get_all().await
                            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "get address set all err {}", e))?;
                        for item in all.iter() {
                            addresses.push(item.parse::<IpAddr>().map_err(into_server_err!(ServerErrorCode::ProcessChainError, "parse ip err"))?);
                        }
                        let mut name_info = NameInfo::from_address_vec(name.as_str(), addresses);
                        name_info.ttl = Some(ttl);
                        Ok(name_info)
                    },
                    _ => Err(server_err!(ServerErrorCode::ProcessChainError, "address is not set"))
                }
            } else {
                return Err(server_err!(ServerErrorCode::ProcessChainError, "address is not exist"));
            }
        }
        "CNAME" => {
            let cname = map.get("cname").await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "get cname err {}", e))?;
            if let Some(cname) = cname {
                match cname {
                    CollectionValue::String(s) => {
                        let mut name_info = NameInfo::new(name.as_str());
                        name_info.cname = Some(s);
                        Ok(name_info)
                    },
                    _ => Err(server_err!(ServerErrorCode::ProcessChainError, "cname is not string"))
                }
            } else {
                return Err(server_err!(ServerErrorCode::ProcessChainError, "cname is not exist"));
            }
        }
        "TXT" => {
            let mut name_info = NameInfo::new(name.as_str());
            let txt = map.get("txt").await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "get txt err {}", e))?;
            if let Some(txt) = txt {
                match txt {
                    CollectionValue::String(s) => {
                        name_info.txt = Some(s);
                    },
                    _ => return Err(server_err!(ServerErrorCode::ProcessChainError, "txt is not string"))
                }
            }

            let did_document = map.get("did_document").await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "get did_document err {}", e))?;
            if let Some(did_document) = did_document {
                match did_document {
                    CollectionValue::String(s) => {
                        name_info.did_document = Some(EncodedDocument::from_str(s)
                            .map_err(into_server_err!(ServerErrorCode::ProcessChainError, "parse did_document err"))?);
                    }
                    _ => return Err(server_err!(ServerErrorCode::ProcessChainError, "did_document is not string"))
                }
            }

            let pk_x_list = map.get("pk_x_list").await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "get pk_x_list err {}", e))?;
            if let Some(pk_x_list) = pk_x_list {
                match pk_x_list {
                    CollectionValue::Set(s) => {
                        let mut pk_x_list = Vec::new();
                        let all = s.get_all().await
                            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "get pk_x_list set all err {}", e))?;
                        for item in all.iter() {
                            pk_x_list.push(item.clone());
                        }
                        name_info.pk_x_list = Some(pk_x_list);
                    }
                    _ => return Err(server_err!(ServerErrorCode::ProcessChainError, "pk_x_list is not set"))
                }
            }
            name_info.ttl = Some(ttl);
            Ok(name_info)
        }
        _ => {
            Err(server_err!(ServerErrorCode::InvalidParam, "Unknown record type:{}", record_type))
        }
    }
}
