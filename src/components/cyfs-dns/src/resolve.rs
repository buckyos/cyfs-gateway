use std::net::{IpAddr, SocketAddr};
use clap::{Arg, Command};
use hickory_proto::xfer::Protocol;
use log::error;
use name_client::{DnsProvider, NameInfo, NameProof, NsProvider, RecordType};
use name_lib::{EncodedDocument, DID};
use cyfs_gateway_lib::{server_err, InnerService, InnerServiceManagerRef, ServerResult};
use cyfs_process_chain::{command_help, CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, EnvLevel, ExternalCommand};
use crate::nameinfo_to_map_collection;

pub struct Resolve {
    name: String,
    cmd: Command,
    inner_services: InnerServiceManagerRef,
}

impl Resolve {
    pub fn new(inner_services: InnerServiceManagerRef) -> Self {
        let cmd = Command::new("resolve")
            .about("resolve a domain name")
            .after_help(
                r#"
Examples:
    resolve example.com A
    resolve example.com AAAA
    resolve example.com A 127.0.0.1
    resolve example.com A sn
                "#
            )
            .arg(
                Arg::new("domain")
                    .help("domain name")
                    .required(true)
                    .index(1),
            )
            .arg(
                Arg::new("record_type")
                    .help("The type of record to query")
                    .required(true)
                    .index(2),
            )
            .arg(
                Arg::new("server_address")
                    .help("Server address can be either a DNS server address or an inner service name. The local DNS server is used by default.")
                    .required(false)
                    .index(3),
            );

        Self {
            name: "resolve".to_string(),
            cmd,
            inner_services,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[async_trait::async_trait]
impl ExternalCommand for Resolve {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid resolve command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;
        Ok(())
    }

    async fn exec(&self,
                  context: &Context,
                  args: &[CollectionValue],
                  origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        let mut str_args = Vec::with_capacity(args.len());
        for arg in args.iter() {
            if !arg.is_string() {
                let msg = format!("Invalid argument type: expected string, got {:?}", arg);
                error!("{}", msg);
                return Err(msg);
            }
            str_args.push(arg.as_str().unwrap());
        }

        let matches = self.cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid resolve command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let domain = matches.get_one::<String>("domain").ok_or_else(|| {
            let msg = "Invalid resolve command: missing domain";
            error!("{}", msg);
            msg
        })?;

        let record_type_str = matches.get_one::<String>("record_type").ok_or_else(|| {
            let msg = "Invalid resolve command: missing record type";
            error!("{}", msg);
            msg
        })?;

        let record_type = RecordType::from_str(record_type_str.as_str()).ok_or_else(|| {
            let msg = format!("Invalid record type: {}", record_type_str);
            error!("{}", msg);
            msg
        })?;

        let server_address = matches.get_one::<String>("server_address");
        let name_info = if server_address.is_none() {
            let provider = DnsProvider::new(None);
            match provider.query(domain.as_str(), Some(record_type), None).await {
                Ok(name_info) => name_info,
                Err(e) => {
                    return Ok(CommandResult::Error(format!("Failed to resolve domain {} record_type {}: {:?}", domain, record_type_str, e)));
                }
            }
        } else {
            let server_address = server_address.unwrap();
            if let Ok(address) = server_address.parse::<IpAddr>() {
                let provider = DnsProvider::new(Some(server_address.to_string()));
                match provider.query(domain.as_str(), Some(record_type), None).await {
                    Ok(name_info) => name_info,
                    Err(e) => {
                        return Ok(CommandResult::Error(format!("Failed to resolve domain {} record_type {}: {:?}", domain, record_type_str, e)));
                    }
                }
            } else if let Ok(address) = server_address.parse::<SocketAddr>() {
                let provider = DnsProvider::new(Some(address.to_string()));
                match provider.query(domain.as_str(), Some(record_type), None).await {
                    Ok(name_info) => name_info,
                    Err(e) => {
                        return Ok(CommandResult::Error(format!("Failed to resolve domain {} record_type {}: {:?}", domain, record_type_str, e)));
                    }
                }
            } else {
                if let Some(service) = self.inner_services.get_service(server_address) {
                    if let InnerService::DnsService(dns_service) = service {
                        if record_type == RecordType::DID {
                            let did = DID::from_str(domain).map_err(|_e| {
                                let msg = format!("Invalid DID: {}", domain);
                                error!("{}", msg);
                                msg
                            })?;
                            match dns_service.query(domain, Some(record_type), None).await
                                .map_err(|e| {
                                    let msg = format!("Failed to resolve domain {} record_type {}: {:?}", domain, record_type_str, e);
                                    error!("{}", msg);
                                    msg
                                }) {
                                Ok(name_info) => name_info,
                                Err(e) => {
                                    return Ok(CommandResult::Error(e))
                                }
                            }
                            // match dns_service.query_did(&did, None, None).await
                            //     .map_err(|e| {
                            //         let msg = format!("Failed to resolve domain {} record_type {}: {:?}", domain, record_type_str, e);
                            //         error!("{}", msg);
                            //         msg
                            //     }) {
                            //     Ok(name_info) => {
                            //         NameInfo {
                            //             name: domain.to_string(),
                            //             address: vec![],
                            //             cname: None,
                            //             txt: None,
                            //             did_document: Some(name_info),
                            //             pk_x_list: None,
                            //             proof_type: NameProof::None,
                            //             create_time: 0,
                            //             ttl: None,
                            //         }
                            //     },
                            //     Err(e) => {
                            //         return Ok(CommandResult::Error(e))
                            //     }
                            // }
                        } else {
                            match dns_service.query(domain, Some(record_type), None).await
                                .map_err(|e| {
                                    let msg = format!("Failed to resolve domain {} record_type {}: {:?}", domain, record_type_str, e);
                                    error!("{}", msg);
                                    msg
                                }) {
                                Ok(name_info) => name_info,
                                Err(e) => {
                                    return Ok(CommandResult::Error(e))
                                }
                            }
                        }
                    } else {
                        let msg = format!("Invalid resolve command: inner service {} is not a DNS service", server_address);
                        error!("{}", msg);
                        return Err(msg);
                    }
                } else {
                    let msg = format!("Invalid resolve command: inner service {} not found", server_address);
                    error!("{}", msg);
                    return Ok(CommandResult::Error(msg))
                }
            }
        };
        let result = nameinfo_to_map_collection(record_type_str.as_str(), &name_info).await
            .map_err(|e| format!("Failed to convert name info to map collection: {:?}", e))?;

        context.env().create("RESP", CollectionValue::Map(result), EnvLevel::Chain).await?;
        Ok(CommandResult::Success("RESP".to_string()))
    }
}
