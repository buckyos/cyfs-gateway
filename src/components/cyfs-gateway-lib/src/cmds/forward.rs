use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use clap::{Arg, Command};
use cyfs_process_chain::*;
use url::Url;

#[derive(Clone, Debug)]
struct UpstreamNode {
    url: String,
    weight: u32,
}

pub struct Forward {
    name: String,
    cmd: Command,
    rr_counter: AtomicUsize,
}

impl Forward {
    pub fn new() -> Self {
        let cmd = Command::new("forward")
            .about("Set forward destination URL")
            .after_help(
                r#"
Examples:
    forward tcp:///127.0.0.1:80
    forward rtcp://remote_server/path
    forward tcp:///127.0.0.1:80 tcp:///127.0.0.1:81
    forward ip_hash tcp:///127.0.0.1:80,weight=3 tcp:///127.0.0.1:81,weight=1
                "#
            )
            .arg(
                Arg::new("dest_urls")
                    .help("Destination URLs, format: <url> or <url>,weight=<N>")
                    .required(true)
                    .num_args(1..)
            );
        Self {
            name: "forward".to_string(),
            cmd,
            rr_counter: AtomicUsize::new(0),
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    fn parse_upstream(spec: &str) -> Result<UpstreamNode, String> {
        const WEIGHT_MARK: &str = ",weight=";

        let (url, weight) = if let Some(idx) = spec.rfind(WEIGHT_MARK) {
            let url = &spec[..idx];
            let weight_str = &spec[idx + WEIGHT_MARK.len()..];
            if url.is_empty() {
                return Err(format!("Invalid upstream spec '{}': url is empty", spec));
            }

            let weight = weight_str.parse::<u32>().map_err(|e| {
                format!(
                    "Invalid upstream weight in '{}': {}, expected positive integer",
                    spec, e
                )
            })?;

            if weight == 0 {
                return Err(format!(
                    "Invalid upstream weight in '{}': weight must be greater than 0",
                    spec
                ));
            }

            (url.to_string(), weight)
        } else {
            (spec.to_string(), 1)
        };

        Url::parse(url.as_str()).map_err(|e| format!("Invalid upstream url '{}': {}", url, e))?;

        Ok(UpstreamNode { url, weight })
    }

    fn parse_upstreams(upstreams: Vec<String>) -> Result<Vec<UpstreamNode>, String> {
        let mut nodes = Vec::with_capacity(upstreams.len());
        for item in upstreams {
            nodes.push(Self::parse_upstream(item.as_str())?);
        }

        if nodes.is_empty() {
            return Err("dest_urls is required".to_string());
        }

        Ok(nodes)
    }

    fn split_algo_and_upstreams(dest_urls: Vec<String>) -> Result<(String, Vec<String>), String> {
        if dest_urls.is_empty() {
            return Err("dest_urls is required".to_string());
        }

        let first = dest_urls[0].as_str();
        if first == "round_robin" || first == "ip_hash" {
            if dest_urls.len() < 2 {
                return Err("dest_url is required".to_string());
            }

            return Ok((first.to_string(), dest_urls[1..].to_vec()));
        }

        Ok(("round_robin".to_string(), dest_urls))
    }

    fn weighted_round_robin(&self, upstreams: &[UpstreamNode]) -> Result<String, String> {
        let total_weight = upstreams.iter().try_fold(0usize, |acc, node| {
            acc.checked_add(node.weight as usize)
                .ok_or_else(|| "sum of upstream weights overflowed".to_string())
        })?;

        if total_weight == 0 {
            return Err("sum of upstream weights must be greater than 0".to_string());
        }

        let index = self.rr_counter.fetch_add(1, Ordering::Relaxed) % total_weight;
        let mut cursor = index;
        for node in upstreams {
            let w = node.weight as usize;
            if cursor < w {
                return Ok(node.url.clone());
            }
            cursor -= w;
        }

        Err("failed to select upstream with round_robin".to_string())
    }

    fn nginx_ip_hash_key(ip: &IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                vec![octets[0], octets[1], octets[2]]
            }
            IpAddr::V6(v6) => v6.octets().to_vec(),
        }
    }

    fn nginx_ip_hash(ip: &IpAddr) -> usize {
        let key = Self::nginx_ip_hash_key(ip);
        let mut hash = 89usize;
        for b in key {
            hash = (hash * 113 + b as usize) % 6271;
        }
        hash
    }

    async fn extract_source_ip(context: &Context) -> Option<IpAddr> {
        if let Ok(Some(req)) = context.env().get("REQ", None).await {
            if let Some(req) = req.into_map() {
                if let Ok(Some(value)) = req.get("source_ip").await {
                    if let Some(ip) = value.as_str().and_then(|v| v.parse::<IpAddr>().ok()) {
                        return Some(ip);
                    }
                }
            }
        }

        None
    }

    async fn select_upstream(
        &self,
        context: &Context,
        algo: &str,
        upstreams: &[UpstreamNode],
    ) -> Result<String, String> {
        match algo {
            "round_robin" => self.weighted_round_robin(upstreams),
            "ip_hash" => {
                let ip = Self::extract_source_ip(context).await;
                if ip.is_none() {
                    return Err("ip_hash requires source ip, but request has no client ip".to_string());
                }

                let total_weight = upstreams.iter().try_fold(0usize, |acc, node| {
                    acc.checked_add(node.weight as usize)
                        .ok_or_else(|| "sum of upstream weights overflowed".to_string())
                })?;
                if total_weight == 0 {
                    return Err("sum of upstream weights must be greater than 0".to_string());
                }

                let hash_ip = ip.ok_or_else(|| "missing source ip".to_string())?;
                let mut cursor = Self::nginx_ip_hash(&hash_ip) % total_weight;
                for node in upstreams {
                    let w = node.weight as usize;
                    if cursor < w {
                        return Ok(node.url.clone());
                    }
                    cursor -= w;
                }

                Err("failed to select upstream with ip_hash".to_string())
            }
            _ => Err(format!(
                "Unsupported algorithm '{}': expected round_robin or ip_hash",
                algo
            )),
        }
    }
}

#[async_trait::async_trait]
impl ExternalCommand for Forward {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid forward command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let dest_urls = matches
            .get_many::<String>("dest_urls")
            .ok_or_else(|| "dest_urls is required".to_string())?
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        let (_algo, upstream_specs) = Self::split_algo_and_upstreams(dest_urls)?;

        if upstream_specs.len() > 1 {
            Self::parse_upstreams(upstream_specs)?;
        }

        Ok(())
    }

    async fn exec(&self, context: &Context, args: &[CollectionValue], _origin_args: &CommandArgs) -> Result<CommandResult, String> {
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
                let msg = format!("Invalid forward command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let dest_urls = matches
            .get_many::<String>("dest_urls")
            .ok_or_else(|| "dest_urls is required".to_string())?
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        let (algo, upstream_specs) = Self::split_algo_and_upstreams(dest_urls)?;

        let selected = if upstream_specs.len() == 1 {
            upstream_specs[0].clone()
        } else {
            let upstreams = Self::parse_upstreams(upstream_specs)?;
            self.select_upstream(context, algo.as_str(), upstreams.as_slice()).await?
        };

        Ok(CommandResult::return_with_string(
            CommandControlLevel::Lib,
            format!(r#"forward "{}""#, selected),
        ))
    }
}
