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
    forward round_robin --map $UPSTREAMS
    forward ip_hash --map $UPSTREAMS
                "#,
            )
            .arg(
                Arg::new("upstream_map")
                    .long("map")
                    .help("Map collection variable containing <url, weight> pairs")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("dest_urls")
                    .help("Destination URLs, format: <url> or <url>,weight=<N>")
                    .required(false)
                    .num_args(0..),
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
            return Ok(("round_robin".to_string(), vec![]));
        }

        let first = dest_urls[0].as_str();
        if first == "round_robin" || first == "ip_hash" {
            return Ok((first.to_string(), dest_urls[1..].to_vec()));
        }

        Ok(("round_robin".to_string(), dest_urls))
    }

    fn parse_weight_value(value: &CollectionValue, url: &str) -> Result<u32, String> {
        match value {
            CollectionValue::String(weight) => {
                let weight = weight.parse::<u32>().map_err(|e| {
                    format!(
                        "Invalid upstream weight for '{}': {}, expected positive integer",
                        url, e
                    )
                })?;
                if weight == 0 {
                    return Err(format!(
                        "Invalid upstream weight for '{}': weight must be greater than 0",
                        url
                    ));
                }
                Ok(weight)
            }
            CollectionValue::Number(NumberValue::Int(weight)) => {
                if *weight <= 0 {
                    return Err(format!(
                        "Invalid upstream weight for '{}': weight must be greater than 0",
                        url
                    ));
                }
                u32::try_from(*weight).map_err(|_| {
                    format!(
                        "Invalid upstream weight for '{}': {} is too large for u32",
                        url, weight
                    )
                })
            }
            CollectionValue::Number(NumberValue::Float(weight)) => {
                if !weight.is_finite() || *weight <= 0.0 || weight.fract() != 0.0 {
                    return Err(format!(
                        "Invalid upstream weight for '{}': {} is not a positive integer",
                        url, weight
                    ));
                }

                if *weight > u32::MAX as f64 {
                    return Err(format!(
                        "Invalid upstream weight for '{}': {} is too large for u32",
                        url, weight
                    ));
                }

                Ok(*weight as u32)
            }
            _ => Err(format!(
                "Invalid upstream weight for '{}': expected string or number, got {}",
                url,
                value.get_type()
            )),
        }
    }

    async fn parse_upstream_map(map: &MapCollectionRef) -> Result<Vec<UpstreamNode>, String> {
        let mut entries = map.dump().await?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut nodes = Vec::with_capacity(entries.len());
        for (url, weight_value) in entries {
            Url::parse(url.as_str())
                .map_err(|e| format!("Invalid upstream url '{}' in --map: {}", url, e))?;

            let weight = Self::parse_weight_value(&weight_value, url.as_str())?;
            nodes.push(UpstreamNode { url, weight });
        }

        Ok(nodes)
    }

    fn build_parse_args(
        args: &[CollectionValue],
        origin_args: &CommandArgs,
    ) -> Result<Vec<String>, String> {
        if args.len() != origin_args.len() {
            return Err(format!(
                "Invalid forward command args length: expected {}, got {}",
                origin_args.len(),
                args.len()
            ));
        }

        let origin_str_args = origin_args.as_str_list();
        let mut parse_args = Vec::with_capacity(args.len());
        for (index, arg) in args.iter().enumerate() {
            if let Some(value) = arg.as_str() {
                parse_args.push(value.to_string());
            } else {
                parse_args.push(origin_str_args[index].to_string());
            }
        }

        Ok(parse_args)
    }

    fn collect_inline_upstream_specs(
        args: &[CollectionValue],
        matches: &clap::ArgMatches,
    ) -> Result<Vec<String>, String> {
        let mut dest_urls = Vec::new();
        if let Some(indices) = matches.indices_of("dest_urls") {
            for index in indices {
                let arg = args.get(index).ok_or_else(|| {
                    format!("Missing forward command argument at position {}", index)
                })?;

                let value = arg.as_str().ok_or_else(|| {
                    format!(
                        "Invalid upstream argument at position {}: expected string, got {}",
                        index,
                        arg.get_type()
                    )
                })?;
                dest_urls.push(value.to_string());
            }
        }

        Ok(dest_urls)
    }

    fn collect_map_upstreams_arg(
        args: &[CollectionValue],
        matches: &clap::ArgMatches,
    ) -> Result<Option<MapCollectionRef>, String> {
        let Some(index) = matches.index_of("upstream_map") else {
            return Ok(None);
        };

        let arg = args
            .get(index)
            .ok_or_else(|| format!("Missing upstream map argument at position {}", index))?;
        let map = arg.as_map().ok_or_else(|| {
            format!(
                "Invalid --map argument: expected map collection, got {}",
                arg.get_type()
            )
        })?;

        Ok(Some(map.clone()))
    }

    fn weighted_round_robin(&self, upstreams: &[UpstreamNode]) -> Result<String, String> {
        let gcd = upstreams.iter().fold(0u32, |acc, node| {
            if acc == 0 {
                node.weight
            } else {
                Self::gcd_u32(acc, node.weight)
            }
        });
        let normalized_weights = upstreams
            .iter()
            .map(|node| {
                let divisor = if gcd == 0 { 1 } else { gcd };
                (node.weight / divisor) as usize
            })
            .collect::<Vec<_>>();

        let total_weight = normalized_weights.iter().try_fold(0usize, |acc, weight| {
            acc.checked_add(*weight)
                .ok_or_else(|| "sum of upstream weights overflowed".to_string())
        })?;

        if total_weight == 0 {
            return Err("sum of upstream weights must be greater than 0".to_string());
        }

        let target_step = self.rr_counter.fetch_add(1, Ordering::Relaxed) % total_weight;
        let mut current_weights = vec![0isize; upstreams.len()];
        let total_weight_isize = total_weight as isize;

        for step in 0..=target_step {
            for (index, weight) in normalized_weights.iter().enumerate() {
                current_weights[index] += *weight as isize;
            }

            let mut selected_index = 0usize;
            for index in 1..current_weights.len() {
                if current_weights[index] > current_weights[selected_index] {
                    selected_index = index;
                }
            }

            current_weights[selected_index] -= total_weight_isize;
            if step == target_step {
                return Ok(upstreams[selected_index].url.clone());
            }
        }

        Err("failed to select upstream with round_robin".to_string())
    }

    fn gcd_u32(left: u32, right: u32) -> u32 {
        let mut a = left;
        let mut b = right;
        while b != 0 {
            let remainder = a % b;
            a = b;
            b = remainder;
        }
        a
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
                    return Err(
                        "ip_hash requires source ip, but request has no client ip".to_string()
                    );
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
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid forward command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let dest_urls = matches
            .get_many::<String>("dest_urls")
            .map(|values| values.map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();

        let (_algo, upstream_specs) = Self::split_algo_and_upstreams(dest_urls)?;
        let has_map = matches.index_of("upstream_map").is_some();

        if upstream_specs.is_empty() && !has_map {
            return Err("forward requires at least one upstream or --map".to_string());
        }

        if upstream_specs.len() > 1 {
            Self::parse_upstreams(upstream_specs)?;
        }

        Ok(())
    }

    async fn exec(
        &self,
        context: &Context,
        args: &[CollectionValue],
        origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        let parse_args = Self::build_parse_args(args, origin_args)?;

        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&parse_args)
            .map_err(|e| {
                let msg = format!("Invalid forward command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let dest_urls = Self::collect_inline_upstream_specs(args, &matches)?;
        let upstream_map = Self::collect_map_upstreams_arg(args, &matches)?;

        let (algo, inline_upstream_specs) = Self::split_algo_and_upstreams(dest_urls)?;
        let mut upstreams = Vec::new();
        if !inline_upstream_specs.is_empty() {
            upstreams.extend(Self::parse_upstreams(inline_upstream_specs)?);
        }
        if let Some(map) = upstream_map {
            upstreams.extend(Self::parse_upstream_map(&map).await?);
        }

        if upstreams.is_empty() {
            return Err("forward requires at least one upstream or --map".to_string());
        }

        let selected = if upstreams.len() == 1 {
            upstreams[0].url.clone()
        } else {
            self.select_upstream(context, algo.as_str(), upstreams.as_slice())
                .await?
        };

        Ok(CommandResult::return_with_string(
            CommandControlLevel::Lib,
            format!(r#"forward "{}""#, selected),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_process_chain::{CollectionValue, CommandArg, CommandArgs, MemoryMapCollection};

    #[tokio::test]
    async fn test_parse_upstream_map_supports_string_and_number_weights() {
        let map = MemoryMapCollection::new_ref();
        map.insert(
            "tcp:///127.0.0.1:80",
            CollectionValue::String("3".to_string()),
        )
        .await
        .unwrap();
        map.insert(
            "tcp:///127.0.0.1:81",
            CollectionValue::Number(NumberValue::Int(1)),
        )
        .await
        .unwrap();

        let upstreams = Forward::parse_upstream_map(&map).await.unwrap();

        assert_eq!(upstreams.len(), 2);
        assert_eq!(upstreams[0].url, "tcp:///127.0.0.1:80");
        assert_eq!(upstreams[0].weight, 3);
        assert_eq!(upstreams[1].url, "tcp:///127.0.0.1:81");
        assert_eq!(upstreams[1].weight, 1);
    }

    #[tokio::test]
    async fn test_parse_upstream_map_rejects_invalid_weight() {
        let map = MemoryMapCollection::new_ref();
        map.insert(
            "tcp:///127.0.0.1:80",
            CollectionValue::String("0".to_string()),
        )
        .await
        .unwrap();

        let err = Forward::parse_upstream_map(&map).await.unwrap_err();
        assert!(err.contains("weight must be greater than 0"));
    }

    #[test]
    fn test_check_accepts_algo_with_map_only() {
        let forward = Forward::new();
        let args = CommandArgs::new(vec![
            CommandArg::Literal("forward".to_string()),
            CommandArg::Literal("ip_hash".to_string()),
            CommandArg::Literal("--map".to_string()),
            CommandArg::Var("$UPSTREAMS".to_string()),
        ]);

        forward.check(&args).unwrap();
    }

    #[test]
    fn test_weighted_round_robin_smooths_equal_large_weights() {
        let forward = Forward::new();
        let upstreams = vec![
            UpstreamNode {
                url: "http://127.0.0.1:10162".to_string(),
                weight: 100,
            },
            UpstreamNode {
                url: "http://127.0.0.1:10163".to_string(),
                weight: 100,
            },
        ];

        let first = forward.weighted_round_robin(&upstreams).unwrap();
        let second = forward.weighted_round_robin(&upstreams).unwrap();
        let third = forward.weighted_round_robin(&upstreams).unwrap();

        assert_eq!(first, "http://127.0.0.1:10162");
        assert_eq!(second, "http://127.0.0.1:10163");
        assert_eq!(third, "http://127.0.0.1:10162");
    }
}
