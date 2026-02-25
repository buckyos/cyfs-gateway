use std::net::{IpAddr, Ipv4Addr};

use super::parse_mac_text;
use crate::{lookup_err, LookupResult};

pub async fn lookup_mac_once(ip: IpAddr) -> LookupResult<Option<String>> {
    let target = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Ok(None),
    };

    let content = tokio::fs::read_to_string("/proc/net/arp")
        .await
        .map_err(|e| lookup_err!("read /proc/net/arp for {} failed: {}", target, e))?;
    Ok(parse_proc_net_arp(&content, target))
}

fn parse_proc_net_arp(content: &str, target: Ipv4Addr) -> Option<String> {
    for line in content.lines().skip(1) {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 4 {
            continue;
        }

        if columns[0].parse::<Ipv4Addr>().ok() != Some(target) {
            continue;
        }

        if let Some(mac) = parse_mac_text(columns[3]) {
            return Some(mac);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::parse_proc_net_arp;

    #[test]
    fn test_parse_proc_net_arp() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.3      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
        let target = Ipv4Addr::new(192, 168, 1, 3);
        assert_eq!(
            parse_proc_net_arp(content, target),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }
}
