use std::net::IpAddr;

use crate::{lookup_err, LookupResult};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

pub async fn lookup_mac_once(ip: IpAddr) -> LookupResult<Option<String>> {
    #[cfg(target_os = "windows")]
    {
        return windows::lookup_mac_once(ip).await;
    }

    #[cfg(target_os = "linux")]
    {
        return linux::lookup_mac_once(ip).await;
    }

    #[cfg(target_os = "macos")]
    {
        return macos::lookup_mac_once(ip).await;
    }

    #[allow(unreachable_code)]
    Err(lookup_err!("lookup_mac unsupported platform for {}", ip))
}

pub async fn active_probe(ip: IpAddr) -> LookupResult<()> {
    #[cfg(target_os = "windows")]
    {
        return windows::active_probe(ip).await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        return crate::probe::active_probe(ip).await;
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err(lookup_err!("active_probe unsupported platform for {}", ip))
    }
}

fn normalize_mac(raw: &[u8]) -> Option<String> {
    if raw.len() < 6 {
        return None;
    }

    let mac = &raw[..6];
    if mac.iter().all(|v| *v == 0) {
        return None;
    }

    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ))
}

#[cfg(any(target_os = "linux", test))]
fn parse_mac_text(raw: &str) -> Option<String> {
    let normalized = raw.replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut bytes = [0u8; 6];
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return None;
        }
        let value = u8::from_str_radix(part, 16).ok()?;
        bytes[index] = value;
    }

    normalize_mac(&bytes)
}

#[cfg(test)]
mod tests {
    use super::{normalize_mac, parse_mac_text};

    #[test]
    fn test_normalize_mac() {
        assert_eq!(
            normalize_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(normalize_mac(&[0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn test_parse_mac_text() {
        assert_eq!(
            parse_mac_text("AA-BB-CC-DD-EE-FF"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            parse_mac_text("aa:bb:cc:dd:ee:ff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(parse_mac_text("invalid"), None);
    }
}
