use std::net::IpAddr;

use crate::{lookup_err, LookupResult};

pub async fn lookup_hostname_once(ip: IpAddr) -> LookupResult<Option<String>> {
    let result = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip)).await;
    let host = match result {
        Ok(Ok(host)) => host,
        Ok(Err(e)) => {
            if is_not_found(&e) {
                return Ok(None);
            }
            return Err(lookup_err!("lookup hostname for {} failed: {}", ip, e));
        }
        Err(e) => {
            return Err(lookup_err!("lookup hostname task for {} failed: {}", ip, e));
        }
    };

    let host = host.trim().trim_end_matches('.').to_string();
    if host.is_empty() {
        Ok(None)
    } else {
        Ok(Some(host))
    }
}

fn is_not_found(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::NotFound {
        return true;
    }

    if let Some(code) = err.raw_os_error() {
        return matches!(code, -2 | 11001 | 11004);
    }

    false
}
