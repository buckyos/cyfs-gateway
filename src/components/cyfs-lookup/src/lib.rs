mod hostname;
mod mac;
mod probe;

use std::net::IpAddr;

pub type LookupResult<T> = sfo_result::Result<T, ()>;
pub type LookupError = sfo_result::Error<()>;

pub use sfo_result::err as lookup_err;
pub use sfo_result::into_err as into_lookup_err;

pub async fn lookup_hostname(ip: IpAddr) -> LookupResult<Option<String>> {
    if let Some(name) = hostname::lookup_hostname_once(ip).await? {
        return Ok(Some(name));
    }

    probe::active_probe(ip).await?;

    hostname::lookup_hostname_once(ip).await
}

pub async fn lookup_mac(ip: IpAddr) -> LookupResult<Option<String>> {
    if let Some(mac) = mac::lookup_mac_once(ip).await? {
        return Ok(Some(mac));
    }

    mac::active_probe(ip).await?;

    mac::lookup_mac_once(ip).await
}
