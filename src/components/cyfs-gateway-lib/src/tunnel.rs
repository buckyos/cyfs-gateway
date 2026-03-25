use crate::TunnelResult;
use async_trait::async_trait;
use buckyos_kit::AsyncStream;
use name_client::resolve_ip;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::SocketAddr;

pub const TUNNEL_OPTION_CLIENT_CERT: &str = "client_cert";
pub const TUNNEL_OPTION_SNI: &str = "sni";

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct TunnelEndpoint {
    pub device_id: String,
    pub port: u16,
}

#[async_trait]
pub trait StreamListener: Send {
    async fn accept(&self) -> Result<(Box<dyn AsyncStream>, TunnelEndpoint), std::io::Error>;
}

#[async_trait]
pub trait DatagramClient: Send + Sync {
    async fn recv_datagram(&self, buffer: &mut [u8]) -> Result<usize, std::io::Error>;
    async fn send_datagram(&self, buffer: &[u8]) -> Result<usize, std::io::Error>;
}
pub trait DatagramClientBox: DatagramClient {
    fn clone_box(&self) -> Box<dyn DatagramClientBox>;
}

impl<T> DatagramClientBox for T
where
    T: 'static + Clone + Send + DatagramClient,
{
    fn clone_box(&self) -> Box<dyn DatagramClientBox> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn DatagramClientBox> {
    fn clone(&self) -> Box<dyn DatagramClientBox> {
        self.clone_box()
    }
}

// one Tunnel to device
#[async_trait]
pub trait Tunnel: Send + Sync {
    async fn ping(&self) -> Result<(), std::io::Error>;
    async fn open_stream_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn AsyncStream>, std::io::Error>;

    async fn open_stream(&self, stream_id: &str) -> Result<Box<dyn AsyncStream>, std::io::Error>;

    async fn create_datagram_client_by_dest(
        &self,
        dest_port: u16,
        dest_host: Option<String>,
    ) -> Result<Box<dyn DatagramClientBox>, std::io::Error>;

    async fn create_datagram_client(
        &self,
        session_id: &str,
    ) -> Result<Box<dyn DatagramClientBox>, std::io::Error>;
}

pub trait TunnelBox: Tunnel {
    fn clone_box(&self) -> Box<dyn TunnelBox>;
}
impl<T> TunnelBox for T
where
    T: 'static + Clone + Send + Tunnel,
{
    fn clone_box(&self) -> Box<dyn TunnelBox> {
        Box::new(self.clone())
    }
}
impl Clone for Box<dyn TunnelBox> {
    fn clone(&self) -> Box<dyn TunnelBox> {
        self.clone_box()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelOptions {
    params: BTreeMap<String, Vec<String>>,
}

impl TunnelOptions {
    pub fn from_query(query: Option<&str>) -> Option<Self> {
        let query = query?;
        let mut params = BTreeMap::new();
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            params
                .entry(key.into_owned())
                .or_insert_with(Vec::new)
                .push(value.into_owned());
        }

        if params.is_empty() {
            None
        } else {
            Some(Self { params })
        }
    }

    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.params.contains_key(key)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.params
            .get(key)
            .and_then(|values| values.first().map(|value| value.as_str()))
    }

    pub fn get_all(&self, key: &str) -> Option<&[String]> {
        self.params.get(key).map(Vec::as_slice)
    }

    pub fn client_cert_alias(&self) -> Option<&str> {
        self.get(TUNNEL_OPTION_CLIENT_CERT)
    }

    pub fn sni(&self) -> Option<&str> {
        self.get(TUNNEL_OPTION_SNI)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.params.iter()
    }
}

pub async fn resolve_host_ip_with_options(
    dest_host: &str,
    options: Option<&TunnelOptions>,
) -> Result<IpAddr, std::io::Error> {
    if let Some(ip_str) = options.and_then(|options| options.get(dest_host)) {
        return ip_str.parse::<IpAddr>().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid ip for host {}: {}", dest_host, e),
            )
        });
    }

    resolve_ip(dest_host)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

#[async_trait]
pub trait TunnelBuilder: Send + Sync + 'static {
    async fn create_tunnel(
        &self,
        tunnel_stack_id: Option<&str>,
        options: Option<TunnelOptions>,
    ) -> TunnelResult<Box<dyn TunnelBox>>;
}

#[async_trait]
pub trait TunnelSelector {
    async fn select_tunnel_for_http_upstream(
        &self,
        req_host: &str,
        req_path: &str,
    ) -> Option<String>;
}

pub fn is_ipv4_addr_str(addr: &str) -> Result<bool, std::io::Error> {
    let ip_addr = addr
        .parse::<IpAddr>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    Ok(ip_addr.is_ipv4())
}

pub fn get_dest_info_from_url_path(path: &str) -> Result<(Option<String>, u16), std::io::Error> {
    let path = path.trim_start_matches('/');
    let path = std::path::Path::new(path);

    let first_component = path.iter().next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid path: empty path")
    })?;

    let addr_str = first_component.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid path: contains non-UTF8 characters",
        )
    })?;

    // 处理以冒号开头的情况（如 ":8000"）和 host:port 的情况
    if addr_str.starts_with(':') {
        let dest_port = addr_str[1..]
            .parse::<u16>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        Ok((None, dest_port))
    } else {
        if let Ok(sock_addr) = addr_str.parse::<SocketAddr>() {
            let dest_host = sock_addr.ip().to_string();
            let dest_port = sock_addr.port();
            return Ok((Some(dest_host), dest_port));
        }

        let parts = addr_str.split(':').collect::<Vec<&str>>();
        if parts.len() != 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid address format",
            ));
        }

        let dest_host = parts[0];
        let dest_port = parts[1]
            .parse::<u16>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        Ok((Some(dest_host.to_string()), dest_port))
    }
}

pub fn has_scheme(s: &str) -> bool {
    let re = regex::Regex::new(r"^[a-zA-Z][a-zA-Z0-9+.-]*://").unwrap();
    re.is_match(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use percent_encoding::percent_decode_str;
    use url::Url;

    #[test]
    fn test_tunnel_options_from_query() {
        let options = TunnelOptions::from_query(Some(
            "client_cert=partner_a&sni=api.example.com&repeat=a&repeat=b&empty=",
        ))
        .unwrap();
        assert_eq!(options.client_cert_alias(), Some("partner_a"));
        assert_eq!(options.sni(), Some("api.example.com"));
        assert_eq!(
            options.get_all("repeat"),
            Some(&["a".to_string(), "b".to_string()][..])
        );
        assert_eq!(options.get("empty"), Some(""));
        assert!(options.contains_key(TUNNEL_OPTION_CLIENT_CERT));
    }

    #[test]
    fn test_tunnel_options_from_empty_query() {
        assert!(TunnelOptions::from_query(None).is_none());
        assert!(TunnelOptions::from_query(Some("")).is_none());
    }

    #[tokio::test]
    async fn test_resolve_host_ip_with_options_prefers_configured_ip() {
        let options = TunnelOptions::from_query(Some("example.com=127.0.0.1")).unwrap();
        let ip = resolve_host_ip_with_options("example.com", Some(&options))
            .await
            .unwrap();
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn test_resolve_host_ip_with_options_rejects_invalid_ip() {
        let options = TunnelOptions::from_query(Some("example.com=invalid-ip")).unwrap();
        let err = resolve_host_ip_with_options("example.com", Some(&options))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_get_dest_info_from_url_path() {
        unsafe {
            std::env::set_var("BUCKY_LOG", "debug");
        }
        buckyos_kit::init_logging("test_get_dest_info_from_url_path", false);
        let (host, port) = get_dest_info_from_url_path("127.0.0.1:8080").unwrap();
        assert_eq!(host, Some("127.0.0.1".to_string()));
        assert_eq!(port, 8080);

        let (host, port) =
            get_dest_info_from_url_path("xba.dev.did:8080/krpc/api_test?a=1&b=2").unwrap();
        assert_eq!(host, Some("xba.dev.did".to_string()));
        assert_eq!(port, 8080);

        let (host, port) = get_dest_info_from_url_path(
            "/[2600:1700:1150:9440:f65:adec:9b77:cb2]:8080/krpc/api_test",
        )
        .unwrap();
        assert_eq!(
            host,
            Some("2600:1700:1150:9440:f65:adec:9b77:cb2".to_string())
        );
        assert_eq!(port, 8080);

        let (host, port) = get_dest_info_from_url_path(":8080").unwrap();
        assert_eq!(host, None);
        assert_eq!(port, 8080);

        let ipv4_addr = is_ipv4_addr_str("127.0.0.1").unwrap();
        assert_eq!(ipv4_addr, true);
        let ipv6_addr = is_ipv4_addr_str("::1").unwrap();
        assert_eq!(ipv6_addr, false);

        let upstream_url =
            Url::parse("rtcp://TeVOLYpilvPwXNVh4dSRH4VQ6y-4t-sawmn3thKOqJM.dev.did/:80").unwrap();
        assert_eq!(
            upstream_url.host_str().unwrap(),
            "TeVOLYpilvPwXNVh4dSRH4VQ6y-4t-sawmn3thKOqJM.dev.did"
        );

        let upstream_url = Url::parse("rtcp://TeVOLYpilvPwXNVh4dSRH4VQ6y-4t-sawmn3thKOqJM.dev.did/rtcp%3A%2F%2FTeVOLYpilvPwXNVh4dSRH4VQ6y-4t-sawmn3thKOqJM.dev.did%2F%3A443").unwrap();
        assert_eq!(
            upstream_url.host_str().unwrap(),
            "TeVOLYpilvPwXNVh4dSRH4VQ6y-4t-sawmn3thKOqJM.dev.did"
        );
        let path = upstream_url.path();
        // Use percent_encoding instead of urlencoding and fix str_as_str lint

        let org_path = percent_decode_str(path).decode_utf8().unwrap();
        println!("org_path: {}", org_path);
    }
}
