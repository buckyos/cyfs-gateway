mod cloudflare;
mod digitalocean;
mod gandi;
mod godaddy;
mod google;
mod hetzner;
mod hostinger;
mod inwx;
mod namecom;
mod netcup;
mod netcup_cloud;
mod ovh;
mod route53;
mod sakura;
mod transip;
mod wrapped;

use crate::credential::DnsCredential;
use crate::engine::{Backend, PerRecord};
use crate::provider::{DnsProviderError, DnsProviderResult};
use wrapped::Wrapped;

pub(crate) fn backend(
    credential: &DnsCredential,
    origin: &str,
) -> DnsProviderResult<Box<dyn Backend>> {
    let field = |id: &str| credential.field(id).unwrap_or_default();
    let endpoint = credential.endpoint.as_deref();
    let fixed_address = || match endpoint {
        Some(_) => Err(DnsProviderError::Unsupported(
            "this service has a fixed API address".to_string(),
        )),
        None => Ok(()),
    };
    Ok(match credential.provider.as_str() {
        "cloudflare" => Box::new(PerRecord(cloudflare::Cloudflare::new(
            field("api_token"),
            origin,
            endpoint,
        )?)),
        "godaddy" => Box::new(PerRecord(godaddy::GoDaddy::new(
            field("access_token"),
            origin,
            endpoint,
        )?)),
        "route53" => Box::new(route53::Route53::new(
            field("access_key_id"),
            field("secret_access_key"),
            credential.field("hosted_zone_id"),
            origin,
            endpoint,
        )?),
        "porkbun" => {
            fixed_address()?;
            Box::new(Wrapped::porkbun(
                field("api_key"),
                field("secret_api_key"),
                origin,
            )?)
        }
        "ionos" => {
            fixed_address()?;
            Box::new(Wrapped::ionos(field("api_key"), origin)?)
        }
        "ovh" => Box::new(PerRecord(ovh::Ovh::new(
            field("region"),
            field("application_key"),
            field("application_secret"),
            field("consumer_key"),
            origin,
            endpoint,
        )?)),
        "hetzner" => Box::new(hetzner::Hetzner::new(field("api_token"), origin, endpoint)?),
        "gandi" => Box::new(gandi::Gandi::new(
            field("personal_access_token"),
            origin,
            endpoint,
        )?),
        "digitalocean" => Box::new(PerRecord(digitalocean::DigitalOcean::new(
            field("api_token"),
            origin,
            endpoint,
        )?)),
        "google_cloud" => Box::new(google::Google::new(
            field("service_account_json"),
            credential.field("project_id"),
            origin,
            endpoint,
        )?),
        "azure" => {
            fixed_address()?;
            Box::new(Wrapped::azure(
                field("tenant_id"),
                field("client_id"),
                field("client_secret"),
                field("subscription_id"),
                field("resource_group"),
                origin,
            )?)
        }
        "namecom" => Box::new(PerRecord(namecom::NameCom::new(
            field("username"),
            field("api_token"),
            origin,
            endpoint,
        )?)),
        "hostinger" => Box::new(hostinger::Hostinger::new(
            field("api_token"),
            origin,
            endpoint,
        )?),
        "desec" => {
            fixed_address()?;
            Box::new(Wrapped::desec(field("api_token"), origin)?)
        }
        "inwx" => Box::new(PerRecord(inwx::Inwx::new(
            field("username"),
            field("password"),
            credential.field("shared_secret"),
            origin,
            endpoint,
        )?)),
        "netcup" => match credential.field("customer_number") {
            Some(customer_number) => Box::new(netcup::Netcup::new(
                customer_number,
                field("api_key"),
                field("api_password"),
                origin,
                endpoint,
            )?),
            None => Box::new(netcup_cloud::NetcupCloud::new(
                field("api_key"),
                origin,
                endpoint,
            )?),
        },
        "transip" => Box::new(PerRecord(transip::TransIp::new(
            field("login"),
            field("private_key"),
            origin,
            endpoint,
        )?)),
        "alidns" => {
            fixed_address()?;
            Box::new(Wrapped::alidns(
                field("access_key_id"),
                field("access_key_secret"),
                origin,
            )?)
        }
        "dnspod" => {
            fixed_address()?;
            Box::new(Wrapped::dnspod(
                field("secret_id"),
                field("secret_key"),
                origin,
            )?)
        }
        "sakura" => Box::new(sakura::Sakura::new(
            field("access_token"),
            field("access_token_secret"),
            origin,
            endpoint,
        )?),
        other => {
            return Err(DnsProviderError::Unsupported(format!(
                "unknown DNS service: {other}"
            )));
        }
    })
}
