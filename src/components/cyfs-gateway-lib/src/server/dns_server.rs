use std::net::{IpAddr};
use name_client::{NameInfo, RecordType};
use name_lib::{EncodedDocument, DID};

use crate::ServerResult;

#[async_trait::async_trait]
pub trait NameServer: Send + Sync {
    fn id(&self) -> String;
    async fn query(&self, name: &str, record_type: Option<RecordType>, from_ip: Option<IpAddr>) -> ServerResult<NameInfo>;
    async fn query_did(&self, did: &DID, fragment: Option<&str>, from_ip: Option<IpAddr>) -> ServerResult<EncodedDocument>;
}
