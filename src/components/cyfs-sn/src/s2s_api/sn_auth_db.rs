use super::read_cache::RemoteReadCache;
use crate::{
    sn_err, AccountSession, AllocateZoneRelayReq, AssignZoneRelayReq, DomainBinding,
    RegisterUserWithRelayAllocationReq, RegisterUserWithRelayAllocationResult,
    RelayAdmissionDecision, RelayAdmissionReq, RelayAssignment, RelayHeartbeat, RelayMigrationReq,
    RelayNode, RelayNodeAddressUpdate, RelayNodeHealth, RelayNodeIpMapReq, RelayNodeIpMapSnapshot,
    RelayNodeRegistration, SNUserInfo, SnAuthDB, SnAuthDbCapabilities, SnAuthInfo,
    SnClearStateResult, SnError, SnErrorCode, SnResult, UserDnsChangePage, UserDnsLookup,
    UserDnsMutationResult, UserDnsRecordType, UserDnsRrset, UserState, ZoneInfo, ZoneInfoPatch,
};
use ::kRPC::{kRPC, RPCErrors, RPCHandler, RPCRequest, RPCResponse, RPCResult};
use async_trait::async_trait;
use serde::de::{DeserializeOwned, Error as DeError};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub const SN_AUTH_DB_RPC_PATH: &str = "/kapi/sn/s2s/auth-db";
// Auth metadata changes relatively infrequently; bound staleness without caching
// the in-process SQLite path used by all-in-one deployments.
const SN_AUTH_DB_READ_CACHE_TTL: Duration = Duration::from_secs(5);
const SN_AUTH_DB_READ_CACHE_CAPACITY: usize = 4096;

pub const METHOD_CAPABILITIES: &str = "sn_auth_db.capabilities";
pub const METHOD_GET_ACTIVATION_CODES: &str = "sn_auth_db.get_activation_codes";
pub const METHOD_INSERT_ACTIVATION_CODE: &str = "sn_auth_db.insert_activation_code";
pub const METHOD_GENERATE_ACTIVATION_CODES: &str = "sn_auth_db.generate_activation_codes";
pub const METHOD_CHECK_ACTIVE_CODE: &str = "sn_auth_db.check_active_code";
pub const METHOD_CLEAR_STATE_BY_ACTIVE_CODE: &str = "sn_auth_db.clear_state_by_active_code";
pub const METHOD_REGISTER_USER: &str = "sn_auth_db.register_user";
pub const METHOD_REGISTER_USER_WITH_RELAY_ALLOCATION: &str =
    "sn_auth_db.register_user_with_relay_allocation";
pub const METHOD_CREATE_AUTH: &str = "sn_auth_db.create_auth";
pub const METHOD_IS_USER_EXIST: &str = "sn_auth_db.is_user_exist";
pub const METHOD_GET_USER_BY_EMAIL: &str = "sn_auth_db.get_user_by_email";
pub const METHOD_REGISTER_USER_WITH_OWNER_KEY: &str = "sn_auth_db.register_user_with_owner_key";
pub const METHOD_GET_USER_BY_PUBLIC_KEY: &str = "sn_auth_db.get_user_by_public_key";
pub const METHOD_GET_USER_INFO: &str = "sn_auth_db.get_user_info";
pub const METHOD_GET_USER_BY_DOMAIN: &str = "sn_auth_db.get_user_by_domain";
pub const METHOD_SET_USER_STATE: &str = "sn_auth_db.set_user_state";
pub const METHOD_UPDATE_USER_PUBLIC_KEY: &str = "sn_auth_db.update_user_public_key";
pub const METHOD_UPDATE_USER_ZONE_CONFIG: &str = "sn_auth_db.update_user_zone_config";
pub const METHOD_UPDATE_USER_SELF_CERT: &str = "sn_auth_db.update_user_self_cert";
pub const METHOD_UPDATE_USER_DOMAIN: &str = "sn_auth_db.update_user_domain";
pub const METHOD_GET_USER_SN_IPS: &str = "sn_auth_db.get_user_sn_ips";
pub const METHOD_GET_AUTH: &str = "sn_auth_db.get_auth";
pub const METHOD_UPDATE_LAST_LOGIN: &str = "sn_auth_db.update_last_login";
pub const METHOD_ACTIVATE_USER_DOMAIN_BINDING: &str = "sn_auth_db.activate_user_domain_binding";
pub const METHOD_UNBIND_USER_DOMAIN: &str = "sn_auth_db.unbind_user_domain";
pub const METHOD_PUT_USER_DNS_VALUE: &str = "sn_auth_db.put_user_dns_value";
pub const METHOD_REMOVE_USER_DNS_VALUE: &str = "sn_auth_db.remove_user_dns_value";
pub const METHOD_DELETE_USER_DNS_RRSET: &str = "sn_auth_db.delete_user_dns_rrset";
pub const METHOD_SET_USER_DNS_RRSET_TTL: &str = "sn_auth_db.set_user_dns_rrset_ttl";
pub const METHOD_GET_USER_DNS_RRSET: &str = "sn_auth_db.get_user_dns_rrset";
pub const METHOD_LIST_USER_DNS_RRSETS: &str = "sn_auth_db.list_user_dns_rrsets";
pub const METHOD_LIST_USER_DNS_CHANGES: &str = "sn_auth_db.list_user_dns_changes";
pub const METHOD_GET_ZONE_INFO: &str = "sn_auth_db.get_zone_info";
pub const METHOD_UPDATE_ZONE_INFO: &str = "sn_auth_db.update_zone_info";
pub const METHOD_UPDATE_ZONE_RELAY_SN: &str = "sn_auth_db.update_zone_relay_sn";
pub const METHOD_REGISTER_RELAY_NODE: &str = "sn_auth_db.register_relay_node";
pub const METHOD_HEARTBEAT_RELAY_NODE: &str = "sn_auth_db.heartbeat_relay_node";
pub const METHOD_UPDATE_RELAY_NODE_ADDRESSES: &str = "sn_auth_db.update_relay_node_addresses";
pub const METHOD_GET_RELAY_NODE: &str = "sn_auth_db.get_relay_node";
pub const METHOD_LIST_RELAY_NODES: &str = "sn_auth_db.list_relay_nodes";
pub const METHOD_GET_RELAY_NODES_IP_MAP: &str = "sn_auth_db.get_relay_nodes_ip_map";
pub const METHOD_ASSIGN_ZONE_RELAY: &str = "sn_auth_db.assign_zone_relay";
pub const METHOD_ALLOCATE_ZONE_RELAY: &str = "sn_auth_db.allocate_zone_relay";
pub const METHOD_GET_ZONE_RELAY: &str = "sn_auth_db.get_zone_relay";
pub const METHOD_START_RELAY_MIGRATION: &str = "sn_auth_db.start_relay_migration";
pub const METHOD_COMPLETE_RELAY_MIGRATION: &str = "sn_auth_db.complete_relay_migration";
pub const METHOD_CHECK_RELAY_ADMISSION: &str = "sn_auth_db.check_relay_admission";
pub const METHOD_CREATE_ACCOUNT_SESSION: &str = "sn_auth_db.create_account_session";
pub const METHOD_REVOKE_ACCOUNT_SESSION: &str = "sn_auth_db.revoke_account_session";
pub const METHOD_REVOKE_USER_SESSIONS: &str = "sn_auth_db.revoke_user_sessions";
pub const METHOD_GET_ACCOUNT_SESSION: &str = "sn_auth_db.get_account_session";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRpcErrorInfo {
    pub code: SnErrorCode,
    pub message: String,
}

impl SnAuthDbRpcErrorInfo {
    pub fn from_sn_error(error: SnError) -> Self {
        Self {
            code: error.code(),
            message: error.msg().to_string(),
        }
    }

    pub fn into_sn_error(self) -> SnError {
        SnError::new(self.code, self.message)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SnAuthDbRpcEnvelope<T> {
    pub ok: bool,
    pub result: Option<T>,
    pub error: Option<SnAuthDbRpcErrorInfo>,
}

#[derive(Deserialize)]
struct SnAuthDbRpcEnvelopeWire {
    ok: bool,
    #[serde(default, deserialize_with = "deserialize_present_json_value")]
    result: Option<Value>,
    error: Option<SnAuthDbRpcErrorInfo>,
}

fn deserialize_present_json_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

impl<'de, T> Deserialize<'de> for SnAuthDbRpcEnvelope<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SnAuthDbRpcEnvelopeWire::deserialize(deserializer)?;
        let result = if wire.ok {
            wire.result
                .map(serde_json::from_value)
                .transpose()
                .map_err(DeError::custom)?
        } else {
            None
        };

        Ok(Self {
            ok: wire.ok,
            result,
            error: wire.error,
        })
    }
}

impl<T> SnAuthDbRpcEnvelope<T> {
    pub fn success(result: T) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(error: SnError) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(SnAuthDbRpcErrorInfo::from_sn_error(error)),
        }
    }

    pub fn into_result(self) -> SnResult<T> {
        if self.ok {
            self.result.ok_or_else(|| {
                sn_err!(
                    SnErrorCode::RemoteError,
                    "SnAuthDB RPC envelope missing result"
                )
            })
        } else {
            Err(self
                .error
                .map(SnAuthDbRpcErrorInfo::into_sn_error)
                .unwrap_or_else(|| {
                    sn_err!(
                        SnErrorCode::RemoteError,
                        "SnAuthDB RPC envelope missing error"
                    )
                }))
        }
    }
}

macro_rules! impl_req_from_json {
    ($ty:ident) => {
        pub fn from_json(value: Value) -> Result<Self, RPCErrors> {
            serde_json::from_value(value).map_err(|e| {
                RPCErrors::ParseRequestError(format!("Failed to parse {}: {}", stringify!($ty), e))
            })
        }
    };
}

fn parse_request<T: DeserializeOwned>(value: Value) -> Result<T, RPCErrors> {
    serde_json::from_value(value).map_err(|e| {
        RPCErrors::ParseRequestError(format!(
            "Failed to parse {}: {}",
            std::any::type_name::<T>(),
            e
        ))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbGetActivationCodesReq {}

impl SnAuthDbGetActivationCodesReq {
    pub fn new() -> Self {
        Self {}
    }

    impl_req_from_json!(SnAuthDbGetActivationCodesReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbInsertActivationCodeReq {
    pub code: String,
}

impl SnAuthDbInsertActivationCodeReq {
    pub fn new(code: &str) -> Self {
        Self {
            code: code.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbInsertActivationCodeReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbGenerateActivationCodesReq {
    pub count: usize,
}

impl SnAuthDbGenerateActivationCodesReq {
    pub fn new(count: usize) -> Self {
        Self { count }
    }

    impl_req_from_json!(SnAuthDbGenerateActivationCodesReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbCheckActiveCodeReq {
    pub active_code: String,
}

impl SnAuthDbCheckActiveCodeReq {
    pub fn new(active_code: &str) -> Self {
        Self {
            active_code: active_code.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbCheckActiveCodeReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbClearStateByActiveCodeReq {
    pub active_code: String,
}

impl SnAuthDbClearStateByActiveCodeReq {
    pub fn new(active_code: &str) -> Self {
        Self {
            active_code: active_code.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbClearStateByActiveCodeReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRegisterUserReq {
    pub active_code: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub password_salt: String,
    pub password_algo: String,
}

impl SnAuthDbRegisterUserReq {
    pub fn new(
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> Self {
        Self {
            active_code: active_code.to_string(),
            username: username.to_string(),
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            password_salt: password_salt.to_string(),
            password_algo: password_algo.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbRegisterUserReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbCreateAuthReq {
    pub username: String,
    pub password_hash: String,
    pub password_salt: String,
    pub password_algo: String,
}

impl SnAuthDbCreateAuthReq {
    pub fn new(
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> Self {
        Self {
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            password_salt: password_salt.to_string(),
            password_algo: password_algo.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbCreateAuthReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUsernameReq {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbEmailReq {
    pub email: String,
}

impl SnAuthDbEmailReq {
    pub fn new(email: &str) -> Self {
        Self {
            email: email.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbEmailReq);
}

impl SnAuthDbUsernameReq {
    pub fn new(username: &str) -> Self {
        Self {
            username: username.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbUsernameReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRegisterUserWithOwnerKeyReq {
    pub active_code: String,
    pub username: String,
    pub email: String,
    pub public_key: String,
    pub zone_config: String,
    pub user_domain: Option<String>,
    pub sn_ips: Option<String>,
}

impl SnAuthDbRegisterUserWithOwnerKeyReq {
    pub fn new(
        active_code: &str,
        username: &str,
        email: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> Self {
        Self {
            active_code: active_code.to_string(),
            username: username.to_string(),
            email: email.to_string(),
            public_key: public_key.to_string(),
            zone_config: zone_config.to_string(),
            user_domain,
            sn_ips,
        }
    }

    impl_req_from_json!(SnAuthDbRegisterUserWithOwnerKeyReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbPublicKeyReq {
    pub public_key: String,
}

impl SnAuthDbPublicKeyReq {
    pub fn new(public_key: &str) -> Self {
        Self {
            public_key: public_key.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbPublicKeyReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbDomainReq {
    pub domain: String,
}

impl SnAuthDbDomainReq {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbDomainReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbSetUserStateReq {
    pub username: String,
    pub state: UserState,
}

impl SnAuthDbSetUserStateReq {
    pub fn new(username: &str, state: UserState) -> Self {
        Self {
            username: username.to_string(),
            state,
        }
    }

    impl_req_from_json!(SnAuthDbSetUserStateReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateUserPublicKeyReq {
    pub username: String,
    pub public_key: String,
}

impl SnAuthDbUpdateUserPublicKeyReq {
    pub fn new(username: &str, public_key: &str) -> Self {
        Self {
            username: username.to_string(),
            public_key: public_key.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbUpdateUserPublicKeyReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateUserZoneConfigReq {
    pub username: String,
    pub zone_config: String,
}

impl SnAuthDbUpdateUserZoneConfigReq {
    pub fn new(username: &str, zone_config: &str) -> Self {
        Self {
            username: username.to_string(),
            zone_config: zone_config.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbUpdateUserZoneConfigReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateUserSelfCertReq {
    pub username: String,
    pub self_cert: bool,
}

impl SnAuthDbUpdateUserSelfCertReq {
    pub fn new(username: &str, self_cert: bool) -> Self {
        Self {
            username: username.to_string(),
            self_cert,
        }
    }

    impl_req_from_json!(SnAuthDbUpdateUserSelfCertReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateUserDomainReq {
    pub username: String,
    pub user_domain: Option<String>,
}

impl SnAuthDbUpdateUserDomainReq {
    pub fn new(username: &str, user_domain: Option<String>) -> Self {
        Self {
            username: username.to_string(),
            user_domain,
        }
    }

    impl_req_from_json!(SnAuthDbUpdateUserDomainReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateLastLoginReq {
    pub username: String,
    pub last_login_at: u64,
}

impl SnAuthDbUpdateLastLoginReq {
    pub fn new(username: &str, last_login_at: u64) -> Self {
        Self {
            username: username.to_string(),
            last_login_at,
        }
    }

    impl_req_from_json!(SnAuthDbUpdateLastLoginReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbActivateUserDomainBindingReq {
    pub username: String,
    pub domain: String,
    pub pkx: String,
}

impl SnAuthDbActivateUserDomainBindingReq {
    pub fn new(username: &str, domain: &str, pkx: &str) -> Self {
        Self {
            username: username.to_string(),
            domain: domain.to_string(),
            pkx: pkx.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbActivateUserDomainBindingReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUnbindUserDomainReq {
    pub username: String,
    pub domain: String,
}

impl SnAuthDbUnbindUserDomainReq {
    pub fn new(username: &str, domain: &str) -> Self {
        Self {
            username: username.to_string(),
            domain: domain.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbUnbindUserDomainReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbPutUserDnsValueReq {
    pub owner: String,
    pub name: String,
    pub record_type: UserDnsRecordType,
    pub value: String,
    pub ttl: u32,
}

impl SnAuthDbPutUserDnsValueReq {
    pub fn new(
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        value: &str,
        ttl: u32,
    ) -> Self {
        Self {
            owner: owner.to_string(),
            name: name.to_string(),
            record_type,
            value: value.to_string(),
            ttl,
        }
    }

    impl_req_from_json!(SnAuthDbPutUserDnsValueReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRemoveUserDnsValueReq {
    pub owner: String,
    pub name: String,
    pub record_type: UserDnsRecordType,
    pub value: String,
}

impl SnAuthDbRemoveUserDnsValueReq {
    pub fn new(owner: &str, name: &str, record_type: UserDnsRecordType, value: &str) -> Self {
        Self {
            owner: owner.to_string(),
            name: name.to_string(),
            record_type,
            value: value.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbRemoveUserDnsValueReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUserDnsRrsetReq {
    pub owner: String,
    pub name: String,
    pub record_type: UserDnsRecordType,
}

impl SnAuthDbUserDnsRrsetReq {
    pub fn new(owner: &str, name: &str, record_type: UserDnsRecordType) -> Self {
        Self {
            owner: owner.to_string(),
            name: name.to_string(),
            record_type,
        }
    }

    impl_req_from_json!(SnAuthDbUserDnsRrsetReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbSetUserDnsRrsetTtlReq {
    pub owner: String,
    pub name: String,
    pub record_type: UserDnsRecordType,
    pub ttl: u32,
}

impl SnAuthDbSetUserDnsRrsetTtlReq {
    pub fn new(owner: &str, name: &str, record_type: UserDnsRecordType, ttl: u32) -> Self {
        Self {
            owner: owner.to_string(),
            name: name.to_string(),
            record_type,
            ttl,
        }
    }

    impl_req_from_json!(SnAuthDbSetUserDnsRrsetTtlReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbGetUserDnsRrsetReq {
    pub name: String,
    pub record_type: UserDnsRecordType,
}

impl SnAuthDbGetUserDnsRrsetReq {
    pub fn new(name: &str, record_type: UserDnsRecordType) -> Self {
        Self {
            name: name.to_string(),
            record_type,
        }
    }

    impl_req_from_json!(SnAuthDbGetUserDnsRrsetReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbListUserDnsChangesReq {
    pub after_revision: u64,
    pub limit: usize,
}

impl SnAuthDbListUserDnsChangesReq {
    pub fn new(after_revision: u64, limit: usize) -> Self {
        Self {
            after_revision,
            limit,
        }
    }

    impl_req_from_json!(SnAuthDbListUserDnsChangesReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateZoneInfoReq {
    pub username: String,
    pub patch: ZoneInfoPatch,
}

impl SnAuthDbUpdateZoneInfoReq {
    pub fn new(username: &str, patch: ZoneInfoPatch) -> Self {
        Self {
            username: username.to_string(),
            patch,
        }
    }

    impl_req_from_json!(SnAuthDbUpdateZoneInfoReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateZoneRelaySnReq {
    pub zone: String,
    pub relay_sn: String,
    pub source_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRelayIdReq {
    pub relay_id: String,
}

impl SnAuthDbRelayIdReq {
    pub fn new(relay_id: &str) -> Self {
        Self {
            relay_id: relay_id.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbRelayIdReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbZoneReq {
    pub zone: String,
}

impl SnAuthDbZoneReq {
    pub fn new(zone: &str) -> Self {
        Self {
            zone: zone.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbZoneReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbCompleteRelayMigrationReq {
    pub zone: String,
    pub generation: u64,
}

impl SnAuthDbCompleteRelayMigrationReq {
    pub fn new(zone: &str, generation: u64) -> Self {
        Self {
            zone: zone.to_string(),
            generation,
        }
    }

    impl_req_from_json!(SnAuthDbCompleteRelayMigrationReq);
}

impl SnAuthDbUpdateZoneRelaySnReq {
    pub fn new(zone: &str, relay_sn: &str, source_version: Option<&str>) -> Self {
        Self {
            zone: zone.to_string(),
            relay_sn: relay_sn.to_string(),
            source_version: source_version.map(ToString::to_string),
        }
    }

    impl_req_from_json!(SnAuthDbUpdateZoneRelaySnReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbCreateAccountSessionReq {
    pub session_id: String,
    pub username: String,
    pub token_aud: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl SnAuthDbCreateAccountSessionReq {
    pub fn new(
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            session_id: session_id.to_string(),
            username: username.to_string(),
            token_aud: token_aud.to_string(),
            issued_at,
            expires_at,
        }
    }

    impl_req_from_json!(SnAuthDbCreateAccountSessionReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRevokeAccountSessionReq {
    pub session_id: String,
    pub revoked_at: u64,
}

impl SnAuthDbRevokeAccountSessionReq {
    pub fn new(session_id: &str, revoked_at: u64) -> Self {
        Self {
            session_id: session_id.to_string(),
            revoked_at,
        }
    }

    impl_req_from_json!(SnAuthDbRevokeAccountSessionReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRevokeUserSessionsReq {
    pub username: String,
    pub revoked_at: u64,
}

impl SnAuthDbRevokeUserSessionsReq {
    pub fn new(username: &str, revoked_at: u64) -> Self {
        Self {
            username: username.to_string(),
            revoked_at,
        }
    }

    impl_req_from_json!(SnAuthDbRevokeUserSessionsReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbSessionIdReq {
    pub session_id: String,
}

impl SnAuthDbSessionIdReq {
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbSessionIdReq);
}

#[derive(Clone)]
pub enum SnAuthDbClient {
    InProcess(Arc<dyn SnAuthDB>),
    KRPC(Arc<SnAuthDbKrpcClient>),
}

pub struct SnAuthDbKrpcClient {
    client: Arc<kRPC>,
    read_cache: RemoteReadCache,
}

impl SnAuthDbKrpcClient {
    fn new(client: Arc<kRPC>) -> Self {
        Self {
            client,
            read_cache: RemoteReadCache::new(
                SN_AUTH_DB_READ_CACHE_TTL,
                SN_AUTH_DB_READ_CACHE_CAPACITY,
            ),
        }
    }
}

impl SnAuthDbClient {
    pub fn new_in_process(handler: Arc<dyn SnAuthDB>) -> Self {
        Self::InProcess(handler)
    }

    pub fn new_krpc(client: Arc<kRPC>) -> Self {
        Self::KRPC(Arc::new(SnAuthDbKrpcClient::new(client)))
    }

    pub fn new_krpc_url(auth_db_url: &str, session_token: Option<String>) -> Self {
        let endpoint = normalize_sn_auth_db_url(auth_db_url);
        Self::new_krpc(Arc::new(kRPC::new(endpoint.as_str(), session_token)))
    }

    async fn call<Req, Resp>(&self, method: &str, req: &Req) -> SnResult<Resp>
    where
        Req: Serialize + Sync,
        Resp: for<'de> Deserialize<'de>,
    {
        match self {
            Self::InProcess(_) => Err(sn_err!(
                SnErrorCode::RemoteError,
                "generic call is only available for KRPC clients"
            )),
            Self::KRPC(client) => {
                let cache_key = if is_cached_auth_db_read(method) {
                    Some(RemoteReadCache::key(method, req).map_err(|e| {
                        sn_err!(
                            SnErrorCode::RemoteError,
                            "failed to build SnAuthDB RPC {} cache key: {}",
                            method,
                            e
                        )
                    })?)
                } else {
                    None
                };
                if let Some(cached) = cache_key
                    .as_deref()
                    .and_then(|key| client.read_cache.get(key))
                {
                    let envelope: SnAuthDbRpcEnvelope<Resp> = serde_json::from_value(cached)
                        .map_err(|e| {
                            sn_err!(
                                SnErrorCode::RemoteError,
                                "failed to parse cached SnAuthDB RPC {} response: {}",
                                method,
                                e
                            )
                        })?;
                    return envelope.into_result();
                }

                let req_json = serde_json::to_value(req).map_err(|e| {
                    sn_err!(
                        SnErrorCode::RemoteError,
                        "failed to serialize SnAuthDB RPC {} request: {}",
                        method,
                        e
                    )
                })?;
                let result = client.client.call(method, req_json).await.map_err(|e| {
                    sn_err!(
                        SnErrorCode::RemoteError,
                        "SnAuthDB RPC {} transport failed: {}",
                        method,
                        e
                    )
                })?;
                let envelope: SnAuthDbRpcEnvelope<Resp> = serde_json::from_value(result.clone())
                    .map_err(|e| {
                        sn_err!(
                            SnErrorCode::RemoteError,
                            "failed to parse SnAuthDB RPC {} response: {}",
                            method,
                            e
                        )
                    })?;
                let response = envelope.into_result()?;
                if let Some(cache_key) = cache_key {
                    client.read_cache.insert(cache_key, result);
                } else if auth_db_method_invalidates_read_cache(method) {
                    client.read_cache.clear();
                }
                Ok(response)
            }
        }
    }
}

fn is_cached_auth_db_read(method: &str) -> bool {
    matches!(
        method,
        METHOD_GET_USER_INFO
            | METHOD_GET_USER_BY_DOMAIN
            | METHOD_GET_ZONE_INFO
            | METHOD_GET_ZONE_RELAY
    )
}

fn auth_db_method_invalidates_read_cache(method: &str) -> bool {
    matches!(
        method,
        METHOD_CLEAR_STATE_BY_ACTIVE_CODE
            | METHOD_REGISTER_USER
            | METHOD_REGISTER_USER_WITH_RELAY_ALLOCATION
            | METHOD_REGISTER_USER_WITH_OWNER_KEY
            | METHOD_SET_USER_STATE
            | METHOD_UPDATE_USER_PUBLIC_KEY
            | METHOD_UPDATE_USER_ZONE_CONFIG
            | METHOD_UPDATE_USER_SELF_CERT
            | METHOD_UPDATE_USER_DOMAIN
            | METHOD_ACTIVATE_USER_DOMAIN_BINDING
            | METHOD_UNBIND_USER_DOMAIN
            | METHOD_UPDATE_ZONE_INFO
            | METHOD_UPDATE_ZONE_RELAY_SN
            | METHOD_ASSIGN_ZONE_RELAY
            | METHOD_ALLOCATE_ZONE_RELAY
            | METHOD_START_RELAY_MIGRATION
            | METHOD_COMPLETE_RELAY_MIGRATION
    )
}

#[async_trait]
impl SnAuthDB for SnAuthDbClient {
    async fn capabilities(&self) -> SnResult<SnAuthDbCapabilities> {
        match self {
            Self::InProcess(handler) => handler.capabilities().await,
            Self::KRPC(_) => {
                self.call(METHOD_CAPABILITIES, &SnAuthDbGetActivationCodesReq::new())
                    .await
            }
        }
    }

    async fn get_activation_codes(&self) -> SnResult<Vec<String>> {
        match self {
            Self::InProcess(handler) => handler.get_activation_codes().await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_ACTIVATION_CODES,
                    &SnAuthDbGetActivationCodesReq::new(),
                )
                .await
            }
        }
    }

    async fn insert_activation_code(&self, code: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.insert_activation_code(code).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_INSERT_ACTIVATION_CODE,
                    &SnAuthDbInsertActivationCodeReq::new(code),
                )
                .await
            }
        }
    }

    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>> {
        match self {
            Self::InProcess(handler) => handler.generate_activation_codes(count).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GENERATE_ACTIVATION_CODES,
                    &SnAuthDbGenerateActivationCodesReq::new(count),
                )
                .await
            }
        }
    }

    async fn check_active_code(&self, active_code: &str) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => handler.check_active_code(active_code).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_CHECK_ACTIVE_CODE,
                    &SnAuthDbCheckActiveCodeReq::new(active_code),
                )
                .await
            }
        }
    }

    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult> {
        match self {
            Self::InProcess(handler) => handler.clear_state_by_active_code(active_code).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_CLEAR_STATE_BY_ACTIVE_CODE,
                    &SnAuthDbClearStateByActiveCodeReq::new(active_code),
                )
                .await
            }
        }
    }

    async fn register_user(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .register_user(
                        active_code,
                        username,
                        email,
                        password_hash,
                        password_salt,
                        password_algo,
                    )
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_REGISTER_USER,
                    &SnAuthDbRegisterUserReq::new(
                        active_code,
                        username,
                        email,
                        password_hash,
                        password_salt,
                        password_algo,
                    ),
                )
                .await
            }
        }
    }

    async fn register_user_with_relay_allocation(
        &self,
        req: RegisterUserWithRelayAllocationReq,
    ) -> SnResult<RegisterUserWithRelayAllocationResult> {
        match self {
            Self::InProcess(handler) => handler.register_user_with_relay_allocation(req).await,
            Self::KRPC(_) => {
                self.call(METHOD_REGISTER_USER_WITH_RELAY_ALLOCATION, &req)
                    .await
            }
        }
    }

    async fn create_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .create_auth(username, password_hash, password_salt, password_algo)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_CREATE_AUTH,
                    &SnAuthDbCreateAuthReq::new(
                        username,
                        password_hash,
                        password_salt,
                        password_algo,
                    ),
                )
                .await
            }
        }
    }

    async fn is_user_exist(&self, username: &str) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => handler.is_user_exist(username).await,
            Self::KRPC(_) => {
                self.call(METHOD_IS_USER_EXIST, &SnAuthDbUsernameReq::new(username))
                    .await
            }
        }
    }

    async fn get_user_by_email(&self, email: &str) -> SnResult<Option<SNUserInfo>> {
        match self {
            Self::InProcess(handler) => handler.get_user_by_email(email).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_USER_BY_EMAIL, &SnAuthDbEmailReq::new(email))
                    .await
            }
        }
    }

    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .register_user_with_owner_key(
                        active_code,
                        username,
                        email,
                        public_key,
                        zone_config,
                        user_domain,
                        sn_ips,
                    )
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_REGISTER_USER_WITH_OWNER_KEY,
                    &SnAuthDbRegisterUserWithOwnerKeyReq::new(
                        active_code,
                        username,
                        email,
                        public_key,
                        zone_config,
                        user_domain,
                        sn_ips,
                    ),
                )
                .await
            }
        }
    }

    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        match self {
            Self::InProcess(handler) => handler.get_user_by_public_key(public_key).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_USER_BY_PUBLIC_KEY,
                    &SnAuthDbPublicKeyReq::new(public_key),
                )
                .await
            }
        }
    }

    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>> {
        match self {
            Self::InProcess(handler) => handler.get_user_info(username).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_USER_INFO, &SnAuthDbUsernameReq::new(username))
                    .await
            }
        }
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>> {
        match self {
            Self::InProcess(handler) => handler.get_user_by_domain(domain).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_USER_BY_DOMAIN, &SnAuthDbDomainReq::new(domain))
                    .await
            }
        }
    }

    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.set_user_state(username, state).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_SET_USER_STATE,
                    &SnAuthDbSetUserStateReq::new(username, state),
                )
                .await
            }
        }
    }

    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_user_public_key(username, public_key).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_USER_PUBLIC_KEY,
                    &SnAuthDbUpdateUserPublicKeyReq::new(username, public_key),
                )
                .await
            }
        }
    }

    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => {
                handler.update_user_zone_config(username, zone_config).await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_USER_ZONE_CONFIG,
                    &SnAuthDbUpdateUserZoneConfigReq::new(username, zone_config),
                )
                .await
            }
        }
    }

    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_user_self_cert(username, self_cert).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_USER_SELF_CERT,
                    &SnAuthDbUpdateUserSelfCertReq::new(username, self_cert),
                )
                .await
            }
        }
    }

    async fn update_user_domain(
        &self,
        username: &str,
        user_domain: Option<String>,
    ) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_user_domain(username, user_domain).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_USER_DOMAIN,
                    &SnAuthDbUpdateUserDomainReq::new(username, user_domain),
                )
                .await
            }
        }
    }

    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>> {
        match self {
            Self::InProcess(handler) => handler.get_user_sn_ips(username).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_USER_SN_IPS, &SnAuthDbUsernameReq::new(username))
                    .await
            }
        }
    }

    async fn get_auth(&self, username: &str) -> SnResult<Option<SnAuthInfo>> {
        match self {
            Self::InProcess(handler) => handler.get_auth(username).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_AUTH, &SnAuthDbUsernameReq::new(username))
                    .await
            }
        }
    }

    async fn update_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_last_login(username, last_login_at).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_LAST_LOGIN,
                    &SnAuthDbUpdateLastLoginReq::new(username, last_login_at),
                )
                .await
            }
        }
    }

    async fn activate_user_domain_binding(
        &self,
        username: &str,
        domain: &str,
        pkx: &str,
    ) -> SnResult<DomainBinding> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .activate_user_domain_binding(username, domain, pkx)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_ACTIVATE_USER_DOMAIN_BINDING,
                    &SnAuthDbActivateUserDomainBindingReq::new(username, domain, pkx),
                )
                .await
            }
        }
    }

    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.unbind_user_domain(username, domain).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UNBIND_USER_DOMAIN,
                    &SnAuthDbUnbindUserDomainReq::new(username, domain),
                )
                .await
            }
        }
    }

    async fn put_user_dns_value(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        value: &str,
        ttl: u32,
    ) -> SnResult<UserDnsMutationResult> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .put_user_dns_value(owner, name, record_type, value, ttl)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_PUT_USER_DNS_VALUE,
                    &SnAuthDbPutUserDnsValueReq::new(owner, name, record_type, value, ttl),
                )
                .await
            }
        }
    }

    async fn remove_user_dns_value(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        value: &str,
    ) -> SnResult<UserDnsMutationResult> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .remove_user_dns_value(owner, name, record_type, value)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_REMOVE_USER_DNS_VALUE,
                    &SnAuthDbRemoveUserDnsValueReq::new(owner, name, record_type, value),
                )
                .await
            }
        }
    }

    async fn delete_user_dns_rrset(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResult<UserDnsMutationResult> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .delete_user_dns_rrset(owner, name, record_type)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_DELETE_USER_DNS_RRSET,
                    &SnAuthDbUserDnsRrsetReq::new(owner, name, record_type),
                )
                .await
            }
        }
    }

    async fn set_user_dns_rrset_ttl(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        ttl: u32,
    ) -> SnResult<UserDnsMutationResult> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .set_user_dns_rrset_ttl(owner, name, record_type, ttl)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_SET_USER_DNS_RRSET_TTL,
                    &SnAuthDbSetUserDnsRrsetTtlReq::new(owner, name, record_type, ttl),
                )
                .await
            }
        }
    }

    async fn get_user_dns_rrset(
        &self,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResult<UserDnsLookup> {
        match self {
            Self::InProcess(handler) => handler.get_user_dns_rrset(name, record_type).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_USER_DNS_RRSET,
                    &SnAuthDbGetUserDnsRrsetReq::new(name, record_type),
                )
                .await
            }
        }
    }

    async fn list_user_dns_rrsets(&self, owner: &str) -> SnResult<Vec<UserDnsRrset>> {
        match self {
            Self::InProcess(handler) => handler.list_user_dns_rrsets(owner).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_LIST_USER_DNS_RRSETS,
                    &SnAuthDbUsernameReq::new(owner),
                )
                .await
            }
        }
    }

    async fn list_user_dns_changes(
        &self,
        after_revision: u64,
        limit: usize,
    ) -> SnResult<UserDnsChangePage> {
        match self {
            Self::InProcess(handler) => handler.list_user_dns_changes(after_revision, limit).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_LIST_USER_DNS_CHANGES,
                    &SnAuthDbListUserDnsChangesReq::new(after_revision, limit),
                )
                .await
            }
        }
    }

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>> {
        match self {
            Self::InProcess(handler) => handler.get_zone_info(username).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_ZONE_INFO, &SnAuthDbUsernameReq::new(username))
                    .await
            }
        }
    }

    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_zone_info(username, patch).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_ZONE_INFO,
                    &SnAuthDbUpdateZoneInfoReq::new(username, patch),
                )
                .await
            }
        }
    }

    async fn update_zone_relay_sn(
        &self,
        zone: &str,
        relay_sn: &str,
        source_version: Option<&str>,
    ) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .update_zone_relay_sn(zone, relay_sn, source_version)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_ZONE_RELAY_SN,
                    &SnAuthDbUpdateZoneRelaySnReq::new(zone, relay_sn, source_version),
                )
                .await
            }
        }
    }

    async fn register_relay_node(&self, node: RelayNodeRegistration) -> SnResult<RelayNode> {
        match self {
            Self::InProcess(handler) => handler.register_relay_node(node).await,
            Self::KRPC(_) => self.call(METHOD_REGISTER_RELAY_NODE, &node).await,
        }
    }

    async fn heartbeat_relay_node(&self, heartbeat: RelayHeartbeat) -> SnResult<RelayNodeHealth> {
        match self {
            Self::InProcess(handler) => handler.heartbeat_relay_node(heartbeat).await,
            Self::KRPC(_) => self.call(METHOD_HEARTBEAT_RELAY_NODE, &heartbeat).await,
        }
    }

    async fn update_relay_node_addresses(
        &self,
        update: RelayNodeAddressUpdate,
    ) -> SnResult<RelayNode> {
        match self {
            Self::InProcess(handler) => handler.update_relay_node_addresses(update).await,
            Self::KRPC(_) => self.call(METHOD_UPDATE_RELAY_NODE_ADDRESSES, &update).await,
        }
    }

    async fn get_relay_node(&self, relay_id: &str) -> SnResult<Option<RelayNode>> {
        match self {
            Self::InProcess(handler) => handler.get_relay_node(relay_id).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_RELAY_NODE, &SnAuthDbRelayIdReq::new(relay_id))
                    .await
            }
        }
    }

    async fn list_relay_nodes(&self) -> SnResult<Vec<RelayNode>> {
        match self {
            Self::InProcess(handler) => handler.list_relay_nodes().await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_LIST_RELAY_NODES,
                    &SnAuthDbGetActivationCodesReq::new(),
                )
                .await
            }
        }
    }

    async fn get_relay_nodes_ip_map(
        &self,
        req: RelayNodeIpMapReq,
    ) -> SnResult<Option<RelayNodeIpMapSnapshot>> {
        match self {
            Self::InProcess(handler) => handler.get_relay_nodes_ip_map(req).await,
            Self::KRPC(_) => self.call(METHOD_GET_RELAY_NODES_IP_MAP, &req).await,
        }
    }

    async fn assign_zone_relay(&self, req: AssignZoneRelayReq) -> SnResult<RelayAssignment> {
        match self {
            Self::InProcess(handler) => handler.assign_zone_relay(req).await,
            Self::KRPC(_) => self.call(METHOD_ASSIGN_ZONE_RELAY, &req).await,
        }
    }

    async fn allocate_zone_relay(&self, req: AllocateZoneRelayReq) -> SnResult<RelayAssignment> {
        match self {
            Self::InProcess(handler) => handler.allocate_zone_relay(req).await,
            Self::KRPC(_) => self.call(METHOD_ALLOCATE_ZONE_RELAY, &req).await,
        }
    }

    async fn get_zone_relay(&self, zone: &str) -> SnResult<Option<RelayAssignment>> {
        match self {
            Self::InProcess(handler) => handler.get_zone_relay(zone).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_ZONE_RELAY, &SnAuthDbZoneReq::new(zone))
                    .await
            }
        }
    }

    async fn start_relay_migration(&self, req: RelayMigrationReq) -> SnResult<RelayAssignment> {
        match self {
            Self::InProcess(handler) => handler.start_relay_migration(req).await,
            Self::KRPC(_) => self.call(METHOD_START_RELAY_MIGRATION, &req).await,
        }
    }

    async fn complete_relay_migration(&self, zone: &str, generation: u64) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.complete_relay_migration(zone, generation).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_COMPLETE_RELAY_MIGRATION,
                    &SnAuthDbCompleteRelayMigrationReq::new(zone, generation),
                )
                .await
            }
        }
    }

    async fn check_relay_admission(
        &self,
        req: RelayAdmissionReq,
    ) -> SnResult<RelayAdmissionDecision> {
        match self {
            Self::InProcess(handler) => handler.check_relay_admission(req).await,
            Self::KRPC(_) => self.call(METHOD_CHECK_RELAY_ADMISSION, &req).await,
        }
    }

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .create_account_session(session_id, username, token_aud, issued_at, expires_at)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_CREATE_ACCOUNT_SESSION,
                    &SnAuthDbCreateAccountSessionReq::new(
                        session_id, username, token_aud, issued_at, expires_at,
                    ),
                )
                .await
            }
        }
    }

    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => {
                handler.revoke_account_session(session_id, revoked_at).await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_REVOKE_ACCOUNT_SESSION,
                    &SnAuthDbRevokeAccountSessionReq::new(session_id, revoked_at),
                )
                .await
            }
        }
    }

    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64> {
        match self {
            Self::InProcess(handler) => handler.revoke_user_sessions(username, revoked_at).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_REVOKE_USER_SESSIONS,
                    &SnAuthDbRevokeUserSessionsReq::new(username, revoked_at),
                )
                .await
            }
        }
    }

    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>> {
        match self {
            Self::InProcess(handler) => handler.get_account_session(session_id).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_ACCOUNT_SESSION,
                    &SnAuthDbSessionIdReq::new(session_id),
                )
                .await
            }
        }
    }
}

pub struct SnAuthDbRpcHandler<T: SnAuthDB>(pub T);

impl<T: SnAuthDB> SnAuthDbRpcHandler<T> {
    pub fn new(handler: T) -> Self {
        Self(handler)
    }
}

#[async_trait]
impl<T> RPCHandler for SnAuthDbRpcHandler<T>
where
    T: SnAuthDB,
{
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        _ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        match req.method.as_str() {
            METHOD_CAPABILITIES => {
                let _parsed = SnAuthDbGetActivationCodesReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.capabilities().await, &req)
            }
            METHOD_GET_ACTIVATION_CODES | "get_activation_codes" => {
                let _parsed = SnAuthDbGetActivationCodesReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_activation_codes().await, &req)
            }
            METHOD_INSERT_ACTIVATION_CODE | "insert_activation_code" => {
                let parsed = SnAuthDbInsertActivationCodeReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.insert_activation_code(&parsed.code).await, &req)
            }
            METHOD_GENERATE_ACTIVATION_CODES | "generate_activation_codes" => {
                let parsed = SnAuthDbGenerateActivationCodesReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.generate_activation_codes(parsed.count).await, &req)
            }
            METHOD_CHECK_ACTIVE_CODE | "check_active_code" => {
                let parsed = SnAuthDbCheckActiveCodeReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.check_active_code(&parsed.active_code).await, &req)
            }
            METHOD_CLEAR_STATE_BY_ACTIVE_CODE | "clear_state_by_active_code" => {
                let parsed = SnAuthDbClearStateByActiveCodeReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0.clear_state_by_active_code(&parsed.active_code).await,
                    &req,
                )
            }
            METHOD_REGISTER_USER | "register_user" => {
                let parsed = SnAuthDbRegisterUserReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .register_user(
                            &parsed.active_code,
                            &parsed.username,
                            &parsed.email,
                            &parsed.password_hash,
                            &parsed.password_salt,
                            &parsed.password_algo,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_REGISTER_USER_WITH_RELAY_ALLOCATION | "register_user_with_relay_allocation" => {
                let parsed =
                    parse_request::<RegisterUserWithRelayAllocationReq>(req.params.clone())?;
                rpc_envelope_response(
                    self.0.register_user_with_relay_allocation(parsed).await,
                    &req,
                )
            }
            METHOD_CREATE_AUTH | "create_auth" => {
                let parsed = SnAuthDbCreateAuthReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .create_auth(
                            &parsed.username,
                            &parsed.password_hash,
                            &parsed.password_salt,
                            &parsed.password_algo,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_IS_USER_EXIST | "is_user_exist" => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.is_user_exist(&parsed.username).await, &req)
            }
            METHOD_GET_USER_BY_EMAIL | "get_user_by_email" => {
                let parsed = SnAuthDbEmailReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_user_by_email(&parsed.email).await, &req)
            }
            METHOD_REGISTER_USER_WITH_OWNER_KEY | "register_user_with_owner_key" => {
                let parsed = SnAuthDbRegisterUserWithOwnerKeyReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .register_user_with_owner_key(
                            &parsed.active_code,
                            &parsed.username,
                            &parsed.email,
                            &parsed.public_key,
                            &parsed.zone_config,
                            parsed.user_domain,
                            parsed.sn_ips,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_GET_USER_BY_PUBLIC_KEY | "get_user_by_public_key" => {
                let parsed = SnAuthDbPublicKeyReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0.get_user_by_public_key(&parsed.public_key).await,
                    &req,
                )
            }
            METHOD_GET_USER_INFO | "get_user_info" => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_user_info(&parsed.username).await, &req)
            }
            METHOD_GET_USER_BY_DOMAIN | "get_user_by_domain" => {
                let parsed = SnAuthDbDomainReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_user_by_domain(&parsed.domain).await, &req)
            }
            METHOD_SET_USER_STATE | "set_user_state" => {
                let parsed = SnAuthDbSetUserStateReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0.set_user_state(&parsed.username, parsed.state).await,
                    &req,
                )
            }
            METHOD_UPDATE_USER_PUBLIC_KEY | "update_user_public_key" => {
                let parsed = SnAuthDbUpdateUserPublicKeyReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_user_public_key(&parsed.username, &parsed.public_key)
                        .await,
                    &req,
                )
            }
            METHOD_UPDATE_USER_ZONE_CONFIG | "update_user_zone_config" => {
                let parsed = SnAuthDbUpdateUserZoneConfigReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_user_zone_config(&parsed.username, &parsed.zone_config)
                        .await,
                    &req,
                )
            }
            METHOD_UPDATE_USER_SELF_CERT | "update_user_self_cert" => {
                let parsed = SnAuthDbUpdateUserSelfCertReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_user_self_cert(&parsed.username, parsed.self_cert)
                        .await,
                    &req,
                )
            }
            METHOD_UPDATE_USER_DOMAIN | "update_user_domain" => {
                let parsed = SnAuthDbUpdateUserDomainReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_user_domain(&parsed.username, parsed.user_domain)
                        .await,
                    &req,
                )
            }
            METHOD_GET_USER_SN_IPS | "get_user_sn_ips" => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_user_sn_ips(&parsed.username).await, &req)
            }
            METHOD_GET_AUTH | "get_auth" => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_auth(&parsed.username).await, &req)
            }
            METHOD_UPDATE_LAST_LOGIN | "update_last_login" => {
                let parsed = SnAuthDbUpdateLastLoginReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_last_login(&parsed.username, parsed.last_login_at)
                        .await,
                    &req,
                )
            }
            METHOD_ACTIVATE_USER_DOMAIN_BINDING | "activate_user_domain_binding" => {
                let parsed = SnAuthDbActivateUserDomainBindingReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .activate_user_domain_binding(&parsed.username, &parsed.domain, &parsed.pkx)
                        .await,
                    &req,
                )
            }
            METHOD_UNBIND_USER_DOMAIN | "unbind_user_domain" => {
                let parsed = SnAuthDbUnbindUserDomainReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .unbind_user_domain(&parsed.username, &parsed.domain)
                        .await,
                    &req,
                )
            }
            METHOD_PUT_USER_DNS_VALUE => {
                let parsed = SnAuthDbPutUserDnsValueReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .put_user_dns_value(
                            &parsed.owner,
                            &parsed.name,
                            parsed.record_type,
                            &parsed.value,
                            parsed.ttl,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_REMOVE_USER_DNS_VALUE => {
                let parsed = SnAuthDbRemoveUserDnsValueReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .remove_user_dns_value(
                            &parsed.owner,
                            &parsed.name,
                            parsed.record_type,
                            &parsed.value,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_DELETE_USER_DNS_RRSET => {
                let parsed = SnAuthDbUserDnsRrsetReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .delete_user_dns_rrset(&parsed.owner, &parsed.name, parsed.record_type)
                        .await,
                    &req,
                )
            }
            METHOD_SET_USER_DNS_RRSET_TTL => {
                let parsed = SnAuthDbSetUserDnsRrsetTtlReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .set_user_dns_rrset_ttl(
                            &parsed.owner,
                            &parsed.name,
                            parsed.record_type,
                            parsed.ttl,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_GET_USER_DNS_RRSET => {
                let parsed = SnAuthDbGetUserDnsRrsetReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .get_user_dns_rrset(&parsed.name, parsed.record_type)
                        .await,
                    &req,
                )
            }
            METHOD_LIST_USER_DNS_RRSETS => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.list_user_dns_rrsets(&parsed.username).await, &req)
            }
            METHOD_LIST_USER_DNS_CHANGES => {
                let parsed = SnAuthDbListUserDnsChangesReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .list_user_dns_changes(parsed.after_revision, parsed.limit)
                        .await,
                    &req,
                )
            }
            METHOD_GET_ZONE_INFO | "get_zone_info" => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_zone_info(&parsed.username).await, &req)
            }
            METHOD_UPDATE_ZONE_INFO | "update_zone_info" => {
                let parsed = SnAuthDbUpdateZoneInfoReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_zone_info(&parsed.username, parsed.patch)
                        .await,
                    &req,
                )
            }
            METHOD_UPDATE_ZONE_RELAY_SN | "update_zone_relay_sn" => {
                let parsed = SnAuthDbUpdateZoneRelaySnReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_zone_relay_sn(
                            &parsed.zone,
                            &parsed.relay_sn,
                            parsed.source_version.as_deref(),
                        )
                        .await,
                    &req,
                )
            }
            METHOD_REGISTER_RELAY_NODE | "register_relay_node" => {
                let parsed = parse_request::<RelayNodeRegistration>(req.params.clone())?;
                rpc_envelope_response(self.0.register_relay_node(parsed).await, &req)
            }
            METHOD_HEARTBEAT_RELAY_NODE | "heartbeat_relay_node" => {
                let parsed = parse_request::<RelayHeartbeat>(req.params.clone())?;
                rpc_envelope_response(self.0.heartbeat_relay_node(parsed).await, &req)
            }
            METHOD_UPDATE_RELAY_NODE_ADDRESSES | "update_relay_node_addresses" => {
                let parsed = parse_request::<RelayNodeAddressUpdate>(req.params.clone())?;
                rpc_envelope_response(self.0.update_relay_node_addresses(parsed).await, &req)
            }
            METHOD_GET_RELAY_NODE | "get_relay_node" => {
                let parsed = SnAuthDbRelayIdReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_relay_node(&parsed.relay_id).await, &req)
            }
            METHOD_LIST_RELAY_NODES | "list_relay_nodes" => {
                let _parsed = SnAuthDbGetActivationCodesReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.list_relay_nodes().await, &req)
            }
            METHOD_GET_RELAY_NODES_IP_MAP | "get_relay_nodes_ip_map" => {
                let parsed = parse_request::<RelayNodeIpMapReq>(req.params.clone())?;
                rpc_envelope_response(self.0.get_relay_nodes_ip_map(parsed).await, &req)
            }
            METHOD_ASSIGN_ZONE_RELAY | "assign_zone_relay" => {
                let parsed = parse_request::<AssignZoneRelayReq>(req.params.clone())?;
                rpc_envelope_response(self.0.assign_zone_relay(parsed).await, &req)
            }
            METHOD_ALLOCATE_ZONE_RELAY | "allocate_zone_relay" => {
                let parsed = parse_request::<AllocateZoneRelayReq>(req.params.clone())?;
                rpc_envelope_response(self.0.allocate_zone_relay(parsed).await, &req)
            }
            METHOD_GET_ZONE_RELAY | "get_zone_relay" => {
                let parsed = SnAuthDbZoneReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_zone_relay(&parsed.zone).await, &req)
            }
            METHOD_START_RELAY_MIGRATION | "start_relay_migration" => {
                let parsed = parse_request::<RelayMigrationReq>(req.params.clone())?;
                rpc_envelope_response(self.0.start_relay_migration(parsed).await, &req)
            }
            METHOD_COMPLETE_RELAY_MIGRATION | "complete_relay_migration" => {
                let parsed = SnAuthDbCompleteRelayMigrationReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .complete_relay_migration(&parsed.zone, parsed.generation)
                        .await,
                    &req,
                )
            }
            METHOD_CHECK_RELAY_ADMISSION | "check_relay_admission" => {
                let parsed = parse_request::<RelayAdmissionReq>(req.params.clone())?;
                rpc_envelope_response(self.0.check_relay_admission(parsed).await, &req)
            }
            METHOD_CREATE_ACCOUNT_SESSION | "create_account_session" => {
                let parsed = SnAuthDbCreateAccountSessionReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .create_account_session(
                            &parsed.session_id,
                            &parsed.username,
                            &parsed.token_aud,
                            parsed.issued_at,
                            parsed.expires_at,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_REVOKE_ACCOUNT_SESSION | "revoke_account_session" => {
                let parsed = SnAuthDbRevokeAccountSessionReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .revoke_account_session(&parsed.session_id, parsed.revoked_at)
                        .await,
                    &req,
                )
            }
            METHOD_REVOKE_USER_SESSIONS | "revoke_user_sessions" => {
                let parsed = SnAuthDbRevokeUserSessionsReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .revoke_user_sessions(&parsed.username, parsed.revoked_at)
                        .await,
                    &req,
                )
            }
            METHOD_GET_ACCOUNT_SESSION | "get_account_session" => {
                let parsed = SnAuthDbSessionIdReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_account_session(&parsed.session_id).await, &req)
            }
            _ => Err(RPCErrors::UnknownMethod(req.method.clone())),
        }
    }
}

pub fn normalize_sn_auth_db_url(auth_db_url: &str) -> String {
    let trimmed = auth_db_url.trim_end_matches('/');
    if let Some(base) = trimmed.strip_suffix(SN_AUTH_DB_RPC_PATH) {
        return format!("{}{}", base, SN_AUTH_DB_RPC_PATH);
    }
    format!("{}{}", trimmed, SN_AUTH_DB_RPC_PATH)
}

fn rpc_envelope_response<T: Serialize>(
    result: SnResult<T>,
    req: &RPCRequest,
) -> Result<RPCResponse, RPCErrors> {
    let envelope = match result {
        Ok(value) => SnAuthDbRpcEnvelope::success(value),
        Err(error) => SnAuthDbRpcEnvelope::failure(error),
    };
    let value = serde_json::to_value(envelope).map_err(|e| {
        RPCErrors::ParserResponseError(format!("Failed to serialize SnAuthDB RPC envelope: {}", e))
    })?;
    Ok(RPCResponse::create_by_req(RPCResult::Success(value), req))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_sn_auth_db_url() {
        assert_eq!(
            normalize_sn_auth_db_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080/kapi/sn/s2s/auth-db"
        );
        assert_eq!(
            normalize_sn_auth_db_url("http://127.0.0.1:8080/kapi/sn/s2s/auth-db/"),
            "http://127.0.0.1:8080/kapi/sn/s2s/auth-db"
        );
    }

    #[test]
    fn test_hot_path_reads_are_cached_and_mutations_invalidate() {
        for method in [
            METHOD_GET_USER_INFO,
            METHOD_GET_USER_BY_DOMAIN,
            METHOD_GET_ZONE_INFO,
            METHOD_GET_ZONE_RELAY,
        ] {
            assert!(is_cached_auth_db_read(method), "{method}");
            assert!(!auth_db_method_invalidates_read_cache(method), "{method}");
        }

        for method in [
            METHOD_UPDATE_USER_SELF_CERT,
            METHOD_ACTIVATE_USER_DOMAIN_BINDING,
            METHOD_UNBIND_USER_DOMAIN,
            METHOD_UPDATE_ZONE_INFO,
            METHOD_UPDATE_ZONE_RELAY_SN,
        ] {
            assert!(!is_cached_auth_db_read(method), "{method}");
            assert!(auth_db_method_invalidates_read_cache(method), "{method}");
        }

        assert!(!is_cached_auth_db_read(METHOD_GET_AUTH));
        assert!(!auth_db_method_invalidates_read_cache(METHOD_GET_AUTH));
    }

    #[test]
    fn test_krpc_client_clones_share_read_cache() {
        let client = SnAuthDbClient::new_krpc(Arc::new(kRPC::new(
            "http://127.0.0.1:1/kapi/sn/s2s/auth-db",
            None,
        )));
        let cloned = client.clone();

        let (SnAuthDbClient::KRPC(client), SnAuthDbClient::KRPC(cloned)) = (&client, &cloned)
        else {
            panic!("new_krpc must create the cached remote variant");
        };
        assert!(Arc::ptr_eq(client, cloned));
    }

    #[tokio::test]
    async fn test_krpc_client_serves_cached_negative_read_without_transport() {
        let client = SnAuthDbClient::new_krpc(Arc::new(kRPC::new(
            "http://127.0.0.1:1/kapi/sn/s2s/auth-db",
            None,
        )));
        let SnAuthDbClient::KRPC(remote) = &client else {
            panic!("new_krpc must create the cached remote variant");
        };
        let request = SnAuthDbUsernameReq::new("missing-user");
        let key = RemoteReadCache::key(METHOD_GET_USER_INFO, &request).unwrap();
        remote.read_cache.insert(
            key,
            serde_json::to_value(SnAuthDbRpcEnvelope::success(None::<SNUserInfo>)).unwrap(),
        );

        assert!(client
            .get_user_info("missing-user")
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_unit_envelope_roundtrip_allows_null_result() {
        let value = serde_json::to_value(SnAuthDbRpcEnvelope::success(())).unwrap();
        let envelope: SnAuthDbRpcEnvelope<Value> = serde_json::from_value(value).unwrap();

        assert!(envelope.into_result().is_ok());
    }

    #[test]
    fn test_optional_envelope_roundtrip_preserves_null_success() {
        let value = serde_json::to_value(SnAuthDbRpcEnvelope::success(None::<String>)).unwrap();
        assert_eq!(value["result"], Value::Null);

        let envelope: SnAuthDbRpcEnvelope<Option<String>> = serde_json::from_value(value).unwrap();

        assert_eq!(envelope.into_result().unwrap(), None);
    }

    #[test]
    fn test_error_envelope_null_result_does_not_parse_response_type() {
        let value = serde_json::to_value(SnAuthDbRpcEnvelope::<String>::failure(sn_err!(
            SnErrorCode::NotFound,
            "missing"
        )))
        .unwrap();
        assert_eq!(value["result"], Value::Null);

        let envelope: SnAuthDbRpcEnvelope<String> = serde_json::from_value(value).unwrap();
        let error = envelope.into_result().unwrap_err();

        assert_eq!(error.code(), SnErrorCode::NotFound);
    }

    #[test]
    fn test_relay_registration_wire_requires_two_canonical_typed_ips() {
        let base = serde_json::json!({
            "relay_id": "relay-a",
            "relay_sn": "relay-a.example",
            "ips": ["192.0.2.10", "2001:db8::10"],
            "public_host": "relay-a.example",
            "http_endpoint": null,
            "rtcp_endpoint": null,
            "region": "test",
            "isp": null,
            "tags": [],
            "capabilities": ["rtcp_relay"],
            "status": "active",
            "capacity_score": 100
        });
        let registration: RelayNodeRegistration =
            serde_json::from_value(base.clone()).expect("valid typed IP pair");
        assert_eq!(
            serde_json::to_value(registration).unwrap()["ips"],
            serde_json::json!(["192.0.2.10", "2001:db8::10"])
        );

        for ips in [
            serde_json::json!(["192.0.2.10"]),
            serde_json::json!(["192.0.2.10", "2001:db8::10", "198.51.100.10"]),
            serde_json::json!(["192.0.2.10:443", "2001:db8::10"]),
            serde_json::json!(["192.0.2.10", "fe80::1%eth0"]),
            serde_json::json!(["192.0.2.10", "2001:0db8::10"]),
        ] {
            let mut invalid = base.clone();
            invalid["ips"] = ips;
            assert!(
                serde_json::from_value::<RelayNodeRegistration>(invalid).is_err(),
                "invalid relay IP pair must be rejected"
            );
        }
    }

    #[test]
    fn test_relay_s2s_method_names_are_stable() {
        assert_eq!(
            METHOD_GET_RELAY_NODES_IP_MAP,
            "sn_auth_db.get_relay_nodes_ip_map"
        );
        assert_eq!(METHOD_ALLOCATE_ZONE_RELAY, "sn_auth_db.allocate_zone_relay");
        assert_eq!(
            METHOD_CHECK_RELAY_ADMISSION,
            "sn_auth_db.check_relay_admission"
        );
    }

    #[tokio::test]
    async fn test_relay_rpc_handler_roundtrips_node_map_and_not_modified() {
        use crate::SqliteSnAuthDB;
        use std::net::{IpAddr, Ipv4Addr};

        async fn dispatch<T: DeserializeOwned>(
            handler: &SnAuthDbRpcHandler<SqliteSnAuthDB>,
            method: &str,
            params: Value,
        ) -> SnResult<T> {
            let request = RPCRequest::new(method, params);
            let response = handler
                .handle_rpc_call(request, IpAddr::V4(Ipv4Addr::LOCALHOST))
                .await
                .map_err(|e| {
                    sn_err!(
                        SnErrorCode::RemoteError,
                        "loopback relay RPC transport failed: {}",
                        e
                    )
                })?;
            let value = match response.result {
                RPCResult::Success(value) => value,
                RPCResult::Failed(error) => {
                    return Err(sn_err!(SnErrorCode::RemoteError, "{}", error));
                }
            };
            serde_json::from_value::<SnAuthDbRpcEnvelope<T>>(value)
                .map_err(|e| sn_err!(SnErrorCode::RemoteError, "decode envelope failed: {}", e))?
                .into_result()
        }

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("auth.sqlite3");
        let db = SqliteSnAuthDB::new_by_path(path.to_string_lossy().as_ref())
            .await
            .unwrap();
        db.initialize_database().await.unwrap();
        let handler = SnAuthDbRpcHandler::new(db);
        let registration = RelayNodeRegistration {
            relay_id: "relay-a".to_string(),
            relay_sn: "relay-a.example".to_string(),
            ips: [
                "192.0.2.60".parse().unwrap(),
                "2001:db8::60".parse().unwrap(),
            ],
            public_host: "relay-a.example".to_string(),
            http_endpoint: None,
            rtcp_endpoint: None,
            region: None,
            isp: None,
            tags: Vec::new(),
            capabilities: Vec::new(),
            status: None,
            capacity_score: Some(100),
        };
        let node: RelayNode = dispatch(
            &handler,
            METHOD_REGISTER_RELAY_NODE,
            serde_json::to_value(registration).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            node.ips,
            [
                "192.0.2.60".parse::<IpAddr>().unwrap(),
                "2001:db8::60".parse::<IpAddr>().unwrap()
            ]
        );

        let snapshot: Option<RelayNodeIpMapSnapshot> = dispatch(
            &handler,
            METHOD_GET_RELAY_NODES_IP_MAP,
            serde_json::to_value(RelayNodeIpMapReq::default()).unwrap(),
        )
        .await
        .unwrap();
        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.nodes.len(), 1);
        let not_modified: Option<RelayNodeIpMapSnapshot> = dispatch(
            &handler,
            METHOD_GET_RELAY_NODES_IP_MAP,
            serde_json::to_value(RelayNodeIpMapReq {
                if_revision: Some(snapshot.revision),
            })
            .unwrap(),
        )
        .await
        .unwrap();
        assert!(not_modified.is_none());
    }
}
