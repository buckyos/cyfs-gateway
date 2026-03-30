use ::kRPC::RPCErrors;

#[derive(Clone, Copy, Debug)]
pub(crate) enum SnV2ErrorCode {
    InvalidParams = 1000,
    InvalidUsername = 1001,
    UsernameAlreadyExists = 1002,
    InvalidActiveCode = 1003,
    UserAuthNotFound = 1004,
    InvalidPassword = 1005,
    AuthRequired = 1006,
    InvalidToken = 1007,
    UserNotFound = 1008,
    OwnerKeyRequired = 1009,
    InvalidPublicKey = 1010,
    InvalidZoneConfig = 1011,
    DeviceNotFound = 1012,
    DevicePermissionDenied = 1013,
    InvalidDeviceDid = 1014,
    InvalidDomain = 1015,
    DidDocumentNotFound = 1016,
    HostnameNotFound = 1017,
    CrossUserAccessDenied = 1018,
    UnsupportedPasswordAlgo = 1019,
    InvalidPasswordStorage = 1020,
    InvalidDid = 1021,
    InternalError = 1099,
}

impl SnV2ErrorCode {
    pub(crate) fn code(self) -> u32 {
        self as u32
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid_params",
            Self::InvalidUsername => "invalid_username",
            Self::UsernameAlreadyExists => "username_already_exists",
            Self::InvalidActiveCode => "invalid_active_code",
            Self::UserAuthNotFound => "user_auth_not_found",
            Self::InvalidPassword => "invalid_password",
            Self::AuthRequired => "auth_required",
            Self::InvalidToken => "invalid_token",
            Self::UserNotFound => "user_not_found",
            Self::OwnerKeyRequired => "owner_key_required",
            Self::InvalidPublicKey => "invalid_public_key",
            Self::InvalidZoneConfig => "invalid_zone_config",
            Self::DeviceNotFound => "device_not_found",
            Self::DevicePermissionDenied => "device_permission_denied",
            Self::InvalidDeviceDid => "invalid_device_did",
            Self::InvalidDomain => "invalid_domain",
            Self::DidDocumentNotFound => "did_document_not_found",
            Self::HostnameNotFound => "hostname_not_found",
            Self::CrossUserAccessDenied => "cross_user_access_denied",
            Self::UnsupportedPasswordAlgo => "unsupported_password_algo",
            Self::InvalidPasswordStorage => "invalid_password_storage",
            Self::InvalidDid => "invalid_did",
            Self::InternalError => "internal_error",
        }
    }

    pub(crate) fn format(self, message: impl AsRef<str>) -> String {
        format!(
            "[SNV2:{}:{}] {}",
            self.code(),
            self.name(),
            message.as_ref()
        )
    }
}

pub(crate) fn parse_error(code: SnV2ErrorCode, message: impl AsRef<str>) -> RPCErrors {
    RPCErrors::ParseRequestError(code.format(message))
}

pub(crate) fn reason_error(code: SnV2ErrorCode, message: impl AsRef<str>) -> RPCErrors {
    RPCErrors::ReasonError(code.format(message))
}
