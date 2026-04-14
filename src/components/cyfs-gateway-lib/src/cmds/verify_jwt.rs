use crate::json_value_to_collection_value;
use clap::{Arg, Command};
use cyfs_process_chain::{
    CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, ExternalCommand,
    command_help,
};
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::Jwk;
use name_lib::{create_jwt_by_x, decode_json_from_jwt_with_pk, decode_jwt_claim_without_verify};

pub struct VerifyJwt {
    name: String,
    cmd: Command,
}

impl VerifyJwt {
    pub fn new() -> Self {
        let cmd = Command::new("verify-jwt")
            .about("Verify a JWT with an issuer->public key map and return the payload map")
            .after_help(
                r#"
Examples:
    verify-jwt $jwt $JWT_PUBLIC_KEYS
    verify-jwt ${REQ.headers.authorization} $public_key_map

Notes:
    - The second argument must be a map keyed by jwt payload.iss
    - Map values can be a JWK JSON string or an Ed25519 public key x string
                "#,
            )
            .arg(
                Arg::new("jwt")
                    .help("JWT string to verify")
                    .index(1)
                    .required(true),
            )
            .arg(
                Arg::new("public_key_map")
                    .help("Issuer->public key map")
                    .index(2)
                    .required(true),
            );

        Self {
            name: "verify-jwt".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    fn verification_failed(msg: impl Into<String>) -> CommandResult {
        let msg = msg.into();
        error!("{}", msg);
        CommandResult::error_with_string(msg)
    }

    fn parse_jwk(public_key: &str) -> Result<Jwk, String> {
        match serde_json::from_str::<Jwk>(public_key) {
            Ok(jwk) => Ok(jwk),
            Err(_) => create_jwt_by_x(public_key).map_err(|e| {
                format!(
                    "invalid public key '{}': expected JWK json string or Ed25519 x value: {}",
                    public_key, e
                )
            }),
        }
    }
}

#[async_trait::async_trait]
impl ExternalCommand for VerifyJwt {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid verify-jwt command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;
        Ok(())
    }

    async fn exec(
        &self,
        _context: &Context,
        args: &[CollectionValue],
        _origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        if args.len() != 3 {
            return Ok(Self::verification_failed(format!(
                "Invalid verify-jwt command args length: expected 3, got {}",
                args.len()
            )));
        }

        let jwt = match args[1].try_as_str() {
            Ok(jwt) => jwt.trim().to_string(),
            Err(e) => {
                return Ok(Self::verification_failed(format!(
                    "verify-jwt requires jwt string: {}",
                    e
                )));
            }
        };
        if jwt.is_empty() {
            return Ok(Self::verification_failed(
                "verify-jwt requires a non-empty jwt string",
            ));
        }

        let key_map = match args[2].try_as_map() {
            Ok(key_map) => key_map,
            Err(e) => {
                return Ok(Self::verification_failed(format!(
                    "verify-jwt requires issuer->public key map: {}",
                    e
                )));
            }
        };
        let unverified_payload = match decode_jwt_claim_without_verify(jwt.as_str()) {
            Ok(payload) => payload,
            Err(e) => {
                return Ok(Self::verification_failed(format!(
                    "decode jwt payload failed: {}",
                    e
                )));
            }
        };

        let iss = match unverified_payload
            .get("iss")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
        {
            Some(iss) => iss,
            None => return Ok(Self::verification_failed("verify-jwt requires payload.iss")),
        };

        let public_key = match key_map.get(iss).await {
            Ok(Some(public_key)) => public_key,
            Ok(None) => {
                return Ok(Self::verification_failed(format!(
                    "verify-jwt public key not found for iss '{}'",
                    iss
                )));
            }
            Err(e) => {
                return Ok(Self::verification_failed(format!(
                    "get verify-jwt public key for iss '{}' failed: {}",
                    iss, e
                )));
            }
        };
        let public_key = match public_key.try_as_str() {
            Ok(public_key) => public_key.trim().to_string(),
            Err(e) => {
                return Ok(Self::verification_failed(format!(
                    "verify-jwt public key for iss '{}' must be a string: {}",
                    iss, e
                )));
            }
        };
        if public_key.is_empty() {
            return Ok(Self::verification_failed(format!(
                "verify-jwt public key for iss '{}' is empty",
                iss
            )));
        }

        let jwk = match Self::parse_jwk(public_key.as_str()) {
            Ok(jwk) => jwk,
            Err(e) => return Ok(Self::verification_failed(e)),
        };
        let decoding_key = match DecodingKey::from_jwk(&jwk) {
            Ok(decoding_key) => decoding_key,
            Err(e) => {
                return Ok(Self::verification_failed(format!(
                    "build decoding key failed: {}",
                    e
                )));
            }
        };

        let payload = match decode_json_from_jwt_with_pk(jwt.as_str(), &decoding_key) {
            Ok(payload) => payload,
            Err(e) => {
                return Ok(Self::verification_failed(format!(
                    "verify jwt failed: {}",
                    e
                )));
            }
        };
        let payload = json_value_to_collection_value(&payload).await;

        match payload {
            CollectionValue::Map(_) => Ok(CommandResult::success_with_value(payload)),
            _ => Ok(Self::verification_failed("verify-jwt payload is not a map")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_process_chain::{CollectionValue, HookPoint, HookPointEnv, MemoryMapCollection};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use name_lib::generate_ed25519_key_pair;
    use serde_json::json;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_verify_jwt_returns_verified_payload_map() {
        let (private_key, public_key) = generate_ed25519_key_pair();
        let encode_key = EncodingKey::from_ed_pem(private_key.as_bytes()).unwrap();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &json!({
                "iss": "issuer-1",
                "sub": "alice",
                "roles": ["admin", "ops"],
                "exp": 2058838939u64
            }),
            &encode_key,
        )
        .unwrap();

        let public_key_map = MemoryMapCollection::new_ref();
        public_key_map
            .insert(
                "issuer-1",
                CollectionValue::String(serde_json::to_string(&public_key).unwrap()),
            )
            .await
            .unwrap();

        let process_chain = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local payload = $(verify-jwt $JWT $KEYS);
            eq $payload.iss "issuer-1" && eq $payload.sub "alice" && return --from lib "ok";
            return --from lib "bad";
        ]]>
    </block>
</process_chain>
</root>
"#;

        let hook_point = HookPoint::new("test-verify-jwt");
        hook_point
            .load_process_chain_lib("verify_jwt_lib", 0, process_chain)
            .await
            .unwrap();
        let data_dir = TempDir::new().unwrap();
        let hook_point_env = HookPointEnv::new("test-verify-jwt", data_dir.path().to_path_buf());
        hook_point_env
            .register_external_command("verify-jwt", Arc::new(Box::new(VerifyJwt::new())))
            .unwrap();
        hook_point_env
            .hook_point_env()
            .create("JWT", CollectionValue::String(token))
            .await
            .unwrap();
        hook_point_env
            .hook_point_env()
            .create("KEYS", CollectionValue::Map(public_key_map))
            .await
            .unwrap();
        let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
        let result = exec.execute_lib("verify_jwt_lib").await.unwrap();

        assert_eq!(result.value(), "ok");
    }

    #[tokio::test]
    async fn test_verify_jwt_accepts_ed25519_x_value() {
        let (private_key, public_key) = generate_ed25519_key_pair();
        let encode_key = EncodingKey::from_ed_pem(private_key.as_bytes()).unwrap();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &json!({
                "iss": "issuer-x",
                "sub": "alice",
                "exp": 2058838939u64
            }),
            &encode_key,
        )
        .unwrap();

        let public_key_map = MemoryMapCollection::new_ref();
        public_key_map
            .insert(
                "issuer-x",
                CollectionValue::String(
                    public_key
                        .get("x")
                        .and_then(|value| value.as_str())
                        .unwrap()
                        .to_string(),
                ),
            )
            .await
            .unwrap();

        let process_chain = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            local payload = $(verify-jwt $JWT $KEYS);
            eq $payload.iss "issuer-x" && eq $payload.sub "alice" && return --from lib "ok";
            return --from lib "bad";
        ]]>
    </block>
</process_chain>
</root>
"#;

        let hook_point = HookPoint::new("test-verify-jwt-x");
        hook_point
            .load_process_chain_lib("verify_jwt_x_lib", 0, process_chain)
            .await
            .unwrap();
        let data_dir = TempDir::new().unwrap();
        let hook_point_env = HookPointEnv::new("test-verify-jwt-x", data_dir.path().to_path_buf());
        hook_point_env
            .register_external_command("verify-jwt", Arc::new(Box::new(VerifyJwt::new())))
            .unwrap();
        hook_point_env
            .hook_point_env()
            .create("JWT", CollectionValue::String(token))
            .await
            .unwrap();
        hook_point_env
            .hook_point_env()
            .create("KEYS", CollectionValue::Map(public_key_map))
            .await
            .unwrap();
        let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
        let result = exec.execute_lib("verify_jwt_x_lib").await.unwrap();

        assert_eq!(result.value(), "ok");
    }

    #[tokio::test]
    async fn test_verify_jwt_returns_error_result_for_invalid_jwt() {
        let public_key_map = MemoryMapCollection::new_ref();
        public_key_map
            .insert(
                "issuer-1",
                CollectionValue::String(r#"{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.to_string()),
            )
            .await
            .unwrap();

        let process_chain = r#"
<root>
<process_chain id="main">
    <block id="entry">
        <![CDATA[
            match-result $(verify-jwt $JWT $KEYS)
            ok(payload)
                return --from lib $(append "unexpected_ok:" $payload.iss);
            err(err_value)
                return --from lib $(append "handled:" $err_value);
            end
        ]]>
    </block>
</process_chain>
</root>
"#;

        let hook_point = HookPoint::new("test-verify-jwt-invalid");
        hook_point
            .load_process_chain_lib("verify_jwt_invalid_lib", 0, process_chain)
            .await
            .unwrap();
        let data_dir = TempDir::new().unwrap();
        let hook_point_env =
            HookPointEnv::new("test-verify-jwt-invalid", data_dir.path().to_path_buf());
        hook_point_env
            .register_external_command("verify-jwt", Arc::new(Box::new(VerifyJwt::new())))
            .unwrap();
        hook_point_env
            .hook_point_env()
            .create("JWT", CollectionValue::String("not-a-jwt".to_string()))
            .await
            .unwrap();
        hook_point_env
            .hook_point_env()
            .create("KEYS", CollectionValue::Map(public_key_map))
            .await
            .unwrap();
        let exec = hook_point_env.link_hook_point(&hook_point).await.unwrap();
        let result = exec.execute_lib("verify_jwt_invalid_lib").await.unwrap();

        assert!(
            result
                .value()
                .starts_with("handled:decode jwt payload failed:")
        );
    }
}
