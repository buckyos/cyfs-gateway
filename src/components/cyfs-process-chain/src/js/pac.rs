use boa_engine::prelude::*;
use boa_engine::{Context as JsContext, JsResult, js_string};
use std::net::{IpAddr, Ipv4Addr};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;


pub struct PACEnvFunctions;

impl PACEnvFunctions {
    // Check if the host is a plain host name (no dots)
    fn is_plain_host_name(host: &str) -> bool {
        !host.contains('.')
    }

    // Check if the host is in the domain
    fn dns_domain_is(host: &str, domain: &str) -> bool {
        if domain.is_empty() || host.is_empty() {
            return false;
        }

        let host = host.trim_end_matches('.').to_lowercase();
        let domain = domain.trim_end_matches('.').to_lowercase();

        host == domain || host.ends_with(&format!(".{}", domain))
    }

    fn dns_domain_levels(host: &str) -> i32 {
        host.trim_end_matches('.').split('.').count() as i32
    }

    fn dns_resolve(host: &str) -> Result<Option<IpAddr>, String> {
        let resolver =
            Resolver::new(ResolverConfig::default(), ResolverOpts::default()).map_err(|e| {
                let msg = format!("Failed to create DNS resolver: {}", e);
                error!("{}", msg);
                msg
            })?;

        let ret = match resolver.lookup_ip(host) {
            Ok(response) => response.iter().next(),
            Err(e) => {
                warn!("failed to resolve host: {:?}", e);
                None
            }
        };

        Ok(ret)
    }

    fn is_resolvable(host: &str) -> Result<bool, String> {
        let host = host.trim();
        if host.is_empty() {
            return Ok(false);
        }

        Self::dns_resolve(host).map(|ip| ip.is_some())
    }

    fn is_in_net(host: &str, pattern: &str, mask: &str) -> Result<bool, String> {
        if host.is_empty() || pattern.is_empty() || mask.is_empty() {
            return Ok(false);
        }

        let ip = match Self::dns_resolve(host)? {
            Some(IpAddr::V4(ip)) => ip,
            _ => return Ok(false),
        };

        let pattern_ip: Ipv4Addr = pattern.parse().map_err(|e| {
            let msg = format!("Invalid pattern IP: {}", e);
            warn!("{}", msg);
            msg
        })?;

        let mask_ip: Ipv4Addr = mask.parse().map_err(|e| {
            let msg = format!("Invalid mask IP: {}", e);
            warn!("{}", msg);
            msg
        })?;

        let ip_u32 = u32::from(ip);
        let pattern_u32 = u32::from(pattern_ip);
        let mask_u32 = u32::from(mask_ip);

        Ok((ip_u32 & mask_u32) == (pattern_u32 & mask_u32))
    }

    fn local_host_or_domain_is(host: &str, host_dom: &str) -> bool {
        let host = host.trim_end_matches('.').to_lowercase();
        let host_dom = host_dom.trim_end_matches('.').to_lowercase();

        let parts: Vec<&str> = host.split('.').collect();
        let dom_parts: Vec<&str> = host_dom.split('.').collect();

        for (part, dom_part) in parts.iter().zip(dom_parts.iter()) {
            if part != dom_part {
                return false;
            }
        }

        true
    }

    fn sh_exp_match(s: &str, sh_exp: &str) -> bool {
        if s.is_empty() || sh_exp.is_empty() {
            return false;
        }

        match globset::GlobBuilder::new(sh_exp)
            .literal_separator(true)
            .build()
        {
            Ok(glob) => {
                let pattern = glob.compile_matcher();
                pattern.is_match(s)
            }
            Err(e) => {
                warn!("Failed to compile shell expression '{}': {}", sh_exp, e);
                false
            }
        }
    }
}

struct PACEnvFunctionsWrapper {}

impl PACEnvFunctionsWrapper {
    fn register_env(context: &mut Context) -> Result<(), String> {
        
        // Register the isPlainHostName function
        context
            .register_global_builtin_callable(
                js_string!("isPlainHostName"),
                1,
                NativeFunction::from_fn_ptr(Self::is_plain_host_name),
            )
            .map_err(|e| {
                let msg = format!("failed to register isPlainHostName: {:?}", e);
                error!("{}", msg);
                msg
            })?;

        // Register the dnsDomainIs function
        context
            .register_global_builtin_callable(
                js_string!("dnsDomainIs"),
                2,
                NativeFunction::from_fn_ptr(Self::dns_domain_is),
            )
            .map_err(|e| {
                let msg = format!("failed to register dnsDomainIs: {:?}", e);
                error!("{}", msg);
                msg
            })?;

        // Register the dnsDomainLevels function
        context
            .register_global_builtin_callable(
                js_string!("dnsDomainLevels"),
                1,
                NativeFunction::from_fn_ptr(Self::dns_domain_levels),
            )
            .map_err(|e| {
                let msg = format!("failed to register dnsDomainLevels: {:?}", e);
                error!("{}", msg);
                msg
            })?;

        // Register the dnsResolve function
        context
            .register_global_builtin_callable(
                js_string!("dnsResolve"),
                1,
                NativeFunction::from_fn_ptr(Self::dns_resolve),
            )
            .map_err(|e| {
                let msg = format!("failed to register dnsResolve: {:?}", e);
                error!("{}", msg);
                msg
            })?;

        // Register the isResolvable function
        context
            .register_global_builtin_callable(
                js_string!("isResolvable"),
                1,
                NativeFunction::from_fn_ptr(Self::is_resolvable),
            )
            .map_err(|e| {
                let msg = format!("failed to register isResolvable: {:?}", e);
                error!("{}", msg);
                msg
            })?;

        // Register the isInNet function
        context
            .register_global_builtin_callable(
                js_string!("isInNet"),
                3,
                NativeFunction::from_fn_ptr(Self::is_in_net),
            )
            .map_err(|e| {
                let msg = format!("failed to register isInNet: {:?}", e);
                error!("{}", msg);
                msg
            })?;

        // Register the localHostOrDomainIs function
        context
            .register_global_builtin_callable(
                js_string!("localHostOrDomainIs"),
                2,
                NativeFunction::from_fn_ptr(Self::local_host_or_domain_is),
            )
            .map_err(|e| {
                let msg = format!("failed to register localHostOrDomainIs: {:?}", e);
                error!("{}", msg);
                msg
            })?;

        // Register the shExpMatch function
        context
            .register_global_builtin_callable(
                js_string!("shExpMatch"),
                2,
                NativeFunction::from_fn_ptr(Self::sh_exp_match),
            )
            .map_err(|e| {
                let msg = format!("failed to register shExpMatch: {:?}", e);
                error!("{}", msg);
                msg
            })?;

        Ok(())
    }

    pub fn assert(_this: &JsValue, args: &[JsValue], _ctx: &mut JsContext) -> JsResult<JsValue> {
        if args.is_empty() {
            return Err(JsNativeError::error()
                .with_message("Expected at least one argument")
                .into());
        }

        let condition = &args[0];
        if condition.is_null()
            || condition.is_undefined()
            || (condition.is_boolean() && !condition.as_boolean().unwrap())
        {
            let message = args
                .get(1)
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_else(|| "Assertion failed".to_string());

            let msg = format!("AssertionError: {}", message);
            error!("{}", msg);
            return Err(JsError::from_opaque(JsValue::from(JsString::from(msg))));
        }

        Ok(JsValue::Undefined)
    }

    pub fn is_plain_host_name(
        _this: &JsValue,
        args: &[JsValue],
        _ctx: &mut JsContext,
    ) -> JsResult<JsValue> {
        if args.is_empty() {
            return Err(JsNativeError::error()
                .with_message("Expected a string argument for host")
                .into());
        }

        // Get the host argument
        let host = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for host")
            })?;

        let is_plain = PACEnvFunctions::is_plain_host_name(&host);

        Ok(JsValue::from(is_plain))
    }

    pub fn dns_domain_is(
        _this: &JsValue,
        args: &[JsValue],
        _ctx: &mut JsContext,
    ) -> JsResult<JsValue> {
        if args.len() < 2 {
            return Err(JsNativeError::error()
                .with_message("Expected two string arguments for host and domain")
                .into());
        }

        let host = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for host")
            })?;
        let domain = args[1]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for domain")
            })?;

        let is_in_domain = PACEnvFunctions::dns_domain_is(&host, &domain);

        Ok(JsValue::from(is_in_domain))
    }

    pub fn dns_domain_levels(
        _this: &JsValue,
        args: &[JsValue],
        _ctx: &mut JsContext,
    ) -> JsResult<JsValue> {
        if args.is_empty() {
            return Err(JsNativeError::error()
                .with_message("Expected a string argument for host")
                .into());
        }

        let host = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for host")
            })?;

        let levels = PACEnvFunctions::dns_domain_levels(&host);

        Ok(JsValue::from(levels))
    }

    pub fn dns_resolve(
        _this: &JsValue,
        args: &[JsValue],
        _ctx: &mut JsContext,
    ) -> JsResult<JsValue> {
        if args.is_empty() {
            return Err(JsNativeError::error()
                .with_message("Expected a string argument for host")
                .into());
        }

        let host = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for host")
            })?;

        let ip = PACEnvFunctions::dns_resolve(&host).map_err(|e| {
            JsNativeError::error().with_message(format!("DNS resolve error: {}", e))
        })?;

        match ip {
            Some(ip) => Ok(JsValue::String(ip.to_string().into())),
            None => Ok(JsValue::undefined()),
        }
    }

    pub fn is_resolvable(
        _this: &JsValue,
        args: &[JsValue],
        _ctx: &mut JsContext,
    ) -> JsResult<JsValue> {
        if args.is_empty() {
            return Err(JsNativeError::error()
                .with_message("Expected a string argument for host")
                .into());
        }

        let host = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for host")
            })?;

        let resolvable = PACEnvFunctions::is_resolvable(&host).map_err(|e| {
            JsNativeError::error().with_message(format!("DNS resolvable check error: {}", e))
        })?;

        Ok(JsValue::from(resolvable))
    }

    pub fn is_in_net(_this: &JsValue, args: &[JsValue], _ctx: &mut JsContext) -> JsResult<JsValue> {
        if args.len() < 3 {
            return Err(JsNativeError::error()
                .with_message("Expected three string arguments for host, pattern, and mask")
                .into());
        }

        let host = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for host")
            })?;
        let pattern = args[1]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for pattern")
            })?;
        let mask = args[2]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for mask")
            })?;

        let in_net = PACEnvFunctions::is_in_net(&host, &pattern, &mask).map_err(|e| {
            JsNativeError::error().with_message(format!("Network check error: {}", e))
        })?;

        Ok(JsValue::from(in_net))
    }

    pub fn local_host_or_domain_is(
        _this: &JsValue,
        args: &[JsValue],
        _ctx: &mut JsContext,
    ) -> JsResult<JsValue> {
        if args.len() < 2 {
            return Err(JsNativeError::error()
                .with_message("Expected two string arguments for host and domain")
                .into());
        }

        let host = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for host")
            })?;
        let host_dom = args[1]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for domain")
            })?;

        let is_local = PACEnvFunctions::local_host_or_domain_is(&host, &host_dom);

        Ok(JsValue::from(is_local))
    }

    pub fn sh_exp_match(
        _this: &JsValue,
        args: &[JsValue],
        _ctx: &mut JsContext,
    ) -> JsResult<JsValue> {
        if args.len() < 2 {
            return Err(JsNativeError::error()
                .with_message("Expected two string arguments for string and shell expression")
                .into());
        }

        let s = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error().with_message("Expected a string argument for string")
            })?;
        let sh_exp = args[1]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                JsNativeError::error()
                    .with_message("Expected a string argument for shell expression")
            })?;

        let matches = PACEnvFunctions::sh_exp_match(&s, &sh_exp);

        Ok(JsValue::from(matches))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boa_engine::prelude::*;
    use boa_engine::{Context as JsContext, JsResult, JsValue, };
    use boa_engine::property::Attribute;
    use boa_runtime::Console;

    const SRC: &str = r#"
    // Test for isPlainHostName
    assert(isPlainHostName("example"));
    assert(!isPlainHostName("example.com"));
    "#;
    #[test]
    fn test_pac() {
        let mut context = Context::default();

        // Register pac environment functions
        PACEnvFunctionsWrapper::register_env(&mut context).unwrap_or_else(|e| {
            panic!("Failed to register PAC environment functions: {}", e);
        });

        // Register console object
        let console = Console::init(&mut context);

        // Register the console as a global property to the context.
        context
            .register_global_property(js_string!(Console::NAME), console, Attribute::all())
            .expect("the console object shouldn't exist yet");
    }

    // Additional tests for other functions can be added here
}
