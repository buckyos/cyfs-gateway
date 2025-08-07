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
        host.trim_end_matches('.').split('.').count() as i32 - 1
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
            .literal_separator(false)
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

pub struct PACEnvFunctionsWrapper {}

impl PACEnvFunctionsWrapper {
    pub fn register_env(context: &mut Context) -> Result<(), String> {
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
    use super::super::exec::*;

    const SRC: &str = r#"
    // Test for isPlainHostName
    function testIsPlainHostName() {
        console.info("Testing isPlainHostName function");
        console.assert(isPlainHostName("example"), "Expected 'example' to be a plain host name");
        console.assert(!isPlainHostName("example.com"), "Expected 'example.com' not to be a plain host name");
        console.assert(isPlainHostName("") === true, "Expected empty string to be a plain hostname");
    }

    // Test for dnsDomainIs
    function testDnsDomainIs() {
        console.info("Testing dnsDomainIs function");
        console.assert(dnsDomainIs("example.com", "example.com"), "Expected 'example.com' to match 'example.com'");
        console.assert(dnsDomainIs("sub.example.com", "example.com"), "Expected 'sub.example.com' to match 'example.com'");
        console.assert(!dnsDomainIs("example.org", "example.com"), "Expected 'example.org' not to match 'example.com'");
        console.assert(dnsDomainIs("", "example.com") === false, "Expected empty string to not belong to 'example.com'");
        console.assert(dnsDomainIs("www.example.com", "") === false, "Expected 'www.example.com' to not belong to empty string");
    }

    // Test for dnsDomainLevels
    function testDnsDomainLevels() {
        console.info("Testing dnsDomainLevels function");
        console.assert(dnsDomainLevels("example.com") === 1, "Expected 'example.com' to have 1 levels");
        console.assert(dnsDomainLevels("sub.example.com") === 2, "Expected 'sub.example.com' to have 2 levels");
        console.assert(dnsDomainLevels("localhost") === 0, "Expected 'localhost' to have 0 level");
        console.assert(dnsDomainLevels("") === 0, "Expected empty string to have 0 levels");
    }

    // Test for dnsResolve
    function testDnsResolve() {
        console.info("Testing dnsResolve function");
        let ip = dnsResolve("example.com");
        console.info(`Resolved 'example.com' to IP: ${ip}`);
        console.assert(ip !== null, "Expected 'example.com' to resolve to an IP address");
        let ip2 = dnsResolve("nonexistent.domain.xyz.zzz");
        console.info(`Resolved 'nonexistent.domain.xyz.zzz' to IP: ${ip2}`);
        console.assert(ip2 == null, "Expected 'nonexistent.domain' to resolve to null");

        // Test with an empty string
        let ip_empty = dnsResolve("");
        console.info(`Resolved empty string to IP: ${ip_empty}`);
        console.assert(ip_empty == null, "Expected empty string to resolve to null");
    }

    // Test for isResolvable
    function testIsResolvable() {
        console.info("Testing isResolvable function");
        console.assert(isResolvable("example.com") === true, "Expected 'example.com' to be resolvable");
        console.assert(isResolvable("nonexistent.domain.xyz.zzz") === false, "Expected 'nonexistent.domain.xyz.zzz' not to be resolvable");
        console.assert(isResolvable("") === false, "Expected empty string to resolve to null");
    }

    // Test for isInNet
    function testIsInNet() {
        console.info("Testing isInNet function");
        console.assert(isInNet("192.168.1.1", "192.168.1.0", "255.255.255.0") === true, "Expected '192.168.1.1' to be in network '192.168.1.0/24'");
        console.assert(isInNet("192.168.2.1", "192.168.1.0", "255.255.255.0") === false, "Expected '192.168.2.1' to not be in network '192.168.1.0/24'");
        console.assert(isInNet("", "192.168.1.0", "255.255.255.0") === false, "Expected empty host to not be in network");
        console.assert(isInNet("192.168.1.1", "", "255.255.255.0") === false, "Expected empty pattern to not match");
        console.assert(isInNet("192.168.1.1", "192.168.1.0", "") === false, "Expected empty mask to not match");
        // Assuming the pattern is a valid IP address
        // console.assert(isInNet("google.com", "172.217.0.0", "255.255.0.0") === true, "Expected 'google.com' to be in network '172.217.0.0/16'");
    }

    // Test for localHostOrDomainIs
    function testLocalHostOrDomainIs() {
        console.info("Testing localHostOrDomainIs function");
        console.assert(localHostOrDomainIs("example.com", "example.com") === true, "Expected 'example.com' to match 'example.com'");
        console.assert(localHostOrDomainIs("localhost", "localhost") === true, "Expected 'localhost' to match 'localhost' as local host");
        console.assert(localHostOrDomainIs("www.example.com", "example.com") === false, "Expected 'www.example.com' to not match 'example.com'");
        console.assert(localHostOrDomainIs("localhost", "example.com") === false, "Expected 'localhost' to not match 'example.com'");
        console.assert(localHostOrDomainIs("", "example.com") === false, "Expected empty string to not match 'example.com'");
    }

    function testShExpMatch() {
        console.info("Testing shExpMatch function");
        console.assert(shExpMatch("http://example.com", "http://*.com") === true, "Expected 'http://example.com' to match 'http://*.com'");
        console.assert(shExpMatch("http://example.com", "*.example.com") === false, "Expected 'http://example.com' to not match '*.example.com'");
        console.assert(shExpMatch("http://home.netscape.com/people/ari/index.html", "*/ari/*") === true, "Expected 'http://home.netscape.com/people/ari/index.html' to match '*/ari/*'");
        console.assert(shExpMatch("http://home.netscape.com/people/montulli/index.html", "*/ari/*") === false, "Expected 'http://home.netscape.com/people/montulli/index.html' to not match '*/ari/*'");
        console.assert(shExpMatch("http://test.com", "*.example.com") === false, "Expected 'http://test.com' to not match '*.example.com'");
        console.assert(shExpMatch("file.txt", "file?.txt") === false, "Expected 'file.txt' to match 'file?.txt'");
        console.assert(shExpMatch("file1.txt", "file?.txt") === true, "Expected 'file1.txt' to match 'file?.txt'");
        console.assert(shExpMatch("file.txt", "file.txt") === true, "Expected 'file.txt' to match 'file.txt'");
        console.assert(shExpMatch("file.txt", "file[0-9].txt") === false, "Expected 'file.txt' to not match 'file[0-9].txt'");
        console.assert(shExpMatch("", "*.example.com") === false, "Expected empty string to not match '*.example.com'");
    }
    
    // Test all functions
    function testAll() {
        testIsPlainHostName();
        testDnsDomainIs();
        testDnsDomainLevels();
        testDnsResolve();
        testIsResolvable();
        testIsInNet();
        testLocalHostOrDomainIs();
        testShExpMatch();
        console.info("All tests passed");
    }
    "#;

    #[test]
    fn test_pac() {
        let exec = JavaScriptExecutor::new().unwrap();
        exec.init_pac_env().unwrap();
        exec.load(SRC).unwrap();

        let func =
            JavaScriptFunctionCaller::load("testAll", &mut exec.context().lock().unwrap()).unwrap();

        let ret = func
            .call(&mut exec.context().lock().unwrap(), Vec::new())
            .unwrap();
        assert!(
            ret.is_success(),
            "Expected function to return success, got: {:?}",
            ret
        );
    }
}
