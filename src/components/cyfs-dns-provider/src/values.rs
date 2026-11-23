//! Names and values in the form the trait uses, and how services write them.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::provider::{DnsProviderError, DnsProviderResult, RecordType};

const MAX_TXT_CHUNK: usize = 255;

/// Lower case, without the trailing dot.
pub(crate) fn host(value: &str) -> String {
    value
        .trim()
        .strip_suffix('.')
        .unwrap_or(value.trim())
        .to_ascii_lowercase()
}

pub(crate) fn fqdn(value: &str) -> String {
    format!("{}.", host(value))
}

pub(crate) fn is_under(name: &str, zone: &str) -> bool {
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// `name` relative to `origin`; `apex` when they are the same.
pub(crate) fn relative(name: &str, origin: &str, apex: &str) -> String {
    if name == origin {
        apex.to_string()
    } else {
        name.strip_suffix(origin)
            .and_then(|rest| rest.strip_suffix('.'))
            .unwrap_or(name)
            .to_string()
    }
}

/// The value as the trait's caller gives it, checked.
pub(crate) fn input_value(ty: RecordType, value: &str) -> DnsProviderResult<String> {
    let invalid = || DnsProviderError::Api(format!("invalid {ty:?} value: {value}"));
    match ty {
        RecordType::A => value
            .trim()
            .parse::<Ipv4Addr>()
            .map(|ip| ip.to_string())
            .map_err(|_| invalid()),
        RecordType::AAAA => value
            .trim()
            .parse::<Ipv6Addr>()
            .map(|ip| ip.to_string())
            .map_err(|_| invalid()),
        RecordType::CNAME | RecordType::NS => {
            let value = host(value);
            if value.is_empty() || value.contains(char::is_whitespace) {
                return Err(invalid());
            }
            Ok(value)
        }
        RecordType::TXT => {
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(invalid());
            }
            Ok(value.to_string())
        }
        RecordType::SOA | RecordType::CAA => Err(DnsProviderError::Unsupported(format!(
            "{ty:?} records are not written"
        ))),
    }
}

/// A value as a service stores it, in the form [`input_value`] returns.
pub(crate) fn stored_value(ty: RecordType, raw: &str) -> String {
    match ty {
        RecordType::A => raw
            .trim()
            .parse::<Ipv4Addr>()
            .map_or_else(|_| raw.to_string(), |ip| ip.to_string()),
        RecordType::AAAA => raw
            .trim()
            .parse::<Ipv6Addr>()
            .map_or_else(|_| raw.to_string(), |ip| ip.to_string()),
        RecordType::CNAME | RecordType::NS => host(raw),
        RecordType::TXT => unquote_txt(raw),
        RecordType::SOA | RecordType::CAA => raw.trim().to_string(),
    }
}

/// Quoted character strings of at most 255 bytes.
pub(crate) fn quote_txt(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    let mut chunk = 0;
    for ch in value.chars() {
        if chunk + ch.len_utf8() > MAX_TXT_CHUNK {
            out.push_str("\" \"");
            chunk = 0;
        }
        if matches!(ch, '"' | '\\') {
            out.push('\\');
        }
        out.push(ch);
        chunk += ch.len_utf8();
    }
    out.push('"');
    out
}

/// The text of quoted character strings; anything unquoted is returned as is.
pub(crate) fn unquote_txt(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() < 2 || !trimmed.starts_with('"') || !trimmed.ends_with('"') {
        return value.to_string();
    }
    let mut bytes = Vec::with_capacity(trimmed.len());
    let mut quoted = false;
    let mut rest = trimmed.bytes().peekable();
    while let Some(byte) = rest.next() {
        match byte {
            b'"' => quoted = !quoted,
            b'\\' if quoted => {
                let digits: Vec<u8> = rest.clone().take(3).collect();
                let code = (digits.len() == 3 && digits.iter().all(u8::is_ascii_digit))
                    .then(|| {
                        digits
                            .iter()
                            .fold(0u16, |code, digit| code * 10 + u16::from(digit - b'0'))
                    })
                    .and_then(|code| u8::try_from(code).ok());
                if let Some(code) = code {
                    bytes.push(code);
                    rest.by_ref().take(3).for_each(drop);
                } else if let Some(next) = rest.next() {
                    bytes.push(next);
                }
            }
            _ if quoted => bytes.push(byte),
            _ => {}
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub(crate) fn type_name(ty: RecordType) -> &'static str {
    match ty {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::CNAME => "CNAME",
        RecordType::NS => "NS",
        RecordType::TXT => "TXT",
        RecordType::SOA => "SOA",
        RecordType::CAA => "CAA",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_round_trip() {
        for text in [
            "plain",
            "PKX(abc+/=)",
            "with \"quotes\" and \\",
            &"x".repeat(700),
            "é".repeat(300).as_str(),
        ] {
            let quoted = quote_txt(text);
            assert_eq!(unquote_txt(&quoted), text);
        }
        assert_eq!(unquote_txt("bare text"), "bare text");
        assert_eq!(unquote_txt("\"a\" \"b\""), "ab");
        assert_eq!(unquote_txt("\"a\\059b\""), "a;b");
    }

    #[test]
    fn names() {
        assert!(is_under("a.example.com", "example.com"));
        assert!(is_under("example.com", "example.com"));
        assert!(!is_under("badexample.com", "example.com"));
        assert_eq!(relative("*.a.example.com", "example.com", "@"), "*.a");
        assert_eq!(relative("example.com", "example.com", "@"), "@");
        assert_eq!(host("Foo.Example.com."), "foo.example.com");
    }

    #[test]
    fn values() {
        assert_eq!(
            input_value(RecordType::AAAA, "2001:DB8:0::1").unwrap(),
            "2001:db8::1"
        );
        assert!(input_value(RecordType::A, "2001:db8::1").is_err());
        assert!(input_value(RecordType::TXT, "a\nb").is_err());
        assert!(matches!(
            input_value(RecordType::SOA, "x"),
            Err(DnsProviderError::Unsupported(_))
        ));
        assert_eq!(
            stored_value(RecordType::CNAME, "A.Example.com."),
            "a.example.com"
        );
    }
}
