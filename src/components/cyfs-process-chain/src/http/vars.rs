// Shared HTTP variable definitions used by request visitors.

pub const HTTP_REQUEST_HEADER_VARS: &[(&str, &str, bool)] = &[
    ("REQ_host", "host", true),
    ("REQ_method", "method", true),
    ("REQ_content_length", "content-length", true),
    ("REQ_content_type", "content-type", true),
    ("REQ_user_agent", "user-agent", true),
];

