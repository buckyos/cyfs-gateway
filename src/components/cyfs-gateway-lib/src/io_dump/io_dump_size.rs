pub fn parse_io_dump_size(input: &str) -> Result<u64, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("size is empty".to_string());
    }

    let upper = trimmed.to_ascii_uppercase();
    let mut split_at = upper.len();
    for (idx, ch) in upper.char_indices() {
        if !ch.is_ascii_digit() {
            split_at = idx;
            break;
        }
    }

    let number_part = upper[..split_at].trim();
    let unit_part = upper[split_at..].trim();
    if number_part.is_empty() {
        return Err(format!("invalid size number: {input}"));
    }

    let value: u64 = number_part
        .parse()
        .map_err(|_| format!("invalid size number: {input}"))?;

    let unit = if unit_part.is_empty() { "B" } else { unit_part };
    let multiplier = match unit {
        "B" => 1,
        "KB" => 1024,
        "MB" => 1024 * 1024,
        "GB" => 1024 * 1024 * 1024,
        "TB" => 1024_u64.pow(4),
        _ => return Err(format!("unsupported size unit: {input}")),
    };

    Ok(value.saturating_mul(multiplier))
}

#[cfg(test)]
mod tests {
    use super::parse_io_dump_size;

    #[test]
    fn test_parse_io_dump_size() {
        assert_eq!(parse_io_dump_size("1").unwrap(), 1);
        assert_eq!(parse_io_dump_size("1KB").unwrap(), 1024);
        assert_eq!(parse_io_dump_size("1 mb").unwrap(), 1024 * 1024);
        assert_eq!(parse_io_dump_size("2GB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_io_dump_size("XX").is_err());
        assert!(parse_io_dump_size("1PB").is_err());
    }
}
