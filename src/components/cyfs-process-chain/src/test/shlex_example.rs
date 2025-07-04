use shlex::Shlex;

/// shlex 使用示例
/// 
/// shlex 是一个用于解析 shell 风格字符串的库，
/// 特别适合解析命令行参数，能够正确处理引号、转义字符等
pub fn shlex_examples() {
    println!("=== shlex 使用示例 ===\n");

    // 示例 1: 基本用法 - 解析简单的命令行参数
    basic_parsing_example();

    // 示例 2: 处理带引号的参数
    quoted_arguments_example();

    // 示例 3: 处理转义字符
    escaped_characters_example();

    // 示例 4: 处理复杂的命令行
    complex_command_example();

    // 示例 5: 错误处理
    error_handling_example();
}

fn basic_parsing_example() {
    println!("1. 基本解析示例:");
    let command = "ls -la /home/user";
    
    let args: Vec<String> = Shlex::new(command).collect();
    println!("原始命令: {}", command);
    println!("解析结果: {:?}", args);
    println!();
}

fn quoted_arguments_example() {
    println!("2. 带引号的参数示例:");
    let command = r#"echo "Hello World" 'Single Quote' "Path with spaces""#;
    
    let args: Vec<String> = Shlex::new(command).collect();
    println!("原始命令: {}", command);
    println!("解析结果: {:?}", args);
    println!();
}

fn escaped_characters_example() {
    println!("3. 转义字符示例:");
    let command = r#"echo "Hello \"World\"" 'It\'s a test' "Line1\nLine2""#;
    
    let args: Vec<String> = Shlex::new(command).collect();
    println!("原始命令: {}", command);
    println!("解析结果: {:?}", args);
    println!();
}

fn complex_command_example() {
    println!("4. 复杂命令示例:");
    let command = r#"docker run -it --name "my container" -v "/host/path:/container/path" ubuntu:latest bash -c "echo 'Hello from container'""#;
    
    let args: Vec<String> = Shlex::new(command).collect();
    println!("原始命令: {}", command);
    println!("解析结果: {:?}", args);
    println!();
}

fn error_handling_example() {
    println!("5. 错误处理示例:");
    
    // 处理不完整的引号
    let invalid_command = r#"echo "Unclosed quote"#;
    println!("无效命令: {}", invalid_command);
    
    let mut shlex = Shlex::new(invalid_command);
    let mut args = Vec::new();
    
    while let Some(token) = shlex.next() {
        args.push(token.clone());
    }
    
    println!("解析结果: {:?}", args);
    println!();
}

/// 实用的命令行解析函数
pub fn parse_command_line(command: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut shlex = Shlex::new(command);
    
    while let Some(token) = shlex.next() {
        args.push(token.clone());
    }
    
    Ok(args)
}

/// 示例：模拟 shell 命令执行
pub fn simulate_shell_command(command: &str) {
    println!("执行命令: {}", command);
    
    match parse_command_line(command) {
        Ok(args) => {
            println!("解析的参数:");
            for (i, arg) in args.iter().enumerate() {
                println!("  [{}]: {}", i, arg);
            }
        }
        Err(e) => {
            println!("错误: {}", e);
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_parsing() {
        let command = "ls -la";
        let args: Vec<String> = Shlex::new(command).collect();
        assert_eq!(args, vec!["ls", "-la"]);
    }

    #[test]
    fn test_quoted_arguments() {
        let command = r#"echo "Hello World""#;
        let args: Vec<String> = Shlex::new(command).collect();
        assert_eq!(args, vec!["echo", "Hello World"]);

        let command = r#"echo "${HOME}""#;
        let args: Vec<String> = Shlex::new(command).collect();
        assert_eq!(args, vec!["echo", "${HOME}"]);

    }

    #[test]
    fn test_parse_command_line() {
        let command = r#"docker run -it --name "test container" ubuntu"#;
        let result = parse_command_line(command);
        assert!(result.is_ok());
        
        let args = result.unwrap();
        assert_eq!(args[0], "docker");
        assert_eq!(args[1], "run");
        assert_eq!(args[2], "-it");
        assert_eq!(args[3], "--name");
        assert_eq!(args[4], "test container");
        assert_eq!(args[5], "ubuntu");
    }
} 