use shlex::Shlex;

fn main() {
    println!("=== shlex 使用示例 ===\n");

    // 示例 1: 基本用法 - 解析简单的命令行参数
    println!("1. 基本解析示例:");
    let command = "ls -la /home/user";
    let args: Vec<String> = Shlex::new(command).collect();
    println!("原始命令: {}", command);
    println!("解析结果: {:?}", args);
    println!();

    // 示例 2: 处理带引号的参数
    println!("2. 带引号的参数示例:");
    let command = r#"echo "Hello World" 'Single Quote' "Path with spaces""#;
    let args: Vec<String> = Shlex::new(command).collect();
    println!("原始命令: {}", command);
    println!("解析结果: {:?}", args);
    println!();

    // 示例 3: 处理转义字符
    println!("3. 转义字符示例:");
    let command = r#"echo "Hello \"World\"" 'It\'s a test' "Line1\nLine2""#;
    let args: Vec<String> = Shlex::new(command).collect();
    println!("原始命令: {}", command);
    println!("解析结果: {:?}", args);
    println!();

    // 示例 4: 处理复杂的命令行
    println!("4. 复杂命令示例:");
    let command = r#"docker run -it --name "my container" -v "/host/path:/container/path" ubuntu:latest bash -c "echo 'Hello from container'""#;
    let args: Vec<String> = Shlex::new(command).collect();
    println!("原始命令: {}", command);
    println!("解析结果: {:?}", args);
    println!();

    // 示例 5: 错误处理 - 使用 shlex::split
    println!("5. 错误处理示例:");
    let invalid_command = r#"echo "Unclosed quote"#;
    println!("无效命令: {}", invalid_command);
    match shlex::split(invalid_command) {
        Some(args) => println!("解析结果: {:?}", args),
        None => println!("解析错误: 引号不匹配或语法错误"),
    }
    println!();

    // 实用函数示例
    println!("=== 实用函数示例 ===");
    
    // 解析命令并显示每个参数
    let commands = vec![
        "ls -la",
        r#"echo "Hello World""#,
        r#"docker run -it --name "test container" ubuntu"#,
        r#"echo "Hello \"World\"" 'It\'s a test'"#,
    ];

    for command in commands {
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
}

/// 实用的命令行解析函数
fn parse_command_line(command: &str) -> Result<Vec<String>, String> {
    match shlex::split(command) {
        Some(args) => Ok(args),
        None => Err("解析错误: 引号不匹配或语法错误".to_string()),
    }
} 