use cyfs_process_chain::shlex_example;

fn main() {
    // 运行所有 shlex 示例
    shlex_example::shlex_examples();
    
    println!("=== 实用示例 ===");
    
    // 示例 1: 解析简单的命令
    shlex_example::simulate_shell_command("ls -la /home/user");
    
    // 示例 2: 解析带引号的命令
    shlex_example::simulate_shell_command(r#"echo "Hello World" 'Single Quote'"#);
    
    // 示例 3: 解析复杂的 Docker 命令
    shlex_example::simulate_shell_command(
        r#"docker run -it --name "my container" -v "/host/path:/container/path" ubuntu:latest"#
    );
    
    // 示例 4: 解析带转义字符的命令
    shlex_example::simulate_shell_command(r#"echo "Hello \"World\"" 'It\'s a test'"#);
    
    // 示例 5: 错误处理
    shlex_example::simulate_shell_command(r#"echo "Unclosed quote"#);
} 