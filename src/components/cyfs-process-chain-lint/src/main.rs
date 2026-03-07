use clap::{Parser, Subcommand, ValueEnum};
use cyfs_process_chain_lint::{
    classify_parse_error, default_known_vars, lint_file, Diagnostic, LintConfig, LintSeverity,
};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "pc-lint")]
#[command(about = "Static analyzer for cyfs-process-chain scripts")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Check(CheckArgs),
}

#[derive(Parser, Debug)]
struct CheckArgs {
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    #[arg(long = "format", default_value = "text")]
    format: OutputFormat,

    #[arg(long = "fail-on", default_value = "error")]
    fail_on: FailOn,

    #[arg(long = "known-var")]
    known_var: Vec<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailOn {
    Error,
    Warning,
    Info,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    let code = match cli.command {
        Commands::Check(args) => run_check(args),
    };

    std::process::exit(code);
}

fn run_check(args: CheckArgs) -> i32 {
    let files = match collect_input_files(&args.input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("pc-lint: {}", e);
            return 2;
        }
    };

    if files.is_empty() {
        eprintln!(
            "pc-lint: no .xml/.json files found under '{}'",
            args.input.display()
        );
        return 2;
    }

    let mut known_vars = default_known_vars();
    for var in args.known_var {
        if !var.trim().is_empty() {
            known_vars.insert(var);
        }
    }
    let config = LintConfig { known_vars };

    let mut all = Vec::<Diagnostic>::new();
    for file in files {
        match lint_file(file.as_path(), &config) {
            Ok(mut diagnostics) => all.append(&mut diagnostics),
            Err(err) => {
                let (code, message) = classify_parse_error(&err).unwrap_or((
                    "PC-LINT-0001".to_string(),
                    format!("Failed to lint file: {}", err),
                ));
                all.push(Diagnostic {
                    code,
                    severity: LintSeverity::Error,
                    message,
                    file: file.display().to_string(),
                    lib: "-".to_string(),
                    chain: "-".to_string(),
                    block: "-".to_string(),
                    line: 0,
                    source: "-".to_string(),
                })
            }
        }
    }

    match args.format {
        OutputFormat::Text => print_text(&all),
        OutputFormat::Json => match serde_json::to_string_pretty(&all) {
            Ok(json) => println!("{}", json),
            Err(err) => {
                eprintln!("pc-lint: failed to serialize JSON output: {}", err);
                return 2;
            }
        },
    }

    let threshold = match args.fail_on {
        FailOn::Error => LintSeverity::Error.rank(),
        FailOn::Warning => LintSeverity::Warning.rank(),
        FailOn::Info => LintSeverity::Info.rank(),
    };
    let has_fail = all.iter().any(|d| d.severity.rank() >= threshold);
    if has_fail { 2 } else { 0 }
}

fn print_text(all: &[Diagnostic]) {
    if all.is_empty() {
        println!("pc-lint: no issues found");
        return;
    }

    for d in all {
        println!(
            "[{}][{}] {}:{} lib={} chain={} block={} {}",
            d.code,
            severity_str(d.severity),
            d.file,
            d.line,
            d.lib,
            d.chain,
            d.block,
            d.message
        );
        if d.source != "-" {
            println!("  source: {}", d.source);
        }
    }

    let mut errors = 0usize;
    let mut warnings = 0usize;
    let mut infos = 0usize;
    for d in all {
        match d.severity {
            LintSeverity::Error => errors += 1,
            LintSeverity::Warning => warnings += 1,
            LintSeverity::Info => infos += 1,
        }
    }

    println!(
        "pc-lint summary: {} issue(s), {} error(s), {} warning(s), {} info(s)",
        all.len(),
        errors,
        warnings,
        infos
    );
}

fn severity_str(severity: LintSeverity) -> &'static str {
    match severity {
        LintSeverity::Error => "error",
        LintSeverity::Warning => "warning",
        LintSeverity::Info => "info",
    }
}

fn collect_input_files(input: &Path) -> Result<Vec<PathBuf>, String> {
    if input.is_file() {
        return Ok(vec![input.to_path_buf()]);
    }
    if !input.is_dir() {
        return Err(format!(
            "input '{}' is neither a file nor a directory",
            input.display()
        ));
    }

    let mut files = Vec::new();
    collect_from_dir(input, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_from_dir(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("failed to read directory '{}': {}", dir.display(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read directory entry: {}", e))?;
        let path = entry.path();
        if path.is_dir() {
            collect_from_dir(path.as_path(), out)?;
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ext == "xml" || ext == "json" {
            out.push(path);
        }
    }
    Ok(())
}
