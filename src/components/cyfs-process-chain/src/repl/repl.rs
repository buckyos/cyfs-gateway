use super::complete::ProcessChainCommandCompleter;
use crate::*;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::{DefaultEditor, Editor, Helper};
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicUsize};

pub struct ProcessChainREPL {
    root_dir: PathBuf,
    env: HookPointEnvRef,
    line_index: AtomicUsize,
    pipe: SharedMemoryPipe, // Pipe for command execution
    context: Context,       // Context for the REPL chain
}

impl ProcessChainREPL {
    pub fn new() -> Result<Self, String> {
        let app_data_dir = dirs_next::data_dir()
            .ok_or_else(|| "Failed to get application data directory".to_string())?;

        let data_dir = app_data_dir.join("cyfs-process-chain-repl/data");
        if !data_dir.exists() {
            std::fs::create_dir_all(&data_dir).map_err(|e| {
                let msg = format!("Failed to create data directory: {}", e);
                error!("{}", msg);
                msg
            })?;
        }
        let env = HookPointEnv::new("repl-default", data_dir);

        let pipe = SharedMemoryPipe::new_empty();
        let counter = Arc::new(GotoCounter::new());
        let context = Context::new(env.global_env().clone(), counter, pipe.pipe().clone());

        Ok(Self {
            env: Arc::new(env),
            root_dir: app_data_dir,
            line_index: AtomicUsize::new(0),
            pipe,
            context,
        })
    }

    pub async fn init(&self) -> Result<(), String> {
        // Initialize the REPL environment
        // Load some collections for file
        self.env
            .load_collection(
                "host",
                CollectionType::MultiMap,
                CollectionFileFormat::Json,
                true,
            )
            .await?;

        self.env
            .load_collection(
                "ip",
                CollectionType::MultiMap,
                CollectionFileFormat::Json,
                true,
            )
            .await?;

        info!("REPL environment initialized successfully");
        Ok(())
    }

    pub async fn run(&self) -> Result<(), String> {
        let config = rustyline::Config::builder()
            .completion_type(rustyline::CompletionType::List)
            .build();

        let mut rl = Editor::<ProcessChainCommandCompleter, DefaultHistory>::with_config(config)
            .map_err(|e| {
                let msg = format!("Failed to create REPL editor: {}", e);
                error!("{}", msg);
                msg
            })?;

        let completer = ProcessChainCommandCompleter::new();
        rl.set_helper(Some(completer));

        println!(
            "Welcome to the interactive console for cyfs-process-chain tool! Type 'exit' to quit."
        );

        loop {
            let readline = rl.readline("> ");
            match readline {
                Ok(line) => {
                    let line = line.trim().to_string();
                    if line == "exit" {
                        println!("Exiting REPL.");
                        break;
                    }

                    if let Err(e) = rl.add_history_entry(line.as_str()) {
                        let msg = format!("Failed to add history entry: {}", e);
                        error!("{}", msg);
                        return Err(msg);
                    }

                    if let Err(e) = self.execute_line(&line).await {
                        eprint!("Error executing command: {}", e);
                    }

                    let history_file = self.root_dir.join("history.txt");
                    if let Err(e) = rl.save_history(&history_file) {
                        warn!("Failed to save repl history: {}", e);
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("Ctrl-C pressed, exiting REPL.");
                    break;
                }
                Err(ReadlineError::Eof) => {
                    println!("End of file reached, exiting REPL.");
                    break;
                }
                Err(e) => {
                    error!("Error reading line: {}", e);
                    break;
                }
            }
        }

        // Implement the REPL logic here
        // This could involve reading commands, executing them, and returning results
        Ok(())
    }

    async fn execute_line(&self, line: &str) -> Result<(), String> {
        let line_index = self
            .line_index
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let block_id = format!("repl_block_{}", line_index);
        let block_parser = BlockParser::new(&block_id);

        // Parse block content
        let mut item = block_parser.parse(&line).map_err(|e| {
            let msg = format!("Parse line error: {}, {}", line, e);
            error!("{}", msg);
            msg
        })?;

        // Translate the block
        let translator = BlockCommandTranslator::new(COMMAND_PARSER_FACTORY.clone());
        if let Err(e) = translator.translate(&mut item).await {
            let msg = format!("Translate block error: {}, {}", line, e);
            error!("{}", msg);
            return Err(msg);
        }

        let block_executer = BlockExecuter::new(&block_id);
        let block_context = self.context.fork_block();
        let result = block_executer.execute_block(&item, &block_context).await?;
        match result {
            CommandResult::Success(value) => {
                println!("Command executed successfully: {}", value);
            }
            CommandResult::Error(value) => {
                println!("Command execution failed: {}", value);
            }
            CommandResult::Control(action) => {
                eprintln!("Control action not used in REPL: {:?}", action);
            }
        }

        // Get output from pipe
        let output = self.pipe.stdout.clone_string();
        self.pipe.stdout.reset_buffer();
        if !output.is_empty() {
            println!("{}", output);
        }

        Ok(())
    }
}
