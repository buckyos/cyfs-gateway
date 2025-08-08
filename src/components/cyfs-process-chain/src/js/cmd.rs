use super::exec::{JavaScriptExecutor, JavaScriptFunctionCaller};
use crate::block::CommandArgs;
use crate::chain::Context;
use crate::cmd::CommandResult;
use crate::cmd::*;
use crate::collection::CollectionValue;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
use tokio::sync::OnceCell;

struct JavaScriptExternalCommand {
    name: String,
    context: JavaScriptExecutor,
    help: Option<JavaScriptFunctionCaller>,
    check: Option<JavaScriptFunctionCaller>,
    exec: JavaScriptFunctionCaller,
}

impl JavaScriptExternalCommand {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn load(name: &str, src: &str) -> Result<Self, String> {
        let context: JavaScriptExecutor = JavaScriptExecutor::new()?;
        context.load(src).map_err(|e| {
            let msg = format!("Failed to load JavaScript source: {}, {}", name, e);
            error!("{}", msg);
            msg
        })?;

        let mut js_context = context.context().lock().unwrap();
        let exec = JavaScriptFunctionCaller::load(name, &mut js_context)?;

        let help = JavaScriptFunctionCaller::load_option("help", &mut js_context)?;
        let check = JavaScriptFunctionCaller::load_option("check", &mut js_context)?;

        drop(js_context);
        Ok(Self {
            name: name.to_string(),
            context,
            help,
            check,
            exec,
        })
    }

    pub fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        if let Some(help) = &self.help {
            let mut context = self.context.context().lock().unwrap();
            let args = vec![
                CollectionValue::String(name.to_string()),
                CollectionValue::String(help_type.as_str().to_string()),
            ];

            match help.call(&mut context, args) {
                Ok(result) => match result {
                    CommandResult::Success(s) => s,
                    CommandResult::Error(e) => {
                        let msg = format!("Help function returned with error: {}, {}", name, e);
                        error!("{}", msg);
                        msg
                    }
                    _ => format!("Help function did not return a string: {:?}", result),
                },
                Err(e) => {
                    let msg = format!("Failed to call help function: {}, {}", name, e);
                    error!("{}", msg);
                    msg
                }
            }
        } else {
            format!("No help function defined for command: {}", name)
        }
    }

    pub fn exec(&self, args: Vec<CollectionValue>) -> Result<CommandResult, String> {
        let mut js_context = self.context.context().lock().unwrap();
        self.exec.call(&mut js_context, args).map_err(|e| {
            let msg = format!("Failed to execute command: {}, {}", self.name, e);
            error!("{}", msg);
            msg
        })
    }
}

enum AsyncRequest {
    Exit(()),
    Load(String, String, oneshot::Sender<Result<(), String>>),
    Help(String, CommandHelpType, oneshot::Sender<String>),
    // FIXME: The Check command is not used in the current implementation, but it can be added later if needed.
    // Check(String, CommandArgs, oneshot::Sender<Result<(), String>>),
    Exec(
        String,
        Vec<CollectionValue>,
        oneshot::Sender<Result<CommandResult, String>>,
    ),
}

impl AsyncRequest {
    pub fn is_exit(&self) -> bool {
        matches!(self, AsyncRequest::Exit(_))
    }

    pub fn _type(&self) -> &'static str {
        match self {
            AsyncRequest::Exit(_) => "Exit",
            AsyncRequest::Load(_, _, _) => "Load",
            AsyncRequest::Help(_, _, _) => "Help",
            // AsyncRequest::Check(_, _, _) => "Check",
            AsyncRequest::Exec(_, _, _) => "Exec",
        }
    }
}

type AsyncRequestSenderRef = Arc<Mutex<mpsc::Sender<AsyncRequest>>>;

thread_local! {
    static COMMANDS: RefCell<HashMap<String, JavaScriptExternalCommand>> = RefCell::new(HashMap::new());
}

#[derive(Clone)]
pub struct AsyncJavaScriptCommandExecutor {
    sender: Arc<OnceCell<AsyncRequestSenderRef>>,
}

impl Drop for AsyncJavaScriptCommandExecutor {
    fn drop(&mut self) {
        // Stop the executor when it is dropped
        self.stop();
    }
}

impl AsyncJavaScriptCommandExecutor {
    pub fn new() -> Self {
        let ret = Self {
            sender: Arc::new(OnceCell::new()),
        };

        ret
    }

    async fn get_sender(&self) -> &AsyncRequestSenderRef {
        self.sender
            .get_or_init(|| async {
                let (tx, rx) = mpsc::channel::<AsyncRequest>();
                Self::start(rx);
                Arc::new(Mutex::new(tx))
            }).await
    }

    pub async fn load_command(
        &self,
        name: String,
        src: String,
    ) -> Result<AsyncJavaScriptExternalCommand, String> {
        let sender = self.get_sender().await;
        let ret = AsyncJavaScriptExternalCommand::new(name, sender.clone());
        ret.load(src).await?;

        Ok(ret)
    }

    fn start(rx: mpsc::Receiver<AsyncRequest>) {
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    loop {
                        match rx.recv() {
                            Ok(request) => {
                                if request.is_exit() {
                                    info!("AsyncJavaScriptCommandExecutor received exit request");
                                    break;
                                }
                                Self::handle_request(request);
                            }
                            Err(e) => {
                                error!("Failed to receive request: {}", e);
                                break;
                            }
                        }
                    }

                    COMMANDS.with(|cmds| {
                        info!("Stopping AsyncJavaScriptCommandExecutor, clearing commands: {}", cmds.borrow().len());
                        cmds.borrow_mut().clear();
                    });
                    info!("AsyncJavaScriptCommandExecutor stopped");
                });
        });

        tokio::task::spawn_blocking(move || {
            thread
                .join()
                .expect("Failed to join async command executor thread");
        });
    }

    pub fn stop(&self) {
        if let Some(sender) = self.sender.get() {
            if let Err(e) = sender.lock().unwrap().send(AsyncRequest::Exit(())) {
                error!("Failed to send exit request: {}", e);
            }
        }
    }

    fn handle_request(request: AsyncRequest) {
        match request {
            AsyncRequest::Load(name, src, responder) => Self::on_load(name, src, responder),
            AsyncRequest::Help(name, help_type, responder) => {
                Self::on_help(name, help_type, responder)
            }
            AsyncRequest::Exec(name, args, responder) => Self::on_exec(name, args, responder),
            _ => unreachable!("Unexpected request type: {:?}", request._type()),
        }
    }

    fn on_load(name: String, src: String, responder: oneshot::Sender<Result<(), String>>) {
        let contains = COMMANDS.with(|cmds| cmds.borrow().contains_key(&name));
        if contains {
            let msg = format!("Command {} already loaded", name);
            error!("{}", msg);
            if let Err(_) = responder.send(Err(msg)) {
                error!("Failed to send load error for {}", name);
            }
            return;
        }

        match JavaScriptExternalCommand::load(&name, &src) {
            Ok(cmd) => {
                COMMANDS.with(|cmds| {
                    cmds.borrow_mut().insert(name.clone(), cmd);
                });

                if let Err(_) = responder.send(Ok(())) {
                    error!("Failed to send load result for {}", name);
                } else {
                    info!("Successfully loaded js command: {}", name);
                }
            }
            Err(e) => {
                if let Err(_) = responder.send(Err(e)) {
                    error!("Failed to send load error for {}", name);
                }
            }
        }
    }

    fn on_help(
        name: String,
        help_type: CommandHelpType,
        responder: oneshot::Sender<String>,
    ) {
        COMMANDS.with(|cmds| {
            if let Some(cmd) = cmds.borrow().get(&name) {
                let help = cmd.help(&name, help_type);
                if let Err(_) = responder.send(help) {
                    error!("Failed to send help for {}", name);
                }
            } else {
                let msg = format!("Command {} not found", name);
                error!("{}", msg);
                let _ = responder.send(msg);
            }
        });
    }

    fn on_exec(
        name: String,
        args: Vec<CollectionValue>,
        responder: oneshot::Sender<Result<CommandResult, String>>,
    ) {
        COMMANDS.with(|cmds| {
            if let Some(cmd) = cmds.borrow().get(&name) {
                match cmd.exec(args) {
                    Ok(result) => {
                        if let Err(_) = responder.send(Ok(result)) {
                            error!("Failed to send exec result for {}", name);
                        }
                    }
                    Err(e) => {
                        if let Err(_) = responder.send(Err(e)) {
                            error!("Failed to send exec error for {}", name);
                        }
                    }
                }
            } else {
                let msg = format!("Command {} not found", name);
                error!("{}", msg);
                let _ = responder.send(Err(msg));
            }
        });
    }
}

pub struct AsyncJavaScriptExternalCommand {
    name: String,
    sender: AsyncRequestSenderRef,
}

impl AsyncJavaScriptExternalCommand {
    fn new(name: String, sender: AsyncRequestSenderRef) -> Self {
        Self { name, sender }
    }

    pub async fn load(&self, src: String) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let request = AsyncRequest::Load(self.name.clone(), src, tx);
        let ret = self.sender.lock().unwrap().send(request);
        if ret.is_ok() {
            match rx.await {
                Ok(result) => result,
                Err(e) => {
                    let msg = format!("Failed to receive load response: {}", e);
                    error!("{}", msg);
                    Err(msg)
                }
            }
        } else {
            Err(format!("Failed to send load request for {}", self.name))
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[async_trait::async_trait]
impl ExternalCommand for AsyncJavaScriptExternalCommand {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        todo!();
        /*
        assert_eq!(self.name, name);
        let (tx, rx) = oneshot::channel();
        let request = AsyncRequest::Help(name.to_string(), help_type, tx);
        if let Ok(sender) = self.sender.lock().send(request) {
            match rx.recv() {
                Ok(help) => help,
                Err(e) => {
                    error!("Failed to receive help response: {}", e);
                    format!("Failed to get help for command {}: {}", name, e)
                }
            }
        } else {
            format!("Failed to send help request for command {}", name)
        }
        */
    }

    fn check(&self, _args: &CommandArgs) -> Result<(), String> {
        Ok(()) // No check implemented for async js commands
    }

    async fn exec(
        &self,
        _context: &Context,
        args: &[CollectionValue],
        _origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        let (tx, rx) = oneshot::channel();
        let request = AsyncRequest::Exec(self.name.clone(), args.to_vec(), tx);

        let ret = self.sender.lock().unwrap().send(request);
        if ret.is_ok() {
            // Wait for the response
            match rx.await {
                Ok(result) => result,
                Err(e) => {
                    let msg = format!("Failed to receive exec response: {}", e);
                    error!("{}", msg);
                    Err(msg)
                }
            }
        } else {
            Err(format!(
                "Failed to send exec request for command {}",
                self.name
            ))
        }
    }
}
