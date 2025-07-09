use tokio::io::{AsyncRead, AsyncWrite};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Async Pipe with stdin, stdout, stderr
#[derive(Clone)]
pub struct CommandPipe {
    pub stdin:  Arc<Mutex<Box<dyn AsyncRead  + Sync + Send + Unpin>>>,
    pub stdout: Arc<Mutex<Box<dyn AsyncWrite + Sync + Send + Unpin>>>,
    pub stderr: Arc<Mutex<Box<dyn AsyncWrite + Sync + Send + Unpin>>>,
}

impl CommandPipe {
    pub fn new(
        stdin: Box<dyn AsyncRead + Sync + Send + Unpin>,
        stdout: Box<dyn AsyncWrite + Sync + Send + Unpin>,
        stderr: Box<dyn AsyncWrite + Sync + Send + Unpin>,
    ) -> Self {
        Self {
            stdin:  Arc::new(Mutex::new(stdin)),
            stdout: Arc::new(Mutex::new(stdout)),
            stderr: Arc::new(Mutex::new(stderr)),
        }
    }

    pub fn default() -> Self {
        Self {
            stdin:  Arc::new(Mutex::new(Box::new(tokio::io::empty()))),
            stdout: Arc::new(Mutex::new(Box::new(tokio::io::sink()))),
            stderr: Arc::new(Mutex::new(Box::new(tokio::io::sink()))),
        }
    }

    pub fn default_std() -> Self {
        Self {
            stdin:  Arc::new(Mutex::new(Box::new(tokio::io::stdin()))),
            stdout: Arc::new(Mutex::new(Box::new(tokio::io::stdout()))),
            stderr: Arc::new(Mutex::new(Box::new(tokio::io::stderr()))),
        }
    }
}

