use super::pipe::CommandPipe;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Clone)]
pub struct SharedMemoryOutput {
    buffer: Arc<Mutex<BufWriter<Cursor<Vec<u8>>>>>,
}

impl SharedMemoryOutput {
    pub fn new() -> Self {
        let buffer = Cursor::new(Vec::new());
        let buffer = BufWriter::new(buffer);
        let buffer = Arc::new(Mutex::new(buffer));
        Self { buffer }
    }

    pub fn clone_buffer(&self) -> Vec<u8> {
        let buffer = self.buffer.lock().unwrap();
        buffer.get_ref().get_ref().clone()
    }

    pub fn clone_string(&self) -> String {
        let buffer = self.clone_buffer();
        String::from_utf8_lossy(&buffer).to_string()
    }

    pub fn reset_buffer(&self) {
        let mut buffer = self.buffer.lock().unwrap();
        *buffer.get_mut() = Cursor::new(Vec::new());
    }

    pub async fn into_buffer(self) -> Result<Vec<u8>, String> {
        let out = Arc::try_unwrap(self.buffer)
            .map_err(|_| "Failed to unwrap SharedMemoryOutput buffer".to_string())?;
        let mut buffer = out
            .into_inner()
            .map_err(|_| "Failed to lock SharedMemoryOutput buffer".to_string())?;

        buffer
            .flush()
            .await
            .map_err(|e| format!("Failed to flush buffer: {}", e))?;

        let cursor = buffer.into_inner();
        Ok(cursor.into_inner())
    }
}

impl AsyncWrite for SharedMemoryOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut buffer = self.buffer.lock().unwrap();
        Pin::new(&mut *buffer).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut buffer = self.buffer.lock().unwrap();
        Pin::new(&mut *buffer).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let mut buffer = self.buffer.lock().unwrap();
        Pin::new(&mut *buffer).poll_shutdown(cx)
    }
}

type SharedMemoryOutputRef = Arc<Mutex<SharedMemoryOutput>>;

#[derive(Clone)]
pub struct SharedMemoryInput {
    buffer: Arc<Mutex<BufReader<Cursor<Vec<u8>>>>>,
}

impl AsyncRead for SharedMemoryInput {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let mut buffer = self.buffer.lock().unwrap();
        Pin::new(&mut *buffer).poll_read(cx, buf)
    }
}

impl SharedMemoryInput {
    pub fn new(data: Vec<u8>) -> Self {
        let cursor = Cursor::new(data);
        let buffer = BufReader::new(cursor);
        let buffer = Arc::new(Mutex::new(buffer));
        Self { buffer }
    }

    pub fn new_empty() -> Self {
        let cursor = Cursor::new(Vec::new());
        let buffer = BufReader::new(cursor);
        let buffer = Arc::new(Mutex::new(buffer));
        Self { buffer }
    }
}

type SharedMemoryInputRef = Arc<Mutex<SharedMemoryInput>>;

#[derive(Clone)]
pub struct SharedMemoryPipe {
    pub stdin: SharedMemoryInput,
    pub stdout: SharedMemoryOutput,
    pub stderr: SharedMemoryOutput,

    pub pipe: CommandPipe,
}

impl SharedMemoryPipe {
    pub fn new(stdin: Vec<u8>) -> Self {
        let stdin = SharedMemoryInput::new(stdin);
        let stdout = SharedMemoryOutput::new();
        let stderr = SharedMemoryOutput::new();

        let pipe = CommandPipe {
            stdin: Arc::new(AsyncMutex::new(
                Box::new(stdin.clone()) as Box<dyn AsyncRead + Sync + Send + Unpin>
            )),
            stdout: Arc::new(AsyncMutex::new(
                Box::new(stdout.clone()) as Box<dyn AsyncWrite + Sync + Send + Unpin>
            )),
            stderr: Arc::new(AsyncMutex::new(
                Box::new(stderr.clone()) as Box<dyn AsyncWrite + Sync + Send + Unpin>
            )),
        };

        Self {
            stdin,
            stdout,
            stderr,

            pipe,
        }
    }

    pub fn new_empty() -> Self {
        let stdin = SharedMemoryInput::new_empty();
        let stdout = SharedMemoryOutput::new();
        let stderr = SharedMemoryOutput::new();

        let pipe = CommandPipe {
            stdin: Arc::new(AsyncMutex::new(
                Box::new(stdin.clone()) as Box<dyn AsyncRead + Sync + Send + Unpin>
            )),
            stdout: Arc::new(AsyncMutex::new(
                Box::new(stdout.clone()) as Box<dyn AsyncWrite + Sync + Send + Unpin>
            )),
            stderr: Arc::new(AsyncMutex::new(
                Box::new(stderr.clone()) as Box<dyn AsyncWrite + Sync + Send + Unpin>
            )),
        };

        Self {
            stdin,
            stdout,
            stderr,

            pipe,
        }
    }

    pub fn pipe(&self) -> &CommandPipe {
        &self.pipe
    }
}
