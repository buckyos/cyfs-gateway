use super::io_dump_frame::IoDumpFrame;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoDumpResolvedConfig {
    pub file_path: PathBuf,
    pub rotate_size: u64,
    pub rotate_max_files: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct IoDumpWriter {
    tx: mpsc::Sender<IoDumpFrame>,
    disabled_due_to_disk_full: Arc<AtomicBool>,
    dropped_frames: Arc<AtomicU64>,
}

impl IoDumpWriter {
    pub fn new(config: IoDumpResolvedConfig) -> Self {
        let (tx, mut rx) = mpsc::channel::<IoDumpFrame>(1024);
        let disabled_due_to_disk_full = Arc::new(AtomicBool::new(false));
        let dropped_frames = Arc::new(AtomicU64::new(0));
        let disabled = disabled_due_to_disk_full.clone();

        tokio::spawn(async move {
            let mut state = match WriterState::open(config).await {
                Ok(state) => state,
                Err(e) => {
                    log::error!("io dump open failed: {e}");
                    return;
                }
            };
            while let Some(frame) = rx.recv().await {
                if disabled.load(Ordering::Relaxed) {
                    continue;
                }
                let encoded = frame.encode();
                if let Err(e) = state.write_record(&encoded).await {
                    if is_disk_full(&e) {
                        disabled.store(true, Ordering::Relaxed);
                        log::warn!("io dump disabled due to disk full: {e}");
                    } else {
                        log::error!("io dump write failed: {e}");
                    }
                }
            }
        });

        Self {
            tx,
            disabled_due_to_disk_full,
            dropped_frames,
        }
    }

    pub fn submit(&self, frame: IoDumpFrame) {
        if self.disabled_due_to_disk_full.load(Ordering::Relaxed) {
            self.dropped_frames.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.tx.try_send(frame).is_err() {
            self.dropped_frames.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct WriterState {
    config: IoDumpResolvedConfig,
    file: File,
    active_size: u64,
    rotate_seq: u64,
}

impl WriterState {
    async fn open(config: IoDumpResolvedConfig) -> std::io::Result<Self> {
        if let Some(parent) = config.file_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.file_path)
            .await?;
        let metadata = file.metadata().await?;
        Ok(Self {
            config,
            file,
            active_size: metadata.len(),
            rotate_seq: 0,
        })
    }

    async fn write_record(&mut self, encoded: &[u8]) -> std::io::Result<()> {
        let next_size = self.active_size.saturating_add(encoded.len() as u64);
        if self.config.rotate_size > 0 && self.active_size > 0 && next_size > self.config.rotate_size {
            self.rotate().await?;
        }
        self.file.write_all(encoded).await?;
        self.active_size = self.active_size.saturating_add(encoded.len() as u64);
        Ok(())
    }

    async fn rotate(&mut self) -> std::io::Result<()> {
        self.file.flush().await?;
        let ts = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
        self.rotate_seq = self.rotate_seq.saturating_add(1);
        let file_name = self
            .config
            .file_path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("io_dump");
        let rotated_name = format!("{file_name}.{ts}.{}", self.rotate_seq);
        let rotated_path = self
            .config
            .file_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(rotated_name);

        match fs::rename(&self.config.file_path, &rotated_path).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.config.file_path)
            .await?;
        self.active_size = 0;
        self.cleanup_rotated_files().await?;
        Ok(())
    }

    async fn cleanup_rotated_files(&self) -> std::io::Result<()> {
        let Some(max_files) = self.config.rotate_max_files else {
            return Ok(());
        };
        let parent = self.config.file_path.parent().unwrap_or(Path::new("."));
        let prefix = self
            .config
            .file_path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("io_dump");

        let mut entries: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        let mut dir = fs::read_dir(parent).await?;
        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(&(prefix.to_string() + ".")) {
                continue;
            }
            let meta = entry.metadata().await?;
            entries.push((
                meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                entry.path(),
            ));
        }
        entries.sort_by_key(|(modified, _)| *modified);
        if entries.len() <= max_files as usize {
            return Ok(());
        }
        let to_delete = entries.len() - max_files as usize;
        for (_, path) in entries.into_iter().take(to_delete) {
            if let Err(e) = fs::remove_file(path).await {
                log::warn!("io dump cleanup rotated file failed: {e}");
            }
        }
        Ok(())
    }
}

fn is_disk_full(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        match err.raw_os_error() {
            Some(code) if code == libc::ENOSPC || code == libc::EDQUOT => true,
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        matches!(err.kind(), std::io::ErrorKind::StorageFull)
    }
}
