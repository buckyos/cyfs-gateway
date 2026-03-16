use p2p_frame::networks::{TunnelStreamRead, TunnelStreamWrite};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct P2pAsyncStream {
    read: TunnelStreamRead,
    write: TunnelStreamWrite,
}

impl P2pAsyncStream {
    pub fn new(read: TunnelStreamRead, write: TunnelStreamWrite) -> Self {
        Self { read, write }
    }
}

impl AsyncRead for P2pAsyncStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for P2pAsyncStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write.as_mut().poll_shutdown(cx)
    }
}
