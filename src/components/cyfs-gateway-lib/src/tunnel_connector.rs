use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use url::Url;
use std::error::Error as StdError;
use std::task::{Context, Poll};
use tower_service::Service;
use hyper::rt::{Read, Write};
use buckyos_kit::AsyncStream;
use std::pin::Pin;
use std::future::Future;
use hyper::Uri;
use log::*;
use crate::TunnelManager;

pub struct TunnelStreamConnection {
    inner: Box<dyn AsyncStream>
}

impl TunnelStreamConnection {
    pub fn new(inner: Box<dyn AsyncStream>) -> Self {
        TunnelStreamConnection { inner }
    }
}

impl AsyncRead for TunnelStreamConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        //info!("TunnelStreamConnection poll_read len:{}",buf.filled().len());
        // 使用 Pin::new_unchecked 将 inner 的可变引用转换为 Pin<&mut dyn AsyncRead>
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
    }
}


impl AsyncWrite for TunnelStreamConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        //info!("TunnelStreamConnection poll_write len:{}",buf.len());
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        //info!("TunnelStreamConnection poll_flush");
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        //info!("TunnelStreamConnection poll_shutdown");
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

// Implement hyper::rt::Read trait
impl Read for TunnelStreamConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let n = unsafe {
            let mut tbuf = ReadBuf::uninit(buf.as_mut());
            match AsyncRead::poll_read(self, cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                other => return other,
            }
        };

        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

// Implement hyper::rt::Write trait
impl Write for TunnelStreamConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

// Implement Connection trait for TunnelStreamConnection
impl hyper_util::client::legacy::connect::Connection for TunnelStreamConnection {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}


#[derive(Clone)]
pub struct TunnelConnector {
    pub target_stream_url: String,
    pub tunnel_manager: TunnelManager,
}

//open stream by url
impl Service<Uri> for TunnelConnector {
    type Response = TunnelStreamConnection;
    type Error = Box<dyn StdError + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let target_stream_url = self.target_stream_url.clone();
        let tunnel_manager = self.tunnel_manager.clone();
        Box::pin(async move {
            debug!("TunnelConnector call uri: {}", target_stream_url.as_str());
            let stream_url = Url::parse(&target_stream_url.to_string()).unwrap();

            let target_stream = tunnel_manager.open_stream_by_url(&stream_url).await.map_err(|e| {
                warn!("TunnelConnector open_stream_by_url {} failed! {}", stream_url, e);
                Box::new(e) as Box<dyn StdError + Send + Sync>
            })?;

            Ok(TunnelStreamConnection::new(target_stream))
        })
    }
}
