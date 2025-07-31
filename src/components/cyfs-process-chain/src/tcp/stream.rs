use buckyos_kit::AsyncStream;
use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    /// A wrapper that prepends a prefix buffer to the head of the stream.
    pub struct PrefixedStream<S: AsyncStream> {
        prefix: Vec<u8>,
        read_pos: usize, // Records how many bytes of the prefix have been read

        #[pin]
        inner: S,      // The inner stream that we are wrapping
    }
}

impl<S: AsyncStream> PrefixedStream<S> {
    /// Creates a new PrefixedStream with the given prefix and inner stream.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            read_pos: 0,
            inner,
        }
    }
}

impl<S: AsyncStream> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();

        // Phase 1: If there is still data in the prefix buffer, then read it first
        if *this.read_pos < this.prefix.len() {
            let remaining_prefix = &this.prefix[*this.read_pos..];
            let len_to_copy = std::cmp::min(remaining_prefix.len(), buf.remaining());

            buf.put_slice(&remaining_prefix[..len_to_copy]);
            *this.read_pos += len_to_copy;

            return Poll::Ready(Ok(()));
        }

        // Phase 2: If the prefix has been fully read, then read from the inner stream
        this.inner.poll_read(cx, buf)
    }
}

// Impl the AsyncWrite trait for PrefixedStream, just forwarding to the inner stream
impl<S: AsyncStream> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    type MockStream = Cursor<Vec<u8>>;

    #[tokio::test]
    async fn main() {
        let mut original_stream = MockStream::new(Vec::new());
        tokio::io::AsyncWriteExt::write_all(&mut original_stream, b"world!")
            .await
            .unwrap();

        original_stream.set_position(0);

        let prefix = b"Hello, ".to_vec();

        let mut new_stream = PrefixedStream::new(prefix.clone(), original_stream);

        let mut result = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut new_stream, &mut result)
            .await
            .unwrap();

        println!("Read from new stream: {}", String::from_utf8_lossy(&result));

        let mut expected = prefix.clone();
        expected.extend_from_slice(b"world!");

        assert_eq!(result, expected);
        println!("Assertion successful!");
    }
}
