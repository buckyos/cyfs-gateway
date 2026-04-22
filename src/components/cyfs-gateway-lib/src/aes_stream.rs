use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use futures::ready;
use sha2::{Digest, Sha256};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// RTCP tunnel / stream record layer built on AES-256-GCM (AEAD).
//
// On-wire record format:
//
//   +--------+---------------------+---------+
//   | len u16| ciphertext (N)      | tag(16) |
//   +--------+---------------------+---------+
//
//   len   : big-endian, equals N + TAG_LEN. Excludes the 2-byte len field.
//   N     : 0..=MAX_PLAINTEXT
//   tag   : 16-byte GCM authentication tag
//
// Each record uses a fresh 96-bit nonce derived as:
//     nonce = nonce_base XOR (seq as 8 bytes, BE) placed in the low 8 bytes.
//
// The two directions of a connection use DIFFERENT nonce bases, derived from
// the shared IV via domain-separated SHA-256. This prevents keystream reuse
// that would otherwise occur when both peers share the same (key, iv).

const TAG_LEN: usize = 16;
const LEN_FIELD: usize = 2;
pub const MAX_PLAINTEXT: usize = 16 * 1024;
const NONCE_LEN: usize = 12;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncryptionRole {
    // The side that initiated the underlying transport (TCP connector, or the
    // side that sent the Hello / HelloStream plaintext first packet).
    Initiator,
    // The side that accepted the underlying transport.
    Responder,
}

enum ReadPhase {
    NeedHeader,
    NeedBody,
}

pub struct EncryptedStream<S> {
    inner: S,
    cipher: Aes256Gcm,

    write_nonce_base: [u8; NONCE_LEN],
    read_nonce_base: [u8; NONCE_LEN],
    write_seq: u64,
    read_seq: u64,

    // Write buffer: holds an encrypted record that is being flushed to `inner`.
    write_buf: Vec<u8>,
    write_pos: usize,
    shutdown_started: bool,

    // Read state machine.
    read_phase: ReadPhase,
    header_buf: [u8; LEN_FIELD],
    header_filled: usize,
    body_buf: Vec<u8>,
    body_needed: usize,
    body_filled: usize,
    plaintext: Vec<u8>,
    plaintext_pos: usize,
    read_eof: bool,
    // True once at least one AEAD record has been authenticated. Used to
    // distinguish a legitimate post-record close from an early FIN (peer
    // dropped or on-wire truncation) that must be surfaced as an error
    // rather than a silent Ok(0).
    first_record_received: bool,
}

impl<S> EncryptedStream<S> {
    pub fn new(inner: S, key: &[u8; 32], iv: &[u8; 16], role: EncryptionRole) -> Self {
        let (nonce_a, nonce_b) = derive_nonce_bases(iv);
        let (write_nonce_base, read_nonce_base) = match role {
            EncryptionRole::Initiator => (nonce_a, nonce_b),
            EncryptionRole::Responder => (nonce_b, nonce_a),
        };
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        Self {
            inner,
            cipher,
            write_nonce_base,
            read_nonce_base,
            write_seq: 0,
            read_seq: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            shutdown_started: false,
            read_phase: ReadPhase::NeedHeader,
            header_buf: [0; LEN_FIELD],
            header_filled: 0,
            body_buf: Vec::new(),
            body_needed: 0,
            body_filled: 0,
            plaintext: Vec::new(),
            plaintext_pos: 0,
            read_eof: false,
            first_record_received: false,
        }
    }
}

fn derive_nonce_bases(iv: &[u8; 16]) -> ([u8; NONCE_LEN], [u8; NONCE_LEN]) {
    let mut a = [0u8; NONCE_LEN];
    let mut b = [0u8; NONCE_LEN];
    let mut ha = Sha256::new();
    ha.update(b"rtcp-aead-nonce/A");
    ha.update(iv);
    a.copy_from_slice(&ha.finalize()[..NONCE_LEN]);
    let mut hb = Sha256::new();
    hb.update(b"rtcp-aead-nonce/B");
    hb.update(iv);
    b.copy_from_slice(&hb.finalize()[..NONCE_LEN]);
    (a, b)
}

fn make_nonce(base: &[u8; NONCE_LEN], seq: u64) -> [u8; NONCE_LEN] {
    let mut n = *base;
    let seq_bytes = seq.to_be_bytes();
    // XOR the 64-bit counter into the low 8 bytes of the 96-bit nonce.
    for i in 0..8 {
        n[NONCE_LEN - 8 + i] ^= seq_bytes[i];
    }
    n
}

fn io_err(kind: std::io::ErrorKind, msg: &'static str) -> std::io::Error {
    std::io::Error::new(kind, msg)
}

impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            // 1. Deliver any pending plaintext first.
            if this.plaintext_pos < this.plaintext.len() {
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                let remaining = &this.plaintext[this.plaintext_pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                this.plaintext_pos += n;
                return Poll::Ready(Ok(()));
            }

            if this.read_eof {
                return Poll::Ready(Ok(()));
            }

            match this.read_phase {
                ReadPhase::NeedHeader => {
                    let (result, bytes_read) = {
                        let mut rb = ReadBuf::new(&mut this.header_buf[this.header_filled..]);
                        let result = Pin::new(&mut this.inner).poll_read(cx, &mut rb);
                        (result, rb.filled().len())
                    };
                    match result {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            if bytes_read == 0 {
                                if this.header_filled != 0 {
                                    return Poll::Ready(Err(io_err(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "unexpected EOF in AEAD record header",
                                    )));
                                }
                                // Inner stream closed at a record boundary.
                                // Only clean EOF if at least one record was
                                // authenticated: a FIN injected before any
                                // AEAD record was ever received is a
                                // truncation or reject-and-drop, not a clean
                                // end-of-stream, and must surface as an error.
                                if !this.first_record_received {
                                    return Poll::Ready(Err(io_err(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "peer closed before any AEAD record",
                                    )));
                                }
                                this.read_eof = true;
                                return Poll::Ready(Ok(()));
                            }
                            this.header_filled += bytes_read;
                            if this.header_filled == LEN_FIELD {
                                let record_len = u16::from_be_bytes(this.header_buf) as usize;
                                if record_len < TAG_LEN
                                    || record_len > MAX_PLAINTEXT + TAG_LEN
                                {
                                    return Poll::Ready(Err(io_err(
                                        std::io::ErrorKind::InvalidData,
                                        "invalid AEAD record length",
                                    )));
                                }
                                this.body_needed = record_len;
                                this.body_buf.resize(record_len, 0);
                                this.body_filled = 0;
                                this.read_phase = ReadPhase::NeedBody;
                            }
                        }
                    }
                }
                ReadPhase::NeedBody => {
                    let (result, bytes_read) = {
                        let mut rb = ReadBuf::new(&mut this.body_buf[this.body_filled..]);
                        let result = Pin::new(&mut this.inner).poll_read(cx, &mut rb);
                        (result, rb.filled().len())
                    };
                    match result {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            if bytes_read == 0 {
                                return Poll::Ready(Err(io_err(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF in AEAD record body",
                                )));
                            }
                            this.body_filled += bytes_read;
                            if this.body_filled == this.body_needed {
                                let nonce = make_nonce(&this.read_nonce_base, this.read_seq);
                                match this.read_seq.checked_add(1) {
                                    Some(v) => this.read_seq = v,
                                    None => {
                                        return Poll::Ready(Err(io_err(
                                            std::io::ErrorKind::Other,
                                            "AEAD read sequence overflow",
                                        )));
                                    }
                                }
                                match this.cipher.decrypt(
                                    Nonce::from_slice(&nonce),
                                    this.body_buf.as_slice(),
                                ) {
                                    Ok(pt) => {
                                        this.plaintext = pt;
                                        this.plaintext_pos = 0;
                                        this.first_record_received = true;
                                    }
                                    Err(_) => {
                                        return Poll::Ready(Err(io_err(
                                            std::io::ErrorKind::InvalidData,
                                            "AEAD authentication failed",
                                        )));
                                    }
                                }
                                this.header_filled = 0;
                                this.body_buf.clear();
                                this.body_filled = 0;
                                this.body_needed = 0;
                                this.read_phase = ReadPhase::NeedHeader;
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> EncryptedStream<S> {
    // Drain `write_buf[write_pos..]` into the inner stream. Returns Ready when
    // fully drained, Pending otherwise. Propagates errors and write-zero.
    fn drain_pending(
        this: &mut EncryptedStream<S>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        while this.write_pos < this.write_buf.len() {
            let slice = &this.write_buf[this.write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, slice) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io_err(
                        std::io::ErrorKind::WriteZero,
                        "inner stream accepted zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
            }
        }
        this.write_buf.clear();
        this.write_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if this.shutdown_started {
            return Poll::Ready(Err(io_err(
                std::io::ErrorKind::BrokenPipe,
                "encrypted stream already shut down",
            )));
        }

        // 1. Finish any in-flight record before accepting new bytes.
        ready!(Self::drain_pending(this, cx))?;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // 2. Build one record from (up to) MAX_PLAINTEXT bytes of input.
        let accept = buf.len().min(MAX_PLAINTEXT);
        let nonce = make_nonce(&this.write_nonce_base, this.write_seq);
        match this.write_seq.checked_add(1) {
            Some(v) => this.write_seq = v,
            None => {
                return Poll::Ready(Err(io_err(
                    std::io::ErrorKind::Other,
                    "AEAD write sequence overflow",
                )));
            }
        }

        let ct = match this
            .cipher
            .encrypt(Nonce::from_slice(&nonce), &buf[..accept])
        {
            Ok(c) => c,
            Err(_) => {
                return Poll::Ready(Err(io_err(
                    std::io::ErrorKind::Other,
                    "AEAD encrypt failed",
                )));
            }
        };
        debug_assert_eq!(ct.len(), accept + TAG_LEN);

        let record_len = ct.len();
        let mut record = Vec::with_capacity(LEN_FIELD + record_len);
        record.extend_from_slice(&(record_len as u16).to_be_bytes());
        record.extend_from_slice(&ct);

        this.write_buf = record;
        this.write_pos = 0;

        // 3. Opportunistically drain. A partial drain is fine; the remainder
        //    is flushed by the next poll_write / poll_flush / poll_shutdown.
        match Self::drain_pending(this, cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(accept)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(Self::drain_pending(this, cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(Self::drain_pending(this, cx))?;
        this.shutdown_started = true;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for i in 0..32 {
            k[i] = i as u8;
        }
        k
    }

    fn iv() -> [u8; 16] {
        let mut v = [0u8; 16];
        for i in 0..16 {
            v[i] = (i as u8).wrapping_mul(7);
        }
        v
    }

    #[tokio::test]
    async fn roundtrip_small() {
        let (a, b) = duplex(64 * 1024);
        let mut ini = EncryptedStream::new(a, &key(), &iv(), EncryptionRole::Initiator);
        let mut res = EncryptedStream::new(b, &key(), &iv(), EncryptionRole::Responder);

        let msg = b"hello rtcp aead world";
        let writer = tokio::spawn(async move {
            ini.write_all(msg).await.unwrap();
            ini.flush().await.unwrap();
            ini
        });

        let mut got = vec![0u8; msg.len()];
        res.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], &msg[..]);

        let _ = writer.await.unwrap();
    }

    #[tokio::test]
    async fn roundtrip_large_multirecord() {
        let (a, b) = duplex(4 * 1024 * 1024);
        let mut ini = EncryptedStream::new(a, &key(), &iv(), EncryptionRole::Initiator);
        let mut res = EncryptedStream::new(b, &key(), &iv(), EncryptionRole::Responder);

        let mut payload = vec![0u8; 3 * MAX_PLAINTEXT + 123];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }

        let payload_clone = payload.clone();
        let writer = tokio::spawn(async move {
            ini.write_all(&payload_clone).await.unwrap();
            ini.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        res.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, payload);

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn bidirectional() {
        let (a, b) = duplex(64 * 1024);
        let mut ini = EncryptedStream::new(a, &key(), &iv(), EncryptionRole::Initiator);
        let mut res = EncryptedStream::new(b, &key(), &iv(), EncryptionRole::Responder);

        let t1 = tokio::spawn(async move {
            ini.write_all(b"ping").await.unwrap();
            ini.flush().await.unwrap();
            let mut buf = [0u8; 4];
            ini.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
        });
        let t2 = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            res.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            res.write_all(b"pong").await.unwrap();
            res.flush().await.unwrap();
        });
        t1.await.unwrap();
        t2.await.unwrap();
    }

    #[tokio::test]
    async fn tampered_record_is_rejected() {
        // Initiator writes one record. We intercept the ciphertext, flip a
        // bit, feed it into a responder's read half, and verify decrypt fails.
        let (mut pa, pb) = duplex(64 * 1024);
        let mut writer = EncryptedStream::new(pb, &key(), &iv(), EncryptionRole::Initiator);

        writer.write_all(b"do not tamper").await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        let mut wire = Vec::new();
        pa.read_to_end(&mut wire).await.unwrap();
        assert!(wire.len() > 2 + TAG_LEN);
        // Flip a bit inside the ciphertext (not the length header).
        let body_start = 2;
        wire[body_start] ^= 0x01;

        // Deliver tampered bytes to a responder reader.
        let (mut sender, recv_side) = duplex(64 * 1024);
        let mut reader = EncryptedStream::new(recv_side, &key(), &iv(), EncryptionRole::Responder);
        sender.write_all(&wire).await.unwrap();
        drop(sender);

        let mut sink = [0u8; 64];
        let err = reader.read(&mut sink).await.err().expect("must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn eof_before_any_record_is_error() {
        // Peer closes without sending any AEAD record (reject/drop): reader
        // must see an UnexpectedEof error, not a silent clean close.
        let (writer_side, reader_side) = duplex(64 * 1024);
        drop(writer_side); // close immediately with zero bytes
        let mut reader =
            EncryptedStream::new(reader_side, &key(), &iv(), EncryptionRole::Responder);
        let mut sink = [0u8; 64];
        let err = reader.read(&mut sink).await.err().expect("must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn eof_after_records_is_clean() {
        // Post-record boundary close is a legitimate end-of-stream.
        let (a, b) = duplex(64 * 1024);
        let mut ini = EncryptedStream::new(a, &key(), &iv(), EncryptionRole::Initiator);
        let mut res = EncryptedStream::new(b, &key(), &iv(), EncryptionRole::Responder);

        let writer = tokio::spawn(async move {
            ini.write_all(b"one record").await.unwrap();
            ini.shutdown().await.unwrap();
        });

        let mut buf = Vec::new();
        res.read_to_end(&mut buf).await.unwrap();
        assert_eq!(&buf, b"one record");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn nonce_bases_differ_per_direction() {
        // Regression check: without role-based nonce derivation, both sides
        // would write with identical nonces and (key, nonce) would collide.
        let iv = iv();
        let (a, b) = derive_nonce_bases(&iv);
        assert_ne!(a, b);
    }
}
