use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 4] = b"CGDP";
const VERSION: u8 = 1;

#[derive(Clone, Debug)]
pub struct IoDumpFrame {
    pub connect_timestamp_ms: u64,
    pub write_timestamp_ms: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub upload: Vec<u8>,
    pub download: Vec<u8>,
}

impl IoDumpFrame {
    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    pub fn encode(&self) -> Vec<u8> {
        let src = self.src_ip.as_bytes();
        let dst = self.dst_ip.as_bytes();
        let payload_len =
            8 + 8 + 2 + src.len() + 2 + dst.len() + 4 + self.upload.len() + 4 + self.download.len();
        let frame_len = 4 + 1 + 4 + payload_len;
        let mut buf = Vec::with_capacity(frame_len);

        buf.extend_from_slice(MAGIC);
        buf.push(VERSION);
        buf.extend_from_slice(&(frame_len as u32).to_le_bytes());
        buf.extend_from_slice(&self.connect_timestamp_ms.to_le_bytes());
        buf.extend_from_slice(&self.write_timestamp_ms.to_le_bytes());

        let src_len = u16::try_from(src.len()).unwrap_or(u16::MAX);
        buf.extend_from_slice(&src_len.to_le_bytes());
        buf.extend_from_slice(&src[..usize::from(src_len)]);

        let dst_len = u16::try_from(dst.len()).unwrap_or(u16::MAX);
        buf.extend_from_slice(&dst_len.to_le_bytes());
        buf.extend_from_slice(&dst[..usize::from(dst_len)]);

        let upload_len = u32::try_from(self.upload.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&upload_len.to_le_bytes());
        buf.extend_from_slice(&self.upload[..upload_len as usize]);

        let download_len = u32::try_from(self.download.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&download_len.to_le_bytes());
        buf.extend_from_slice(&self.download[..download_len as usize]);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::IoDumpFrame;

    #[test]
    fn test_frame_encode_has_header() {
        let frame = IoDumpFrame {
            connect_timestamp_ms: 1,
            write_timestamp_ms: 2,
            src_ip: "127.0.0.1:1".to_string(),
            dst_ip: "127.0.0.1:2".to_string(),
            upload: vec![1, 2, 3],
            download: vec![4, 5],
        };
        let encoded = frame.encode();
        assert!(encoded.len() > 16);
        assert_eq!(&encoded[0..4], b"CGDP");
        assert_eq!(encoded[4], 1);
    }
}
