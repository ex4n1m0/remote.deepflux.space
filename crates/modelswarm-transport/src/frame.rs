//! Length-prefixed JSON frames over tokio I/O (ADR-018 staging).
//!
//! Wire format: a `u32` big-endian length prefix followed by that many bytes
//! of JSON payload. The declared length is validated against
//! [`MAX_FRAME_BYTES`] **before** the body is read or allocated, so a
//! hostile length prefix can never force a huge buffer or a body read.
//!
//! The deadline-aware wrappers ([`read_frame`], [`write_frame`]) bound every
//! operation with `tokio::time::timeout`; the `_raw` variants are used by the
//! session's reader/writer tasks, which are bounded by the session shutdown
//! signal instead.

use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::FrameError;

/// Maximum frame size: 256 KiB (msp-v1 §6.4 "max frames 256 KiB").
///
/// The cap applies to the JSON payload announced by the length prefix; the
/// 4-byte prefix itself is not counted.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Reads one frame, bounded by `deadline`.
pub async fn read_frame<R>(reader: &mut R, deadline: Duration) -> Result<Bytes, FrameError>
where
    R: AsyncReadExt + Unpin,
{
    match tokio::time::timeout(deadline, read_frame_raw(reader)).await {
        Ok(result) => result,
        Err(_) => Err(FrameError::Timeout),
    }
}

/// Reads one frame with no deadline (session reader task internal use).
///
/// Ordering guarantee: the length prefix is read, validated against
/// [`MAX_FRAME_BYTES`], and only then is the body buffer allocated and read.
pub async fn read_frame_raw<R>(reader: &mut R) -> Result<Bytes, FrameError>
where
    R: AsyncReadExt + Unpin,
{
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 {
        return Err(FrameError::Io(crate::error::invalid_data(
            "frame rejected",
            "zero-length payload",
        )));
    }
    if len > MAX_FRAME_BYTES {
        // Refuse BEFORE reading (or allocating for) the body.
        return Err(FrameError::TooLarge);
    }
    let mut body = BytesMut::zeroed(len);
    reader.read_exact(&mut body).await?;
    Ok(body.freeze())
}

/// Writes one frame, bounded by `deadline`.
pub async fn write_frame<W>(
    writer: &mut W,
    payload: &[u8],
    deadline: Duration,
) -> Result<(), FrameError>
where
    W: AsyncWriteExt + Unpin,
{
    match tokio::time::timeout(deadline, write_frame_raw(writer, payload)).await {
        Ok(result) => result,
        Err(_) => Err(FrameError::Timeout),
    }
}

/// Writes one frame with no deadline (session writer task internal use).
pub async fn write_frame_raw<W>(writer: &mut W, payload: &[u8]) -> Result<(), FrameError>
where
    W: AsyncWriteExt + Unpin,
{
    if payload.len() > u32::MAX as usize {
        return Err(FrameError::TooLarge);
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut buf = BytesMut::with_capacity(4 + payload.len());
    buf.put_u32(payload.len() as u32);
    buf.put_slice(payload);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut a, mut b) = duplex(1024);
        write_frame(&mut a, br#"{"x":1}"#, Duration::from_secs(5))
            .await
            .unwrap();
        let payload = read_frame(&mut b, Duration::from_secs(5)).await.unwrap();
        assert_eq!(&payload[..], br#"{"x":1}"#);
    }

    #[tokio::test]
    async fn oversized_payload_is_refused_without_writing() {
        let (mut a, mut b) = duplex(1024);
        let huge = vec![b'x'; MAX_FRAME_BYTES + 1];
        let err = write_frame(&mut a, &huge, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::TooLarge));
        // Nothing was written: the peer sees EOF, not a huge frame.
        drop(a);
        let mut sink = Vec::new();
        use tokio::io::AsyncReadExt as _;
        let n = b.read_to_end(&mut sink).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn oversized_prefix_is_refused_before_body_read() {
        let (mut a, mut b) = duplex(64);
        // Announce an oversized frame and send nothing else.
        a.write_all(&(MAX_FRAME_BYTES as u32 + 1).to_be_bytes())
            .await
            .unwrap();
        a.flush().await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(2), read_frame_raw(&mut b))
            .await
            .expect("must not wait for the body")
            .unwrap_err();
        assert!(matches!(err, FrameError::TooLarge));
    }

    #[tokio::test]
    async fn zero_length_prefix_is_rejected() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&0u32.to_be_bytes()).await.unwrap();
        a.flush().await.unwrap();
        let err = read_frame_raw(&mut b).await.unwrap_err();
        assert!(
            matches!(err, FrameError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData)
        );
    }

    #[tokio::test]
    async fn read_deadline_expires() {
        let (_a, mut b) = duplex(64);
        let err = read_frame(&mut b, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::Timeout));
    }
}
