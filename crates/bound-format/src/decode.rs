//! Strict zstd decoding of blobs.
//!
//! A compressed blob must hold exactly one zstd frame and nothing else. The
//! frame's window may not exceed [`MAX_ZSTD_WINDOW`], which is checked from
//! the frame header before any memory is allocated for it; the stored bytes
//! must end exactly where the frame ends; and a truncated or malformed frame
//! is an error. Decoding is done in pure Rust (`ruzstd`), since the input is
//! untrusted.

use std::io::{self, Read, Take};

use ruzstd::decoding::{FrameDecoder, StreamingDecoder};

use crate::limits::MAX_ZSTD_WINDOW;

/// Decoder state, allocated once and reused for every blob of an artifact.
pub(crate) struct DecoderScratch {
    frame: FrameDecoder,
}

impl DecoderScratch {
    pub(crate) fn new() -> DecoderScratch {
        let mut frame = FrameDecoder::new();
        frame.set_max_window_size(MAX_ZSTD_WINDOW);
        DecoderScratch { frame }
    }
}

enum State<'s, R: Read> {
    Start(Take<R>, &'s mut FrameDecoder),
    Frame(StreamingDecoder<Take<R>, &'s mut FrameDecoder>),
    Finished,
    Failed,
}

/// Decodes the single zstd frame that fills a blob's stored bytes.
pub(crate) struct ZstdReader<'s, R: Read> {
    state: State<'s, R>,
}

impl<'s, R: Read> ZstdReader<'s, R> {
    pub(crate) fn new(src: Take<R>, scratch: &'s mut DecoderScratch) -> Self {
        ZstdReader { state: State::Start(src, &mut scratch.frame) }
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("invalid compressed data: {error}"))
}

impl<R: Read> Read for ZstdReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match std::mem::replace(&mut self.state, State::Failed) {
                State::Start(src, frame) => {
                    self.state = State::Frame(StreamingDecoder::new_with_decoder(src, frame).map_err(invalid)?);
                }
                State::Frame(mut decoder) => {
                    let n = decoder.read(buf).map_err(invalid)?;
                    if n > 0 {
                        self.state = State::Frame(decoder);
                        return Ok(n);
                    }
                    // The frame is complete; nothing may follow it.
                    if decoder.get_ref().limit() != 0 {
                        return Err(invalid("data follows the end of the zstd frame"));
                    }
                    self.state = State::Finished;
                    return Ok(0);
                }
                State::Finished => {
                    self.state = State::Finished;
                    return Ok(0);
                }
                State::Failed => return Err(invalid("decoding failed earlier")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zstd frame with one raw block holding `x`, whose window is
    /// 2^(10 + `window_exponent`) bytes.
    fn frame(window_exponent: u8) -> Vec<u8> {
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd];
        frame.push(0x00); // no content size, no checksum, no dictionary
        frame.push(window_exponent << 3);
        frame.extend_from_slice(&[0x09, 0x00, 0x00]); // last, raw, 1 byte
        frame.push(b'x');
        frame
    }

    fn decode(stored: &[u8]) -> io::Result<Vec<u8>> {
        let mut scratch = DecoderScratch::new();
        let mut out = Vec::new();
        ZstdReader::new(stored.take(stored.len() as u64), &mut scratch).read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn a_single_frame_decodes() {
        assert_eq!(decode(&frame(0)).unwrap(), b"x");
    }

    #[test]
    fn trailing_data_is_rejected() {
        let mut stored = frame(0);
        stored.push(0);
        assert!(decode(&stored).unwrap_err().to_string().contains("follows the end"));
        let twice = [frame(0), frame(0)].concat();
        assert!(decode(&twice).is_err(), "a second frame is trailing data too");
    }

    #[test]
    fn oversized_windows_are_refused_before_allocation() {
        // 2^30 bytes: far more than bound ever uses.
        let err = decode(&frame(20)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_and_malformed_frames_are_rejected() {
        let whole = frame(0);
        for cut in 0..whole.len() {
            assert!(decode(&whole[..cut]).is_err(), "cut at {cut}");
        }
        let mut bad_magic = frame(0);
        bad_magic[0] ^= 1;
        assert!(decode(&bad_magic).is_err());
    }
}
