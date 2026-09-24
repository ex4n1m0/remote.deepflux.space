//! Annex-B byte-stream helpers (pure, unit-testable).
//!
//! The MF H.264 encoders emit Annex-B (start-code prefixed NAL units) and
//! the decoders accept it, so the M1 loop is a direct byte passthrough —
//! these helpers only classify packets (keyframe detection for counters
//! and for the renderer's "wait for IDR after reset" logic).

/// Iterate `(nal_type, offset, len)` over an Annex-B stream. NAL type is
/// the low 5 bits of the first byte after the start code.
pub fn annex_b_nal_types(bytes: &[u8]) -> Vec<(u8, usize, usize)> {
    let mut nals = Vec::new();
    let mut i = 0usize;
    // find first start code
    let starts = |i: usize| -> Option<(usize, usize)> {
        // returns (payload_start, start_code_len)
        if i + 3 < bytes.len() && bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1 {
            Some((i + 3, 3))
        } else if i + 4 < bytes.len()
            && bytes[i] == 0
            && bytes[i + 1] == 0
            && bytes[i + 2] == 0
            && bytes[i + 3] == 1
        {
            Some((i + 4, 4))
        } else {
            None
        }
    };
    while i < bytes.len() {
        match starts(i) {
            Some((payload, _len)) => {
                // scan for the next start code
                let mut j = payload;
                let mut end = bytes.len();
                while j + 2 < bytes.len() {
                    if bytes[j] == 0
                        && bytes[j + 1] == 0
                        && (bytes[j + 2] == 1
                            || (bytes[j + 2] == 0 && j + 3 < bytes.len() && bytes[j + 3] == 1))
                    {
                        end = j;
                        break;
                    }
                    j += 1;
                }
                if payload < bytes.len() {
                    let nal_type = bytes[payload] & 0x1F;
                    nals.push((nal_type, payload, end.saturating_sub(payload)));
                }
                i = end;
            }
            None => i += 1,
        }
    }
    nals
}

/// True when the stream contains an IDR slice (NAL type 5). SPS (7) is
/// typically present in the same access unit.
pub fn annex_b_is_keyframe(bytes: &[u8]) -> bool {
    annex_b_nal_types(bytes).iter().any(|(t, _, _)| *t == 5)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn au(nals: &[(u8, &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        for (t, payload) in nals {
            v.extend_from_slice(&[0, 0, 0, 1, *t]);
            v.extend_from_slice(payload);
        }
        v
    }

    #[test]
    fn parses_sps_pps_idr() {
        // SPS(7) + PPS(8) + IDR(5) with 3-byte start codes.
        let mut v = vec![0, 0, 1, 0x67, 0xAA];
        v.extend_from_slice(&[0, 0, 1, 0x68, 0xBB]);
        v.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x11, 0x22]);
        let nals = annex_b_nal_types(&v);
        assert_eq!(nals.len(), 3);
        assert_eq!(nals[0].0, 7);
        assert_eq!(nals[1].0, 8);
        assert_eq!(nals[2].0, 5);
        assert_eq!(nals[2].2, 3); // 0x65 + 2 payload bytes
        assert!(annex_b_is_keyframe(&v));
    }

    #[test]
    fn non_idr_is_not_keyframe() {
        let v = au(&[(6, &[0xEE]), (1, &[0x00, 0x00, 0x03])]);
        assert!(!annex_b_is_keyframe(&v));
    }

    #[test]
    fn garbage_yields_nothing_and_no_panic() {
        assert!(annex_b_nal_types(&[]).is_empty());
        assert!(annex_b_nal_types(&[0, 0, 0, 0]).is_empty());
        assert!(annex_b_nal_types(&[0xFF; 33]).is_empty());
        // start code at the very end: no payload byte.
        assert!(annex_b_nal_types(&[0, 0, 1]).is_empty());
    }
}
