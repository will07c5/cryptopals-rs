use std::u8;

pub fn pkcs7_pad(a: &[u8], block_size: usize) -> Vec<u8> {
    let out_pad = block_size - a.len() % block_size;
    let mut out = Vec::with_capacity(a.len() + out_pad);

    out.extend_from_slice(a);

    assert!(out_pad <= u8::MAX as usize);

    out.extend((0..out_pad).map(|_| out_pad as u8));

    out
}

fn pkcs7_validate_internal(a: &[u8], block_size: usize) -> Option<u8> {
    assert_eq!(a.len() % block_size, 0);

    let pad_count = a[a.len() - 1] as usize;

    if pad_count > block_size {
        return None;
    }

    let pad_bytes = &a[a.len() - pad_count..];

    for b in pad_bytes {
        if *b as usize != pad_count {
            return None;
        }
    }

    Some(pad_count as u8)  
}

pub fn pkcs7_validate(a: &[u8], block_size: usize) -> bool {
    match pkcs7_validate_internal(a, block_size) {
        Some(_) => true,
        None => false,
    }
}

pub fn pkcs7_strip(a: &[u8], block_size: usize) -> Option<Vec<u8>> {
    let pad_count = match pkcs7_validate_internal(a, block_size) {
        Some(x) => x,
        None => return None,
    };

    Some((&a[..a.len() - pad_count as usize]).to_vec())
}

#[cfg(test)]
mod tests {
    #[test]
    fn pkcs7_pad_test() {
        assert_eq!(b"DATA\x04\x04\x04\x04", super::pkcs7_pad(b"DATA", 4).as_slice());
        assert_eq!(b"DATAD\x03\x03\x03", super::pkcs7_pad(b"DATAD", 4).as_slice());
        assert_eq!(b"DATADA\x02\x02", super::pkcs7_pad(b"DATADA", 4).as_slice());
        assert_eq!(b"DATADAT\x01", super::pkcs7_pad(b"DATADAT", 4).as_slice());
    }

    #[test]
    fn pkcs7_validate_test() {
        assert_eq!(super::pkcs7_validate(b"DATA\x04\x04\x04\x04", 4), true);
        assert_eq!(super::pkcs7_validate(b"DATA\x05\x04\x04\x04", 4), false);
        assert_eq!(super::pkcs7_validate(b"DATA\x04\x04\x04\x05", 4), false);
        assert_eq!(super::pkcs7_validate(b"DATA\x04\x04\x04\x03", 4), false);
    }

    #[test]
    fn pkcs7_strip_test() {
        assert_eq!(super::pkcs7_strip(b"DATA\x04\x04\x04\x04", 4), Some(b"DATA".to_vec()));
        assert_eq!(super::pkcs7_strip(b"DATA\x05\x04\x04\x04", 4), None);
        assert_eq!(super::pkcs7_strip(b"DATA\x04\x04\x04\x05", 4), None);
        assert_eq!(super::pkcs7_strip(b"DATA\x04\x04\x04\x03", 4), None);
    }
}