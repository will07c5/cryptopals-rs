use std::u8;

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
	assert_eq!(a.len(), b.len());

	let mut out = Vec::with_capacity(a.len());

	for (ab, bb) in a.iter().zip(b.iter()) {
		out.push(ab ^ bb);
	}

	out
}

pub fn xor_1b(a: &[u8], b: u8) -> Vec<u8> {
	a.iter().map(|x| x ^ b).collect()
}

pub fn xor_rk(a: &[u8], b: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(a.len());

	for (idx, ab) in a.iter().enumerate() {
		let bb = b[idx % b.len()];

		out.push(ab ^ bb);
	}

	out
}

pub fn hamming_dist(a: &[u8], b: &[u8]) -> Result<usize, ()> {
	if a.len() != b.len() {
		Err(())
	} else {
		let mut dist = 0;

		for (ai, bi) in a.iter().zip(b.iter()) {
			for bit in 0..=7 {
				if ((ai >> bit) & 1u8) != ((bi >> bit) & 1u8) {
					dist += 1;
				}
			}
		}

		Ok(dist)
	}
}

pub fn hamming_dist_str(a: String, b: String) -> Result<usize, ()> {
	hamming_dist(&a.into_bytes(), &b.into_bytes())
}

pub fn pkcs7_pad(a: &[u8], block_size: usize) -> Vec<u8> {
	let out_pad = block_size - a.len() % block_size;
	let mut out = Vec::with_capacity(a.len() + out_pad);

	out.extend_from_slice(a);

	assert!(out_pad <= u8::MAX as usize);

	out.extend((0..out_pad).map(|_| out_pad as u8));

	out
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
}