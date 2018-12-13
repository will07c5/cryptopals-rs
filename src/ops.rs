
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
	a.iter().zip(b.iter()).map(|(ab, bb)| ab ^ bb).collect()
}

pub fn xor_1b(a: &[u8], b: u8) -> Vec<u8> {
	a.iter().map(|x| x ^ b).collect()
}

pub fn xor_rk(a: &[u8], b: &[u8]) -> Vec<u8> {
	a.iter().zip(b.iter().cycle()).map(|(ab, bb)| ab ^ bb
		).collect()
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
