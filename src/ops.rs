use ramp::int::Int;

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

// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures

pub fn inv_mod(a: &Int, n: &Int) -> Option<Int> {
	let mut t = Int::from(0);
	let mut new_t = Int::from(1);
	let mut r = n.clone();
	let mut new_r = a.clone();

	while new_r != 0 {
		let quotient = &r / &new_r;
		let saved_t = new_t.clone();
		new_t = &t - &quotient * &new_t;
		t = saved_t;

		let saved_r = new_r.clone();
		new_r = &r - &quotient * &new_r;
		r = saved_r;
	}

	if r > 1 {
		None
	} else if t < 0 {
		Some(t + n)
	} else {
		Some(t)
	}
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_inv_mod() {
    	assert_eq!(super::inv_mod_u64(17, 3120), Some(2753));
    }
}
