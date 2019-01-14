use ramp::int::Int;
use hex;

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

pub trait IntOpsExt {
	fn inv_mod(&self, n: &Int) -> Option<Int>;

	fn nth_root(&self, n: usize) -> Int;	

	fn to_bytes(&self) -> Vec<u8>;

	fn from_bytes(bytes: &[u8]) -> Int;
}

impl IntOpsExt for Int {
	// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures
	fn inv_mod(&self, n: &Int) -> Option<Int> {
		let mut t = Int::from(0);
		let mut new_t = Int::from(1);
		let mut r = n.clone();
		let mut new_r = self.clone();

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

	fn nth_root(&self, n: usize) -> Int {
		let mut x = self / &Int::from(2);
		let mut x_prev = Int::from(0);
		while x != x_prev {
			x_prev = x.clone();
			x = (&x*(n - 1) + self / (x.pow(n - 1))) / &Int::from(n);
		}

		x
	}

	// XXX dumb hack to work around ramp not having to/from_bytes methods
	// (at least that I'm aware of)
	fn to_bytes(&self) -> Vec<u8> {
		let mut hex_encoded = self.to_str_radix(16, false);
		if hex_encoded.len() % 2 != 0 {
			hex_encoded.insert(0, '0');
		}

		hex::decode(&hex_encoded).unwrap()
	}

	fn from_bytes(bytes: &[u8]) -> Int {
		Int::from_str_radix(&hex::encode(bytes), 16).unwrap()
	}
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_inv_mod() {
    }
}
