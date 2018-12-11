use rand;
use rand::Rng;

use crate::ops;

#[derive(Clone, Debug)]
pub struct Crack1BResult {
	pub plaintext: Vec<u8>,
	pub score: usize,
	pub key: u8,
}

// XXX I don't really love this but it seems to work
pub fn score_ascii_bytes(data: &[u8]) -> usize{
	let bucket_expected: [f64; 26] =
		[
			8.167 / 100.0,
			1.492 / 100.0,
			2.782 / 100.0,
			4.253 / 100.0,
			12.702 / 100.0,
			2.228 / 100.0,
			2.015 / 100.0,
			6.094 / 100.0,
			6.966 / 100.0,
			0.153 / 100.0,
			0.772 / 100.0,
			4.025 / 100.0,
			2.406 / 100.0,
			6.749 / 100.0,
			7.507 / 100.0,
			1.929 / 100.0,
			0.095 / 100.0,
			5.987 / 100.0,
			6.327 / 100.0,
			9.056 / 100.0,
			2.758 / 100.0,
			0.978 / 100.0,
			2.360 / 100.0,
			0.150 / 100.0,
			1.974 / 100.0,
			0.074 / 100.0
		];
	let mut bucket: [f64; 26] = [0.0; 26];
	let mut score: f64 = 0.0;
	let mut count: f64 = 0.0;

	for b in data.iter() {
		match *b {
		// control character excluding CR, LF, TAB
		0..=8 | 11..=12 | 14..=31 => score += 1000.0,
		9 | 10 | 13 => (),
		// A-Z
		b'A'..=b'Z' => { bucket[(*b as usize) - 65] += 1.0; count += 1.0; },
		// a-z
		b'a'..=b'z' => { bucket[(*b as usize) - 97] += 1.0; count += 1.0; },

		// XXX unscientific scores for numbers and punctuation
		b'#' => score += 10.0,
		b'=' => score += 10.0,
		b'%' => score += 10.0,
		b'{' => score += 100.0,
		b'}' => score += 100.0,
		b'|' => score += 100.0,
		b'<' => score += 100.0,
		b'>' => score += 100.0,
		b'*' => score += 100.0,

		// anything over 128 is pretty obviously bogus
		128..=255 => score += 100000.0,

		_ => (),
		}
	}

	if count > 0.0 {
		for (b, e) in bucket.iter().zip(bucket_expected.iter()) {
			let bn = b / count as f64;

			score += (bn - e).abs() * 100.0;
		}
	}

	score as usize
}

pub fn crack_1b_xor(ciphertext: &[u8]) -> Option<Crack1BResult> {
	let mut scores = Vec::new();

	for i in 0..=255 {
		let test_plain_bytes = ops::xor_1b(ciphertext, i);

		let score = score_ascii_bytes(&test_plain_bytes);

		scores.push(Crack1BResult { plaintext: test_plain_bytes, score: score, key: i })
	}

	scores.sort_by_key(|k| { k.score });

	if scores.len() > 0 {
		Some(scores[0].clone())
	} else {
		None
	}
}

pub fn random_bytes(count: usize) -> Vec<u8> {
	let mut rng = rand::thread_rng();

	(0..count).map(|_| rng.gen::<u8>()).collect()
}

pub fn identify_ecb(ciphertext: &[u8], block_size: usize) -> bool {
	let block_count = ciphertext.len() / block_size;
	for block1 in 0..(block_count - 1) {
		for block2 in (block1 + 1)..block_count {
			let block1_start = block1 * block_size;
			let block1_end = (block1 + 1) * block_size;
			let block2_start = block2 * block_size;
			let block2_end = (block2 + 1) * block_size;

			if &ciphertext[block1_start..block1_end] == &ciphertext[block2_start..block2_end] {
				return true;
			}
		}
	}

	false
}
