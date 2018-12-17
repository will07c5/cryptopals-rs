use rand;
use rand::Rng;
use std::fmt::Write;

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
			8.167,
			1.492,
			2.782,
			4.253,
			12.702,
			2.228,
			2.015,
			6.094,
			6.966,
			0.153,
			0.772,
			4.025,
			2.406,
			6.749,
			7.507,
			1.929,
			0.095,
			5.987,
			6.327,
			9.056,
			2.758,
			0.978,
			2.360,
			0.150,
			1.974,
			0.074
		];
	let mut bucket_count: [usize; 26] = [0; 26];
	let mut score: f64 = 0.0;
	let mut letter_count: usize = 0;
	let mut total_count: usize = 0;

	for b in data.iter() {
		match *b {
		// control character excluding CR, LF, TAB
		0..=8 | 11..=12 | 14..=31 => score += 1000.0,
		9 | 10 | 13 => (),
		// A-Z
		b'A'..=b'Z' => { bucket_count[(*b as usize) - 65] += 1; letter_count += 1; },
		// a-z
		b'a'..=b'z' => { bucket_count[(*b as usize) - 97] += 1; letter_count += 1; },
		b' ' => total_count += 1,

		// XXX unscientific scores for numbers and punctuation
		// b'#' => score += 10.0,
		// b'=' => score += 10.0,
		// b'%' => score += 10.0,
		// b'{' => score += 100.0,
		// b'}' => score += 100.0,
		// b'|' => score += 100.0,
		// b'<' => score += 100.0,
		// b'>' => score += 100.0,
		// b'*' => score += 100.0,
		// b'/' => score += 100.0,
		// b'^' => score += 100.0,
		// b'+' => score += 100.0,
		// b'`' => score += 100.0,
		// b'(' => score += 10.0,
		// b')' => score += 10.0,

		// anything over 128 is pretty obviously bogus
		128..=255 => score += 100000.0,

		_ => (),
		}
	}

	total_count += letter_count;

	let bucket: Vec<_> =
		bucket_count
		.iter()
		.map(|c| *c as f64 / letter_count as f64 * 100.0)
		.collect();

	score += (data.len() - total_count) as f64 * 10.0;

	if letter_count > 0 {
		score += bucket.iter().zip(bucket_expected.iter()).fold(0.0, |a, (b, e)| a + (b - e).abs());
	}

	score as usize
}

pub fn crack_1b_xor(ciphertext: &[u8]) -> Option<Crack1BResult> {
	let mut scores = Vec::new();

	for key in 0..=255 {
		let plaintext = ops::xor_1b(ciphertext, key);

		let score = score_ascii_bytes(&plaintext);

		scores.push(Crack1BResult { plaintext, score, key })
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

pub fn print_hex(buf: &[u8]) {
	let mut cur = 0;
	let mut output = String::new();
	while cur < buf.len() {
		for i in 0..16 {
			if cur + i < buf.len() {
				let b = buf[cur + i];

				write!(&mut output, "{:2X} ", b).unwrap();
			} else {
				write!(&mut output, "   ").unwrap();
			}
		}

		for i in 0..16 {

			if cur + i < buf.len() {
				let b = buf[cur + i];

				if b < 128 {
					let c = b as char;

					if c.is_ascii_control() {
						output.push('.');
					} else {
						output.push(c);
					}
				} else {
					output.push('.');
				}
			} else {
				output.push(' ');
			}
		}

		output.push('\n');

		cur += 16;
	}

	print!("{}", output);
}