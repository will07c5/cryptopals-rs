#[macro_use]
extern crate common;
extern crate base64;

fn score_key_size(ciphertext: &[u8], size: usize) -> Option<usize> {
	if ciphertext.len() < 2*size {
		None
	} else {
		let mut total = 0;
		for i in 0..(ciphertext.len()/size - 1) {
			let dist = common::ops::hamming_dist(&ciphertext[(i*size)..((i+1)*size)], &ciphertext[((i+1)*size)..((i+2)*size)]).unwrap();
			total += dist;
		}
		total /= ciphertext.len()/size - 1;

		Some(total / size)
	}
}

fn main() {
	let input = challenge_data!("c6.txt");
	let input_bytes = base64::decode_config(input, base64::MIME).unwrap();

	let mut ks_scores = Vec::new();
	for size in 2..40 {
		ks_scores.push((score_key_size(&input_bytes, size).unwrap(), size));
	}

	ks_scores.sort_by_key(|k| { let (s, _) = *k; s });

	for (_, s) in (0..1).zip(ks_scores.iter()) {
		let (_, size) = *s;
		println!("Trying key size = {}", size);

		let mut blocks = Vec::new();
		for _ in 0..size {
			blocks.push(Vec::new());
		}

		let mut idx = 0;
		for b in input_bytes.iter() {
			blocks[idx % size].push(*b);
			idx += 1;
		}

		let mut key = Vec::new();
		for block in blocks.iter() {
			let result = match common::util::crack_1b_xor(block.as_slice()) {
				Some(x) => x,
				None => continue,
			};
			key.push(result.key);
		}

		let plaintext = common::ops::xor_rk(&input_bytes, &key);
		match String::from_utf8(plaintext) {
				Ok(x) => println!("plaintext: {}", x),
				Err(_) => println!("didn't decode"),
			};
	}

	println!("OK");
}
