extern crate common;
extern crate rand;
extern crate crypto;

use crypto::aessafe::AesSafe128Encryptor;
use crypto::symmetriccipher::BlockEncryptor;
use rand::Rng;

const BLOCK_SIZE: usize = 16;

fn encryption_oracle(input: &[u8]) -> (Vec<u8>, bool) {
	let mut rng = rand::thread_rng();
	let key = common::util::random_bytes(BLOCK_SIZE);

	let mut input_padded = Vec::new();

	input_padded.append(&mut common::util::random_bytes(5 + rng.gen::<usize>() % 5));
	input_padded.extend_from_slice(input);
	input_padded.append(&mut common::util::random_bytes(5 + rng.gen::<usize>() % 5));

	let input_final = common::ops::pkcs7_pad(&input_padded, BLOCK_SIZE);
	let encryptor = AesSafe128Encryptor::new(&key);
	let mut ciphertext = Vec::new();
	let cbc_mode;
	if rng.gen() {
		// CBC
		println!("CBC");

		// Random IV
		let mut prev_block = [0u8; BLOCK_SIZE];
		prev_block[0..].copy_from_slice(&common::util::random_bytes(BLOCK_SIZE));

		for block in 0..(input_final.len() / BLOCK_SIZE) {
			let block_start = block * BLOCK_SIZE;
			let block_end = (block + 1) * BLOCK_SIZE;
			let input_block = &input_final[block_start..block_end];
			let mut output = [0u8; BLOCK_SIZE];
			let input_block_cbc = common::ops::xor(&prev_block, &input_block);

			encryptor.encrypt_block(&input_block_cbc, &mut output);
			prev_block[0..].copy_from_slice(&output);

			ciphertext.extend_from_slice(&output);

		}

		cbc_mode = true;
	} else {
		// ECB
		println!("ECB");

		for block in 0..(input_final.len() / BLOCK_SIZE) {
			let block_start = block * BLOCK_SIZE;
			let block_end = (block + 1) * BLOCK_SIZE;
			let input_block = &input_final[block_start..block_end];
			let mut output = [0u8; BLOCK_SIZE];

			encryptor.encrypt_block(input_block, &mut output);

			ciphertext.extend_from_slice(&output);
		}

		cbc_mode = false;
	}

	(ciphertext, cbc_mode)
}


fn main() {
	let input = [1u8; 1024];
	
	for _ in 0..10 {
		let (unknown, actual_mode) = encryption_oracle(&input);
		let detect_mode = !common::util::identify_ecb(&unknown, BLOCK_SIZE);

		println!("{} {}", actual_mode, detect_mode);
		assert_eq!(actual_mode, detect_mode);
	}

	println!("OK");
}
