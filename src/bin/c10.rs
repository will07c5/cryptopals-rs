#[macro_use]
extern crate common;
extern crate base64;
extern crate crypto;

use crypto::aessafe::AesSafe128Decryptor;
use crypto::symmetriccipher::BlockDecryptor;

fn main() {
	let input = challenge_data!("c10.txt");
	let key = b"YELLOW SUBMARINE";
	const block_size: usize = 16;

	assert_eq!(key.len(), block_size);

	let input_bytes = base64::decode_config(input, base64::MIME).unwrap();

	let decryptor = AesSafe128Decryptor::new(key);
	let mut plaintext = Vec::new();
	let mut prev_block = [0u8; block_size];
	for block in 0..(input_bytes.len() / block_size) {
		let block_start = block * block_size;
		let block_end = (block + 1) * block_size;
		let input_block = &input_bytes[block_start..block_end];
		let mut output = [0u8; block_size];

		decryptor.decrypt_block(input_block, &mut output);

		let mut plain_block = common::ops::xor(&prev_block, &output);

		prev_block[0..].copy_from_slice(input_block);

		plaintext.append(&mut plain_block);

	}

	let plaintext_str = String::from_utf8(plaintext).unwrap();
	println!("{}", plaintext_str);

	println!("OK");
}
