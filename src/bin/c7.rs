#[macro_use]
extern crate common;
extern crate base64;
extern crate crypto;

use crypto::aessafe::AesSafe128Decryptor;
use crypto::symmetriccipher::BlockDecryptor;

fn main() {
	let input = challenge_data!("c7.txt");
	let key = b"YELLOW SUBMARINE";
	let block_size = 16;

	assert_eq!(key.len(), block_size);

	let input_bytes = base64::decode_config(input, base64::MIME).unwrap();

	let decryptor = AesSafe128Decryptor::new(key);
	let mut plaintext = Vec::new();
	for block in 0..(input_bytes.len() / block_size) {
		let block_start = block * block_size;
		let block_end = (block + 1) * block_size;
		let input_block = &input_bytes[block_start..block_end];
		let mut output = [0u8; 16];

		decryptor.decrypt_block(input_block, &mut output);

		plaintext.extend_from_slice(&output);
	}

	let plaintext_str = String::from_utf8(plaintext).unwrap();
	println!("{}", plaintext_str);

	println!("OK");
}
