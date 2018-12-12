#[macro_use]
extern crate common;
extern crate base64;
extern crate crypto;

use crypto::aessafe::AesSafe128Decryptor;
use crypto::symmetriccipher::BlockDecryptor;

const BLOCK_SIZE: usize = 16;

fn main() {
	let input = challenge_data!("c7.txt");
	let key = b"YELLOW SUBMARINE";

	assert_eq!(key.len(), BLOCK_SIZE);

	let input_bytes = base64::decode_config(input, base64::MIME).unwrap();

	let decryptor = AesSafe128Decryptor::new(key);
	let mut plaintext = Vec::new();
	for input_block in input_bytes.chunks(BLOCK_SIZE) {
		let mut output = [0u8; 16];

		decryptor.decrypt_block(input_block, &mut output);

		plaintext.extend_from_slice(&output);
	}

	let plaintext_str = String::from_utf8(plaintext).unwrap();
	println!("{}", plaintext_str);

	println!("OK");
}
