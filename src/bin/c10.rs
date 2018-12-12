#[macro_use]
extern crate common;
extern crate base64;
extern crate crypto;

use crypto::aessafe::AesSafe128Decryptor;
use crypto::symmetriccipher::BlockDecryptor;

const BLOCK_SIZE: usize = 16;
const INPUT: &str = challenge_data!("c10.txt");
const KEY: &[u8] = b"YELLOW SUBMARINE";

fn main() {
	assert_eq!(KEY.len(), BLOCK_SIZE);

	let input_bytes = base64::decode_config(INPUT, base64::MIME).unwrap();

	let decryptor = AesSafe128Decryptor::new(KEY);
	let mut plaintext = Vec::new();
	let mut prev_block = [0u8; BLOCK_SIZE];
	for input_block in input_bytes.chunks(BLOCK_SIZE) {
		let mut output = [0u8; BLOCK_SIZE];

		decryptor.decrypt_block(input_block, &mut output);

		let mut plain_block = common::ops::xor(&prev_block, &output);

		prev_block[0..].copy_from_slice(input_block);

		plaintext.append(&mut plain_block);
	}

	let plaintext_str = String::from_utf8(plaintext).unwrap();
	println!("{}", plaintext_str);

	println!("OK");
}
