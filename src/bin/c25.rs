#[macro_use]
extern crate common;
extern crate base64;

use common::crypto_helper::{decrypt_ecb, crypt_ctr, BLOCK_SIZE};
use common::ops::xor;

const PLAINTEXT: &str = challenge_data!("25.txt");
const KEY: &[u8] = b"YELLOW SUBMARINE";

fn encrypt() -> (Vec<u8>, Vec<u8>) {
	let key = common::util::random_bytes(BLOCK_SIZE);

	let ecb_ct = base64::decode_config(PLAINTEXT, base64::MIME).unwrap();
	let pt = decrypt_ecb(&KEY, &ecb_ct);
	let ct = crypt_ctr(&key, 0, &pt);

	(key, ct)
}

fn edit(key: &[u8], ct: &[u8], offset: usize, new_data: &[u8]) -> Vec<u8> {
	let mut pt = crypt_ctr(&key, 0, &ct);

	assert!(offset + new_data.len() <= pt.len());

	for (a, b) in pt.iter_mut().skip(offset).zip(new_data.iter()) {
		*a = *b;
	}

	crypt_ctr(&key, 0, &pt)
}

fn main() {
	let (key, ct) = encrypt();

	let zeroes = vec![0u8; ct.len()];

	let ks = edit(&key, &ct, 0, &zeroes);

	let pt = xor(&ct, &ks);

	println!("{}", String::from_utf8_lossy(&pt));

}