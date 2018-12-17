extern crate common;

use common::sha1::{sha1_digest, HASH_SIZE};
use std::io::Write;

fn auth_internal(key: &[u8], msg: &[u8]) -> Vec<u8> {
	let mut sha_input = Vec::new();

	sha_input.extend_from_slice(&key);
	sha_input.extend_from_slice(&msg);

	sha1_digest(&sha_input)
}

fn create(msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
	let key = common::util::random_bytes(10);
	let sha = auth_internal(&key, &msg);

	let mut out = Vec::new();
	out.write_all(&sha).unwrap();
	out.write_all(&msg).unwrap();

	(key, out)
}

fn verify(key: &[u8], auth_msg: &[u8]) -> bool {
	let auth = &auth_msg[..HASH_SIZE];
	let msg = &auth_msg[HASH_SIZE..];

	let verify_auth = auth_internal(&key, &msg);

	auth.to_vec() == verify_auth
}

fn main() {
	let msg = b"this is a message";

	let (key, auth_msg) = create(msg);

	// Untampered message
	assert_eq!(verify(&key, &auth_msg), true);

	// Make sure tampering with hash fails
	let mut tamper_hash = auth_msg.clone();
	tamper_hash[0] ^= 0x1;
	assert_eq!(verify(&key, &tamper_hash), false);

	// Make sure tampering with message fails
	let mut tamper_msg = auth_msg.clone();
	tamper_msg[HASH_SIZE + 2] ^= 0x1;
	assert_eq!(verify(&key, &tamper_msg), false);

	println!("OK");
}