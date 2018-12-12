extern crate common;
//extern crate percent_encoding;
extern crate crypto;

use crypto::aessafe::{AesSafe128Encryptor, AesSafe128Decryptor};
use crypto::symmetriccipher::{BlockEncryptor, BlockDecryptor};
use common::pkcs7::pkcs7_pad;
//use percent_encoding::{percent_decode, utf8_percent_encode, DEFAULT_ENCODE_SET};

const BLOCK_SIZE: usize = 16;

fn decode_kv(data: &str) -> Option<Vec<(String, String)>> {
	let mut out = Vec::new();

	for kv in data.split('&') {
		let eq_pos = match kv.find('=') {
			Some(x) => x,
			None => return None
		};

		let key = &kv[0..eq_pos];

		let value = &kv[(eq_pos+1)..kv.len()];

		// We'd check here for invalid characters but whatever

		out.push((key.to_string(), value.to_string()));
	}

	Some(out)
}

fn encode_kv(kv: Vec<(String, String)>) -> String {
	let mut out = String::new();

	for (i, kv) in kv.iter().enumerate() {
		let (ref key, ref val) = *kv;
		if i > 0 {
			out.push('&');
		}

		out.push_str(&key);
		out.push('=');
		out.push_str(&val);
	}

	out
}

fn profile_for(user: &str, uid: usize) -> String {
	let mut profile = Vec::new();
	profile.push(("email".to_string(), user.to_string()));
	profile.push(("uid".to_string(), uid.to_string()));
	profile.push(("role".to_string(), "user".to_string()));

	encode_kv(profile)
}

fn encrypt_profile(profile: &str, key: &[u8]) -> Vec<u8> {
	let input = pkcs7_pad(profile.as_bytes(), BLOCK_SIZE);
	let mut output = Vec::with_capacity(input.len());

	let encryptor = AesSafe128Encryptor::new(key);
	for block in 0..(input.len() / BLOCK_SIZE) {
		let block_start = block * BLOCK_SIZE;
		let block_end = (block + 1) * BLOCK_SIZE;
		let input_block = &input[block_start..block_end];
		let mut output_block = [0u8; BLOCK_SIZE];

		encryptor.encrypt_block(&input_block, &mut output_block);

		output.extend_from_slice(&output_block);
	}

	output
}

fn decrypt_profile(profile: &[u8], key: &[u8]) -> Option<Vec<(String, String)>> {
	assert!((profile.len() % BLOCK_SIZE) == 0);
	let mut output = Vec::with_capacity(profile.len());

	let decryptor = AesSafe128Decryptor::new(key);
	for block in 0..(profile.len() / BLOCK_SIZE) {
		let block_start = block * BLOCK_SIZE;
		let block_end = (block + 1) * BLOCK_SIZE;
		let input_block = &profile[block_start..block_end];
		let mut output_block = [0u8; BLOCK_SIZE];

		decryptor.decrypt_block(&input_block, &mut output_block);

		output.extend_from_slice(&output_block);
	}

	decode_kv(&String::from_utf8(output).unwrap())
}

fn main() {
	let key = common::util::random_bytes(BLOCK_SIZE); // NO PEEKING

	// First:
	// 0123456789ABCDEF 0123456789ABCDEF
	// email=aaaaaaaaaa admin???????????
	// Second:
	// email=aaaaaa@bs. com&uid=10&role=
	// Combined:
	// email=aaaaaa@bs. com&uid=10&role= admin???????????
	//
	// ? = PKCS padding = 11 = 0xb
	let exploit_string = "aaaaaaaaaaadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b@bs.com";
	let exploit_profile = profile_for(exploit_string, 10);
	println!("{}", exploit_profile);

	let exploit_string2 = "aaaaaa@bs.com";
	let exploit_profile2 = profile_for(exploit_string2, 11);
	println!("{}", exploit_profile2);

	let exploit_enc = encrypt_profile(&exploit_profile, &key);
	let exploit_enc2 = encrypt_profile(&exploit_profile2, &key);
	
	let mut admin_enc = Vec::new();
	admin_enc.extend_from_slice(&exploit_enc2[0..(BLOCK_SIZE*2)]);
	admin_enc.extend_from_slice(&exploit_enc[BLOCK_SIZE..(BLOCK_SIZE*2)]);

	let admin_profile = decrypt_profile(&admin_enc, &key).unwrap();
	println!("{:?}", admin_profile);

	println!("OK");
}

#[test]
fn test_decode() {
	let data = "foo=bar&baz=qux&zap=zazzle";

	let decoded = decode_kv(data).unwrap();
	println!("{:?}", decoded);

	assert_eq!(decoded[0], ("foo".to_string(), "bar".to_string()));
	assert_eq!(decoded[1], ("baz".to_string(), "qux".to_string()));
	assert_eq!(decoded[2], ("zap".to_string(), "zazzle".to_string()));
}

#[test]
fn test_encode() {
	let data = vec![
		("email".to_string(), "foo@bar.com".to_string()),
		("uid".to_string(), "10".to_string()),
		("role".to_string(), "user".to_string())
		];

	let encoded = encode_kv(data);
	assert_eq!(encoded, "email=foo@bar.com&uid=10&role=user");
}
