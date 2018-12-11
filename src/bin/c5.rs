extern crate common;
extern crate hex;

fn main() {
	let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	let key = b"ICE";
	let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

	let ciphertext = common::ops::xor_rk(input, key);

	let ciphertext_hex = hex::encode(&ciphertext);

	assert_eq!(ciphertext_hex, expected);

	println!("OK");
}
