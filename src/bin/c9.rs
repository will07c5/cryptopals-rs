extern crate common;

fn main() {
	let input = b"YELLOW SUBMARINE";
	let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
	let pad_len = 20;

	let output = common::ops::pkcs7_pad(input, pad_len);

	assert_eq!(&expected, &output.as_slice());

	println!("OK");
}
