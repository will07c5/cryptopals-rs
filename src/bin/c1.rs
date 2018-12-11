extern crate common;
extern crate base64;
extern crate hex;

fn main() {
	let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

	let bytes = hex::decode(input).unwrap();

	let output = base64::encode(&bytes);

	assert_eq!(output, expected);

	println!("OK");
}
