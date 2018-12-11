extern crate common;
extern crate hex;

fn main() {
	let input_a = "1c0111001f010100061a024b53535009181c";
	let input_b = "686974207468652062756c6c277320657965";
	let expected = "746865206b696420646f6e277420706c6179";

	let bytes_a = hex::decode(input_a).unwrap();
	let bytes_b = hex::decode(input_b).unwrap();

	let output = common::ops::xor(&bytes_a, &bytes_b);

	let output_hex = hex::encode(&output);

	assert_eq!(output_hex, expected);

	println!("OK");
}
