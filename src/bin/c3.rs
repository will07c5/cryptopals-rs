extern crate common;
extern crate hex;

fn main() {
	let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

	let input_bytes = hex::decode(input).unwrap();
	let result = common::util::crack_1b_xor(&input_bytes).unwrap();

	println!("{:?}", result);

	let result_str = String::from_utf8(result.plaintext).unwrap();
	println!("{}", result_str);
}
