#[macro_use]
extern crate common;
extern crate hex;

fn main() {
	let input = challenge_data!("c4.txt");
	let mut scores = Vec::new();

	for line in input.lines() {
		let bytes = hex::decode(line).unwrap();
		
		let result = match common::util::crack_1b_xor(&bytes) {
			Some(x) => x,
			None => continue,
		};

		scores.push(result);
	}

	scores.sort_by_key(|k| { k.score });

	println!("{:?}", scores[0]);

	let plain_str = String::from_utf8(scores[0].plaintext.clone()).unwrap();

	println!("{}", plain_str);
	
	println!("OK");
}
