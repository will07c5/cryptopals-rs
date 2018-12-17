#[macro_use]
extern crate common;
extern crate hex;

const BLOCK_SIZE: usize = 16;

fn main() {
	let input = challenge_data!("c8.txt");

	let mut found = None;

	'outer: for (line_num, line) in input.lines().enumerate() {
		let bytes = hex::decode(line).unwrap();
		assert_eq!(bytes.len() % BLOCK_SIZE, 0);

		for (chunk_idx, block1) in bytes.chunks(BLOCK_SIZE).enumerate() {
			for block2 in bytes[(chunk_idx + 1) * BLOCK_SIZE..].chunks(BLOCK_SIZE) {
				if block1 == block2 {
					println!("Line = {}", line_num);
					assert_eq!(found, None);
					found = Some(line);
					continue 'outer;
				}
			}
		}
	}

	println!("{:?}", found);

	println!("OK");
}
