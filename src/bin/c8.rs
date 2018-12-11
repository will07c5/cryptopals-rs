#[macro_use]
extern crate common;
extern crate hex;

fn main() {
	let input = challenge_data!("c8.txt");
	let block_size = 16;

	let mut found = None;

	'outer: for (line_num, line) in input.lines().enumerate() {
		let bytes = hex::decode(line).unwrap();
		let block_count = bytes.len() / block_size;
		assert_eq!(block_count * block_size, bytes.len());

		for block1 in 0..(block_count-1) {
			for block2 in (block1+1)..block_count {
				let block1_start = block1 * block_size;
				let block1_end = (block1 + 1) * block_size;
				let block2_start = block2 * block_size;
				let block2_end = (block2 + 1) * block_size;

				if &bytes[block1_start..block1_end] == &bytes[block2_start..block2_end] {
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
