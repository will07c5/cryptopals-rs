extern crate common;
extern crate crypto;
extern crate base64;

use crypto::aessafe::AesSafe128Encryptor;
use crypto::symmetriccipher::BlockEncryptor;
use std::u8;
use common::pkcs7::pkcs7_pad;

const BLOCK_SIZE: usize = 16;

fn encryption_oracle(chosen: &[u8], key: &[u8]) -> Vec<u8> {
	let super_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	let super_secret_bytes = base64::decode(super_secret).unwrap();
	let mut input = Vec::new();
	let mut output = Vec::new();

	input.extend_from_slice(chosen);
	input.extend(super_secret_bytes.iter());

	let input_final = pkcs7_pad(&input, BLOCK_SIZE);

	assert_eq!(key.len(), BLOCK_SIZE);

	let encryptor = AesSafe128Encryptor::new(key);
	for block in 0..(input_final.len() / BLOCK_SIZE) {
		let block_start = block * BLOCK_SIZE;
		let block_end = (block + 1) * BLOCK_SIZE;
		let input_block = &input_final[block_start..block_end];
		let mut output_block = [0u8; BLOCK_SIZE];

		encryptor.encrypt_block(&input_block, &mut output_block);

		output.extend_from_slice(&output_block);
	}

	output
}


fn main() {
	let key = common::util::random_bytes(BLOCK_SIZE); // NO PEEKING

	// detect blocksize
	let mut input = Vec::new();
	let mut current_len = None;
	let mut block_size = 0;
	for count in 1..65 {
		input.push(b'A');

		let output = encryption_oracle(&input, &key);

		if current_len == None {
			current_len = Some(output.len());
		}
		else if output.len() > current_len.unwrap() {
			block_size = output.len() - current_len.unwrap();
			break;
		}
	}

	// detect ECB mode
	input = vec![b'A'; block_size*2];
	let output = encryption_oracle(&input, &key);
	assert_eq!(&output[0..block_size], &output[block_size..(block_size*2)]);
	
	let mut plaintext = vec![b'A'; block_size - 1];
	for (pos, byte) in (0..(output.len() - block_size*2)).enumerate() {
		let mut found_byte = None;

		{
			let current_block = pos / block_size;
			//println!("In block {}", current_block);
			let needed_padding = block_size - pos % block_size - 1;
			let target_input = vec![b'A'; needed_padding];
			//println!("Target input {:?}", target_input);
			let target_cipher = encryption_oracle(&target_input, &key);

			// identify the byte
			for test in 0..255 {
				let mut check_input = Vec::with_capacity(block_size);
				check_input.extend_from_slice(&plaintext[(plaintext.len() - (block_size - 1))..]);
				check_input.push(test);
				assert_eq!(check_input.len(), block_size);
				
				//println!("Checking input {:?}", check_input);

				let check_cipher = encryption_oracle(&check_input, &key);

			//	println!("Testing {:?} {:?}", &check_cipher[(current_block*block_size)..((current_block+1)*block_size)],
			//		&target_cipher[(current_block*block_size)..((current_block+1)*block_size)]);

				if &check_cipher[0..block_size] ==
					&target_cipher[(current_block*block_size)..((current_block+1)*block_size)] {
					found_byte = Some(test);
					println!("{:?}", found_byte);
					break;
				}
			}
		}
		
		match found_byte {
			Some(x) => plaintext.push(x),
			None => break,
		};
	}

	println!("{}", String::from_utf8(plaintext).unwrap());


	println!("OK");
}
