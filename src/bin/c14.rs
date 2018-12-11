extern crate common;
extern crate crypto;
extern crate base64;
extern crate rand;
extern crate hex;

use crypto::aessafe::AesSafe128Encryptor;
use crypto::symmetriccipher::BlockEncryptor;
use std::u8;
use std::fmt;
use rand::Rng;
use std::collections::HashSet;
use std::str::from_utf8;

const BLOCK_SIZE: usize = 16;
const RAND_MIN_LEN: usize = 1;
const RAND_MAX_LEN: usize = 255;

const MIN_BLOCK_SIZE: usize = 8;
const MAX_BLOCK_SIZE: usize = 32;

const MAX_ATTEMPTS: usize = 1000;

fn encryption_oracle(chosen: &[u8], key: &[u8]) -> Vec<u8> {
	let mut rng = rand::thread_rng();
	let super_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	let super_secret_bytes = base64::decode(super_secret).unwrap();
	let mut input = Vec::new();
	let mut output = Vec::new();

	let rand_count = RAND_MIN_LEN + rng.gen::<usize>() % (RAND_MAX_LEN - RAND_MIN_LEN);
	let rand_bytes = common::util::random_bytes(rand_count);

	input.extend(rand_bytes.iter());
	input.extend_from_slice(chosen);
	input.extend(super_secret_bytes.iter());

	let input_final = common::ops::pkcs7_pad(&input, BLOCK_SIZE);

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

fn print_ct(ct: &[u8]) {
	let block_len = ct.len() / BLOCK_SIZE;

	for block_idx in 0..block_len {
		let block_start = block_idx * BLOCK_SIZE;

		print!("{}", hex::encode(&ct[block_start..block_start+BLOCK_SIZE]));
	}

	println!("");
}

fn find_block_size(key: &[u8]) -> Option<usize> {
	for block_size in MIN_BLOCK_SIZE..MAX_BLOCK_SIZE {
		let zero_pt = vec![0u8; block_size*3 - 1];
		let ct = encryption_oracle(&zero_pt, &key);

		if ct.len() % block_size != 0 {
			continue;
		}

		if common::util::identify_ecb(&ct, block_size) {
			return Some(block_size);
		}
	}

	None
}

fn find_marker(key: &[u8], block_size: usize) -> Option<Vec<u8>> {

	// Construct "marker" plaintext
	let marker_pt: Vec<u8> = 
		(0..block_size*3).map(|x| (x % block_size) as u8).collect();

	// keep re-encrypting until the marker plaintext is aligned and then
	// keep track of the resulting ciphertext
	for _ in 0..MAX_ATTEMPTS {
		let ct = encryption_oracle(&marker_pt, &key);

		let block_len = ct.len() / block_size;

		assert!(block_len >= 3);

		for block_idx in 0..block_len-2 {
			let block_start = block_idx * block_size;
			let block =
				&ct[block_start..block_start + block_size];
			let next_block =
				&ct[block_start + block_size..block_start + block_size*2];
			let next_next_block =
				&ct[block_start + block_size*2..block_start + block_size*3];

			if block == next_block &&
			   next_block == next_next_block {
			   	return Some(block.to_vec());
			}
		}
	}

	None
}

fn calc_block_variants(key: &[u8], block_size: usize) -> Vec<HashSet<Vec<u8>>> {
	// the chosen part of the plaintext is long enough that the random
	// and fixed parts can be differentiated
	let chosen_pt = vec![0u8; block_size * 2];

	let mut block_variants = Vec::new();

	for _ in 0..MAX_ATTEMPTS {
		let ct = encryption_oracle(&chosen_pt, &key);
		let block_len = ct.len() / block_size;

		for block_from_end in 0..block_len {
			let block_start = (block_len - block_from_end - 1) * block_size;
			let block = &ct[block_start..block_start + block_size];

			if block_variants.len() <= block_from_end {
				block_variants.push(HashSet::new());
			}

			block_variants[block_from_end].insert(block.to_vec());
		}
	}

	block_variants.into_iter().take_while(|x| x.len() <= block_size).collect()
}

fn find_block_after(ct: &[u8], target: &[u8], block_size: usize) -> Option<Vec<u8>> {
	assert_eq!(ct.len() % block_size, 0);
	assert_eq!(target.len(), block_size);

	let block_len = ct.len() / block_size;

	for block_idx in 0..block_len {
		let block_start = block_idx * block_size;
		let block = &ct[block_start..block_start + block_size];

		if block == target {
			return Some((&ct[block_start + block_size..block_start + block_size * 2]).to_vec());
		}
	}

	None
}

fn crack_byte(
	key: &[u8],
	block_size: usize,
	block_variants: &Vec<HashSet<Vec<u8>>>,
	marker_ct: &[u8],
	cracked_pt: &[u8]) -> Option<u8> {

	for test_byte in 1..256 {
		let mut test_pt = Vec::new();

		let padding_len =
			if cracked_pt.len() < block_size
				{ block_size - cracked_pt.len() - 1 }
			else
				{ 0 };

		let cracked_pt_len =
			if cracked_pt.len() >= block_size
				{ block_size - 1 }
			else
				{ cracked_pt.len() };

		test_pt.append(&mut vec![0u8; padding_len]);
		test_pt.extend_from_slice(&cracked_pt[cracked_pt.len() - cracked_pt_len..]);
		test_pt.push(test_byte as u8);

		// print!("Test pt:");
		// print_ct(&test_pt);

		assert_eq!(test_pt.len(), block_size);

		let mut full_test_pt = Vec::new();

		for _ in 0..block_size {
			full_test_pt.push(0xffu8);
			full_test_pt.extend(0..16u8);
			full_test_pt.extend(test_pt.iter());
		}

		// print!("Full test pt:");
		// print_ct(&full_test_pt);

		let ct = encryption_oracle(&full_test_pt, &key);

		let test_block = match find_block_after(&ct, &marker_ct, block_size) {
			Some(blk) => blk,
			None => continue,
		};

		for blk in block_variants {
			if blk.contains(&test_block) {
				return Some(test_byte as u8);
			}
		}
	}

	None
}

fn do_crack(
	key: &[u8],
	block_size: usize,
	block_variants: &Vec<HashSet<Vec<u8>>>,
	marker_ct: &[u8]) -> Vec<u8> {
	let pt_len = block_variants.iter().fold(0, |a, x| a + x.len()) - block_size;

	let mut cracked_pt = Vec::new();

	for pos in 0..pt_len {
		println!("At pos {}", pos);
		let b = crack_byte(key, block_size, &block_variants, &marker_ct, &cracked_pt).unwrap();

		cracked_pt.push(b);
	}

	cracked_pt
}

fn main() {
	let key = common::util::random_bytes(BLOCK_SIZE); // NO PEEKING

	let block_size = find_block_size(&key).expect("failed to id block size");

	assert_eq!(block_size, BLOCK_SIZE);

	let marker_ct = find_marker(&key, block_size).expect("missing marker");

	let block_variants = calc_block_variants(&key, block_size);

	for bv in block_variants.iter() {
		println!("{}", bv.len());
	}

	let pt = do_crack(&key, block_size, &block_variants, &marker_ct);

	println!("{:?}", pt);
	println!("{}", from_utf8(&pt).unwrap());

	println!("OK");
}

