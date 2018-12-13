extern crate common;
extern crate base64;
extern crate rand;

use common::crypto_helper::{encrypt_cbc, decrypt_cbc, BLOCK_SIZE};
use common::pkcs7::{pkcs7_pad, pkcs7_validate};
use common::util::print_hex;
use common::ops::xor;
use rand::Rng;

const PLAINTEXTS: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93" ];

fn encrypt_random_string(key: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let choice = rng.gen::<usize>() % 10;

    let pt_encoded = PLAINTEXTS[choice];
    let pt = base64::decode_config(pt_encoded, base64::MIME).unwrap();
    let pt_padded = pkcs7_pad(&pt, BLOCK_SIZE);

    let iv = common::util::random_bytes(BLOCK_SIZE);

    let ct = encrypt_cbc(&key, &iv, &pt_padded);

    let mut iv_ct = Vec::with_capacity(iv.len() + ct.len());

    iv_ct.extend_from_slice(&iv);
    iv_ct.extend_from_slice(&ct);

    iv_ct
}

fn check_padding(key: &[u8], ct: &[u8]) -> bool {
    let iv = &ct[..BLOCK_SIZE];
    let pt = decrypt_cbc(&key, &iv, &ct[BLOCK_SIZE..]);

    // println!("PT");
    // print_hex(&pt);

    pkcs7_validate(&pt, BLOCK_SIZE)
}

fn crack_pad_length(key: &[u8], ct: &[u8]) -> Option<usize> {
    let second_last_block = ct.rchunks(BLOCK_SIZE).nth(1).unwrap();

    for i in 1..BLOCK_SIZE - 1 {
        let bitflips: Vec<u8> = (0..BLOCK_SIZE).map(|x| if x < i { 0x01 } else { 0x00 }).collect();

        let mod_slb = xor(&bitflips, &second_last_block);

        let mut mod_ct = Vec::new();
        mod_ct.extend_from_slice(&ct[..ct.len() - BLOCK_SIZE * 2]);
        mod_ct.extend_from_slice(&mod_slb);
        mod_ct.extend_from_slice(&ct[ct.len() - BLOCK_SIZE..]);

        if !check_padding(&key, &mod_ct) {
            return Some(BLOCK_SIZE - i + 1);
        }
    }

    None
}

fn crack(key: &[u8], ct: &[u8], pad_len: usize) -> Vec<u8> {
    let pt_len = ct.len() - BLOCK_SIZE - pad_len; 
    let mut pt = Vec::with_capacity(ct.len());
    pt.extend(vec![pad_len as u8; pad_len].into_iter());

    for idx in (0..pt_len).rev() {
        let block_idx = idx / BLOCK_SIZE;
        let block_offset = idx % BLOCK_SIZE;
        let block = ct.chunks(BLOCK_SIZE).nth(block_idx).unwrap();

        println!("Idx: {} Block idx: {} Block offset: {}", idx, block_idx, block_offset);
        println!("PT so far: {}", String::from_utf8_lossy(&pt));

        let mut found = false;

        for test_byte in 0..256 {
            let test_pad = BLOCK_SIZE - block_offset;
            let mut attack_block = Vec::new();
            attack_block.extend(vec![0u8; block_offset].into_iter());
            attack_block.push(test_byte as u8);
            attack_block.extend(vec![test_pad as u8; test_pad - 1].into_iter());

            let mut pt_block = Vec::new();
            pt_block.extend(vec![0u8; block_offset + 1].into_iter());
            pt_block.extend((&pt[pt.len() - (test_pad - 1)..]).iter().cloned().rev());

            let mod_ct_block = xor(&attack_block, &xor(&pt_block, &block));

            let mut mod_ct = Vec::new();
            mod_ct.extend_from_slice(&ct[..block_idx * BLOCK_SIZE]);
            mod_ct.extend(mod_ct_block.into_iter());
            mod_ct.extend_from_slice(&ct[(block_idx + 1) * BLOCK_SIZE..(block_idx + 2) * BLOCK_SIZE]);

            if check_padding(&key, &mod_ct) {
                let pt_byte = test_byte ^ test_pad;

                println!("Found {} {} {}", test_byte, test_pad, pt_byte);

                pt.push(pt_byte as u8);

                found = true;
                break;
            }
        }

        assert!(found);
    }

    pt
}

fn main() {
    let key = common::util::random_bytes(BLOCK_SIZE);

    let ct = encrypt_random_string(&key);

    println!("Initial ciphertext");
    print_hex(&ct);

    let pad_len = crack_pad_length(&key, &ct).unwrap();

    println!("Padding length: {}", pad_len);

    // The "real" length of the plaintext is the length of the ciphertext
    // minus the size of the IV and any padding.
    let pt = crack(&key, &ct, pad_len);

    println!("PT");
    print_hex(&pt);

    let pt_rev: Vec<_> = pt.into_iter().rev().collect();
    println!("{}", String::from_utf8_lossy(&pt_rev));
}