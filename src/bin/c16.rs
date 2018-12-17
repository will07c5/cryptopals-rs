extern crate common;
extern crate percent_encoding;
extern crate crypto;

use common::crypto_helper::{encrypt_cbc, decrypt_cbc, BLOCK_SIZE};
use percent_encoding::{utf8_percent_encode, DEFAULT_ENCODE_SET};
use common::ops::xor;

fn enc_userdata(userdata: &str) -> (Vec<u8>, Vec<u8>) {
    let userdata_quoted = utf8_percent_encode(userdata, DEFAULT_ENCODE_SET);

    let mut input = Vec::new();

    input.extend(b"comment1=cooking%20MCs;userdata=".iter());
    input.extend(userdata_quoted.to_string().as_bytes().iter());
    input.extend(b";comment2=%20like%20a%20pound%20of%20bacon".iter());

    let input_padded = common::pkcs7::pkcs7_pad(&input, BLOCK_SIZE);

    println!("Plaintext");
    common::util::print_hex(&input_padded);

    let key = common::util::random_bytes(BLOCK_SIZE);
    let iv = [0u8; BLOCK_SIZE];

    let blob = encrypt_cbc(&key, &iv, &input_padded);

    (key, blob)
}

fn is_admin(key: &[u8], blob: &[u8]) -> bool {
    let iv = [0u8; BLOCK_SIZE];

    let pt_buf = decrypt_cbc(&key, &iv, &blob);
    println!("Plaintext decrypted");
    common::util::print_hex(&pt_buf);

    let pt = String::from_utf8_lossy(&pt_buf);

    for tuple_str in pt.split(';') {
        let tuple: Vec<&str> = tuple_str.split('=').collect();

        assert_eq!(tuple.len(), 2);

        if tuple[0] == "admin" && tuple[1] == "true" {
            return true;
        }
    }

    false
}

fn main() {
    let userdata = "junkjunkjunkjunkjunkjunkjunkjunk";

    let (key, blob) = enc_userdata(userdata);

    println!("Ciphertext");
    common::util::print_hex(&blob);

    let new_block = xor(&xor(&blob[32..48], b"junkjunkjunkjunk"), b"blah;admin=true;");

    let mut mod_blob = Vec::new();
    mod_blob.extend_from_slice(&blob[..32]);
    mod_blob.extend_from_slice(&new_block);
    mod_blob.extend_from_slice(&blob[48..]);

    println!("Modified ciphertext");
    common::util::print_hex(&mod_blob);

    assert_eq!(is_admin(&key, &mod_blob), true);

    println!("OK");
}