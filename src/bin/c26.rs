extern crate common;
extern crate percent_encoding;
extern crate crypto;

use common::crypto_helper::{crypt_ctr, BLOCK_SIZE};
use percent_encoding::{utf8_percent_encode, DEFAULT_ENCODE_SET};
use common::ops::xor;

fn enc_userdata(userdata: &str) -> (Vec<u8>, Vec<u8>) {
    let userdata_quoted = utf8_percent_encode(userdata, DEFAULT_ENCODE_SET);

    let mut input = Vec::new();

    input.extend(b"comment1=cooking%20MCs;userdata=".iter());
    input.extend(userdata_quoted.to_string().as_bytes().iter());
    input.extend(b";comment2=%20like%20a%20pound%20of%20bacon".iter());

    println!("Plaintext");
    common::util::print_hex(&input);

    let key = common::util::random_bytes(BLOCK_SIZE);

    let blob = crypt_ctr(&key, 0, &input);

    (key, blob)
}

fn is_admin(key: &[u8], blob: &[u8]) -> bool {
    let pt_buf = crypt_ctr(&key, 0, &blob);
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
    let userdata = "aaaaaaaaaaaa";

    let (key, blob) = enc_userdata(userdata);

    println!("Ciphertext");
    common::util::print_hex(&blob);

    let new_data = xor(&xor(&blob[32..44], b"aaaaaaaaaaaa"), b"a;admin=true");

    let mut mod_blob = Vec::new();
    mod_blob.extend_from_slice(&blob[..32]);
    mod_blob.extend_from_slice(&new_data);
    mod_blob.extend_from_slice(&blob[44..]);

    println!("Modified ciphertext");
    common::util::print_hex(&mod_blob);

    assert_eq!(is_admin(&key, &mod_blob), true);

    println!("OK");
}