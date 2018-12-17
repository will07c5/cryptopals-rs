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

    let blob = encrypt_cbc(&key, &key, &input_padded);

    (key, blob)
}

fn is_admin(key: &[u8], blob: &[u8]) -> Result<bool, Vec<u8>> {

    let pt_buf = decrypt_cbc(&key, &key, &blob);
    println!("Plaintext decrypted");
    common::util::print_hex(&pt_buf);

    let pt = match String::from_utf8(pt_buf.clone()) {
        Ok(v) => v,
        Err(_) => return Err(pt_buf),
    };

    for tuple_str in pt.split(';') {
        let tuple: Vec<&str> = tuple_str.split('=').collect();

        assert_eq!(tuple.len(), 2);

        if tuple[0] == "admin" && tuple[1] == "true" {
            return Ok(true);
        }
    }

    Ok(false)
}

fn main() {

    let (key, blob) = enc_userdata("asdf");

    let mut attack_blob = Vec::new();
    attack_blob.extend_from_slice(&blob[..BLOCK_SIZE]);
    attack_blob.extend_from_slice(&[0u8; BLOCK_SIZE]);
    attack_blob.extend_from_slice(&blob[..BLOCK_SIZE]);

    let pt = match is_admin(&key, &attack_blob) {
        Ok(_) => panic!("Want this to fail"),
        Err(v) => v,
    };

    let recovered_key = xor(&pt[..BLOCK_SIZE], &pt[BLOCK_SIZE*2..BLOCK_SIZE*3]);

    assert_eq!(key, recovered_key);

    println!("OK");
}