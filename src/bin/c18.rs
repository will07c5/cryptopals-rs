extern crate common;
extern crate base64;

use common::crypto_helper::{crypt_ctr, BLOCK_SIZE};

const KEY: &[u8] = b"YELLOW SUBMARINE";
const INPUT: &str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

fn main() {
    let input = base64::decode_config(&INPUT, base64::MIME).unwrap();
    let output = crypt_ctr(&KEY, 0, &input);

    println!("PT: {}", String::from_utf8_lossy(&output));
}