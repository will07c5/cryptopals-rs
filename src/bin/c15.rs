extern crate common;

use common::pkcs7::pkcs7_strip;

fn main() {
    assert_eq!(
        pkcs7_strip(b"ICE ICE BABY\x04\x04\x04\x04", 16),
        Some(b"ICE ICE BABY".to_vec()));
    assert_eq!(pkcs7_strip(b"ICE ICE BABY\x05\x05\x05\x05", 16), None);
    assert_eq!(pkcs7_strip(b"ICE ICE BABY\x01\x02\x03\x04", 16), None);

    println!("OK");
}