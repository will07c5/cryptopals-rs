extern crate rand;
extern crate crypto;
extern crate byteorder;
extern crate hex;
extern crate ramp;
#[macro_use]
extern crate lazy_static;

pub mod ops;
pub mod pkcs7;
pub mod util;
pub mod crypto_helper;
pub mod mtrng;
pub mod sha1;
pub mod md4;
pub mod dh;
pub mod prime;

#[macro_export]
macro_rules! challenge_data {
    ($file:expr) => (
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/data/", $file))
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
