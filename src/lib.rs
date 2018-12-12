extern crate rand;
extern crate crypto;

pub mod ops;
pub mod pkcs7;
pub mod util;
pub mod crypto_helper;

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
