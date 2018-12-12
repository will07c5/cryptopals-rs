extern crate rand;

pub mod ops;
pub mod pkcs7;
pub mod util;

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
