extern crate common;

use common::mtrng::MTRNG;

fn main() {
    let mut rng = MTRNG::new(0x1234_5678);

    for _ in 0..10 {
        println!("{}", rng.gen())
    }

}