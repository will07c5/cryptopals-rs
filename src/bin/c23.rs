extern crate common;
extern crate rand;

use common::mtrng::{MTRNG, untemper, N};
use rand::Rng;

fn main() {
    let mut rng = MTRNG::new(rand::thread_rng().gen::<u32>());

    let mut calc_x = [0u32; N];

    for x in calc_x.iter_mut() {
        *x = untemper(rng.gen());
    }

    let mut cloned_rng = MTRNG::with_x(&calc_x);

    for _ in 0..1000 {
        assert_eq!(rng.gen(), cloned_rng.gen());
    }

    println!("OK");
}