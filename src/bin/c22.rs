extern crate common;
extern crate rand;

use std::time::{SystemTime, UNIX_EPOCH};
use common::mtrng::MTRNG;
use rand::Rng;

fn main() {
    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    println!("Start time: {}", start);

    let mut rng = MTRNG::new(start as u32);

    let wait_time = rand::thread_rng().gen_range::<u64>(40, 1000);

    println!("Simulating advancing by {} seconds", wait_time);

    let now = start + wait_time;

    println!("Now: {}", now);

    let random_val = rng.gen();
    let mut test_seed = now;

    println!("Random val: {}", random_val);

    loop {
        let mut test_rng = MTRNG::new(test_seed as u32);

        let test_val = test_rng.gen();

        if test_val == random_val {
            println!("Found seed: {}", test_seed);
            return;
        }

        test_seed -= 1;
    }

}