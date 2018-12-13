extern crate common;
extern crate rand;

use common::mtrng::MTRNG;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;

const KNOWN: &[u8] = b"AAAAAAAAAAAAAA";

fn crypt_mtrng(seed: u16, input: &[u8]) -> Vec<u8> {
    let mut rng = MTRNG::new(seed as u32);

    input.into_iter().map(|x| rng.gen() as u8 ^ x).collect()
}

fn main() {
    // First part: Breaking MTRNG stream cipher
    let mut rng = rand::thread_rng();
    let random_count = rng.gen_range::<usize>(40, 1000);
    let mut pt = Vec::new();
    pt.extend((0..random_count).map(|_| rng.gen::<u8>()));
    pt.extend_from_slice(&KNOWN);

    let seed = rng.gen::<u16>();

    let ct = crypt_mtrng(seed, &pt);

    for test_seed in 0..=0xffff {
        let pt_maybe = crypt_mtrng(test_seed, &ct);

        if &pt_maybe[pt_maybe.len()-KNOWN.len()..] == KNOWN {
            println!("Found seed {}", test_seed);
            assert_eq!(seed, test_seed);
            break;
        }
    }

    // Second part: Breaking password reset token

    // XXX Prompt seems too vague so figure out later

    
}