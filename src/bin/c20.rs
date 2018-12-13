#[macro_use]
extern crate common;
extern crate base64;

use std::usize;
use common::util::crack_1b_xor;
use common::ops::xor;
use common::crypto_helper::{crypt_ctr, BLOCK_SIZE};

const INPUT: &str = challenge_data!("20.txt");

fn main() {
    let key = common::util::random_bytes(BLOCK_SIZE);
    let ciphertexts: Vec<_> =
        INPUT.lines()
            .map(|pt_enc| {
                let pt = base64::decode_config(pt_enc, base64::MIME).unwrap();
                crypt_ctr(&key, 0, &pt)
            })
            .collect();

    let shortest =
        ciphertexts
        .iter()
        .map(|x| x.len())
        .fold(usize::MAX, |a, x| if x < a { x } else { a });

    let ks: Vec<_> =
        (0..shortest).map(
            |pos| {
                let data: Vec<_> = ciphertexts.iter().map(|x| x[pos]).collect();
                let result = crack_1b_xor(&data).unwrap();

                println!("Pos: {} Key: {} Score: {}", pos, result.key, result.score);
                result.key
            }).collect();

    let plaintexts: Vec<_> =
        ciphertexts
        .iter()
        .map(|x| xor(&x, &ks))
        .collect();

    for pt in plaintexts.iter() {
        println!("PT: {}", String::from_utf8_lossy(&pt));
    }

}