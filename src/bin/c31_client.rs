extern crate common;
extern crate reqwest;
extern crate hex;

use reqwest::Client;
use std::time::Instant;
use common::sha1::HASH_SIZE;

fn time_request(client: &Client, test_hash: &str) -> u64 {
    let start = Instant::now();
    client.get("http://localhost:8000/test")
        .query(&[("file", "README.md"),
                 ("signature", test_hash)])
        .send()
        .unwrap();
    let elapsed = start.elapsed();

    elapsed.as_secs() * 1_000_000 + u64::from(elapsed.subsec_micros())
}

fn main() {
    let client = Client::new();

    let mut hash = Vec::new();
    for pos in 0..HASH_SIZE {
        let padding = HASH_SIZE - (pos + 1); 

        let times: Vec<_> = (0..256).map(|x| {
            let mut test_hash = Vec::with_capacity(HASH_SIZE); 
            test_hash.extend_from_slice(&hash);
            test_hash.push(x as u8);
            test_hash.extend_from_slice(&vec![0u8; padding]);

            time_request(&client, &hex::encode(&test_hash))
        }).collect();

        let (largest_idx, largest_time) = times.iter()
            .enumerate()
            .fold(
                (0, 0),
                |(ia, a), (ib, b)| if *b > a { (ib, *b) } else { (ia, a) });

        println!("{}: {:x} with {} us", pos, largest_idx, largest_time);

        hash.push(largest_idx as u8);
    }

    println!("Full hash: {}", hex::encode(&hash));

}