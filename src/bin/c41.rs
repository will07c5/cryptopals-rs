extern crate common;
extern crate ramp;
extern crate rand;

use common::ops::IntOpsExt;
use ramp::int::{Int, RandomInt};
use common::rsa::{gen_rsa_pair, encrypt_rsa, decrypt_rsa};

fn main() {
    let m = Int::from_bytes(b"unknown encrypted data");
    println!("m = {}", m);

    let (pub_key, priv_key) = gen_rsa_pair(512);
    println!("pub_key = {:?}", pub_key);
    println!("priv_key = {:?}", priv_key);

    let c = &encrypt_rsa(&pub_key, &m).unwrap();
    let n = &pub_key.n;
    let e = &pub_key.e;
    let s = &rand::thread_rng().gen_int_range(&Int::from(2), n);
    println!("c = {}", c);
    println!("n = {}", n);
    println!("e = {}", e);
    println!("s = {}", s);

    let cp = (s.pow_mod(e, n) * c) % n;
    println!("cp = {}", cp);

    // "Submit" ciphertext to "server" 
    let pp = &decrypt_rsa(&priv_key, &cp).unwrap();
    println!("pp = {}", pp);

    let p = (pp * &s.inv_mod(n).unwrap()) % n;
    println!("p = {}", p);

    println!("recovered message = {}", String::from_utf8_lossy(&p.to_bytes()));

}