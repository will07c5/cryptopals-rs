// https://csrc.nist.gov/CSRC/media/Publications/fips/186/1/archive/1998-12-15/documents/fips186-1.pdf

use crate::sha1::{sha1_digest, HASH_SIZE};
use crate::ops::xor;
use crate::prime::test_prime;
use crate::asn1;

use crate::ops::IntOpsExt;

use ramp::{Int, RandomInt};

use std::fs::File;
use std::path::Path;
use std::io::{Read, Write};

use rand;
use hex;

const SEED_BIT_LEN: usize = HASH_SIZE*8;
const CACHED_PRIMES_FILE: &str = ".cached_primes";

#[derive(Debug, Clone)]
pub struct DSACommonParams {
    pub p: Int,
    pub q: Int,
    pub g: Int,
}

#[derive(Debug, Clone)]
pub struct DSAPubKey {
    pub common: DSACommonParams,
    pub y: Int,
}

#[derive(Debug, Clone)]
pub struct DSAPrivKey {
    pub common: DSACommonParams,
    pub x: Int,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DSASignature {
    pub r: Int,
    pub s: Int,
}

fn gen_params_with_seed(len: usize, seed: &Int) -> Option<(Int, Int, usize)> {
    println!("seed: {}", hex::encode(seed.to_bytes()));
    
    let seed_modulo = Int::from(2).pow(SEED_BIT_LEN);

    let seed_plus_1 = (seed + Int::from(1)) % &seed_modulo;

    println!("seed+1: {}", hex::encode(seed_plus_1.to_bytes()));

    let mut u = Int::from_bytes(
        &xor(
            &sha1_digest(&seed.to_bytes()),
            &sha1_digest(&seed_plus_1.to_bytes())
        )
    );

    println!("u: {}", hex::encode(u.to_bytes()));

    u.set_bit((SEED_BIT_LEN - 1) as u32, true);
    u.set_bit(0, true);

    let q = u;

    println!("q: {}", hex::encode(q.to_bytes()));

    if !test_prime(&q, 50) {
        println!("q not prime");
        return None;
    }

    let n = (len - 1) / 160;
    let b = (len - 1) % 160;

    println!("n: {} b: {}", n, b);

    for counter in 0..4097 {
        let offset = 2 + (n + 1) * counter;

        println!("counter: {} offset: {}", counter, offset);

        let mut w = Int::from(0);
        for k in 0..n {
            let sha_input: Int = (seed + offset + k) % &seed_modulo;

            let v_k = Int::from_bytes(&sha1_digest(&sha_input.to_bytes()));

            println!("V_{}: {} {}", k, sha_input, v_k);

            w += v_k << (SEED_BIT_LEN * k);
        }

        let sha_input_last: Int = (seed + offset + n) % &seed_modulo;

        let v_n = Int::from_bytes(&sha1_digest(&sha_input_last.to_bytes())) % (Int::from(2).pow(b));

        println!("V_{}: {} {}", n, sha_input_last, v_n);

        w += v_n << (SEED_BIT_LEN * n);

        println!("w: {} (bit len {})", w, w.bit_length());

        w.set_bit((len - 1) as u32, true);
        let x = w;

        println!("x: {} (bit len {})", x, x.bit_length());

        let c = &x % (&q * 2);

        println!("c: {}", c);

        let p: Int = x - (c - 1);

        println!("p: {} (bit len {})", p, p.bit_length());

        if p.bit_length() < len as u32 {
            continue;
        }

        if test_prime(&p, 50) {
            println!("Found primes!");
            println!("Counter: {}", counter);
            println!("Seed: {}", seed);

            return Some((p, q, counter));
        }
    }

    None
}

fn gen_dsa_primes(len: usize) -> (Int, Int) {
    // make sure len conforms to the requirement that len is a multiple of 64
    // between 512 and 1024 inclusive.
    assert!(len >= 512 && len <= 1024);
    assert_eq!(len % 64, 0);

    loop {
        let seed = rand::thread_rng().gen_uint(SEED_BIT_LEN);

        if let Some((p, q, _)) = gen_params_with_seed(len, &seed) {
            return (p, q);
        }
    }
}

pub fn get_cached_primes() -> (Int, Int) {
    if Path::new(CACHED_PRIMES_FILE).exists() {
        let mut data = Vec::new();
        File::open(CACHED_PRIMES_FILE).unwrap().read_to_end(&mut data).unwrap();

        let (_, seq) = asn1::decode_asn1_sequence(&data).unwrap();
        let (seq, p) = asn1::decode_asn1_integer(&seq).unwrap();
        let (_, q) = asn1::decode_asn1_integer(&seq).unwrap();

        // if I cared I would validate the primes with the seed and counter here
        // but I don't because this is an amateur implementation of an
        // obsolete version of DSA
        println!("Cached primes: p: {} q: {}", p, q);

        (p, q)
    } else {
        let mut file = File::create(CACHED_PRIMES_FILE).unwrap();

        let (p, q) = gen_dsa_primes(512);

        println!("Generated primes: p: {} q: {}", p, q);

        let data = asn1::encode_asn1_sequence(
            &[
                asn1::encode_asn1_integer(&p),
                asn1::encode_asn1_integer(&q)
            ]
        );

        file.write_all(&data).unwrap();

        (p, q)
    }
}

fn gen_param_g(p: &Int, q: &Int) -> Int {
    // generate g
    let e = (p - 1) / q;

    loop {
        let h = rand::thread_rng().gen_int_range(&Int::from(2), &(p - 1));

        let g = h.pow_mod(&e, p);
        
        if &g != &Int::from(1) {
            return g;
        }
    }
}

pub fn gen_dsa_pair_with(p: &Int, q: &Int, g: &Int) -> (DSAPubKey, DSAPrivKey) {

    let x = rand::thread_rng().gen_uint_below(q);

    let y = g.pow_mod(&x, p);

    let common = DSACommonParams { p: p.clone(), q: q.clone(), g: g.clone() };

    (DSAPubKey { common: common.clone(), y }, DSAPrivKey { common, x: x.clone() })
}

pub fn gen_dsa_pair() -> (DSAPubKey, DSAPrivKey) {
    let (p, q) = get_cached_primes();

    let g = gen_param_g(&p, &q);

    gen_dsa_pair_with(&p, &q, &g)
}

pub fn sign_dsa_internal(key: &DSAPrivKey, msg: &[u8], k: &Int) -> DSASignature {
    let (p, q) = (&key.common.p, &key.common.q);
    let g = &key.common.g;
    let x = &key.x;

    // println!("DSA sign");
    // println!("p: {} q: {}", p, q);
    // println!("g: {}", g);
    // println!("x: {}", x);
    // println!("k: {}", k);

    let r = &g.pow_mod(k, p) % q;
    // println!("r: {}", r);

    let msg_digest = &Int::from_bytes(&sha1_digest(&msg));

    let s = &(k.inv_mod(q).unwrap() * (msg_digest + x * &r)) % q;
    // println!("s: {}", s);

    DSASignature { r, s }

}

pub fn sign_dsa(key: &DSAPrivKey, msg: &[u8]) -> DSASignature {
    let k = &rand::thread_rng().gen_uint_below(&key.common.q);

    sign_dsa_internal(key, msg, &k)
}

pub fn verify_dsa(key: &DSAPubKey, msg: &[u8], sig: &DSASignature) -> bool {
    // Work with references since it makes the math cleaner
    let (r, s) = (&sig.r, &sig.s);
    let (p, q) = (&key.common.p, &key.common.q);
    let g = &key.common.g;
    let y = &key.y;

    // println!("DSA verify");
    // println!("r: {} s: {}", r, s);
    // println!("p: {} q: {}", p, q);
    // println!("g: {}", g);
    // println!("y: {}", y);
    
    assert!(r < q);
    assert!(s < q);

    let w = &s.inv_mod(q).unwrap();
    // println!("w: {}", w);
    let u1 = (&Int::from_bytes(&sha1_digest(msg)) * w) % q;
    // println!("u1: {}", u1);
    let u2 = (r * w) % q;
    // println!("u2: {}", u2);
    let a = g.pow_mod(&u1, p);
    // println!("a: {}", a);
    let b = y.pow_mod(&u2, p);
    // println!("b: {}", b);
    let v = ((a * b) % p) % q;
    // println!("v: {}", v);

    &v == r
}

#[cfg(test)]
mod tests {
    use ramp::Int;
    use super::*;

    #[test]
    fn gen_dsa_primes() {
        // Test vectors taken from FIPS 186-1
        let seed = Int::from_str_radix("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3", 16).unwrap();

        let (p, q, counter) = gen_params_with_seed(512, &seed).unwrap();

        println!("p: {} q: {}", p, q);

        assert_eq!(counter, 105);

    }

    #[test]
    fn sign_known_params() {
        let p = Int::from_str_radix("8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291", 16).unwrap();
        let q = Int::from_str_radix("c773218c737ec8ee993b4f2ded30f48edace915f", 16).unwrap();
        let g = Int::from_str_radix("626d027839ea0a13413163a55b4cb500299d5522956cefcb3bff10f399ce2c2e71cb9de5fa24babf58e5b79521925c9cc42e9f6f464b088cc572af53e6d78802", 16).unwrap();
        let x = Int::from_str_radix("2070b3223dba372fde1c0ffc7b2e3b498b260614", 16).unwrap();
        let k = Int::from_str_radix("358dad571462710f50e254cf1a376b2bdeaadfbf", 16).unwrap();

        let r = Int::from_str_radix("8bac1ab66410435cb7181f95b16ab97c92b341c0", 16).unwrap();
        let s = Int::from_str_radix("41e2345f1f56df2458f426d155b4ba2db6dcd8c8", 16).unwrap();
        let msg = b"abc";

        let priv_key = DSAPrivKey { common: DSACommonParams { p, q, g }, x };

        let sig = sign_dsa_internal(&priv_key, msg, &k);

        assert_eq!(sig.r, r);
        assert_eq!(sig.s, s);
    }

    #[test]
    fn verify_known_params() {
        let p = Int::from_str_radix("8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291", 16).unwrap();
        let q = Int::from_str_radix("c773218c737ec8ee993b4f2ded30f48edace915f", 16).unwrap();
        let g = Int::from_str_radix("626d027839ea0a13413163a55b4cb500299d5522956cefcb3bff10f399ce2c2e71cb9de5fa24babf58e5b79521925c9cc42e9f6f464b088cc572af53e6d78802", 16).unwrap();
        let y = Int::from_str_radix("19131871d75b1612a819f29d78d1b0d7346f7aa77bb62a859bfd6c5675da9d212d3a36ef1672ef660b8c7c255cc0ec74858fba33f44c06699630a76b030ee333", 16).unwrap();

        let r = Int::from_str_radix("8bac1ab66410435cb7181f95b16ab97c92b341c0", 16).unwrap();
        let s = Int::from_str_radix("41e2345f1f56df2458f426d155b4ba2db6dcd8c8", 16).unwrap();
        let msg = b"abc";

        let pub_key = DSAPubKey { common: DSACommonParams { p, q, g }, y };
        let sig = DSASignature { r, s };

        assert!(verify_dsa(&pub_key, msg, &sig));

    }

    #[test]
    fn sign_verify() {
        let (pub_key, priv_key) = gen_dsa_pair();

        let msg = b"test message";

        let sig = sign_dsa(&priv_key, msg);

        assert!(verify_dsa(&pub_key, msg, &sig));
    }

    #[test]
    fn test_inverse() {
        let k = Int::from_str_radix("358dad571462710f50e254cf1a376b2bdeaadfbf", 16).unwrap();
        let q = Int::from_str_radix("c773218c737ec8ee993b4f2ded30f48edace915f", 16).unwrap();
        let k_inv_expected = Int::from_str_radix("0d5167298202e49b4116ac104fc3f415ae52f917", 16).unwrap();

        let k_inv = k.inv_mod(&q).unwrap();

        assert_eq!(k_inv, k_inv_expected);

    }
}
