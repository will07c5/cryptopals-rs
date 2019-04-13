
#[macro_use]
extern crate common;
extern crate ramp;
extern crate base64;

use std::str::from_utf8;

use common::rsa::{RSAPrivKey, RSAPubKey};
use common::rsa::{gen_rsa_pair, encrypt_rsa, decrypt_rsa};
use common::ops::IntOpsExt;

use ramp::Int;

const SECRET_PT: &str = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";

struct Oracle {
    priv_key: RSAPrivKey,
    pub_key: RSAPubKey,
    ct: Int,
}

impl Oracle {
    fn new() -> Self {
        let (pub_key, priv_key) = gen_rsa_pair(1024); 

        let pt_bytes = base64::decode_config(SECRET_PT, base64::MIME).unwrap();
        let pt = Int::from_bytes(&pt_bytes);

        let ct = encrypt_rsa(&pub_key, &pt).unwrap();

        Oracle { pub_key, priv_key, ct }
    }

    fn check_parity(&self, c: &Int) -> bool {
        let pt = decrypt_rsa(&self.priv_key, c).unwrap();

        pt.bit(0)
    }
}

fn main() {
    let oracle = Oracle::new();

    let (mut lo, mut hi) = (Int::from(0), oracle.pub_key.n.clone());

    let mut old_ct = oracle.ct.clone();


    while (&hi - &lo) > Int::from(1) {
        let new_ct = (old_ct * Int::from(2).pow_mod(&oracle.pub_key.e, &oracle.pub_key.n)) % &oracle.pub_key.n;

        println!("{} {}", lo, hi);

        if oracle.check_parity(&new_ct) {
            lo = &lo + (&hi - &lo) / Int::from(2);
        } else {
            hi = &hi - (&hi - &lo) / Int::from(2);
        }

        old_ct = new_ct;
    }

    let cracked_pt = hi.to_bytes();

    println!("{:?}", from_utf8(&cracked_pt));
}