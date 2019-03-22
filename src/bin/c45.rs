
#[macro_use]
extern crate common;
extern crate ramp;

use ramp::{Int, RandomInt};

use common::dsa::{gen_dsa_pair_with, get_cached_primes, sign_dsa, verify_dsa};
use common::dsa::DSASignature;
use common::ops::IntOpsExt;

use rand;

fn main() {
    let (p, q) = get_cached_primes();

    {
        println!("g = 0");

        let g = Int::from(0);

        let (pub_key, priv_key) = gen_dsa_pair_with(&p, &q, &g);

        println!("y: {}", pub_key.y);
        
        let msg1 = b"message1";
        let msg2 = b"message2";

        let sig = sign_dsa(&priv_key, msg1);
        println!("sig: {:?}", sig);

        println!("verify sig (msg1): {}", verify_dsa(&pub_key, msg1, &sig));
        println!("verify sig (msg2): {}", verify_dsa(&pub_key, msg2, &sig));

        let bogus_sig = DSASignature { r: Int::from(0), s: Int::from(12345678) };
        println!("verify bogus sig (msg1): {}", verify_dsa(&pub_key, msg1, &bogus_sig));
        println!("verify bogus sig (msg2): {}", verify_dsa(&pub_key, msg2, &bogus_sig));
    }

    {
        println!();
        println!("g = p + 1");

        let g = &p + Int::from(1);

        let (pub_key, priv_key) = gen_dsa_pair_with(&p, &q, &g);

        println!("y: {}", pub_key.y);

        // z is arbitrary so just give it some random value
        let z = rand::thread_rng().gen_int_range(&Int::from(0), &q);

        let r = &pub_key.y.pow_mod(&z, &p) % &q;
        let s = (&z.inv_mod(&q).unwrap() * &r) % &q;

        let sig = DSASignature { r, s };

        println!("magic sig: {:?}", sig);

        println!("verify magic sig: {}", verify_dsa(&pub_key, b"Hello, world", &sig));
        println!("verify magic sig: {}", verify_dsa(&pub_key, b"Goodbye, world", &sig));


    }
}