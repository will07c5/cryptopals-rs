extern crate common;
extern crate ramp;

use common::prime::gen_prime;
use common::ops::inv_mod;
use ramp::int::Int;

fn main() {
    {
        let p = Int::from(5);
        let q = Int::from(11);

        let n = &p * &q;
        println!("p = {}, q = {}, n = {}", p, q, n);

        let et = (p - 1) * (q - 1); 
        let e = Int::from(3);
        println!("e = {}, et = {}", e, et);

        let d = inv_mod(&e, &et).unwrap();
        println!("d = {}", d);

        let pub_key = (&e, &n);
        let priv_key = (&d, &n);
        println!("pub_key = ({}, {})", pub_key.0, pub_key.1);
        println!("priv_key = ({}, {})", priv_key.0, priv_key.1);

        let m = Int::from(42);
        let c = m.pow_mod(&e, &n);
        let m_dec = c.pow_mod(&d, &n);
        println!("m = {}, c = {}, m_dec = {}", m, c, m_dec);
    }
}