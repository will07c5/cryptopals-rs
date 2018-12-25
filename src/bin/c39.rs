extern crate common;
extern crate ramp;
extern crate hex;

use common::ops::inv_mod;
use ramp::int::Int;
use common::rsa::{gen_rsa_pair, encrypt_rsa, decrypt_rsa};

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

    {
        let (pub_key, priv_key) = gen_rsa_pair();

        // convert string to big int
        let data = b"encrypt test string";
        let hex_data = hex::encode(&data);
        let m = Int::from_str_radix(&hex_data, 16).unwrap();

        println!("m = {}", m);
        let c = encrypt_rsa(&pub_key, &m).unwrap();
        println!("c = {}", c);
        let mp = decrypt_rsa(&priv_key, &c).unwrap();
        println!("m' = {}", mp);

        println!("m' as string = {}", String::from_utf8_lossy(&hex::decode(mp.to_str_radix(16, false)).unwrap()));
    }
}