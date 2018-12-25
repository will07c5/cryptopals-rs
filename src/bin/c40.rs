use common::ops::{inv_mod, nth_root};
use ramp::int::Int;
use common::rsa::{gen_rsa_pair, encrypt_rsa};

fn main() {
    let m = Int::from_str_radix(&hex::encode(&b"unknown encrypted data"), 16).unwrap();
    println!("m = {}", m);

    println!("Gen RSA 1");
    let (pub0, _) = gen_rsa_pair();
    println!("pub0 = {:?}", pub0);
    println!("Gen RSA 2");
    let (pub1, _) = gen_rsa_pair();
    println!("pub1 = {:?}", pub1);
    println!("Gen RSA 3");
    let (pub2, _) = gen_rsa_pair();
    println!("pub2 = {:?}", pub2);
    println!("Done generating keys");

    let c0 = encrypt_rsa(&pub0, &m).unwrap();
    println!("c0 = {}", c0);
    let c1 = encrypt_rsa(&pub1, &m).unwrap();
    println!("c1 = {}", c1);
    let c2 = encrypt_rsa(&pub2, &m).unwrap();
    println!("c2 = {}", c2);

    let n0 = pub0.n;
    let n1 = pub1.n;
    let n2 = pub2.n;

    // XXX challenge description says to leave off the final modulus operation
    // but it doesn't seem to work without it?
    let recovered_m = (&c0*&n1*&n2*&inv_mod(&(&n1*&n2), &n0).unwrap() +
        &c1*&n0*&n2*&inv_mod(&(&n0*&n2), &n1).unwrap() +
        &c2*&n0*&n1*&inv_mod(&(&n0*&n1), &n2).unwrap())%(&n0*&n1*&n2);
    let recovered_m_root = nth_root(&recovered_m, 3);

    println!("recovered_m = {}", recovered_m);
    println!("recovered_m_root = {}", recovered_m_root);

    println!("recovered message = {}", String::from_utf8_lossy(&hex::decode(recovered_m_root.to_str_radix(16, false)).unwrap()));

}