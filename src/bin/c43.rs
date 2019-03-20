extern crate common;
extern crate ramp;
extern crate hex;

use std::str::FromStr;

use common::dsa::DSASignature;
use common::sha1::sha1_digest;

use common::ops::IntOpsExt;

use ramp::Int;

const MSG: &[u8] = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";

fn k_to_x(msg_hash: &Int, q: &Int, sig: &DSASignature, k: &Int) -> Int {
    (((&sig.s * k) - msg_hash) * sig.r.inv_mod(q).unwrap()) % q
}

fn main() {
    let p = Int::from_str_radix("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16).unwrap();
    let q = Int::from_str_radix("f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap();
    let g = Int::from_str_radix("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16).unwrap();
    let y = Int::from_str_radix("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16).unwrap();

    let r = Int::from_str("548099063082341131477253921760299949438196259240").unwrap();
    let s = Int::from_str("857042759984254168557880549501802188789837994940").unwrap();

    let sig = DSASignature { r, s };

    let msg_hash_bytes = sha1_digest(MSG);

    assert_eq!(msg_hash_bytes, hex::decode("d2d0714f014a9784047eaeccf956520045c45265").unwrap());

    let msg_hash = Int::from_bytes(&msg_hash_bytes);

    // let tgt_x_hash = hex::decode("0954edd5e0afe5542a4adf012611a91912a3ec16").unwrap();

    for test_k in (2..65536u32).map(|k| Int::from(k)) {
        if &test_k % 1000 == 0 {
            println!("current k is {}", test_k);
        }

        let test_x = k_to_x(&msg_hash, &q, &sig, &test_k);

        // let x_bytes = test_x.to_bytes();

        // let x_hash = sha1_digest(&x_bytes);

        // if tgt_x_hash == x_hash {
        //     println!("Found k = {} x = {}", test_k, test_x);
        //     break;
        // }


        let test_y = g.pow_mod(&test_x, &p);

        if y == test_y {
            println!("Found private key x = {}", test_x);
            break;
        }
    }
}

// fn main() {
//     let k = Int::from(123);

//     let (pub_key, priv_key) = gen_dsa_pair();

//     println!("Pub key: {:?}", pub_key.y);
//     println!("Priv key: {:?}", priv_key.x);

//     let sig = sign_dsa_internal(&priv_key, MSG, &k);

//     println!("sig: {:?}", sig);

//     let msg_hash_bytes = sha1_digest(MSG);
//     let msg_hash = Int::from_bytes(&msg_hash_bytes);

//     let x = k_to_x(&msg_hash, &pub_key.common.q, &sig, &k);

//     println!("calc x = {}", x);


// }
