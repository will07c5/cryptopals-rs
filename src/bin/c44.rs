#[macro_use]
extern crate common;
extern crate ramp;
extern crate hex;
#[macro_use]
extern crate nom;

use std::str::FromStr;

use nom::{space, not_line_ending, hex_digit};
use nom::types::CompleteStr;

use ramp::Int;
use ramp::int::ParseIntError;

use common::sha1::sha1_digest;
use common::ops::IntOpsExt;
use common::dsa::{verify_dsa, DSAPubKey, DSACommonParams, DSASignature};

const DATA: &str = challenge_data!("44.txt");

// because the modulus operation returns negative numbers because reasons
fn real_modulus(a: &Int, b: &Int) -> Int {
    let result = a % b;

    if result < 0 {
        b - result
    } else {
        result
    }
}

fn k_to_x(msg_hash: &Int, q: &Int, sig: &DSASignature, k: &Int) -> Int {
    (((&sig.s * k) - msg_hash) * sig.r.inv_mod(q).unwrap()) % q
}

fn ms_to_k(m1: &Int, m2: &Int, s1: &Int, s2: &Int, q: &Int) -> Int {
    let numer = real_modulus(&(m1 - m2), q);
    let denom = real_modulus(&(s1 - s2), q);

    &(denom.inv_mod(q).unwrap() * numer) % q
}

#[derive(Debug)]
struct Msg {
    msg: String,
    r: Int,
    s: Int,
    m: Int,
}

fn from_str_hex(src: CompleteStr) -> Result<Int, ParseIntError> {
    Int::from_str_radix(src.0, 16)
}

fn from_str(src: CompleteStr) -> Result<Int, ParseIntError> {
    Int::from_str(src.0)
}

named!(parse_hex<CompleteStr, Int>,
    map_res!(hex_digit, from_str_hex)
);

named!(parse_int<CompleteStr, Int>,
    map_res!(hex_digit, from_str)
);

named!(parse_msg<CompleteStr, Msg>,
    do_parse!(
        take_until_and_consume!("msg:") >> space >>
        msg: not_line_ending >>
        take_until_and_consume!("s:") >> space >>
        s: parse_int >>
        take_until_and_consume!("r:") >> space >>
        r: parse_int >>
        take_until_and_consume!("m:") >> space >>
        m: parse_hex >>
        (Msg { msg: msg.to_string(), r, s, m })
    )
);

named!(parse_msgs<CompleteStr, Vec<Msg>>,
    many1!(parse_msg)
);

fn main() {
    let p = Int::from_str_radix("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16).unwrap();
    let q = Int::from_str_radix("f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap();
    let g = Int::from_str_radix("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16).unwrap();
    let y = Int::from_str_radix("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16).unwrap();

    let common = DSACommonParams { p, q, g };
    let pub_key = DSAPubKey { common, y };

    let (_, msgs) = parse_msgs(CompleteStr(DATA)).unwrap();

    println!("{:#?}", msgs);

    for msg in msgs.iter() {
        let msg_hash = Int::from_bytes(&sha1_digest(msg.msg.as_bytes()));

        assert_eq!(msg_hash, msg.m);

        let sig = DSASignature { r: msg.r.clone(), s: msg.s.clone() };

        assert_eq!(verify_dsa(&pub_key, msg.msg.as_bytes(), &sig), true);
    }

    for (i, msg1) in msgs.iter().enumerate() {
        for msg2 in (&msgs[i + 1..]).iter() {
            let test_k = ms_to_k(&msg1.m, &msg2.m, &msg1.s, &msg2.s, &pub_key.common.q);
            println!("test_k: {}", test_k);

            if test_k < 2 {
                continue;
            }

            let sig = DSASignature { r: msg1.r.clone(), s: msg1.s.clone() };
            let test_x = k_to_x(&msg1.m, &pub_key.common.q, &sig, &test_k);
            println!("test_x: {}", test_x);

            let test_y = pub_key.common.g.pow_mod(&test_x, &pub_key.common.p);

            if pub_key.y == test_y {
                println!("Msg1: {:#?}", msg1);
                println!("Msg2: {:#?}", msg2);
                println!("k: {}", test_k);
                return;
            }

        }
    }

}

