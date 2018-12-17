extern crate common;
extern crate rand;
extern crate ramp;

use rand::Rng;
use ramp::int::{Int, RandomInt};

const P: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";

const G: usize = 2;

fn main() {
    let mut rng = rand::thread_rng();

    {
        let p: u128 = 37;
        let g: u128 = 5;

        let a_priv = rng.gen_range::<u32>(0, p as u32);
        let a_pub = g.pow(a_priv) % p;
        println!("a pub {} a priv {}", a_pub, a_priv);

        let b_priv = rng.gen_range::<u32>(0, p as u32);
        let b_pub = g.pow(b_priv) % p;
        println!("b pub {} b priv {}", b_pub, b_priv);

        let s_a = b_pub.pow(a_priv) % p;
        let s_b = a_pub.pow(b_priv) % p;
        println!("s a {} s b {}", s_a, s_b);

        assert_eq!(s_a, s_b);
    }

    {
        let p = Int::from_str_radix(&P, 16).unwrap();
        let g = Int::from(G);

        let a_priv = rng.gen_uint_below(&p);
        let a_pub = g.pow_mod(&a_priv, &p);
        println!("a pub {} a priv {}", a_pub, a_priv);

        let b_priv = rng.gen_uint_below(&p);
        let b_pub = g.pow_mod(&b_priv, &p);
        println!("b pub {} b priv {}", b_pub, b_priv);

        let s_a = b_pub.pow_mod(&a_priv, &p);
        let s_b = a_pub.pow_mod(&b_priv, &p);
        println!("s a {} s b {}", s_a, s_b);

        assert_eq!(s_a, s_b);
    }

}