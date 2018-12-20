use ramp::int::{Int, RandomInt};

lazy_static! {
    pub static ref P: Int = Int::from_str_radix(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
        16).unwrap();

    pub static ref G: Int = Int::from(2);
}

pub fn gen_dh_pair(p: &Int, g: &Int) -> (Int, Int) {
    let mut rng = rand::thread_rng();

    let priv_key = rng.gen_uint_below(&p);
    let pub_key = g.pow_mod(&priv_key, &p);

    (pub_key, priv_key)
}

pub fn gen_session_key(pub_key: &Int, priv_key: &Int, p: &Int) -> Int {
    pub_key.pow_mod(&priv_key, &p)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_dh() {
        let pair_a = super::gen_dh_pair(&super::P, &super::G);
        let pair_b = super::gen_dh_pair(&super::P, &super::G);

        let s_a = super::gen_session_key(&pair_b.0, &pair_a.1, &super::P);
        let s_b = super::gen_session_key(&pair_a.0, &pair_b.1, &super::P);

        assert_eq!(s_a, s_b);
    }
}
