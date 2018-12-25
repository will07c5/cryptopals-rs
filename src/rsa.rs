use ramp::int::Int;
use crate::prime::gen_prime;
use crate::ops::inv_mod;

#[derive(Debug)]
pub struct RSAPubKey {
	pub e: Int,
	pub n: Int,
}

#[derive(Debug)]
pub struct RSAPrivKey {
	d: Int,
	n: Int,
}

// Generate a prime (p) where gcd(p - 1, e) is 1.
// This only works if e is prime.
//
// This is required since the modular inverse requires
// that gcd((p - 1)(q - 1), e) (where p, q are primes) is 1.
fn gen_good_prime(e: &Int, bits: usize) -> Int {
    loop {
        let p = gen_prime(bits);

        if (&p - 1) % e != Int::from(0) {
            return p;
        }
    }
}

pub fn gen_rsa_pair() -> (RSAPubKey, RSAPrivKey) {
    let e = Int::from(3);

    let p = gen_good_prime(&e, 256);
    let q = gen_good_prime(&e, 256);

    let n = &p * &q;

    let et = (p - 1) * (q - 1); 

    let d = inv_mod(&e, &et).unwrap();

    (RSAPubKey { e, n: n.clone() }, RSAPrivKey { d, n })
}

pub fn encrypt_rsa(key: &RSAPubKey, m: &Int) -> Result<Int, ()> {
	if m >= &key.n {
		Err(())
	} else {
		Ok(m.pow_mod(&key.e, &key.n))
	}

}

pub fn decrypt_rsa(key: &RSAPrivKey, c: &Int) -> Result<Int, ()> {
	if c >= &key.n {
		Err(())
	} else {
		Ok(c.pow_mod(&key.d, &key.n))
	}
}