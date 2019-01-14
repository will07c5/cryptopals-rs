use ramp::int::Int;
use crate::prime::gen_prime;
use crate::ops::IntOpsExt;
use crate::asn1::*;
use crate::md4::md4_digest;

const MD4_OID: &[usize] = &[1, 2, 840, 113549, 2, 4];

#[derive(Debug)]
pub struct RSAPubKey {
	pub e: Int,
	pub n: Int,
}

#[derive(Debug)]
pub struct RSAPrivKey {
    p: Int,
    q: Int,
    n: Int,
    e: Int,
	d: Int,
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

pub fn priv_to_asn1(priv_key: RSAPrivKey) -> Vec<u8> {
    let exp1 = &priv_key.d % (&priv_key.p - 1);
    let exp2 = &priv_key.d % (&priv_key.q - 1);

    let coeff = &priv_key.q.inv_mod(&priv_key.p).unwrap();

    encode_asn1_sequence(
        &[encode_asn1_integer(&Int::from(0)), // Version
        encode_asn1_integer(&priv_key.n),
        encode_asn1_integer(&priv_key.e),
        encode_asn1_integer(&priv_key.d),
        encode_asn1_integer(&priv_key.p),
        encode_asn1_integer(&priv_key.q),
        encode_asn1_integer(&exp1),
        encode_asn1_integer(&exp2),
        encode_asn1_integer(&coeff)])
}

pub fn pub_to_asn1(pub_key: RSAPubKey) -> Vec<u8> {
    encode_asn1_sequence(
        &[encode_asn1_integer(&pub_key.n),
        encode_asn1_integer(&pub_key.e)])
}

pub fn gen_rsa_pair(bits: usize) -> (RSAPubKey, RSAPrivKey) {
    let e = Int::from(3);

    let p = gen_good_prime(&e, bits / 2);
    let q = gen_good_prime(&e, bits / 2);

    let n = &p * &q;

    let et = (&p - 1) * (&q - 1); 

    let d = e.inv_mod(&et).unwrap();

    (RSAPubKey { e: e.clone(), n: n.clone() }, RSAPrivKey { p, q, n, e, d })
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

pub fn find_asn1_start(block: &[u8]) -> Option<usize> {
    let mut bytes = block.iter();

    // if *bytes.next()? != 0x00 {
    //     return None;
    // }

    if *bytes.next()? != 0x01 {
        return None;
    }

    if *bytes.next()? != 0xff {
        return None;
    }

    Some(3 + bytes.position(|x| *x == 0x00)?)
}

#[derive(Debug)]
pub enum SigError {
    ASN1Error(ASN1Error),
    DigestMismatch,
    UnsupportedDigest,
    InvalidPadding
}

impl From<ASN1Error> for SigError {
    fn from(error: ASN1Error) -> Self {
        SigError::ASN1Error(error)
    }
}

pub fn verify_rsa(key: &RSAPubKey, msg: &[u8], sig: &[u8]) -> Result<(), SigError> {
    let digest_verify = md4_digest(msg);
    let y = Int::from_bytes(&sig);
    let x = encrypt_rsa(key, &y).unwrap();
    let block = x.to_bytes();

    println!("Decrypt sig {}", hex::encode(&block));

    let asn1_start = match find_asn1_start(&block) {
        Some(v) => v,
        None => return Err(SigError::InvalidPadding),
    };

    let (_, seq) = decode_asn1_sequence(&block[asn1_start..]).unwrap();
    let (seq, oid) = decode_asn1_oid(&seq).unwrap();
    let (_, digest) = decode_asn1_octet_str(&seq).unwrap();

    if oid != MD4_OID {
        return Err(SigError::UnsupportedDigest);
    }

    if digest.to_vec() == digest_verify {
        Ok(())
    } else {
        println!("mismatch {} {}", hex::encode(&digest.to_vec()), hex::encode(&digest_verify));
        Err(SigError::DigestMismatch)
    }
}

pub fn sign_rsa(key: &RSAPrivKey, msg: &[u8]) -> Vec<u8> {
    let digest = md4_digest(msg);

    let digest_info = encode_asn1_sequence(
        &[encode_asn1_oid(MD4_OID),
        encode_asn1_octet_str(&digest)]);
    
    // calculate length of n in octets
    let k = (key.n.bit_length() as usize + 7) / 8;

    let pad_len = k - 3 - digest_info.len();

    let mut enc_block = Vec::with_capacity(k);
    enc_block.push(0x00);
    enc_block.push(0x01); // Block type 0x01 means padding is 0xff
    enc_block.extend_from_slice(&vec![0xffu8; pad_len]);
    enc_block.push(0x00);
    enc_block.extend_from_slice(&digest_info);

    let x = Int::from_bytes(&enc_block);

    let y = decrypt_rsa(key, &x).unwrap();

    y.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let msg = b"foobar";

        let (pub_key, priv_key) = gen_rsa_pair(1024);

        let sig = sign_rsa(&priv_key, msg);

        verify_rsa(&pub_key, msg, &sig).unwrap();
    }
}
