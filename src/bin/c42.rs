extern crate common;
extern crate ramp;
extern crate hex;

use common::rsa::{gen_rsa_pair, verify_rsa};
use common::ops::IntOpsExt;
use common::md4::md4_digest;
use common::asn1::*;
use ramp::Int;

const MD4_OID: &[usize] = &[1, 2, 840, 113549, 2, 4];
const MSG: &[u8] = b"hi mom";

fn main() {
	let (pub_key, _) = gen_rsa_pair(1024);

    let digest = md4_digest(MSG);

    println!("Digest {}", hex::encode(&digest));

    let digest_info = encode_asn1_sequence(
        &[encode_asn1_oid(MD4_OID),
        encode_asn1_octet_str(&digest)]);

	println!("{}", pub_key.n.bit_length());

	let k = (pub_key.n.bit_length() as usize + 7) / 8;

	let pad_len = k - 3 - digest_info.len();

	let mut enc_block = Vec::with_capacity(k);
	enc_block.push(0x00);
	enc_block.push(0x01); // Block type 0x01 means padding is 0xff
	enc_block.push(0xff);
	enc_block.push(0x00);
	enc_block.extend_from_slice(&digest_info);
	enc_block.extend_from_slice(&vec![0xffu8; pad_len]);

    println!("Block {}", hex::encode(&enc_block));

	let mut enc_block_int = Int::from_bytes(&enc_block);

    println!("Block int {}", enc_block_int);

	let forged_sig = enc_block_int.nth_root(3);

    println!("Root {}", forged_sig);

	verify_rsa(&pub_key, MSG, &forged_sig.to_bytes()).unwrap();
}
