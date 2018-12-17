extern crate common;
extern crate byteorder;

use common::md4::{md4_digest, md4_digest_chunk, HASH_SIZE, CHUNK_SIZE};
use std::io::{Write, Cursor};
use common::util::{random_bytes, print_hex};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};


const ORIG_MSG: &[u8] = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
const EVIL_SUFFIX: &[u8] = b";admin=true";

fn auth_internal(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut sha_input = Vec::new();

    sha_input.extend_from_slice(&key);
    sha_input.extend_from_slice(&msg);

    println!("Digest input");
    print_hex(&sha_input);

    md4_digest(&sha_input)
}

fn create(msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key = random_bytes(10);
    let sha = auth_internal(&key, &msg);

    let mut out = Vec::new();
    out.write_all(&sha).unwrap();
    out.write_all(&msg).unwrap();

    (key, out)
}

fn verify(key: &[u8], auth_msg: &[u8]) -> bool {
    let auth = &auth_msg[..HASH_SIZE];
    let msg = &auth_msg[HASH_SIZE..];

    let verify_auth = auth_internal(&key, &msg);

    auth.to_vec() == verify_auth
}

fn do_pad_msg(msg: &mut Vec<u8>, real_len: usize, fake_len: usize) {
    msg.push(0x80);

    let padding = ((CHUNK_SIZE - (real_len + 1) % CHUNK_SIZE) + CHUNK_SIZE - 8) % CHUNK_SIZE;

    msg.extend_from_slice(&vec![0u8; padding]);
    msg.write_u64::<LittleEndian>((fake_len * 8) as u64).unwrap();
}

fn main() {
    // Create original secret prefix message
    let (key, orig_auth_msg) = create(&ORIG_MSG);

    println!("Orig msg");
    print_hex(&orig_auth_msg);

    // Just double check that it passes verification
    assert_eq!(verify(&key, &orig_auth_msg), true);

    let hash = &orig_auth_msg[..HASH_SIZE];
    let mut hash_cursor = Cursor::new(hash);
    let mut abcd = [0u32; 4];
    for val in abcd.iter_mut() {
        *val = hash_cursor.read_u32::<LittleEndian>().unwrap();
    }

    // add padding and length to the modified message
    let orig_msg = &orig_auth_msg[HASH_SIZE..];
    let orig_msg_len = orig_msg.len() + 10; // orignal length + size of secret key
    let mut orig_msg_padded = Vec::new();
    orig_msg_padded.extend_from_slice(&orig_msg);
    do_pad_msg(&mut orig_msg_padded, orig_msg_len, orig_msg_len);

    let mut evil_msg = Vec::new();
    evil_msg.extend_from_slice(EVIL_SUFFIX);
    do_pad_msg(&mut evil_msg, EVIL_SUFFIX.len(), orig_msg_padded.len() + 10 + EVIL_SUFFIX.len());

    println!("Evil msg");
    print_hex(&evil_msg);

    // Hash new evil message
    md4_digest_chunk(&mut abcd, &evil_msg);

    // Prepend the hash
    let mut evil_auth_msg = Vec::new();
    for val in abcd.iter() {
        evil_auth_msg.write_u32::<LittleEndian>(*val).unwrap();
    }
    evil_auth_msg.extend_from_slice(&orig_msg_padded);
    evil_auth_msg.extend_from_slice(&EVIL_SUFFIX);

    println!("Evil auth msg");
    print_hex(&evil_auth_msg);

    // Make sure it still verifies
    assert_eq!(verify(&key, &evil_auth_msg), true);

    println!("OK");
}