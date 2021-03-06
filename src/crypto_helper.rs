// convenience wrappers for crypto library

use crypto::aes::{cbc_encryptor, cbc_decryptor, KeySize};
use crypto::aes::{ecb_encryptor, ecb_decryptor};
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, ReadBuffer, WriteBuffer};
use crypto::aessafe::AesSafe128Encryptor;
use crypto::symmetriccipher::BlockEncryptor;
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use crypto::mac::Mac;
use byteorder::{LittleEndian, WriteBytesExt};

pub const BLOCK_SIZE: usize = 16;

pub fn encrypt_cbc(key: &[u8], iv: &[u8], input: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), BLOCK_SIZE);
    assert_eq!(iv.len(), BLOCK_SIZE);
    assert_eq!(input.len() % BLOCK_SIZE, 0);

    let mut output = vec!(0u8; input.len());

    let mut encryptor = cbc_encryptor(KeySize::KeySize128, &key, &iv, NoPadding);
    let mut input_buf = RefReadBuffer::new(&input);
    let mut output_buf = RefWriteBuffer::new(&mut output);

    encryptor.encrypt(&mut input_buf, &mut output_buf, true).unwrap();

    output_buf.take_read_buffer().take_remaining().to_vec()
}

pub fn decrypt_cbc(key: &[u8], iv: &[u8], input: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), BLOCK_SIZE);
    assert_eq!(iv.len(), BLOCK_SIZE);
    assert_eq!(input.len() % BLOCK_SIZE, 0);

    let mut output = vec!(0u8; input.len());

    let mut decryptor = cbc_decryptor(KeySize::KeySize128, &key, &iv, NoPadding);
    let mut input_buf = RefReadBuffer::new(&input);
    let mut output_buf = RefWriteBuffer::new(&mut output);

    decryptor.decrypt(&mut input_buf, &mut output_buf, true).unwrap();

    output_buf.take_read_buffer().take_remaining().to_vec()
}

pub fn encrypt_ecb(key: &[u8], input: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), BLOCK_SIZE);
    assert_eq!(input.len() % BLOCK_SIZE, 0);

    let mut output = vec!(0u8; input.len());

    let mut encryptor = ecb_encryptor(KeySize::KeySize128, &key, NoPadding);
    let mut input_buf = RefReadBuffer::new(&input);
    let mut output_buf = RefWriteBuffer::new(&mut output);

    encryptor.encrypt(&mut input_buf, &mut output_buf, true).unwrap();

    output_buf.take_read_buffer().take_remaining().to_vec()
}

pub fn decrypt_ecb(key: &[u8], input: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), BLOCK_SIZE);
    assert_eq!(input.len() % BLOCK_SIZE, 0);

    let mut output = vec!(0u8; input.len());

    let mut decryptor = ecb_decryptor(KeySize::KeySize128, &key, NoPadding);
    let mut input_buf = RefReadBuffer::new(&input);
    let mut output_buf = RefWriteBuffer::new(&mut output);

    decryptor.decrypt(&mut input_buf, &mut output_buf, true).unwrap();

    output_buf.take_read_buffer().take_remaining().to_vec()
}

pub fn crypt_ctr(key: &[u8], nonce: u64, input: &[u8]) -> Vec<u8> {
    let encryptor = AesSafe128Encryptor::new(&key);
    let mut output = Vec::with_capacity(input.len());

    for (counter, chunk) in input.chunks(BLOCK_SIZE).enumerate() {
        let mut output_ks = [0u8; BLOCK_SIZE];
        let mut input = Vec::new();

        input.write_u64::<LittleEndian>(nonce).unwrap();
        input.write_u64::<LittleEndian>(counter as u64).unwrap();

        encryptor.encrypt_block(&input, &mut output_ks);

        output.extend(chunk.iter().zip(output_ks.iter()).map(|(b, k)| *b ^ *k));
    }

    output
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(data);
    let mut output_buf = vec![0u8; hmac.output_bytes()];
    hmac.raw_result(&mut output_buf);

    output_buf
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.input(data);
    let mut output_buf = vec![0u8; hasher.output_bytes()];
    hasher.result(&mut output_buf);

    output_buf
}