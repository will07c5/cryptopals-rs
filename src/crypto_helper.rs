// convenience wrappers for crypto library

use crypto::aes::{cbc_encryptor, cbc_decryptor, KeySize};
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, ReadBuffer, WriteBuffer};

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