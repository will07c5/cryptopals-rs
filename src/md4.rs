use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

pub const CHUNK_SIZE: usize = 64;
pub const HASH_SIZE: usize = 16;

// Implemented based on the RFC (https://tools.ietf.org/html/rfc1320)

// NOTE: hasn't really been verified for correctness

pub fn md4_digest_chunk(abcd_in: &mut [u32; 4], chunk: &[u8]) {
    assert_eq!(chunk.len(), CHUNK_SIZE);

    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn op(
        func: fn (u32, u32, u32) -> u32,
        abcd: &mut [u32; 4],
        add_val: &[u32; 4],
        constant: u32,
        rot_val: &[u32; 4]) {
        for (av, rv) in add_val.iter().zip(rot_val.iter()) {
            abcd[0] = abcd[0].wrapping_add(func(abcd[1], abcd[2], abcd[3]))
                .wrapping_add(*av)
                .wrapping_add(constant)
                .rotate_left(*rv);

            abcd.rotate_right(1);
        }
    }

    let mut x = [0u32; 16];

    let mut rdr = Cursor::new(chunk);
    for xi in x.iter_mut() {
        *xi = rdr.read_u32::<LittleEndian>().unwrap();
    }

    let mut abcd = abcd_in.clone();

    // Round 1
    for i in (0..16).step_by(4) {
        op(f, &mut abcd, &[x[i], x[i + 1], x[i + 2], x[i + 3]], 0, &[3, 7, 11, 19]);
    }

    // round 2
    for i in (0..16).step_by(4) {
        op(g, &mut abcd, &[x[i], x[i + 1], x[i + 2], x[i + 3]], 0x5a82_7999, &[3, 5, 9, 13]);
    }

    // round 3
    for i in (0..16).step_by(4) {
        op(h, &mut abcd, &[x[i], x[i + 1], x[i + 2], x[i + 3]], 0x6ed9_eba1, &[3, 9, 11, 15]);
    }

    for (val_in, val) in abcd_in.iter_mut().zip(abcd.iter()) {
        *val_in = (*val_in).wrapping_add(*val);
    }
}

pub fn md4_digest(data: &[u8]) -> Vec<u8> {
    let mut final_data = Vec::new();
    final_data.extend_from_slice(&data);    
    final_data.push(0x80);

    let padding = ((CHUNK_SIZE - final_data.len() % CHUNK_SIZE) + CHUNK_SIZE - 8) % CHUNK_SIZE;

    final_data.extend_from_slice(&vec![0u8; padding]);
    final_data.write_u64::<LittleEndian>((data.len() * 8) as u64).unwrap();

    assert_eq!(final_data.len() % CHUNK_SIZE, 0);

    let mut abcd = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    for chunk in final_data.chunks(CHUNK_SIZE) {
        md4_digest_chunk(&mut abcd, &chunk);
    }

    let mut final_hash = Vec::new();

    for val in abcd.iter() {
        final_hash.write_u32::<LittleEndian>(*val).unwrap();
    }

    final_hash
}
