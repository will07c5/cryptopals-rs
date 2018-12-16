use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

pub const CHUNK_SIZE: usize = 64;
pub const HASH_SIZE: usize = 16;

// Implemented based on the RFC (https://tools.ietf.org/html/rfc1320)

pub fn md4_digest_chunk(a_in: &mut u32, b_in: &mut u32, c_in: &mut u32, d_in: &mut u32, chunk: &[u8]) {
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

    let mut rdr = Cursor::new(chunk);
    let mut x = [0u32; 16];

    for xi in x.iter_mut() {
        *xi = rdr.read_u32::<LittleEndian>().unwrap();
    }

    let mut a = *a_in;
    let mut b = *b_in;
    let mut c = *c_in;
    let mut d = *d_in;

    // Round 1
    a = a.wrapping_add(f(b, c, d)).wrapping_add(x[0]).rotate_left(3);
    d = d.wrapping_add(f(a, b, c)).wrapping_add(x[1]).rotate_left(7);
    c = c.wrapping_add(f(d, a, b)).wrapping_add(x[2]).rotate_left(11);
    b = b.wrapping_add(f(c, d, a)).wrapping_add(x[3]).rotate_left(19);

    a = a.wrapping_add(f(b, c, d)).wrapping_add(x[4]).rotate_left(3);
    d = d.wrapping_add(f(a, b, c)).wrapping_add(x[5]).rotate_left(7);
    c = c.wrapping_add(f(d, a, b)).wrapping_add(x[6]).rotate_left(11);
    b = b.wrapping_add(f(c, d, a)).wrapping_add(x[7]).rotate_left(19);

    a = a.wrapping_add(f(b, c, d)).wrapping_add(x[8]).rotate_left(3);
    d = d.wrapping_add(f(a, b, c)).wrapping_add(x[9]).rotate_left(7);
    c = c.wrapping_add(f(d, a, b)).wrapping_add(x[10]).rotate_left(11);
    b = b.wrapping_add(f(c, d, a)).wrapping_add(x[11]).rotate_left(19);

    a = a.wrapping_add(f(b, c, d)).wrapping_add(x[12]).rotate_left(3);
    d = d.wrapping_add(f(a, b, c)).wrapping_add(x[13]).rotate_left(7);
    c = c.wrapping_add(f(d, a, b)).wrapping_add(x[14]).rotate_left(11);
    b = b.wrapping_add(f(c, d, a)).wrapping_add(x[15]).rotate_left(19);

    // round 2
    a = a.wrapping_add(g(b, c, d)).wrapping_add(x[0]).wrapping_add(0x5a827999).rotate_left(3);
    d = d.wrapping_add(g(a, b, c)).wrapping_add(x[4]).wrapping_add(0x5a827999).rotate_left(5);
    c = c.wrapping_add(g(d, a, b)).wrapping_add(x[8]).wrapping_add(0x5a827999).rotate_left(9);
    b = b.wrapping_add(g(c, d, a)).wrapping_add(x[12]).wrapping_add(0x5a827999).rotate_left(13);

    a = a.wrapping_add(g(b, c, d)).wrapping_add(x[1]).wrapping_add(0x5a827999).rotate_left(3);
    d = d.wrapping_add(g(a, b, c)).wrapping_add(x[5]).wrapping_add(0x5a827999).rotate_left(5);
    c = c.wrapping_add(g(d, a, b)).wrapping_add(x[9]).wrapping_add(0x5a827999).rotate_left(9);
    b = b.wrapping_add(g(c, d, a)).wrapping_add(x[13]).wrapping_add(0x5a827999).rotate_left(13);

    a = a.wrapping_add(g(b, c, d)).wrapping_add(x[2]).wrapping_add(0x5a827999).rotate_left(3);
    d = d.wrapping_add(g(a, b, c)).wrapping_add(x[6]).wrapping_add(0x5a827999).rotate_left(5);
    c = c.wrapping_add(g(d, a, b)).wrapping_add(x[10]).wrapping_add(0x5a827999).rotate_left(9);
    b = b.wrapping_add(g(c, d, a)).wrapping_add(x[14]).wrapping_add(0x5a827999).rotate_left(13);

    a = a.wrapping_add(g(b, c, d)).wrapping_add(x[3]).wrapping_add(0x5a827999).rotate_left(3);
    d = d.wrapping_add(g(a, b, c)).wrapping_add(x[7]).wrapping_add(0x5a827999).rotate_left(5);
    c = c.wrapping_add(g(d, a, b)).wrapping_add(x[11]).wrapping_add(0x5a827999).rotate_left(9);
    b = b.wrapping_add(g(c, d, a)).wrapping_add(x[15]).wrapping_add(0x5a827999).rotate_left(13);

    // round 3
    a = a.wrapping_add(h(b, c, d)).wrapping_add(x[0]).wrapping_add(0x6ed9eba1).rotate_left(3);
    d = d.wrapping_add(h(a, b, c)).wrapping_add(x[8]).wrapping_add(0x6ed9eba1).rotate_left(9);
    c = c.wrapping_add(h(d, a, b)).wrapping_add(x[4]).wrapping_add(0x6ed9eba1).rotate_left(11);
    b = b.wrapping_add(h(c, d, a)).wrapping_add(x[12]).wrapping_add(0x6ed9eba1).rotate_left(15);

    a = a.wrapping_add(h(b, c, d)).wrapping_add(x[2]).wrapping_add(0x6ed9eba1).rotate_left(3);
    d = d.wrapping_add(h(a, b, c)).wrapping_add(x[10]).wrapping_add(0x6ed9eba1).rotate_left(9);
    c = c.wrapping_add(h(d, a, b)).wrapping_add(x[6]).wrapping_add(0x6ed9eba1).rotate_left(11);
    b = b.wrapping_add(h(c, d, a)).wrapping_add(x[14]).wrapping_add(0x6ed9eba1).rotate_left(15);

    a = a.wrapping_add(h(b, c, d)).wrapping_add(x[1]).wrapping_add(0x6ed9eba1).rotate_left(3);
    d = d.wrapping_add(h(a, b, c)).wrapping_add(x[9]).wrapping_add(0x6ed9eba1).rotate_left(9);
    c = c.wrapping_add(h(d, a, b)).wrapping_add(x[5]).wrapping_add(0x6ed9eba1).rotate_left(11);
    b = b.wrapping_add(h(c, d, a)).wrapping_add(x[13]).wrapping_add(0x6ed9eba1).rotate_left(15);

    a = a.wrapping_add(h(b, c, d)).wrapping_add(x[3]).wrapping_add(0x6ed9eba1).rotate_left(3);
    d = d.wrapping_add(h(a, b, c)).wrapping_add(x[11]).wrapping_add(0x6ed9eba1).rotate_left(9);
    c = c.wrapping_add(h(d, a, b)).wrapping_add(x[7]).wrapping_add(0x6ed9eba1).rotate_left(11);
    b = b.wrapping_add(h(c, d, a)).wrapping_add(x[15]).wrapping_add(0x6ed9eba1).rotate_left(15);

    *a_in = (*a_in).wrapping_add(a);
    *b_in = (*b_in).wrapping_add(b);
    *c_in = (*c_in).wrapping_add(c);
    *d_in = (*d_in).wrapping_add(d);
}

pub fn md4_digest(data: &[u8]) -> Vec<u8> {
    let mut final_data = Vec::new();
    final_data.extend_from_slice(&data);    
    final_data.push(0x80);

    let padding = ((CHUNK_SIZE - final_data.len() % CHUNK_SIZE) + CHUNK_SIZE - 8) % CHUNK_SIZE;

    final_data.extend_from_slice(&vec![0u8; padding]);
    final_data.write_u64::<LittleEndian>((data.len() * 8) as u64).unwrap();

    assert_eq!(final_data.len() % CHUNK_SIZE, 0);

    let mut a = 0x67452301;
    let mut b = 0xefcdab89;
    let mut c = 0x98badcfe;
    let mut d = 0x10325476;

    for chunk in final_data.chunks(CHUNK_SIZE) {
        md4_digest_chunk(&mut a, &mut b, &mut c, &mut d, &chunk);
    }

    let mut final_hash = Vec::new();

    final_hash.write_u32::<LittleEndian>(a).unwrap();
    final_hash.write_u32::<LittleEndian>(b).unwrap();
    final_hash.write_u32::<LittleEndian>(c).unwrap();
    final_hash.write_u32::<LittleEndian>(d).unwrap();

    final_hash
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_sha1_digest() {
        let input = b"this is some text";
        let expected = "0393694d16b84deb612e47ce6252bd35f0d86c06";

        let digest = super::sha1_digest(input);
        let digest_hex = hex::encode(&digest);

        assert_eq!(digest_hex, expected);
    }
}