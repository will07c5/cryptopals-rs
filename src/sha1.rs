// from pseudo code at https://en.wikipedia.org/wiki/SHA-1

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use crate::ops::xor;

// Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
//         ml, the message length, which is a 64-bit quantity, and
//         hh, the message digest, which is a 160-bit quantity.
// Note 2: All constants in this pseudo code are in big endian.
//         Within each word, the most significant byte is stored in the leftmost byte position



pub const CHUNK_SIZE: usize = 64;
pub const HASH_SIZE: usize = 20;

pub fn sha1_digest_chunk(h: &mut [u32; 5], chunk: &[u8]) {
	assert_eq!(chunk.len(), CHUNK_SIZE);

	let mut rdr = Cursor::new(chunk);
	let mut w = [0u32; 80];

	// Process the message in successive 512-bit chunks:
	// break message into 512-bit chunks
	// for each chunk
	//     break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
	for wi in w.iter_mut().take(16) {
		*wi = rdr.read_u32::<BigEndian>().unwrap();
	}

	//     Extend the sixteen 32-bit words into eighty 32-bit words:
	//     for i from 16 to 79
	//         w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
	for i in 16..80 {
		w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
	}

	//     Initialize hash value for this chunk:
	//     a = h0
	//     b = h1
	//     c = h2
	//     d = h3
	//     e = h4
	let mut new_h = *h;

	//     Main loop:[3][55]
	//     for i from 0 to 79
	
	for (i, wi) in w.iter().enumerate() {
		//         if 0 ≤ i ≤ 19 then
		//             f = (b and c) or ((not b) and d)
		//             k = 0x5A827999
		//         else if 20 ≤ i ≤ 39
		//             f = b xor c xor d
		//             k = 0x6ED9EBA1
		//         else if 40 ≤ i ≤ 59
		//             f = (b and c) or (b and d) or (c and d) 
		//             k = 0x8F1BBCDC
		//         else if 60 ≤ i ≤ 79
		//             f = b xor c xor d
		//             k = 0xCA62C1D6
		let (f, k) = match i {
			0...19 => ((new_h[1] & new_h[2]) | ((!new_h[1]) & new_h[3]), 0x5A82_7999),
			20...39 => ((new_h[1] ^ new_h[2] ^ new_h[3]), 0x6ED9_EBA1),
			40...59 => ((new_h[1] & new_h[2]) | (new_h[1] & new_h[3]) | (new_h[2] & new_h[3]), 0x8F1B_BCDC),
			60...79 => (new_h[1] ^ new_h[2] ^ new_h[3], 0xCA62_C1D6),
			_ => panic!("impossible"),
		};

		//         temp = (a leftrotate 5) + f + e + k + w[i]
		//         e = d
		//         d = c
		//         c = b leftrotate 30
		//         b = a
		//         a = temp

		let tmp = new_h[0].rotate_left(5).wrapping_add(f).wrapping_add(new_h[4]).wrapping_add(k).wrapping_add(*wi);
		new_h[4] = new_h[3];
		new_h[3] = new_h[2];
		new_h[2] = new_h[1].rotate_left(30);
		new_h[1] = new_h[0];
		new_h[0] = tmp;

	}

	//     Add this chunk's hash to result so far:
	//     h0 = h0 + a
	//     h1 = h1 + b 
	//     h2 = h2 + c
	//     h3 = h3 + d
	//     h4 = h4 + e

	for (old_v, new_v) in h.iter_mut().zip(new_h.iter()) {
		*old_v = (*old_v).wrapping_add(*new_v);
	}

}

pub fn sha1_digest(data: &[u8]) -> Vec<u8> {
	// Pre-processing:
	// append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
	// append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
	//    is congruent to −64 ≡ 448 (mod 512)
	// append ml, the original message length, as a 64-bit big-endian integer. 
	//    Thus, the total length is a multiple of 512 bits.
	let mut final_data = Vec::new();
	final_data.extend_from_slice(&data);	
	final_data.push(0x80);

	let padding = ((CHUNK_SIZE - final_data.len() % CHUNK_SIZE) + CHUNK_SIZE - 8) % CHUNK_SIZE;

	final_data.extend_from_slice(&vec![0u8; padding]);
	final_data.write_u64::<BigEndian>((data.len() * 8) as u64).unwrap();

	assert_eq!(final_data.len() % CHUNK_SIZE, 0);

	// Initialize variables:

	// h0 = 0x67452301
	// h1 = 0xEFCDAB89
	// h2 = 0x98BADCFE
	// h3 = 0x10325476
	// h4 = 0xC3D2E1F0
	let mut h = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
	for chunk in final_data.chunks(CHUNK_SIZE) {
		sha1_digest_chunk(&mut h, &chunk);
	}

	// Produce the final hash value (big-endian) as a 160-bit number:
	// hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4
	let mut hh = Vec::new();

	for val in h.iter() {
		hh.write_u32::<BigEndian>(*val).unwrap();
	}

	hh
}

pub fn sha1_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
	// if key is too long, shorten it by hashing
	let mut key_pad =
		if key.len() > CHUNK_SIZE {
			sha1_digest(&key)
		} else {
			key.to_vec()
		};

	// pad key to block size
	while key_pad.len() < CHUNK_SIZE {
		key_pad.push(0);
	}

	let mut o_key_pad = xor(&key, &[0x5c; CHUNK_SIZE]);
	let mut i_key_pad = xor(&key, &[0x36; CHUNK_SIZE]);

	// hash inner
	i_key_pad.extend_from_slice(&data);
	let i_hash = sha1_digest(&i_key_pad);

	// hash outer
	o_key_pad.extend_from_slice(&i_hash);

	sha1_digest(&o_key_pad)
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









