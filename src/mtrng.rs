const W: u32 = 32;
pub const N: usize = 624;
const M: usize = 397;
//const R: usize = 31;

const A: u32 = 0x9908B0DF;

const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;

const S: u32 = 7;
const B: u32 = 0x9D2C5680;

const T: u32 = 15;
const C: u32 = 0xEFC60000;

const L: u32 = 18;

const F: u32 = 1812433253;

pub fn temper(x: u32) -> u32 {
    let y = x ^ ((x >> U) & D);
    let yp = y ^ ((y << S) & B);
    let ypp = yp ^ ((yp << T) & C);
    
    ypp ^ (ypp >> L)
}

pub fn untemper(z: u32) -> u32 {
    // This solution is specific to these values. It is not general.
    let ypp = z ^ (z >> L);
    let yp = ypp ^ ((ypp << T) & C);
    let mut y = yp;
    y = yp ^ ((y << S) & B);
    y = yp ^ ((y << S) & B);
    y = yp ^ ((y << S) & B);
    y = yp ^ ((y << S) & B);
    let mut x = y;
    x = y ^ ((x >> U) & D);
    x = y ^ ((x >> U) & D);

    x
}


pub struct MTRNG {
    x: [u32; N]
}

impl MTRNG {
    pub fn new(seed: u32) -> MTRNG {
        let mut x = [0u32; N];
        x[0] = seed;

        for i in 1..N {
            x[i] = F.wrapping_mul(x[i-1] ^ (x[i-1] >> (W - 2))).wrapping_add(i as u32);
        }

        MTRNG { x: x }
    }

    pub fn with_x(x: &[u32; N]) -> MTRNG {
        MTRNG { x: *x }
    }

    pub fn gen(&mut self) -> u32 {
        let mut next_x = (self.x[0] & 0xffff0000) | (self.x[1] & 0x0000ffff);

        if next_x & 1 == 0 {
            next_x >>= 1;
        } else {
            next_x = (next_x >> 1) ^ A
        }

        next_x = self.x[M] ^ next_x;

        self.x.rotate_left(1);
        self.x[self.x.len() - 1] = next_x;

        return temper(next_x);
    }
}


