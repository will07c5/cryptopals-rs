use ramp::int::{Int, RandomInt};
use rand;

// based on https://en.wikipedia.org/wiki/Miller–Rabin_primality_test
pub fn test_prime(n: &Int, k: usize) -> bool {
    assert!((n % Int::from(2)) != 0);
    assert!(n > &Int::from(3));
    assert!(k > 0);

    // println!("n = {}", n);

    let r = (n - Int::from(1)).trailing_zeros();
    let d = (n - Int::from(1)) / Int::from(1 << r);

    // println!("r = {}", r);
    // println!("d = {}", d);

    let mut rng = rand::thread_rng();
    'witness_loop: for _ in 0..k {
        // Pick integer in range [2, n - 2]
        // NOTE: gen_int_range picks an integer in the range [x, y) where
        // the upper bound is exclusive.
        let a = rng.gen_int_range(&Int::from(2), &(n - 1));

        let mut x = a.pow_mod(&d, &n);

        if x == 1 || x == n - 1 {
            continue;
        }

        for _ in 0..r - 1 {
            x = x.pow_mod(&Int::from(2), &n);

            if x == n - 1 {
                continue 'witness_loop;
            }
        }

        // Found composite
        return false;
    }

    return true;
}

pub fn gen_prime_with_seed(seed: &Int) -> Int {
    let mut test_num = seed.clone();

    // Ensure the number is odd
    test_num.set_bit(0, true);

    loop {
        // Check if current value is prime
        if test_prime(&test_num, 100) {
            return test_num;
        }

        // Subtract 2 since even numbers cannot be prime 
        test_num -= 2;
    }
}

pub fn gen_prime(bit_len: usize) -> Int {
    'outer: loop {
        // Pick a random value to test
        let mut seed = rand::thread_rng().gen_uint(bit_len); 

        // high bit should be one so that the bit length is correct
        seed.set_bit(bit_len as u32 - 1, true);

        assert_eq!(seed.bit_length(), bit_len as u32);

        let prime = gen_prime_with_seed(&seed);

        if prime.bit_length() < bit_len as u32 {
            continue 'outer;
        } else {
            return prime;
        }
    }
}

#[cfg(test)]
mod tests {
    use ramp::int::Int;
    use std::str::FromStr;

    #[test]
    fn test_prime() {
        let some_prime = Int::from_str("3125250912230709951372256510072774348164206451981118444862954305561681091773335180100000000000000000537").unwrap();
        assert_eq!(
            super::test_prime(&some_prime, 100),
            true);

        let some_composite = Int::from_str("560786457377928169298260996812364519560096887653607013500551151232236510539934714005415345900000000096357808083").unwrap();
        assert_eq!(
            super::test_prime(&some_composite, 100),
            false);
    }
}
