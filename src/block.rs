use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn rol_u8(value: u8, shift: u8) -> u8 {
    (value << shift) | (value >> (8 - shift))
}

#[derive(Clone, Copy)]
pub struct Block {
    pub l: u64,
    pub r: u64,
    pub stripped: usize,
}

impl Block {
    pub fn round_fn(&self, val: u64, key: u8) -> u64 {
        Self::hash(&(Self::hash(&val) ^ Self::hash(&key)))
    }

    #[allow(unused_assignments)]
    pub fn run_n_rounds(&mut self, n: u8, key: u8, encrypt: bool) -> &Block {
        let cmp = match encrypt {
            true => 0,
            false => 1,
        };
        for i in 0..n {
            let ki = match encrypt {
                true => rol_u8(key, i),
                false => rol_u8(key, n - 1 - i),
            };

            // println!("{i}: {ki:0>8b}");
            if (i - n) % 2 == cmp {
                self.l ^= self.round_fn(self.r, ki);
            } else {
                self.r ^= self.round_fn(self.l, ki);
            }
        }

        return self;
    }

    fn hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }
}
