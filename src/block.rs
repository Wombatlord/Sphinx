use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use bytemuck::bytes_of;

fn rol_u8(value: u8, shift: u8) -> u8 {
    (value << shift) | (value >> (8 - shift))
}

#[derive(Copy, Clone)]
pub struct Block<T> {
    pub l: T,
    pub r: T,
}

impl Block<u32> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = vec![];
        v.extend(bytes_of(&self.l));
        v.extend(bytes_of(&self.r));

        return v
    }
}


impl Block<u64> {
    pub fn round_fn(&self, val: u64, key: u8) -> u64 {
        Self::hash(&(Self::hash(&val) ^ Self::hash(&key)))
    }

    #[allow(unused_assignments)]
    pub fn run_n_rounds(&mut self, n: u8, key: u8, encrypt: bool) -> &Block<u64> {
        let cmp = match encrypt {
            true => 0,
            false => 1,
        };
        for i in 0..n {
            let ki = match encrypt {
                true => rol_u8(key, i),
                false => rol_u8(key, n - 1 - i),
            };

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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = vec![];
        v.extend(bytes_of(&self.l));
        v.extend(bytes_of(&self.r));

        return v
    }
}
