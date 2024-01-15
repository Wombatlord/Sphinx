use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy)]
pub struct Block {
    pub l: u64,
    pub r: u64,
}

impl Block {
    pub fn round_fn(&self, val: u64, key: u64) -> u64 {
        Self::hash(&(Self::hash(&val) ^ Self::hash(&key)))
    }

    #[allow(unused_assignments)]
    pub fn run_n_rounds(&mut self, start: usize, stop: usize, key: &[u8], encrypt: bool) -> &Block {
        let cmp = match encrypt {
            true => 1,
            false => 0,
        };
        for i in start..=stop {
            if (i - start) % 2 == cmp {
                self.l ^= self.round_fn(self.r, key[i] as u64);
            } else {
                self.r ^= self.round_fn(self.l, key[i] as u64);
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
