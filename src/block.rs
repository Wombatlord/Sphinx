use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub struct ArrayBlock {
    fields: [u64; 2],
}

impl ArrayBlock {
    fn take_from(data: &mut Vec<u8>) -> Self {
        let mut bytes: Vec<u8> = vec![];
        let mut i = 0;
        while let Some(b) = data.pop() {
            if i == 16 {
                break;
            }
            bytes.push(b);
            i += 1;
        }

        let len = usize::min(bytes.len(), 16);
        for _ in len..16 {
            bytes.push(0);
        }

        let mut pair: [u64; 2] = [0, 0];
        for (i, &b) in bytes.iter().enumerate() {
            let offset = i % 8;
            let index = i / 8;
            pair[index] &= (b as u64) << (offset * 8);
        }

        Self::new(pair)
    }

    fn new(data: [u64; 2]) -> Self {
        Self { fields: data }
    }

    fn hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    fn round_func(key: u64, block: u64) -> u64 {
        Self::hash(&(Self::hash(&key) ^ Self::hash(&block)))
    }

    fn round(&mut self, key: u64) {
        self.fields[0] ^= Self::round_func(key, self.fields[1]);
        let [a, b] = self.fields;
        self.fields = [b, a];
    }

    fn do_rounds(&mut self, keys: &[u64]) -> [u8; 16] {
        keys.iter().for_each(|&k| self.round(k));

        let mut output = [0u8; 16];
        for i in 0..16 {
            let offset = i % 8;
            let index = i / 8;
            let b = ((self.fields[index] >> (offset * 8)) % 255) as u8;
            output[i] = b;
        }

        return output;
    }
}

pub fn scratch() -> bool {
    let mut data = Vec::from("the quick brown turd flew into the slack gob".as_bytes());
    let mut enc: Vec<u8> = vec![];
    let keys: [u64; 10] = [0; 10];
    while data.len() > 0 {
        let mut block = ArrayBlock::take_from(&mut data);
        enc.append(&mut Vec::from(block.do_rounds(&keys)));
    }

    println!("{enc:?}");

    let mut data = enc;
    let mut enc2: Vec<u8> = vec![];
    let keys: [u64; 10] = [0; 10];
    while data.len() > 0 {
        let mut block = ArrayBlock::take_from(&mut data);
        enc2.append(&mut Vec::from(block.do_rounds(&keys)));
    }

    println!("{enc2:?}");
    return true;
}

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
    pub fn run_n_rounds(&mut self, start: usize, stop: usize, key: &[u64], flag: bool) -> &Block {
        let mut flag = flag;
        for i in start..=stop {
            if !flag {
                self.l ^= self.round_fn(self.r, key[i]);
            } else {
                self.r ^= self.round_fn(self.l, key[i]);
            }
            flag = !flag
        }
        return self;
    }

    fn hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }
}
