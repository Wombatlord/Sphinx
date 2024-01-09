use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy)]
pub struct Block {
    pub l: u64,
    pub r: u64,
}

impl Block {
    pub fn round_fn(&self, which_side: bool, key: u64) -> u64 {
        let x: u64 = &self.l + key;
        let y: u64 = &self.r + key;
        let hashed = match which_side {
            true => Block::calculate_hash(&x),
            false => Block::calculate_hash(&y),
        };

        return hashed;
    }

    #[allow(unused_assignments)]
    pub fn run_n_rounds(&mut self, start: usize, stop: usize, key: &[u64]) -> &Block {
        let mut flag = false;
        let mut xored = 0u64;
        for i in start..=stop {
            let round_fn_output: u64 = self.round_fn(flag, key[i]);
            
            if !flag {
                xored = round_fn_output ^ self.l;
            } else {
                xored = round_fn_output ^ self.r;
            }
            self.swap(xored, !flag);
            flag = !flag
        }
        return self;
    }

    pub fn swap(&mut self, xored: u64, which_side: bool) {
        fn swap_a(block: &mut Block, xored:u64) {
            block.l = block.r;
            block.r = xored;
        }
        
        fn swap_b(block: &mut Block, xored:u64) {
            block.r = block.l;
            block.l = xored;
        }

        match which_side {
            true => swap_a(self, xored),
            false => swap_b(self, xored)
        }
    }

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }
}


// Compiler happy with this but it doesn't work as expected
// pub fn swap(&mut self, xored: u64, which_side: bool) {
//     fn swap_a(mut block: Block, xored:u64) {
//         block.l = block.r;
//         block.r = xored;
//     }
    
//     fn swap_b(mut block: Block, xored:u64) {
//         block.r = block.l;
//         block.l = xored;
//     }

//     match which_side {
//         true => swap_a(*self, xored),
//         false => swap_b(*self, xored)
//     }
// }