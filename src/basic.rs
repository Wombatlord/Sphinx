use std::collections::hash_map::DefaultHasher;
use std::fmt::LowerHex;
use std::hash::{Hash, Hasher};
use std::str::from_utf8;
struct Block {
    l: u64,
    r: u64,
}

impl Block {
    fn round_fn(&self, which_side: bool, key: u64) -> u64 {
        let x = &self.l + key;
        let y: u64 = &self.r + key;
        let hashed = match which_side {
            true => calculate_hash(&x),
            false => calculate_hash(&y)
        };

        return hashed
    }
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

fn most_basic() {
    let a: &[u8]  = b"a";
    let b: &[u8] = b"b";
    let c: u64 = a[0] as u64;
    let d: u64 = b[0] as u64;

    let mut x: Block = Block {l:c, r:d};
    
    let r1: u64 = x.round_fn(false, 1 as u64);
    let xored: u64 = r1^x.l as u64; 

    x.l = x.r;
    x.r = xored;
    
    let undo_r1: u64 = x.round_fn(true, 1 as u64);
    let unxored: u64 = undo_r1 ^ x.r as u64;
    
    let k: &[u8; 1] = &[c as u8];
    let k2: &[u8] = &[unxored as u8];
    println!("{0}", from_utf8(k).unwrap());
    println!("{0}", from_utf8(k2).unwrap())
}


// 0000_0101 (5)
// 0000_0001 (1)
// XOR
// 0000_0100 (4)

// 0000_0100 (4)
// 0000_0001 (1)
// XOR
// 0000_0101 (5)

// 0000_0100 (4)
// 0000_0101 (5)
// XOR
// 0000_0001 (1)
