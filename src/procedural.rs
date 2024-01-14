use std::collections::hash_map::DefaultHasher;
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
            false => calculate_hash(&y),
        };

        return hashed;
    }
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

pub fn convert(s: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = 8.min(s.len());
    buf[..len].copy_from_slice(&s[..len]);
    u64::from_ne_bytes(buf)
}

fn main() {
    // Setup
    let plain_text3: &str = "sixteenbyteshere and more!";
    println!("Plain Text: \n{plain_text3}\n");
    let mut ptb: &[u8] = plain_text3.as_bytes();
    println!("Plaintext Bytes: \n{ptb:?}\n");

    let req_padding: usize = plain_text3.len() % 8;
    println!("pad {req_padding}");
    let mut pt_vec: Vec<u8> = ptb.to_vec();

    if req_padding > 0 {
        let space = " ".as_bytes();
        for _ in 0..(8 - req_padding) {
            pt_vec.push(space[0]);
        }

        ptb = &pt_vec;
    }

    let mut xxx: Vec<u64> = vec![];
    for (i, _) in ptb.iter().enumerate().step_by(8) {
        // Take 8 bytes at a time from the byte slice of the plain text input
        let m: &[u8] = &ptb[i..i + 8];

        // convert 8 bytes to a u64 representation
        let as64: u64 = convert(m);

        // push into Vec<u64>
        xxx.push(as64)
    }
    if xxx.len() % 2 != 0 {
        let pad_u64: u64 = convert(&[0u8; 8]);
        xxx.push(pad_u64);
    }

    println!("Plaintext Bytes as Vec<u64>: \n{xxx:?}\n");

    // cryptin'
    // Take the first two u64s from the vec built in the above loop.
    // 1 u64 = 8 bytes from the plaintext
    // So the first two u64s are the first 16 bytes of plaintext
    let mut x: Block = Block {
        l: xxx[0],
        r: xxx[1],
    };

    let b1_r1: u64 = x.round_fn(false, 1 as u64);
    let mut xored: u64 = b1_r1 ^ x.l;

    x.l = x.r;
    x.r = xored;

    let b2_r2: u64 = x.round_fn(true, 2 as u64);
    xored = b2_r2 ^ x.r;

    x.r = x.l;
    x.l = xored;

    let block_1: Block = x;
    x = Block {
        l: xxx[2],
        r: xxx[3],
    };

    let b2_r1: u64 = x.round_fn(false, 1 as u64);
    let mut xored: u64 = b2_r1 ^ x.l;

    x.l = x.r;
    x.r = xored;

    let b2_r2: u64 = x.round_fn(true, 2 as u64);
    xored = b2_r2 ^ x.r;

    x.r = x.l;
    x.l = xored;

    // Mimic serialising cyphertext
    let ct_l: String = format!("{0}", block_1.l);
    let ct_r: String = format!("{0}", block_1.r);
    let ct_l2: String = format!("{0}", x.l);
    let ct_r2: String = format!("{0}", x.r);
    let ct: String = format!("{ct_l}{ct_r}{ct_l2}{ct_r2}");

    let ct_ll1: &str = &ct[..19];
    let ct_rr1: &str = &ct[19..38];
    let ct_ll2: &str = &ct[38..57];
    let ct_rr2: &str = &ct[57..];
    println!("Cypher Text: {0}{1}{2}{3}", block_1.l, block_1.r, x.l, x.r);

    // Mimic deserialise cyphertext into new block
    let ct_l2_u64: u64 = ct_ll2.parse().unwrap();
    let ct_r2_u64: u64 = ct_rr2.parse().unwrap();

    let ct_l_u64: u64 = ct_ll1.parse().unwrap();
    let ct_r_u64: u64 = ct_rr1.parse().unwrap();

    x = Block {
        l: ct_l2_u64,
        r: ct_r2_u64,
    };

    // un-cryptin'
    let undo_r4: u64 = x.round_fn(false, 2);
    let mut unxored: u64 = undo_r4 ^ x.l;
    x.l = x.r;
    x.r = unxored;

    let undo_r3: u64 = x.round_fn(true, 1);
    unxored = undo_r3 ^ x.r;

    x.r = x.l;
    x.l = unxored;

    let block_2: Block = x;

    x = Block {
        l: ct_l_u64,
        r: ct_r_u64,
    };

    let undo_r2: u64 = x.round_fn(false, 2);
    let mut unxored: u64 = undo_r2 ^ x.l;
    x.l = x.r;
    x.r = unxored;

    let undo_r1: u64 = x.round_fn(true, 1);
    unxored = undo_r1 ^ x.r;

    x.r = x.l;
    x.l = unxored;

    let dec_l: [u8; 8] = u64::to_ne_bytes(x.l);
    let dec_r: [u8; 8] = u64::to_ne_bytes(x.r);
    let dec_l2: [u8; 8] = u64::to_ne_bytes(block_2.l);
    let dec_r2: [u8; 8] = u64::to_ne_bytes(block_2.r);
    let dec: Vec<u8> = [dec_l, dec_r, dec_l2, dec_r2].concat();
    println!("Decrypted: {0}", from_utf8(&dec).unwrap())
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
