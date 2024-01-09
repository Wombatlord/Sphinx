mod block;

use std::str::from_utf8;
use block::Block;


fn u8_slice_to_u64(s: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = 8.min(s.len());
    buf[..len].copy_from_slice(&s[..len]);
    u64::from_ne_bytes(buf)
}


fn padding(pt: &str) -> Vec<u8> {
    let mut ptb: Vec<u8> = pt.as_bytes().to_vec();
    let mut pt_vec: Vec<u8> = vec![];
    let padding_required: usize = pt.len() % 8;

    if padding_required > 0 {
        let space: &[u8] = " ".as_bytes();
        for _ in 0..(8 - padding_required) {
            pt_vec.push(space[0]);
        }
        ptb.extend(pt_vec.into_iter());
    }

    return ptb 
}

fn pack_u8s_to_u64(padded_pt_vec: Vec<u8>, u64_vec: &mut Vec<u64>) {
    for (i, _) in padded_pt_vec.iter().enumerate().step_by(8) {
        // Take 8 bytes at a time from the byte slice of the plain text input
        let m: &[u8] = &padded_pt_vec[i..i + 8];

        // convert 8 bytes to a u64 representation
        let as64: u64 = u8_slice_to_u64(m);

        // push into Vec<u64>
        u64_vec.push(as64)
    }
}


fn ensure_block_pairs(u64_vec: &mut Vec<u64>) {
    // Block.l and Block.r must both contain a u64,
    // If u64_vec is not divisible by 2, we need a "null" u64 to pair with the final Block.l
    if u64_vec.len() % 2 != 0 {
        let pad_u64: u64 = u8_slice_to_u64(&[0u8; 8]);
        u64_vec.push(pad_u64);
    }
}

fn main() {
    // Setup
    let plain_text3: &str = "sixteenbyteshere and more!";
    println!("Plain Text: \n{plain_text3}\n");

    let padded = padding(plain_text3);
    let mut u64_encoded: Vec<u64> = vec![];
    pack_u8s_to_u64(padded, &mut u64_encoded);
    ensure_block_pairs(&mut u64_encoded);

    println!("Plaintext Bytes as Vec<u64>: \n{u64_encoded:?}\n");

    // cryptin'
    // Take the first two u64s from vec containing u64 encoded bytes
    // 1 u64 = 8 bytes from the plaintext
    // So the first two u64s are the first 16 bytes of plaintext
    let key = [1u64,2,3,4,5,6];
    let mut x: Block = Block {
        l: u64_encoded[0],
        r: u64_encoded[1],
    };

    let block_0: Block = *x.run_n_rounds(0, 1, &key);
    x = Block {
        l: u64_encoded[2],
        r: u64_encoded[3],
    };
    let block_1: Block = *x.run_n_rounds(2, 3, &key);
    // Mimic serialising cyphertext
    let ct_l: String = format!("{0}", block_0.l);
    let ct_r: String = format!("{0}", block_0.r);
    let ct_l2: String = format!("{0}", block_1.l);
    let ct_r2: String = format!("{0}", block_1.r);
    let ct: String = format!("{ct_l}{ct_r}{ct_l2}{ct_r2}");

    let ct_ll1: &str = &ct[..19];
    let ct_rr1: &str = &ct[19..38];
    let ct_ll2: &str = &ct[38..57];
    let ct_rr2: &str = &ct[57..];
    println!("Cypher Text: {0}{1}{2}{3}", block_0.l, block_0.r, block_1.l, block_1.r);

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
    let undo_r4: u64 = x.round_fn(false, 4);
    let mut unxored: u64 = undo_r4 ^ x.l;
    x.l = x.r;
    x.r = unxored;

    let undo_r3: u64 = x.round_fn(true, 3);
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
