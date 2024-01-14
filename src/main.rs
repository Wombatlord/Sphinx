mod block;
mod io;

use block::Block;
use io::{output_to_file, file_shenanigans};
use std::{collections::VecDeque, fs::read_to_string, str::from_utf8};

fn u8_slice_to_u64(s: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = 8.min(s.len());
    buf[..len].copy_from_slice(&s[..len]);
    u64::from_ne_bytes(buf)
}

fn padding(pt: String) -> Vec<u8> {
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

    return ptb;
}

fn pack_u8s_to_u64(padded_pt_vec: Vec<u8>, u64_vec: &mut VecDeque<u64>) {
    for (i, _) in padded_pt_vec.iter().enumerate().step_by(8) {
        // Take 8 bytes at a time from the byte slice of the plain text input
        let m: &[u8] = &padded_pt_vec[i..i + 8];

        // convert 8 bytes to a u64 representation
        let as64: u64 = u8_slice_to_u64(m);

        // push into Vec<u64>
        u64_vec.push_back(as64)
    }
}

fn ensure_block_pairs(u64_vec: &mut VecDeque<u64>) {
    // Block.l and Block.r must both contain a u64,
    // If u64_vec is not divisible by 2, we need a "null" u64 to pair with the final Block.l
    if u64_vec.len() % 2 != 0 {
        let pad_u64: u64 = u8_slice_to_u64(&[0u8; 8]);
        u64_vec.push_back(pad_u64);
    }
}

fn main() {
    encrypt("input.txt");

    let dec_blocks = decrypt("as_bytes.txt");

    // terminal output
    let mut final_dec = vec![];
    for bl in dec_blocks {
        let l = u64::to_ne_bytes(bl.l);
        let r = u64::to_ne_bytes(bl.r);
        final_dec.push(l);
        final_dec.push(r);
    }
    let f = final_dec.concat();

    println!("Decrypted:\t{0}", from_utf8(&f).unwrap())
}

fn decrypt(path: &str) -> Vec<Block> {
    // deserialise cyphertext
    let bytes_from_ct_file = file_shenanigans(path);
    let mut u64_encoded: VecDeque<u64> = vec![].into();
    pack_u8s_to_u64(bytes_from_ct_file, &mut u64_encoded);
    let required_blocks = u64_encoded.len() / 2;

    // un-cryptin'
    let mut dec_blocks: Vec<Block> = vec![];
    for _ in 0..required_blocks {
        let x = Block {
            l: u64_encoded.pop_front().unwrap(),
            r: u64_encoded.pop_front().unwrap(),
        };

        dec_blocks.push(x)
    }

    let key = [6u64, 5, 4, 3, 2, 1];
    for block in 0..dec_blocks.len() {
        dec_blocks[block].run_n_rounds(0, 5, &key, true);
    }
    output_to_file(&dec_blocks, "decrypted.txt", true);
    dec_blocks
}

fn encrypt(path: &str) {
    let plain_text3: String = read_to_string(path).unwrap();
    let padded = padding(plain_text3);
    let mut u64_encoded: VecDeque<u64> = vec![].into();

    pack_u8s_to_u64(padded, &mut u64_encoded);
    ensure_block_pairs(&mut u64_encoded);

    // cryptin'
    let required_blocks = u64_encoded.len() / 2;
    let mut enc_blocks: Vec<Block> = vec![];
    for _ in 0..required_blocks {
        let x = Block {
            l: u64_encoded.pop_front().unwrap(),
            r: u64_encoded.pop_front().unwrap(),
        };

        enc_blocks.push(x)
    }

    let key = [1u64, 2, 3, 4, 5, 6];
    for block in 0..enc_blocks.len() {
        enc_blocks[block].run_n_rounds(0, 5, &key, false);
    }

    // serialising cyphertext
    output_to_file(&enc_blocks, "as_bytes.txt", false);
}
