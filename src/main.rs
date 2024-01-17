mod block;
mod cli;
mod io;

use argon2::Argon2;
use block::Block;
use bytemuck::bytes_of;
use clap::Parser;
use cli::Args;
use io::output_to_file;
use std::{
    collections::VecDeque,
    fs::{self, read},
    str::from_utf8,
};

fn u8_slice_to_u64(s: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = 8.min(s.len());
    buf[..len].copy_from_slice(&s[..len]);
    u64::from_ne_bytes(buf)
}

fn pad_bytes(mut pt: Vec<u8>) -> Vec<u8> {
    let mut pt_vec: Vec<u8> = vec![];
    let padding_required: usize = pt.len() % 16;

    if padding_required > 0 {
        println!("pad: {0}", 16 - padding_required);
        let space: u8 = 16 - padding_required as u8;
        for _ in 0..(16 - padding_required) {
            pt_vec.push(space);
        }
        pt.extend(pt_vec.into_iter());
    }

    return pt;
}

fn strip_padding(block: Block) -> Vec<u8> {
    // https://www.cryptosys.net/pki/manpki/pki_paddingschemes.html PKCS5

    // TODO: Padding runs across the block boundary now.
    // Change this to just take a vec of the final block bytes
    // Then no need to iterate over the sub block halves separately.

    let mut maybe_padded_l = bytes_of(&block.l).to_vec();
    let padding_amount_l = maybe_padded_l[maybe_padded_l.len() - 1];
    let b = maybe_padded_l.len() as u8 - padding_amount_l;
    println!("L: {maybe_padded_l:?}");
    for _ in b..maybe_padded_l.len() as u8 {
        maybe_padded_l.pop();
    }

    let mut maybe_padded_r = bytes_of(&block.r).to_vec();
    let padding_amount_r = maybe_padded_r[maybe_padded_r.len() - 1];
    let b = maybe_padded_r.len() as u8 - padding_amount_r;
    println!("R: {maybe_padded_r:?}");
    for _ in b..maybe_padded_r.len() as u8 {
        maybe_padded_r.pop();
    }

    maybe_padded_l.extend(maybe_padded_r);

    maybe_padded_l
}


fn strip_padding_vec(mut vec: Vec<u8>) -> Vec<u8> {
    let padding_indication_byte = vec[vec.len() - 1];
    let b = vec.len() as u8 - padding_indication_byte;

    for _ in b..vec.len() as u8{
        vec.pop();
    }

    return vec;
}

fn pack_u8s_to_u64(padded_pt_vec: Vec<u8>, u64_vec: &mut VecDeque<u64>) {
    // Take 8 bytes at a time from the byte slice of the plain text input
    for m in padded_pt_vec.chunks(8) {
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
        let pad_u64: u64 = u8_slice_to_u64(&[8u8; 8]);
        u64_vec.push_back(pad_u64);
    }
}

// KEY STUFF
// https://docs.rs/pbkdf2/latest/pbkdf2/
// https://crates.io/crates/hkdf
//
// gen key with one of these, then bit rotate the key by the round?
// https://levelup.gitconnected.com/learning-rust-rolling-bits-53b6b3b20d02
//
// https://github.com/mikepound/feistel/blob/master/feistel.py
//

fn main() {
    let args = Args::parse();

    let output_key_material: [u8; 32] = derive_key::<32>(&args);

    if let Some(path) = args.encrypt.as_deref() {
        encrypt(path, &output_key_material);
    }
    if let Some(path) = args.decrypt.as_deref() {
        let dec_blocks = decrypt(path, &output_key_material);

        // This is only terminal output related
        if args.verbose {
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
    }
}

fn derive_key<const B: usize>(args: &Args) -> [u8; B] {
    let password = args.key.as_bytes();
    let salt = b"example salt"; // Salt should be unique per password

    let mut output_key_material = [0u8; B]; // Can be any desired size

    Argon2::default()
        .hash_password_into(password, salt, &mut output_key_material)
        .expect("argon broke dawg");

    println!("{output_key_material:?}");
    output_key_material
}

fn key_slice(u64_encoded: &VecDeque<u64>, key: &[u8; 32]) -> (usize, Vec<u8>) {
    let required_blocks = u64_encoded.len() / 2;

    let kk = match required_blocks < key.len() {
        true => key[..required_blocks].to_vec(),
        false => key.to_vec(),
    };

    (required_blocks, kk)
}

fn decrypt(path: &str, key: &[u8; 32]) -> Vec<Block> {
    // deserialise cyphertext
    let bytes_from_ct_file = read(path).unwrap();
    let mut u64_encoded: VecDeque<u64> = vec![].into();
    pack_u8s_to_u64(bytes_from_ct_file, &mut u64_encoded);

    //key prep
    let (required_blocks, kk) = key_slice(&u64_encoded, key);
    // println!("{kk:?}");

    // un-cryptin'
    let mut dec_blocks: Vec<Block> = vec![];
    for _ in 0..required_blocks {
        let x = Block {
            l: u64_encoded.pop_front().unwrap(),
            r: u64_encoded.pop_front().unwrap(),
            stripped: 0,
        };

        dec_blocks.push(x)
    }

    // let key = [6u64, 5, 4, 3, 2, 1];
    for idx in 0..dec_blocks.len() {
        let block_key = kk[idx % kk.len()];
        dec_blocks[idx].run_n_rounds(4, block_key, false);
    }
    // let stripped = strip_padding(dec_blocks[dec_blocks.len() - 1]);

    let end_block = dec_blocks[dec_blocks.len() - 1];
    let mut end_block_vec_l = bytes_of(&end_block.l).to_vec();
    let end_block_vec_r = bytes_of(&end_block.r).to_vec();
    end_block_vec_l.extend(end_block_vec_r);

    let stripped = strip_padding_vec(end_block_vec_l);


    output_to_file(&mut dec_blocks, Some(stripped), "decrypted_file");
    dec_blocks
}

fn encrypt(path: &str, key: &[u8; 32]) {
    let pt = fs::read(path).unwrap();
    let padded = pad_bytes(pt);

    
    let mut u64_encoded: VecDeque<u64> = vec![].into();
    pack_u8s_to_u64(padded, &mut u64_encoded);

    // key prep
    let (_, kk) = key_slice(&u64_encoded, key);
    println!("{kk:?}");

    // cryptin'
    let mut enc_blocks: Vec<Block> = vec![];

    while let (Some(l), Some(r)) = (u64_encoded.pop_front(), u64_encoded.pop_front()) {
        enc_blocks.push(Block { l, r, stripped: 0 })
    }

    for idx in 0..enc_blocks.len() {
        let block_key = kk[idx % kk.len()];
        enc_blocks[idx].run_n_rounds(4, block_key, true);
    }

    // serialising cyphertext
    output_to_file(&mut enc_blocks, None, "encrypted_file");
}
