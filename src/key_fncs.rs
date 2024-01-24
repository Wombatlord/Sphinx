use std::collections::VecDeque;

use argon2::Argon2;

use crate::cli::Args;

pub fn derive_key<const B: usize>(args: &Args) -> [u8; B] {
    let password = args.key.as_bytes();
    let salt = b"example salt"; // Salt should be unique per password
    
    let mut output_key_material = [0u8; B]; // Can be any desired size
    
    Argon2::default()
        .hash_password_into(password, salt, &mut output_key_material)
        .expect("argon broke dawg");
    
    output_key_material
}

pub fn key_slice<const B: usize>(u64_encoded: &VecDeque<u64>, key: &[u8; B]) -> (usize, Vec<u8>) {
    let required_blocks = u64_encoded.len() / 2;
    
    let kk = match required_blocks < key.len() {
        true => key[..required_blocks].to_vec(),
        false => key.to_vec(),
    };
    
    (required_blocks, kk)
}

pub fn key_segment(key: &[u8], n: usize) -> u8 {
    key[n % key.len()]
}