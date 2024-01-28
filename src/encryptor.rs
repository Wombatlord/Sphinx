use std::{collections::VecDeque, fs};

use crate::{io::output_to_file, packer::{PackBytes, Packer}, mode_of_operation::ModeOfOperation, feistel::FeistelNetwork};


#[derive(Debug, Clone, Copy)]
pub struct Encryptor<M, F>(pub M, pub F) where
    M: ModeOfOperation, 
    F: FeistelNetwork;

impl<M, F> Encryptor<M, F> where 
    M: ModeOfOperation,
    F: FeistelNetwork {
        
    pub fn parse<P: PackBytes<u32>>(&self, path: &str) -> VecDeque<u32> {
        let pt: Vec<u8> = fs::read(path).unwrap();
        let padded: Vec<u8> = Packer::pad_bytes(pt, 8);
        
        let mut u32_encoded: VecDeque<u32> = vec![].into();
        P::u8s_to_vecdeque(padded, &mut u32_encoded);

        return u32_encoded;
    }

    pub fn encrypt(&self, message: VecDeque<u32>) {   
        let blocks = self.0.encrypt(message, &self.1);
        let mut enc_bytes = vec![];
    
        for b in blocks {
            enc_bytes.extend(b.to_bytes())
        }
        output_to_file(enc_bytes, "encrypted_file");
    }
}