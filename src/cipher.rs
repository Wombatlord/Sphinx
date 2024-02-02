use std::fs;

use crate::{io::output_to_file, packer::{PackBytes, Packer}, mode_of_operation::ModeOfOperation, feistel::FeistelNetwork};


#[derive(Debug, Clone, Copy)]
pub struct Cipher<M, F>(pub M, pub F) where
    M: ModeOfOperation, 
    F: FeistelNetwork;

impl<M, F> Cipher<M, F> where 
    M: ModeOfOperation,
    F: FeistelNetwork {
        
    pub fn parse<P: PackBytes<u32>>(&self, path: &str) -> Vec<u8> {
        let mut contents: Vec<u8> = vec![];
        let read = fs::read(path);
        match read {
            Ok(v) => {contents = v},
            Err(e) => eprintln!("{e}")
        }
        
        return contents;
    }

    pub fn encrypt<P: PackBytes<u32>>(&self, message: Vec<u8>) {
        let padded: Vec<u8> = Packer::pad_bytes(message, 8);
        
        let u32_encoded = P::u8s_to_vecdeque(padded);

        let blocks = self.0.encrypt(u32_encoded, &self.1);
        let mut enc_bytes = vec![];

        for b in blocks {
            enc_bytes.extend(b.to_bytes())
        }
        output_to_file(enc_bytes, "encrypted_file");
    }

    pub fn decrypt<P: PackBytes<u32>>(&self, message: Vec<u8>) {
        let u32_encoded = P::u8s_to_vecdeque(message);
        
        let blocks = self.0.decrypt(u32_encoded, &self.1);

        let mut dec_bytes = vec![];
    
        for b in blocks {
            dec_bytes.extend(b.to_bytes())
        }
        match Packer::strip_padding_vec(dec_bytes) {
            Ok(v) => output_to_file(v, "decrypted_file"),
            Err(e) => eprintln!("{}", e) 
        }
    }
}