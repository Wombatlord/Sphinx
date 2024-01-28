use std::{collections::VecDeque, fs};

use crate::{mode_of_operation::ModeOfOperation, feistel::FeistelNetwork, io::output_to_file, packer::{PackBytes, Packer}};

#[derive(Debug, Clone, Copy)]
pub struct Decryptor<M: ModeOfOperation, B: FeistelNetwork>(pub M, pub B);

impl<M: ModeOfOperation, B: FeistelNetwork> Decryptor<M, B> {

    pub fn parse<P: PackBytes<u32>>(&self, path: &str) -> VecDeque<u32> {
        let ct: Vec<u8> = fs::read(path).unwrap();
        
        let mut u32_encoded: VecDeque<u32> = vec![].into();
        P::u8s_to_vecdeque(ct, &mut u32_encoded);

        return u32_encoded;
    }

    pub fn decrypt(&self, message: VecDeque<u32>) {
        let blocks = self.0.decrypt(message, &self.1);

        let mut dec_bytes = vec![];
    
        for b in blocks {
            dec_bytes.extend(b.to_bytes())
        }
        let pad_stripped: Vec<u8> = Packer::strip_padding_vec(dec_bytes);
        output_to_file(pad_stripped, "decrypted_file");
    }

}