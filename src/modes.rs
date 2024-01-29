use std::collections::VecDeque;


use crate::{block::Block, feistel::FeistelNetwork, mode_of_operation::ModeOfOperation};
#[derive(Clone, Copy)]
pub struct CBC {
    pub init_vec: u64
}

impl ModeOfOperation for CBC {
    fn encrypt(&self, mut message: VecDeque<u32>, boxes: &impl FeistelNetwork) -> Vec<Block<u32>> {
        let init_vec = self.init_vec;
        let mut enc_blocks: Vec<Block<u32>> = vec![];
        
        let iv_l: u32 = (init_vec >> 32 & u64::MAX) as u32;
        let iv_r: u32 = (init_vec & u64::MAX) as u32;
        let iv_b: Block<u32> = Block{l: iv_l, r: iv_r};
        enc_blocks.push(iv_b);

        while let (Some(l), Some(r)) = (message.pop_front(), message.pop_front()) {
            enc_blocks.push(Block { l, r, })
        }
        
        enc_blocks[1].cbc_mode_xor(init_vec);
        boxes.run(&mut enc_blocks[1]);

        for idx in 2..enc_blocks.len() {
            let pt = enc_blocks[idx-1].full_block();
            enc_blocks[idx].cbc_mode_xor(pt);
            boxes.run(&mut enc_blocks[idx]);
        }


        // let mut windows = enc_blocks.windows(2);
        // enc_blocks[0].cbc_mode_xor(init_vec);
        // boxes.blowfish_feistel(&mut enc_blocks[0]);
        
        // windows.next(); // First block is handled above so advance the iterator before looping.

        // while let Some(&[block_0, mut block_1]) = windows.next() {
        //     let ct = block_0.full_block();
        //     block_1.cbc_mode_xor(ct);
        //     boxes.blowfish_feistel(&mut block_1);
        // }

        return enc_blocks;
    }

    fn decrypt(&self, mut message: VecDeque<u32>, boxes: &impl FeistelNetwork) -> Vec<Block<u32>> {
        let boxes = boxes.with_reversal();
        let mut dec_blocks: Vec<Block<u32>> = vec![];
        let init_vec = ((message.pop_front().unwrap() as u64) << 32) | message.pop_front().unwrap() as u64;
        
        while let (Some(l), Some(r)) = (message.pop_front(), message.pop_front()) {
            dec_blocks.push(Block { l, r, })
        }
        
        let cts = dec_blocks.clone();
        boxes.run(&mut dec_blocks[0]);
        dec_blocks[0].cbc_mode_xor(init_vec);
        for idx in 1..dec_blocks.len() {
            let ct = cts[idx-1].full_block();
            boxes.run(&mut dec_blocks[idx]);
            dec_blocks[idx].cbc_mode_xor(ct);
            
        }
    
        return dec_blocks;
    }
}

#[derive(Clone, Copy)]
pub struct ECB;

impl ModeOfOperation for ECB {
    fn encrypt(&self, mut message: VecDeque<u32>, boxes: &impl FeistelNetwork) -> Vec<Block<u32>> {
        let mut enc_blocks: Vec<Block<u32>> = vec![];
 
        while let (Some(l), Some(r)) = (message.pop_front(), message.pop_front()) {
            enc_blocks.push(Block { l, r, })
        }
        
        for idx in 0..enc_blocks.len() {
                boxes.run(&mut enc_blocks[idx]);
            }
    
        return enc_blocks;
    }

    fn decrypt(&self, message: VecDeque<u32>, boxes: &impl FeistelNetwork) -> Vec<Block<u32>> {
        self.encrypt(message, &boxes.with_reversal())
    }
}