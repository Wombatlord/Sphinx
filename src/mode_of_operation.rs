use crate::{feistel::FeistelNetwork, block::Block};
use std::collections::VecDeque;

pub trait ModeOfOperation {
    fn encrypt(&self, message: VecDeque<u32>, boxes: &impl FeistelNetwork) -> Vec<Block<u32>>;
    fn decrypt(&self, message: VecDeque<u32>, boxes: &impl FeistelNetwork) -> Vec<Block<u32>>;
}