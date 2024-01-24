use std::{collections::VecDeque, sync::mpsc};

use crate::{block::Block, key_fncs::key_segment};

#[derive(Clone)]
pub struct Payload(pub usize, pub Vec<Block<u64>>);



pub struct BlockSpan {
    pub idx: usize,
    pub start: usize,
    span: VecDeque<u64>,
    key_span: Vec<u8>,
    output_channel: mpsc::Sender<Payload>,
}

impl BlockSpan {
    pub fn consume(
        idx: usize,
        length: usize,
        start: usize,
        msg: &mut VecDeque<u64>,
        ks: &[u8],
        output: mpsc::Sender<Payload>,
    ) -> Self {
        let to_consume = usize::min(length, msg.len());
        let mut consumed: VecDeque<u64> = VecDeque::new();
        for _ in 0..to_consume * 2 {
            let Some(item) = msg.pop_front() else {
                break;
            };
            consumed.push_back(item);
        }
        Self {
            idx,
            start,
            span: consumed,
            key_span: ks.into(),
            output_channel: output,
        }
    }

    pub fn do_work(&mut self) {
        let mut enc_blocks: Vec<Block<u64>> = vec![];
        while let (Some(l), Some(r)) = (self.span.pop_front(), self.span.pop_front()) {
            enc_blocks.push(Block { l, r })
        }
        for idx in self.start..enc_blocks.len() {
            let block_key = key_segment(&self.key_span, idx);
            enc_blocks[idx].run_n_rounds(4, block_key, true);
        }

        self.output_channel
            .send(Payload(self.idx, enc_blocks))
            .unwrap();
    }
}
