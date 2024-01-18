mod block;
mod cli;
mod io;

use std::sync::mpsc;
use argon2::Argon2;
use block::Block;
use bytemuck::bytes_of;
use clap::Parser;
use cli::Args;
use io::output_to_file;
use std::{
    collections::VecDeque,
    thread,
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
        // println!("pad: {0}", 16 - padding_required);
        let space: u8 = 16 - padding_required as u8;
        for _ in 0..(16 - padding_required) {
            pt_vec.push(space);
        }
        pt.extend(pt_vec.into_iter());
    } else {
        for _ in 0..16 {
            pt.push(16 as u8)
        }
    }
    // println!("{pt:?}");
    return pt;
}

fn strip_padding_vec(mut vec: Vec<u8>) -> Vec<u8> {
    let padding_indication_byte = vec[vec.len() - 1];
    let b = vec.len() as u8 - padding_indication_byte;
    
    if b == 0 {
        for _ in 0..vec.len() {
            println!("POP");
            vec.pop();
        }
    } else {
        for _ in b..vec.len() as u8{
            vec.pop();
        }
    }
    
    println!("{:?}", vec);
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

fn main() {
    let args = Args::parse();

    let output_key_material: [u8; 32] = derive_key::<32>(&args);

    if let Some(path) = args.encrypt.as_deref() {
        encrypt(path, &output_key_material);
    }
    if let Some(path) = args.decrypt.as_deref() {
        decrypt(path, &output_key_material);
    }
}

fn derive_key<const B: usize>(args: &Args) -> [u8; B] {
    let password = args.key.as_bytes();
    let salt = b"example salt"; // Salt should be unique per password

    let mut output_key_material = [0u8; B]; // Can be any desired size

    Argon2::default()
        .hash_password_into(password, salt, &mut output_key_material)
        .expect("argon broke dawg");

    // println!("{output_key_material:?}");
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

fn decrypt(path: &str, key: &[u8; 32]) {
    // deserialise cyphertext
    let bytes_from_ct_file = read(path).unwrap();
    let mut u64_encoded: VecDeque<u64> = vec![].into();
    pack_u8s_to_u64(bytes_from_ct_file, &mut u64_encoded);

    //key prep
    let (required_blocks, kk) = key_slice(&u64_encoded, key);

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

    for idx in 0..dec_blocks.len() {
        let block_key = kk[idx % kk.len()];
        dec_blocks[idx].run_n_rounds(4, block_key, false);
    }

    let end_block = dec_blocks[dec_blocks.len() - 1];
    dec_blocks.pop();
    let mut end_block_vec_l = bytes_of(&end_block.l).to_vec();
    let end_block_vec_r = bytes_of(&end_block.r).to_vec();
    end_block_vec_l.extend(end_block_vec_r);

    let stripped = strip_padding_vec(end_block_vec_l);

    output_to_file(dec_blocks, Some(stripped), "decrypted_file");
}

fn encrypt(path: &str, key: &[u8; 32]) {
    let pt = fs::read(path).unwrap();
    let padded = pad_bytes(pt);
    
    let mut u64_encoded: VecDeque<u64> = vec![].into();
    pack_u8s_to_u64(padded, &mut u64_encoded);
    // key prep
    let (_, kk) = key_slice(&u64_encoded, key);

    // let enc_blocks = encrypt_in_blocks(u64_encoded, kk);
    let enc_blocks = parallel_encrypt_in_blocks(u64_encoded, kk, 4);

    // // cryptin'
    // let mut enc_blocks: Vec<Block> = vec![];

    // while let (Some(l), Some(r)) = (u64_encoded.pop_front(), u64_encoded.pop_front()) {
    //     enc_blocks.push(Block { l, r, stripped: 0 })
    // }

    // for idx in 0..enc_blocks.len() {
    //     let block_key = kk[idx % kk.len()];
    //     enc_blocks[idx].run_n_rounds(4, block_key, true);
    // }

    // serialising cyphertext
    output_to_file(enc_blocks, None, "encrypted_file");
}

struct BlockSpan {
    pub idx: usize,
    pub start: usize,
    span: VecDeque<u64>,
    key_span: Vec<u8>,
    output_channel: mpsc::Sender<Payload>,
}

impl BlockSpan {
    fn consume(idx: usize, length: usize, start: usize, msg: &mut VecDeque<u64>, ks: &[u8], output: mpsc::Sender<Payload>) -> Self {
        let to_consume = usize::min(length, msg.len());
        let mut consumed: VecDeque<u64> = VecDeque::new();
        for _ in 0..to_consume*2 {
            let Some(item) = msg.pop_front() else { break; };
            consumed.push_back(item);
        }
        println!("sp: {:?}", consumed.len());
        Self {
            idx,
            start,
            span: consumed,
            key_span: ks.into(), 
            output_channel: output
        }
    }

    fn len(&self) -> usize {
        self.span.len()
    }

    fn next_start(&self) -> usize {
        self.start + self.len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn do_work(&mut self) {
        let mut enc_blocks: Vec<Block> = vec![];
        while let (Some(l), Some(r)) = (self.span.pop_front(), self.span.pop_front()) {
            enc_blocks.push(Block { l, r, stripped: 0 })
        }
        println!("SPAN LEN: {}", enc_blocks.len());
        for idx in self.start..enc_blocks.len() { // <<< changed from self.start..self.next_start
            let block_key = key_segment(&self.key_span, idx);
            enc_blocks[idx].run_n_rounds(4, block_key, true);
        }

        self.output_channel.send(Payload(self.idx, enc_blocks)).unwrap();
    }
}

#[derive(Clone)]
struct Payload(usize, Vec<Block>);


fn key_segment(key: &[u8], n: usize) -> u8 {
    key[n % key.len()]
}

fn parallel_encrypt_in_blocks(mut message: VecDeque<u64>, ks: Vec<u8>, mut span_size: usize) -> Vec<Block>  {
    // Prep thy threads foul imp!
    let mut spans: VecDeque<VecDeque<u64>> = VecDeque::new();
    while message.len() > 0 {
        let mut span = VecDeque::new();
        for _ in 0..span_size*16 { // changed from 2
            let Some(chunk) = message.pop_front() else {break;};
            span.push_back(chunk);
        }
        spans.push_back(span);
    }

    // The fruit of thy labour is written
    let (sender, receiver) = mpsc::channel::<Payload>();
    let mut cursor = 0;
    let mut span_idx = 0;
    let mut block_spans: Vec<BlockSpan> = vec![];
    while let Some(mut span) = spans.pop_front() {
        println!("Cursor: {cursor:?}");
        println!("Span len: {}", span.len());
        let block_span = BlockSpan::consume(span_idx, span.len(), cursor.clone(), &mut span, &ks, sender.clone());
        cursor += span.len(); // never increments
        span_idx += 1;
        
        block_spans.push(block_span);
    }

    let thread_count = block_spans.len();
    // I have sealed your fate
    while let Some(mut span) = block_spans.pop() {
        thread::spawn(move || {
            span.do_work();            
        });
    }

    let mut enc_result: Vec<Option<Vec<Block>>> = vec![];
    for _ in 0..thread_count {
        enc_result.push(None);
    }

    // And I will reap my rewards
    while enc_result.iter().map(|r| match r {Some(_) => 1, None => 0}).sum::<usize>() < thread_count {
        let payload: Payload = match receiver.recv() {
            Ok(p) => p,
            Err(e) => panic!("{e}"),
        };
        let Payload(idx, blocks) = payload;
        enc_result[idx] = Some(blocks);
    }

    // and scatter thy ashes to the four winds
    let mut result: Vec<Block> = vec![];
    for (idx, item) in enc_result.iter().enumerate() {
        let Some(blocks) = item else { panic!(); };
        println!("BLOCK {:?}: {:X}", idx, blocks[0].l);

        result.extend(blocks.iter());
    }
    result
}

fn encrypt_in_blocks(mut message: VecDeque<u64>, ks: Vec<u8>) -> Vec<Block> {
    let mut enc_blocks: Vec<Block> = vec![];

    while let (Some(l), Some(r)) = (message.pop_front(), message.pop_front()) {
        enc_blocks.push(Block { l, r, stripped: 0 })
    }

    for idx in 0..enc_blocks.len() {
        let block_key = key_segment(&ks, idx);
        enc_blocks[idx].run_n_rounds(4, block_key, true);
    }

    enc_blocks
}