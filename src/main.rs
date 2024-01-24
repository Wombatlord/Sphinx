mod block;
mod cli;
mod io;
mod boxes;
mod packer;
mod block_span;
mod key_fncs;

use std::{sync::mpsc, time::Instant};
use block::Block;
use block_span::{BlockSpan, Payload};
use key_fncs::{derive_key, key_segment, key_slice};
use packer::{Packer, PackBytes};
use clap::Parser;
use cli::Args;
use io::output_to_file;
use std::{
    collections::VecDeque,
    thread,
    fs::{self, read},
};

use boxes::Blowfish;

const BLOCK_SIZE: usize = 16;


fn main() {
    // if true {
    //     let key_bytes: Vec<u8> = "sixteenbyteshere".as_bytes().to_vec();
    //     Blowfish::subkey_shenanigans(key_bytes);
    //     return;
    // }


    let args = Args::parse();

    let output_key_material: [u8; 32] = derive_key::<32>(&args);
    
    if let Some(path) = args.encrypt.as_deref() {
        if args.parallelize {
            encrypt(path, &output_key_material, parallel_encrypt_in_blocks)
        } else {
            // encrypt(path, &output_key_material, encrypt_in_blocks);
            Blowfish::encrypt(path, "sixteenbyteshere".as_bytes().to_vec());
        }

    }
    if let Some(path) = args.decrypt.as_deref() {
        // decrypt(path, &output_key_material);
        Blowfish::decrypt(path, "sixteenbyteshere".as_bytes().to_vec())
    }
}


fn decrypt(path: &str, key: &[u8; 32]) {
    // deserialise cyphertext
    let bytes_from_ct_file = read(path).unwrap();
    let mut u64_encoded: VecDeque<u64> = vec![].into();
    <Packer as PackBytes<u64>>::u8s_to_vecdeque(bytes_from_ct_file, &mut u64_encoded);

    //key prep
    let (required_blocks, kk) = key_slice::<32>(&u64_encoded, key);

    // un-cryptin'
    let mut dec_blocks: Vec<Block<u64>> = vec![];
    for _ in 0..required_blocks {
        let x = Block {
            l: u64_encoded.pop_front().unwrap(),
            r: u64_encoded.pop_front().unwrap(),
        };

        dec_blocks.push(x)
    }

    for idx in 0..dec_blocks.len() {
        let block_key = kk[idx % kk.len()];
        dec_blocks[idx].run_n_rounds(4, block_key, false);
    }

    let end_block = dec_blocks.pop().unwrap();
    let end_block_vec = end_block.to_bytes();

    let mut dec_bytes: Vec<u8> = vec![];
    for b in dec_blocks {
        dec_bytes.extend(b.to_bytes())
    }
    dec_bytes.extend(Packer::strip_padding_vec(end_block_vec));

    output_to_file(dec_bytes, "decrypted_file");
}

fn encrypt(path: &str, key: &[u8; 32], enc_func: fn(VecDeque<u64>, Vec<u8>) -> Vec<Block<u64>>) {
    let pt = fs::read(path).unwrap();
    let now = Instant::now();

    let padded = Packer::pad_bytes(pt, 16);
    
    let mut u64_encoded: VecDeque<u64> = vec![].into();
    <Packer as PackBytes<u64>>::u8s_to_vecdeque(padded, &mut u64_encoded);
    
    // key prep
    let (_, kk) = key_slice::<32>(&u64_encoded, key);

    let enc_blocks = enc_func(u64_encoded, kk);

    let mut enc_bytes = vec![];

    for b in enc_blocks {
        enc_bytes.extend(b.to_bytes())
    }

    let elapsed_time = now.elapsed();
    println!("{:?}", elapsed_time);
    // serialising cyphertext
    output_to_file(enc_bytes, "encrypted_file");
}


fn parallel_encrypt_in_blocks(mut message: VecDeque<u64>, ks: Vec<u8>) -> Vec<Block<u64>>  {
    let workload = message.len() / 8;

    // Prep thy threads foul imp!
    let mut spans: VecDeque<VecDeque<u64>> = VecDeque::new();
    while message.len() > 0 {
        let mut span = VecDeque::new();
        for _ in 0..workload*BLOCK_SIZE {
            let Some(chunk) = message.pop_front() else {break;};
            span.push_back(chunk);
        }
        spans.push_back(span);
    }

    // The fruit of thy labour is written
    let (sender, receiver) = mpsc::channel::<Payload>();
    let mut span_idx = 0;
    let mut block_spans: Vec<BlockSpan> = vec![];
    while let Some(mut span) = spans.pop_front() {
        let block_span = BlockSpan::consume(span_idx, span.len(), 0, &mut span, &ks, sender.clone());
        
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

    let mut enc_result: Vec<Option<Vec<Block<u64>>>> = vec![];
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
    let mut result: Vec<Block<u64>> = vec![];
    for (_, item) in enc_result.iter().enumerate() {
        let Some(blocks) = item else { panic!(); };

        result.extend(blocks.iter());
    }
    result
}

fn encrypt_in_blocks(mut message: VecDeque<u64>, ks: Vec<u8>) -> Vec<Block<u64>> {
    let mut enc_blocks: Vec<Block<u64>> = vec![];

    while let (Some(l), Some(r)) = (message.pop_front(), message.pop_front()) {
        enc_blocks.push(Block { l, r, })
    }

    for idx in 0..enc_blocks.len() {
        let block_key = key_segment(&ks, idx);
        enc_blocks[idx].run_n_rounds(4, block_key, true);
    }

    enc_blocks
}