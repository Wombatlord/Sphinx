use bytemuck::bytes_of;
use std::fs::OpenOptions;
use std::io::Write;

use crate::block::Block;

pub fn output_to_file(blocks: Vec<Block>, pad_stripped_vec: Option<Vec<u8>>, path: &str) {
    let pad_stripped: Vec<u8> = match pad_stripped_vec {
        Some(s) => s,
        None => vec![],
    };

    let mut v: Vec<u8> = vec![];
    for bl in blocks {
        v.extend(bytes_of(&bl.l));
        v.extend(bytes_of(&bl.r));
    }
    v.extend(pad_stripped);

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .expect("oh boy");

    // println!("{:?}", v);

    file.write_all(&v).expect("uh oh spaghettios");
}
