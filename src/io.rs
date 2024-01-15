use bytemuck::bytes_of;
use std::fs::{read, OpenOptions};
use std::io::Write;

use crate::block::Block;

pub fn file_shenanigans(path: &str) -> Vec<u8> {
    let f = read(path).unwrap();
    return f;
}

pub fn output_to_file(blocks: &Vec<Block>, path: &str, decrypting: bool) {
    let mut v: Vec<u8> = vec![];
    for bl in blocks {
        v.extend(bytes_of(&bl.l));
        v.extend(bytes_of(&bl.r));
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .expect("oh boy");

    if decrypting {
        let s = String::from_utf8(v).expect("gosh darnit");
        let ss = s.trim_matches(char::from(0));
        write!(file, "{ss}").expect("dagnabbit");
    } else {
        file.write_all(&v).expect("uh oh spaghettios");
    }
}
