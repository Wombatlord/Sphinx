use bytemuck::bytes_of;
use std::fs::{read, OpenOptions};
use std::io::Write;

use crate::block::Block;

pub fn file_shenanigans(path: &str) -> Vec<u8> {
    let f = read(path).unwrap();
    return f;
}

pub fn output_to_file(blocks: &Vec<Block>, path: &str, encrypting: bool) {
    let mut v = vec![];
    for bl in blocks {
        let l = bytes_of(&bl.l);
        let r = bytes_of(&bl.r);
        v.push(l);
        v.push(r);
    }
    let v2 = v.as_slice();

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .expect("oh boy");
    
    
    if encrypting {
        let s = String::from_utf8(v.concat()).expect("gosh darnit");
        let ss = s.trim_matches(char::from(0));
        write!(file, "{ss}").expect("dagnabbit");
    } else {
        for i in 0..v2.len() {
            file.write_all(v2[i]).expect("uh oh spaghettios");
        }
    }
}
