use std::fs::OpenOptions;
use std::io::Write;

pub fn output_to_file(blocks: Vec<u8>, path: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .expect("oh boy");


    file.write_all(&blocks).expect("uh oh spaghettios");
}
