use std::collections::VecDeque;

pub struct Packer;

impl Packer {
    pub fn pad_bytes(mut pt: Vec<u8>, n_bytes: u8) -> Vec<u8> {
        let mut pt_vec: Vec<u8> = vec![];
        let padding_required: u8 = (pt.len() % n_bytes as usize) as u8;
    
        if padding_required > 0 {
            let space: u8 = n_bytes - padding_required;
            for _ in 0..(n_bytes - padding_required) {
                pt_vec.push(space);
            }
            pt.extend(pt_vec.into_iter());
        } else {
            for _ in 0..n_bytes {
                pt.push(n_bytes)
            }
        }
        return pt;
    }

    pub fn strip_padding_vec(mut vec: Vec<u8>) -> Vec<u8> {
        let padding_indication_byte = vec[vec.len() - 1];
        let b = vec.len() - padding_indication_byte as usize;
        let slice = &vec[b..];
        
        if slice.iter().all(|&bytes| bytes == padding_indication_byte) {
            for _ in b..vec.len() {
                vec.pop();
            }
        } else {
            panic!("Decryption Failed.")
        }
        
        return vec;
    }

}

pub trait PackBytes<T> {
    fn u8s_to_subblock(u8s: &[u8]) -> T;
    fn u8s_to_vecdeque(padded: Vec<u8>, buf: &mut VecDeque<T>);
}

impl PackBytes<u64> for Packer {
    fn u8s_to_subblock(u8s: &[u8]) -> u64 {
        let mut buf = [0u8; 8];
        let len = 8.min(u8s.len());
        buf[..len].copy_from_slice(&u8s[..len]);
        u64::from_ne_bytes(buf)
    }

    fn u8s_to_vecdeque(padded: Vec<u8>, buf: &mut VecDeque<u64>) {
        // Take 8 bytes at a time from the byte slice of the plain text input
        for m in padded.chunks(8) {
            // convert 8 bytes to a u64 representation
            let as64: u64 = Self::u8s_to_subblock(m);
    
            buf.push_back(as64)
        }
    }
}

impl PackBytes<u32> for Packer {
    fn u8s_to_subblock(u8s: &[u8]) -> u32 {
        let mut buf = [0u8; 4];
        let len = 4.min(u8s.len());
        buf[..len].copy_from_slice(&u8s[..len]);
        u32::from_ne_bytes(buf)
    }

    fn u8s_to_vecdeque(padded: Vec<u8>, buf: &mut VecDeque<u32>) {
        // Take 4 bytes at a time from the byte slice of the plain text input
        for m in padded.chunks(4) {
            // convert 4 bytes to a u32 representation
            let as32: u32 = Self::u8s_to_subblock(m);

            buf.push_back(as32)
        }
    }
}