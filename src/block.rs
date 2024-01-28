use bytemuck::bytes_of;

#[derive(Copy, Clone)]
pub struct Block<T> {
    pub l: T,
    pub r: T,
}

impl Block<u32> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = vec![];
        v.extend(bytes_of(&self.l));
        v.extend(bytes_of(&self.r));

        return v
    }

    pub fn full_block(&self) -> u64 {
        let l = self.l as u64;
        let r = self.r as u64;
        let p = (l << 32) | r;
        return p;
    }

    pub fn cbc_mode_xor(&mut self, xor_with: u64) {
        let l = self.l as u64;
        let r = self.r as u64;
        let mut p = (l << 32) | r;
        p ^= xor_with;
        self.l = ((p & u64::MAX << 32) >> 32)as u32;
        self.r = (p & u64::MAX) as u32;
    }
}
