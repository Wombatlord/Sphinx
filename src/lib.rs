pub mod block;
pub mod blowfish;
pub mod cipher;
pub mod cli;
pub mod errors;
pub mod feistel;
pub mod io;
pub mod mode_of_operation;
pub mod modes;
pub mod packer;

pub mod prelude {
    use crate::{
        blowfish::Blowfish, cipher::Cipher, errors::CipherError, feistel::FeistelNetwork, mode_of_operation::ModeOfOperation, modes::{CBC, ECB}, packer::Packer
    };

    fn enc(cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>, data: Vec<u8>) -> Vec<u8> {
        cipher.encrypt::<Packer>(data)
    }

    fn dec(
        cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, CipherError> {
        cipher.decrypt::<Packer>(data)
    }

    pub fn ecb_encode(key: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, CipherError> {
        let blowfish = Blowfish::initialize::<Packer>(key)?;
        
        Ok(enc(Cipher::<ECB, Blowfish>(ECB, blowfish), data))
    }
    
    pub fn ecb_decode(key: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, CipherError> {
        let blowfish = Blowfish::initialize::<Packer>(key)?;
        
        dec(Cipher::<ECB, Blowfish>(ECB, blowfish), data)
    }
    
    pub fn cbc_encode(key: Vec<u8>, data: Vec<u8>, init_vec: u64) -> Result<Vec<u8>, CipherError> {
        let blowfish = Blowfish::initialize::<Packer>(key)?;
        
        Ok(enc(Cipher::<CBC, Blowfish>(CBC{init_vec}, blowfish), data))
    }
    
    pub fn cbc_decode(key: Vec<u8>, data: Vec<u8>, init_vec: u64) -> Result<Vec<u8>, CipherError> {
        let blowfish = Blowfish::initialize::<Packer>(key)?;
        
        dec(Cipher::<CBC, Blowfish>(CBC{init_vec}, blowfish), data)
    }
}
