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

    #[cfg(test)]
    mod test {
        const FIXTURE_DATA: &str = r"
                  ___                ___                    ___                    ___     
                 /\__\              /\  \                  /\  \                  /\__\    
                /:/  /             /::\  \                 \:\  \                /::|  |   
               /:/  /             /:/\:\  \                 \:\  \              /:|:|  |   
              /:/  /             /:/  \:\  \                /::\  \            /:/|:|__|__ 
             /:/__/             /:/__/_\:\__\              /:/\:\__\          /:/ |::::\__\
             \:\  \             \:\  /\ \/__/             /:/  \/__/          \/__/~~/:/  /
              \:\  \             \:\ \:\__\              /:/  /                     /:/  / 
               \:\  \             \:\/:/  /              \/__/                     /:/  /  
                \:\__\             \::/  /                                        /:/  /   
                 \/__/              \/__/                                         \/__/    
        ";
        
        use super::*;
        #[test]

        fn test_ecb_round_trip() {
            let key = vec![0xDE, 0xAD, 0xBE, 0xEF];
            let data: Vec<u8> = FIXTURE_DATA.as_bytes().into();

            let maybe_encrypted = ecb_encode(key.clone(), data.clone());
            assert!(maybe_encrypted.is_ok());
            let enc = maybe_encrypted.unwrap();

            let maybe_decrypted = ecb_decode(key, enc.clone());
            assert!(maybe_decrypted.is_ok());

            let dec = maybe_decrypted.unwrap();
            
            assert_ne!(enc, dec);
            assert_eq!(data, dec);
        }
        
        #[test]
        fn test_cbc_round_trip() {
            let key = vec![0xDE, 0xAD, 0xBE, 0xEF];
            let init_vec: u64 = 0;
            let data: Vec<u8> = FIXTURE_DATA.as_bytes().into();

            let maybe_encrypted = cbc_encode(key.clone(), data.clone(), init_vec.clone());
            assert!(maybe_encrypted.is_ok());
            let enc = maybe_encrypted.unwrap();

            let maybe_decrypted = cbc_decode(key, enc.clone(), init_vec);
            assert!(maybe_decrypted.is_ok());

            let dec = maybe_decrypted.unwrap();
            
            assert_ne!(enc, dec);
            assert_eq!(data, dec);
        }
    }
}

