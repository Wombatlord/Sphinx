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
    use rand::{rngs::{adapter::ReseedingRng, OsRng}, Rng, SeedableRng};
    use rand_chacha::ChaCha20Core;

    use crate::{
        blowfish::Blowfish,
        cipher::Cipher,
        errors::CipherError,
        feistel::FeistelNetwork,
        mode_of_operation::ModeOfOperation,
        modes::{CBC, ECB},
        packer::Packer,
    };

    fn enc(
        cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, CipherError> {
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

        enc(Cipher::<ECB, Blowfish>(ECB, blowfish), data)
    }

    pub fn ecb_decode(key: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, CipherError> {
        let blowfish = Blowfish::initialize::<Packer>(key)?;

        dec(Cipher::<ECB, Blowfish>(ECB, blowfish), data)
    }

    pub type IVGen = dyn FnMut() -> u64;
    pub fn iv_generator() -> Box<IVGen> {
        let prng = ChaCha20Core::from_entropy();
        let mut reseeding_rng = ReseedingRng::new(prng, 0, OsRng);
        let g = move || reseeding_rng.gen::<u64>();
        Box::new(g)
    }

    pub fn get_rng() -> ReseedingRng<ChaCha20Core, OsRng> {
        let prng = ChaCha20Core::from_entropy();
        ReseedingRng::new(prng, 0, OsRng)
    }

    pub fn cbc_encode(key: Vec<u8>, data: Vec<u8>, mut rng: ReseedingRng<ChaCha20Core, OsRng>) -> Result<Vec<u8>, CipherError> {
        let blowfish = Blowfish::initialize::<Packer>(key)?;
        let iv = rng.gen::<u64>();
        
        enc(
            Cipher::<CBC, Blowfish>(
                CBC {
                    init_vec: Some(iv),
                },
                blowfish,
            ),
            data,
        )
    }

    pub fn cbc_decode(key: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, CipherError> {
        let blowfish = Blowfish::initialize::<Packer>(key)?;

        dec(
            Cipher::<CBC, Blowfish>(CBC { init_vec: None }, blowfish),
            data,
        )
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
            assert!(maybe_encrypted.is_ok(), "{maybe_encrypted:?}");
            let enc = maybe_encrypted.unwrap();

            let maybe_decrypted = ecb_decode(key, enc.clone());
            assert!(maybe_decrypted.is_ok(), "{maybe_decrypted:?}");

            let dec = maybe_decrypted.unwrap();

            assert_ne!(enc, dec);
            assert_eq!(data, dec);
        }

        #[test]
        fn test_cbc_round_trip() {
            let key = vec![0xDE, 0xAD, 0xBE, 0xEF];
            let data: Vec<u8> = FIXTURE_DATA.as_bytes().into();
            let rng = get_rng();
            let maybe_encrypted = cbc_encode(key.clone(), data.clone(), rng);
            assert!(maybe_encrypted.is_ok(), "{maybe_encrypted:?}");
            let enc = maybe_encrypted.unwrap();

            let maybe_decrypted = cbc_decode(key, enc.clone());
            assert!(maybe_decrypted.is_ok(), "{maybe_decrypted:?}");

            let dec = maybe_decrypted.unwrap();

            assert_ne!(enc, dec);
            assert_eq!(data, dec);
        }
    }
}
