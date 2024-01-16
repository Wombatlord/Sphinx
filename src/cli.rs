use clap::Parser;

const LONG: &str = "A Feistel Cipher implementation.
    Encrypt will take an input file and encrypt it with the cipher
    Output will be saved as 'encrypted_file'.\n
    Decrypt will take an input file and decrypt it.
    Output will be saved 'decrypted_file'.\n
    Key is required with encrypt or decrypt.";

#[derive(Parser, Debug)]
#[command(author="Wombatlord", version="0.5", about = "Feistel Cipher", long_about = LONG)]
pub struct Args {
    #[arg(short, long, value_name = "target file path")]
    pub encrypt: Option<String>,

    #[arg(short, long, value_name = "target file path")]
    pub decrypt: Option<String>,

    #[arg(short, long, value_name = "secret key")]
    pub key: String,

    #[arg(short, long, value_name = "verbose", default_value_t = false)]
    pub verbose: bool,
}
