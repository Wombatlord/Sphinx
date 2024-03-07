use clap::Parser;

const LONG: &str = "Blowfish Encryption implementation.\n
    Encrypt will take an input file and encrypt it with the cipher
    Output will be saved as 'encrypted_file'.\n
    Decrypt will take an input file and decrypt it.
    Output will be saved 'decrypted_file'.\n
    Key is required with encrypt or decrypt.\n
    Mode Options are:
    \t0: ECB,
    \t1: CBC";

const SHORT: &str = " Blowfish Encryption.\n
Mode Options are:
\t0: ECB,
\t1: CBC";

#[derive(Parser, Debug)]
#[command(author="Wombatlord", version="0.5", about = SHORT, long_about = LONG)]
pub struct Args {
    #[arg(short, long, value_name = "target file path")]
    pub encrypt: Option<String>,

    #[arg(short, long, value_name = "target file path")]
    pub decrypt: Option<String>,

    #[arg(short, long)]
    pub parallelize: bool,

    #[arg(short, long = "mode", value_name = "mode of operation")]
    pub mode: u8,

    #[arg(short, long, value_name = "secret key")]
    pub key: String,
}
