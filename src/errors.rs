use std::fmt::{self, Display};

pub fn rgb_string(r: u8, g: u8, b: u8) -> String {
    format!(
        "\x1b[38;2;{};{};{}m",
        r.to_string(),
        g.to_string(),
        b.to_string()
    )
}

#[derive(Debug)]
pub enum CipherError {
    DecryptionError(String),
    KeyLen(String),
    PaddingError(String),
}

impl Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecryptionError(s) => write!(f, "{}{}{}", rgb_string(255, 0, 0), s, "\x1b[0m"),
            Self::KeyLen(s) => write!(f, "{}{}{}", rgb_string(255, 0, 0), s, "\x1b[0m"),
            Self::PaddingError(s) => write!(f, "{}{}{}", rgb_string(255, 0, 0), s, "\x1b[0m"),
        }
    }
}
