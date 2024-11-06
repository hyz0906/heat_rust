use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

pub struct PasswordEncryption {
    cipher: Aes256Gcm,
    nonce: Nonce<aes_gcm::aes::Aes256>,
}

impl PasswordEncryption {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("Valid key length");
        let nonce = Nonce::from_slice(nonce).to_owned();
        Self { cipher, nonce }
    }

    pub fn decrypt(&self, encrypted_password: &str) -> Result<String> {
        let encrypted_data = BASE64.decode(encrypted_password)?;
        let decrypted = self.cipher
            .decrypt(&self.nonce, encrypted_data.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        
        String::from_utf8(decrypted)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))
    }

    // Utility function to encrypt a password (useful for generating encrypted passwords)
    pub fn encrypt(&self, password: &str) -> Result<String> {
        let encrypted = self.cipher
            .encrypt(&self.nonce, password.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        Ok(BASE64.encode(encrypted))
    }
}

// Utility functions for generating encryption materials
pub fn generate_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub fn generate_nonce() -> [u8; 12] {
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn encode_base64<T: AsRef<[u8]>>(data: T) -> String {
    BASE64.encode(data)
}

pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
    BASE64.decode(data).map_err(|e| anyhow::anyhow!("Base64 decode error: {}", e))
} 