use anyhow::Result;
use k8s_snapshot_manager::encryption;

fn main() -> Result<()> {
    let key = encryption::generate_key();
    let nonce = encryption::generate_nonce();
    
    println!("Generated encryption key (base64): {}", encryption::encode_base64(key));
    println!("Generated nonce (base64): {}", encryption::encode_base64(nonce));
    
    // If a password is provided as an argument, encrypt it
    if let Some(password) = std::env::args().nth(1) {
        let encryptor = encryption::PasswordEncryption::new(&key, &nonce);
        let encrypted = encryptor.encrypt(&password)?;
        println!("\nEncrypted password: {}", encrypted);
    }
    
    Ok(())
} 