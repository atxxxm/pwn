use std::fs::{File};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

fn encrypt_data(data: &str, master_password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut salt = [0u8; SALT_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);

    let mut key_bytes = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(master_password.as_bytes(), &salt, 100_000, &mut key_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data.as_bytes())
        .map_err(|_| "Encryption failed")?;

    let mut encrypted = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    encrypted.extend_from_slice(&salt);
    encrypted.extend_from_slice(&nonce_bytes);
    encrypted.extend_from_slice(&ciphertext);


    key_bytes.zeroize();

    Ok(encrypted)
}

fn decrypt_data(encrypted: &[u8], master_password: &str) -> Result<String, Box<dyn std::error::Error>> {
    if encrypted.len() < SALT_LEN + NONCE_LEN {
        return Err("The data is corrupted".into());
    }

    let (salt, rest) = encrypted.split_at(SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let mut key_bytes = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(master_password.as_bytes(), salt, 100_000, &mut key_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext_bytes = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed (incorrect password?)")?;

    let plaintext = String::from_utf8(plaintext_bytes)
        .map_err(|_| "Invalid data (not UTF-8)")?;

    key_bytes.zeroize();

    Ok(plaintext)
}

pub struct PasswordStore {
    data: HashMap<String, String>,
}

impl PasswordStore {
    pub fn new() -> Self {
        Self { data: HashMap::new() }
    }

    pub fn load<P: AsRef<Path>>(path: P, master_password: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut data = HashMap::new();

        if path.as_ref().exists() {
            let mut file = File::open(path.as_ref())?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;

            let decrypted = decrypt_data(&content, master_password)?;
            data = serde_json::from_str(&decrypted)?;
        }

        Ok(Self { data })
    }

    pub fn save<P: AsRef<Path>>(&self, path: P, master_password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&self.data)?;
        let encrypted = encrypt_data(&json, master_password)?;

        let mut file = File::create(path)?;
        file.write_all(&encrypted)?;

        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&String> {
        self.data.get(name)
    }

    pub fn set(&mut self, name: &str, password: &str) {
        self.data.insert(name.to_string(), password.to_string());
    }

    pub fn remove(&mut self, name: &str) {
        self.data.remove(name);
    }

    pub fn list_names(&self) -> Vec<&String> {
        self.data.keys().collect()
    }
    
}
