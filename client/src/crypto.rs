use anyhow::Result;
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{
    HEADERBYTES, KEYBYTES, Key, PullState, PushState, TAG_FINAL, TAG_MESSAGE,
};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_SIZE: usize = KEYBYTES;
pub const HEADER_SIZE: usize = HEADERBYTES;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    inner: Vec<u8>,
}

impl SecureKey {
    pub fn generate() -> Result<Self> {
        libsodium_rs::ensure_init()
            .map_err(|e| anyhow::anyhow!("Failed to initialise libsodium: {:?}", e))?;
        let key = Key::generate();
        Ok(SecureKey {
            inner: key.as_bytes().to_vec(),
        })
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        let bytes = self.inner.clone();
        self.inner.zeroize();
        bytes
    }
}

pub fn generate_key() -> Result<Vec<u8>> {
    let key = SecureKey::generate()?;
    Ok(key.into_bytes())
}

pub fn encrypt_stream_simple<R: Read, W: Write>(
    key: &[u8],
    mut reader: R,
    mut writer: W,
    chunk_size: usize,
) -> Result<()> {
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "Invalid key size: expected {} bytes, got {}",
            KEY_SIZE,
            key.len()
        );
    }

    let key = Key::from_bytes(key).map_err(|e| anyhow::anyhow!("Invalid key: {:?}", e))?;
    let (mut state, header) = PushState::init_push(&key)
        .map_err(|e| anyhow::anyhow!("Failed to initialise encryption stream: {:?}", e))?;

    // Write the header first
    writer.write_all(&header)?;

    let mut buffer = vec![0u8; chunk_size];
    let mut next_buffer = vec![0u8; chunk_size];

    // Read first chunk to start the pipeline
    let mut current_len = reader.read(&mut buffer)?;

    loop {
        // Try to read the next chunk to know if current is the last
        let next_len = if current_len > 0 {
            reader.read(&mut next_buffer)?
        } else {
            0
        };

        if current_len == 0 {
            // No data at all - send empty final chunk
            let encrypted_chunk = state
                .push(&[], None, TAG_FINAL)
                .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

            let len = encrypted_chunk.len() as u32;
            writer.write_all(&len.to_le_bytes())?;
            writer.write_all(&encrypted_chunk)?;
            break;
        }

        // Determine if this is the final chunk
        let is_final = next_len == 0;
        let tag = if is_final { TAG_FINAL } else { TAG_MESSAGE };

        // Encrypt current chunk
        let encrypted_chunk = state
            .push(&buffer[..current_len], None, tag)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        // Write chunk length and encrypted data
        let len = encrypted_chunk.len() as u32;
        writer.write_all(&len.to_le_bytes())?;
        writer.write_all(&encrypted_chunk)?;

        if is_final {
            break;
        }

        // Swap buffers for next iteration
        std::mem::swap(&mut buffer, &mut next_buffer);
        current_len = next_len;
    }

    // Zeroize buffers
    buffer.zeroize();
    next_buffer.zeroize();

    writer.flush()?;
    Ok(())
}

pub fn decrypt_stream_simple<R: Read, W: Write>(
    key: &[u8],
    mut reader: R,
    mut writer: W,
) -> Result<()> {
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "Invalid key size: expected {} bytes, got {}",
            KEY_SIZE,
            key.len()
        );
    }

    // Read the header first
    let mut header_bytes = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header_bytes)?;

    let key = Key::from_bytes(key).map_err(|e| anyhow::anyhow!("Invalid key: {:?}", e))?;
    let mut state = PullState::init_pull(&header_bytes, &key)
        .map_err(|e| anyhow::anyhow!("Failed to initialise decryption stream: {:?}", e))?;

    let mut len_buffer = [0u8; 4];

    loop {
        match reader.read_exact(&mut len_buffer) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let chunk_len = u32::from_le_bytes(len_buffer) as usize;
        let mut encrypted_chunk = vec![0u8; chunk_len];
        reader.read_exact(&mut encrypted_chunk)?;

        let (mut decrypted_chunk, tag) = state
            .pull(&encrypted_chunk, None)
            .map_err(|e| anyhow::anyhow!("Decryption failed - authentication error: {:?}", e))?;

        writer.write_all(&decrypted_chunk)?;

        // Zeroize decrypted chunk
        decrypted_chunk.zeroize();
        encrypted_chunk.zeroize();

        if tag == TAG_FINAL {
            break;
        }
    }

    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_generate_key() {
        let key = generate_key().unwrap();
        assert_eq!(key.len(), KEY_SIZE);

        let key2 = generate_key().unwrap();
        assert_ne!(key, key2);
    }

    #[test]
    fn test_secure_key_zeroize() {
        let mut key = SecureKey::generate().unwrap();
        let bytes_ptr = key.inner.as_ptr();
        let bytes_len = key.inner.len();

        // Clone the key data to compare later
        let original = key.inner.clone();

        // Zeroize the key
        key.zeroize();

        // Check that the memory has been zeroized
        unsafe {
            let slice = std::slice::from_raw_parts(bytes_ptr, bytes_len);
            assert!(slice.iter().all(|&b| b == 0));
        }

        // Verify the original data was not all zeros
        assert!(!original.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encrypt_decrypt_stream() {
        let key = generate_key().unwrap();
        let plaintext = b"Hello, World! This is a test message for streaming encryption.";

        let mut encrypted_data = Vec::new();
        encrypt_stream_simple(&key, Cursor::new(plaintext), &mut encrypted_data, 16).unwrap();

        assert!(encrypted_data.len() > HEADER_SIZE);
        assert_ne!(&encrypted_data[HEADER_SIZE..], plaintext);

        let mut decrypted_data = Vec::new();
        decrypt_stream_simple(&key, Cursor::new(&encrypted_data), &mut decrypted_data).unwrap();

        assert_eq!(decrypted_data, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_key().unwrap();
        let key2 = generate_key().unwrap();
        let plaintext = b"Secret message";

        let mut encrypted_data = Vec::new();
        encrypt_stream_simple(&key1, Cursor::new(plaintext), &mut encrypted_data, 16).unwrap();

        let mut decrypted_data = Vec::new();
        let result =
            decrypt_stream_simple(&key2, Cursor::new(&encrypted_data), &mut decrypted_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_large_data() {
        let key = generate_key().unwrap();
        let plaintext = vec![0x42u8; 1024 * 1024]; // 1MB of data

        let mut encrypted_data = Vec::new();
        encrypt_stream_simple(&key, Cursor::new(&plaintext), &mut encrypted_data, 8192).unwrap();

        let mut decrypted_data = Vec::new();
        decrypt_stream_simple(&key, Cursor::new(&encrypted_data), &mut decrypted_data).unwrap();

        assert_eq!(decrypted_data, plaintext);
    }

    #[test]
    fn test_tampered_data_fails() {
        let key = generate_key().unwrap();
        let plaintext = b"Authentic message";

        let mut encrypted_data = Vec::new();
        encrypt_stream_simple(&key, Cursor::new(plaintext), &mut encrypted_data, 16).unwrap();

        // Tamper with the encrypted data
        let tamper_pos = encrypted_data.len() / 2;
        encrypted_data[tamper_pos] ^= 0xff;

        let mut decrypted_data = Vec::new();
        let result = decrypt_stream_simple(&key, Cursor::new(&encrypted_data), &mut decrypted_data);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authentication error")
        );
    }
}
