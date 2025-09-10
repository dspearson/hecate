use anyhow::{Context, Result};
use bip39::Mnemonic;
use shamir::SecretData;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    pub index: u8,
    pub mnemonic: String,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct RawShare {
    pub index: u8,
    pub data: Vec<u8>,
}

pub fn split_secret(secret: &[u8], threshold: u8, total_shares: u8) -> Result<Vec<Share>> {
    if threshold > total_shares {
        anyhow::bail!("Threshold cannot exceed total shares");
    }
    if threshold < 1 || total_shares < 1 {
        anyhow::bail!("Threshold and total shares must be at least 1");
    }
    if secret.is_empty() {
        anyhow::bail!("Secret cannot be empty");
    }

    // Convert secret bytes to hex string for the shamir library
    let secret_hex = hex::encode(secret);
    let secret_data = SecretData::with_secret(&secret_hex, threshold);

    let mut shares = Vec::new();
    for i in 1..=total_shares {
        let share_vec = secret_data
            .get_share(i)
            .map_err(|e| anyhow::anyhow!("Failed to generate share: {:?}", e))?;

        // Convert share to mnemonic for easier human handling
        // Note: share_vec already contains the index as the first byte
        let mnemonic = share_to_mnemonic(&share_vec)?;

        shares.push(Share {
            index: i, // We still store this separately for convenience
            mnemonic,
        });
    }

    Ok(shares)
}

fn share_to_mnemonic(share_data: &[u8]) -> Result<String> {
    // Split large shares into multiple BIP39 mnemonics
    // Each mnemonic can hold 32 bytes total (including metadata)
    // We reserve 1 byte for the chunk length, leaving 31 bytes for data

    let mut mnemonics = Vec::new();
    let mut offset = 0;

    while offset < share_data.len() {
        let chunk_len = (share_data.len() - offset).min(31); // Max 31 bytes to leave room for length byte
        let mut chunk = vec![chunk_len as u8]; // First byte is the actual data length in this chunk
        chunk.extend_from_slice(&share_data[offset..offset + chunk_len]);

        // Pad to 32 bytes for BIP39 with random data
        // Benefits of random padding:
        // 1. Security: Makes shares indistinguishable (no predictable patterns)
        // 2. Privacy: Padding words vary between shares, preventing correlation
        // 3. QR efficiency: Full mnemonics still fit easily in QR codes
        // Note: We keep the full padded mnemonic rather than stripping it because
        // BIP39 checksums prevent truncation, and the size difference is negligible
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        while chunk.len() < 32 {
            chunk.push(rng.next_u32() as u8);
        }

        let mnemonic =
            Mnemonic::from_entropy(&chunk).context("Failed to create mnemonic from share chunk")?;

        mnemonics.push(mnemonic.to_string());
        offset += chunk_len;
    }

    // Join multiple mnemonics with a separator
    Ok(mnemonics.join(" | "))
}

pub fn serialise_share(share: &Share) -> String {
    // Return the full mnemonic - the random padding adds security
    // and the QR code size difference isn't significant
    share.mnemonic.clone()
}

pub fn deserialise_share(data: &str) -> Result<Share> {
    // Simple deserialization - just the mnemonic
    Ok(Share {
        index: 0, // Will be extracted from share data during parsing
        mnemonic: data.to_string(),
    })
}

pub fn parse_shares(inputs: &[String], verbose: bool) -> Result<Vec<RawShare>> {
    let mut raw_shares = Vec::new();

    for input in inputs {
        let share = parse_single_share(input, verbose)?;
        raw_shares.push(share);
    }

    if raw_shares.is_empty() {
        anyhow::bail!("No valid shares provided");
    }

    Ok(raw_shares)
}

fn parse_single_share(input: &str, verbose: bool) -> Result<RawShare> {
    // Check if input is a file path to a QR code
    if Path::new(input).exists() {
        if verbose {
            eprintln!("Reading QR code from file: {input}");
        }
        parse_qr_share(input)
    } else {
        // Assume it's mnemonic words or serialised share format
        // Try to parse as serialised share (handles both old and new formats)
        parse_serialised_share(input)
    }
}

fn parse_qr_share(file_path: &str) -> Result<RawShare> {
    // Use the qr module's function to parse the QR share
    let share = crate::qr::parse_qr_share(file_path)?;
    mnemonic_to_raw_share(&share)
}

fn parse_serialised_share(input: &str) -> Result<RawShare> {
    let share = deserialise_share(input)?;
    mnemonic_to_raw_share(&share)
}

fn mnemonic_to_raw_share(share: &Share) -> Result<RawShare> {
    // Handle multiple mnemonics separated by " | "
    let mnemonic_parts: Vec<&str> = share.mnemonic.split(" | ").collect();

    let mut full_data = Vec::new();

    for part in mnemonic_parts {
        let mnemonic = Mnemonic::parse(part.trim()).context("Failed to parse mnemonic")?;

        let entropy = mnemonic.to_entropy();

        if entropy.is_empty() {
            anyhow::bail!("Invalid mnemonic entropy");
        }

        // First byte is the length of actual data in this chunk
        let data_len = entropy[0] as usize;

        if data_len == 0 || data_len > entropy.len() - 1 {
            anyhow::bail!(
                "Invalid chunk data length: {} (entropy len: {})",
                data_len,
                entropy.len()
            );
        }

        // Extract the actual data from this chunk
        full_data.extend_from_slice(&entropy[1..=data_len]);
    }

    // Extract the index from the share data - it's the first byte
    if full_data.is_empty() {
        anyhow::bail!("Invalid share data: empty");
    }
    
    let actual_index = full_data[0];
    
    Ok(RawShare {
        index: actual_index,
        data: full_data,
    })
}

pub fn combine_shares(shares: &[RawShare]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        anyhow::bail!("No shares provided");
    }

    // The shares contain the actual share data from the shamir library
    // which already includes the index information
    let threshold = shares.len() as u8;

    let mut share_vecs: Vec<Vec<u8>> = Vec::new();
    for share in shares {
        // The data already contains the full share from get_share
        // We just need to use it directly
        share_vecs.push(share.data.clone());
    }

    let recovered_hex = SecretData::recover_secret(threshold, share_vecs)
        .context("Failed to recover secret from shares")?;

    let recovered_bytes =
        hex::decode(&recovered_hex).context("Failed to decode recovered secret")?;

    // Clear the hex string
    let mut hex_chars: Vec<u8> = recovered_hex.into_bytes();
    hex_chars.zeroize();

    Ok(recovered_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_combine() {
        let secret = b"This is a secret key for testing!";
        let shares = split_secret(secret, 2, 5).unwrap();

        assert_eq!(shares.len(), 5);

        // Test with minimum threshold (2 shares)
        let share_strings: Vec<String> = shares.iter().take(2).map(serialise_share).collect();
        let raw_shares = parse_shares(&share_strings, false).unwrap();
        let recovered = combine_shares(&raw_shares).unwrap();
        assert_eq!(recovered, secret);

        // Test with different share combinations
        let share_strings: Vec<String> =
            vec![serialise_share(&shares[1]), serialise_share(&shares[3])];
        let raw_shares = parse_shares(&share_strings, false).unwrap();
        let recovered = combine_shares(&raw_shares).unwrap();
        assert_eq!(recovered, secret);

        // Test with more than threshold
        let share_strings: Vec<String> = vec![
            serialise_share(&shares[0]),
            serialise_share(&shares[2]),
            serialise_share(&shares[4]),
        ];
        let raw_shares = parse_shares(&share_strings, false).unwrap();
        let recovered = combine_shares(&raw_shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"Another secret";
        let shares = split_secret(secret, 3, 5).unwrap();

        // With only 2 shares when we need 3, recovery should fail or produce wrong result
        let share_strings: Vec<String> = shares.iter().take(2).map(serialise_share).collect();
        let raw_shares = parse_shares(&share_strings, false).unwrap();
        let result = combine_shares(&raw_shares);
        // The library may not detect this, but result should be wrong
        if let Ok(recovered) = result {
            assert_ne!(recovered, secret);
        }
    }

    #[test]
    fn test_edge_cases() {
        // Test 1-of-1 sharing
        let secret = b"x";
        let shares = split_secret(secret, 1, 1).unwrap();
        assert_eq!(shares.len(), 1);

        let share_strings: Vec<String> = shares.iter().map(serialise_share).collect();
        let raw_shares = parse_shares(&share_strings, false).unwrap();
        let recovered = combine_shares(&raw_shares).unwrap();
        assert_eq!(recovered, secret);

        // Test invalid threshold
        let result = split_secret(secret, 2, 1);
        assert!(result.is_err());

        // Test empty secret
        let result = split_secret(b"", 1, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_mnemonic_generation() {
        let secret = b"Test secret for mnemonic";
        let shares = split_secret(secret, 2, 3).unwrap();

        for share in &shares {
            // Check that mnemonic is not empty and contains multiple words
            assert!(!share.mnemonic.is_empty());
            assert!(share.mnemonic.split_whitespace().count() > 1);
        }
    }

    #[test]
    fn test_serialisation_roundtrip() {
        let secret = b"Test secret for serialisation";
        let shares = split_secret(secret, 2, 3).unwrap();

        // Test full roundtrip through serialisation
        let serialised: Vec<String> = shares.iter().map(serialise_share).collect();

        // Parse back and recover
        let raw_shares = parse_shares(&serialised[..2], false).unwrap();
        let recovered = combine_shares(&raw_shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        // Test with a 32-byte key (what we actually use)
        let secret = vec![0x42; 32];
        let shares = split_secret(&secret, 2, 3).unwrap();

        // Serialize shares as they would be in QR codes
        let serialised: Vec<String> = shares.iter().map(serialise_share).collect();

        // Parse back the shares
        let raw_shares = parse_shares(&serialised[..2], false).unwrap();

        // Use the public combine_shares function
        let recovered = combine_shares(&raw_shares).unwrap();
        assert_eq!(recovered, secret);
    }
}
