#[cfg(test)]
mod end_to_end_tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    // Helper to create test files
    fn create_test_files(dir: &Path) -> Vec<PathBuf> {
        let files = vec![
            ("test1.txt", b"This is test file 1"),
            ("test2.txt", b"This is test file 2"),
            ("subdir/test3.txt", b"This is test file 3"),
        ];

        let mut paths = Vec::new();
        for (name, content) in files {
            let path = dir.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, content).unwrap();
            paths.push(path);
        }

        paths
    }

    #[test]
    fn test_full_encryption_decryption_cycle() {
        use hecate::archive;
        use hecate::crypto;
        use hecate::shamir;

        let temp_dir = TempDir::new().unwrap();
        let _test_files = create_test_files(temp_dir.path());

        // Generate key
        let key = crypto::generate_key().unwrap();
        assert_eq!(key.len(), crypto::KEY_SIZE);

        // Split key into shares
        let shares = shamir::split_secret(&key, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Create encrypted archive
        let archive_path = temp_dir.path().join("test.hecate");
        archive::create_encrypted_archive(
            &vec![temp_dir.path().to_path_buf()],
            archive_path.to_str().unwrap(),
            &key,
            false,
        )
        .unwrap();

        assert!(archive_path.exists());
        assert!(archive_path.metadata().unwrap().len() > 0);

        // Recover key from shares (using only 2 of 3)
        let share_strings: Vec<String> = shares
            .iter()
            .take(2)
            .map(|s| shamir::serialise_share(s))
            .collect();

        let raw_shares = shamir::parse_shares(&share_strings, false).unwrap();
        let recovered_key = shamir::combine_shares(&raw_shares).unwrap();
        assert_eq!(recovered_key, key);

        // Extract archive
        let extract_dir = temp_dir.path().join("extracted");
        archive::extract_encrypted_archive(
            archive_path.to_str().unwrap(),
            extract_dir.to_str().unwrap(),
            &recovered_key,
            false,
        )
        .unwrap();

        // Verify extracted files
        assert!(extract_dir.join("test1.txt").exists());
        assert!(extract_dir.join("test2.txt").exists());
        assert!(extract_dir.join("subdir/test3.txt").exists());

        let content1 = fs::read(extract_dir.join("test1.txt")).unwrap();
        assert_eq!(content1, b"This is test file 1");
    }

    #[test]
    fn test_wrong_key_fails() {
        use hecate::archive;
        use hecate::crypto;

        let temp_dir = TempDir::new().unwrap();
        create_test_files(temp_dir.path());

        let key1 = crypto::generate_key().unwrap();
        let key2 = crypto::generate_key().unwrap();

        // Create archive with key1
        let archive_path = temp_dir.path().join("test.hecate");
        archive::create_encrypted_archive(
            &vec![temp_dir.path().to_path_buf()],
            archive_path.to_str().unwrap(),
            &key1,
            false,
        )
        .unwrap();

        // Try to extract with key2 - should fail
        let extract_dir = temp_dir.path().join("extracted");
        let result = archive::extract_encrypted_archive(
            archive_path.to_str().unwrap(),
            extract_dir.to_str().unwrap(),
            &key2,
            false,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authentication"));
    }

    #[test]
    fn test_share_recovery() {
        use hecate::crypto;
        use hecate::shamir;

        let key = crypto::generate_key().unwrap();

        // Split key into shares
        let shares = shamir::split_secret(&key, 2, 3).unwrap();

        // Serialize and parse shares
        let share_strings: Vec<String> = shares
            .iter()
            .take(2)
            .map(|s| shamir::serialise_share(s))
            .collect();

        let raw_shares = shamir::parse_shares(&share_strings, false).unwrap();

        // Combine shares
        let recovered_key = shamir::combine_shares(&raw_shares).unwrap();
        assert_eq!(recovered_key, key);
    }

    #[test]
    fn test_insufficient_shares() {
        use hecate::crypto;
        use hecate::shamir;

        let key = crypto::generate_key().unwrap();
        let shares = shamir::split_secret(&key, 2, 3).unwrap();

        // Try to combine with only 1 share (need 2)
        let share_strings: Vec<String> = shares
            .iter()
            .take(1)
            .map(|s| shamir::serialise_share(s))
            .collect();

        let result = shamir::parse_shares(&share_strings, false);
        // Should fail because we don't have enough shares
        assert!(
            result.is_err() || {
                let raw_shares = result.unwrap();
                shamir::combine_shares(&raw_shares).is_err()
            }
        );
    }

    #[test]
    fn test_large_file_encryption() {
        use hecate::archive;
        use hecate::crypto;

        let temp_dir = TempDir::new().unwrap();

        // Create a large test file (10MB)
        let large_file = temp_dir.path().join("large.dat");
        let large_data = vec![0x42u8; 10 * 1024 * 1024];
        fs::write(&large_file, &large_data).unwrap();

        let key = crypto::generate_key().unwrap();

        // Encrypt large file
        let archive_path = temp_dir.path().join("large.hecate");
        archive::create_encrypted_archive(
            &vec![large_file.clone()],
            archive_path.to_str().unwrap(),
            &key,
            false,
        )
        .unwrap();

        // Extract and verify
        let extract_dir = temp_dir.path().join("extracted");
        archive::extract_encrypted_archive(
            archive_path.to_str().unwrap(),
            extract_dir.to_str().unwrap(),
            &key,
            false,
        )
        .unwrap();

        let extracted_file = extract_dir.join("large.dat");
        assert!(extracted_file.exists());

        let extracted_data = fs::read(extracted_file).unwrap();
        assert_eq!(extracted_data.len(), large_data.len());
        assert_eq!(extracted_data, large_data);
    }

    #[test]
    fn test_streaming_encryption() {
        use hecate::crypto;
        use std::io::Cursor;

        let plaintext = b"Test data for streaming encryption";
        let key = crypto::generate_key().unwrap();

        // Encrypt
        let mut encrypted = Vec::new();
        crypto::encrypt_stream_simple(&key, Cursor::new(plaintext), &mut encrypted, 16).unwrap();

        // Decrypt
        let mut decrypted = Vec::new();
        crypto::decrypt_stream_simple(&key, Cursor::new(encrypted), &mut decrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_qr_code_generation_and_parsing() {
        use hecate::crypto;
        use hecate::qr;
        use hecate::shamir;

        let _temp_dir = TempDir::new().unwrap();
        let key = crypto::generate_key().unwrap();
        let shares = shamir::split_secret(&key, 2, 3).unwrap();

        // Generate QR codes
        let output_name = "test-archive";
        let qr_paths = qr::generate_qr_codes(&shares, output_name).unwrap();

        assert_eq!(qr_paths.len(), 3);
        for path in &qr_paths {
            assert!(Path::new(path).exists());

            // Verify it's a valid PNG
            let data = fs::read(path).unwrap();
            assert!(data.starts_with(&[0x89, 0x50, 0x4E, 0x47])); // PNG magic
        }

        // Clean up
        for path in qr_paths {
            fs::remove_file(path).ok();
        }
    }

    #[test]
    fn test_archive_with_symlinks() {
        #[cfg(unix)]
        {
            use hecate::archive;
            use hecate::crypto;
            use std::os::unix::fs;

            let temp_dir = TempDir::new().unwrap();
            let target_file = temp_dir.path().join("target.txt");
            std::fs::write(&target_file, b"Target content").unwrap();

            let symlink = temp_dir.path().join("link.txt");
            fs::symlink(&target_file, &symlink).unwrap();

            let key = crypto::generate_key().unwrap();
            let archive_path = temp_dir.path().join("test.hecate");

            // Archive should handle symlinks (either follow or store as symlink)
            let result = archive::create_encrypted_archive(
                &vec![temp_dir.path().to_path_buf()],
                archive_path.to_str().unwrap(),
                &key,
                false,
            );

            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_concurrent_encryption() {
        use hecate::crypto;
        use std::sync::Arc;
        use std::thread;

        let key = Arc::new(crypto::generate_key().unwrap());
        let mut handles = vec![];

        for i in 0..5 {
            let key_clone = Arc::clone(&key);
            let handle = thread::spawn(move || {
                let data = format!("Thread {} data", i).into_bytes();
                let mut encrypted = Vec::new();

                crypto::encrypt_stream_simple(
                    &key_clone,
                    std::io::Cursor::new(data.clone()),
                    &mut encrypted,
                    16,
                )
                .unwrap();

                let mut decrypted = Vec::new();
                crypto::decrypt_stream_simple(
                    &key_clone,
                    std::io::Cursor::new(encrypted),
                    &mut decrypted,
                )
                .unwrap();

                assert_eq!(decrypted, data);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
