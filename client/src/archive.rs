use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tar::Builder;
use tempfile::NamedTempFile;
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::crypto;

const CHUNK_SIZE: usize = 64 * 1024;

pub fn create_encrypted_archive(
    paths: &[PathBuf],
    output_filename: &str,
    key: &[u8],
    verbose: bool,
) -> Result<()> {
    validate_paths(paths)?;

    let output_file = File::create(output_filename)
        .with_context(|| format!("Failed to create output file: {output_filename}"))?;

    create_encrypted_archive_to_writer(paths, output_file, key, verbose)
}

fn add_to_archive<W: Write>(builder: &mut Builder<W>, path: &Path, verbose: bool) -> Result<()> {
    add_path_to_archive(builder, path, path, verbose)
}

fn add_path_to_archive<W: Write>(
    builder: &mut Builder<W>,
    path: &Path,
    base_path: &Path,
    verbose: bool,
) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("Path does not exist: {:?}", path);
    }

    let metadata =
        fs::metadata(path).with_context(|| format!("Failed to get metadata for {path:?}"))?;

    let relative_path = if path == base_path {
        // For the root path being added, use its name
        path.file_name()
            .map(Path::new)
            .unwrap_or_else(|| Path::new("."))
    } else {
        // For nested paths, strip the base prefix
        path.strip_prefix(base_path).unwrap_or(path)
    };

    if metadata.is_file() {
        if verbose && path != base_path {
            eprintln!("  Adding file: {relative_path:?}");
        }

        let mut file = File::open(path).with_context(|| format!("Failed to open file {path:?}"))?;

        // For root files, use just the filename
        let archive_path = if path == base_path {
            path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
        } else {
            relative_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid path encoding"))?
        };

        builder
            .append_file(archive_path, &mut file)
            .with_context(|| format!("Failed to add file {path:?} to archive"))?;
    } else if metadata.is_dir() {
        if verbose && path != base_path {
            eprintln!("  Adding directory: {relative_path:?}");
        }

        // Add the directory entry itself (except for the root)
        if path != base_path {
            builder
                .append_dir(relative_path, path)
                .with_context(|| format!("Failed to add directory {path:?} to archive"))?;
        }

        // Recursively add directory contents
        let entries =
            fs::read_dir(path).with_context(|| format!("Failed to read directory {path:?}"))?;

        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let entry_path = entry.path();
            add_path_to_archive(builder, &entry_path, base_path, verbose)?;
        }
    } else {
        anyhow::bail!("Unsupported file type for {:?}", path);
    }

    Ok(())
}

fn validate_paths(paths: &[PathBuf]) -> Result<()> {
    if paths.is_empty() {
        anyhow::bail!("No paths specified for archiving");
    }

    for path in paths {
        if !path.exists() {
            anyhow::bail!("Path does not exist: {:?}", path);
        }
    }

    Ok(())
}

pub fn create_encrypted_archive_to_writer<W: Write>(
    paths: &[PathBuf],
    writer: W,
    key: &[u8],
    verbose: bool,
) -> Result<()> {
    validate_paths(paths)?;

    // Create a secure temporary file for the tar.zst
    let temp_tar = NamedTempFile::new().context("Failed to create temporary tar file")?;
    let temp_tar_path = temp_tar.path().to_path_buf();

    // Create the compressed tar archive
    {
        let tar_file = File::create(&temp_tar_path)
            .with_context(|| format!("Failed to create temporary tar file: {temp_tar_path:?}"))?;

        let zstd_encoder = ZstdEncoder::new(tar_file, 3)?;
        let mut tar_builder = Builder::new(zstd_encoder);

        for path in paths {
            if verbose {
                eprintln!("Adding to archive: {path:?}");
            }
            add_to_archive(&mut tar_builder, path, verbose)?;
        }

        let zstd_encoder = tar_builder
            .into_inner()
            .context("Failed to finalise tar archive")?;
        zstd_encoder
            .finish()
            .context("Failed to finish zstd compression")?;
    }

    // Now encrypt and stream to the writer
    let tar_file = File::open(&temp_tar_path)
        .with_context(|| format!("Failed to open temporary tar file: {temp_tar_path:?}"))?;

    crypto::encrypt_stream_simple(key, tar_file, writer, CHUNK_SIZE)?;

    // temp_tar is automatically deleted on drop
    Ok(())
}

pub fn decrypt_to_file(
    input_file: &str,
    output_file: &str,
    key: &[u8],
    verbose: bool,
) -> Result<()> {
    if verbose {
        eprintln!("Decrypting archive: {input_file} -> {output_file}");
    }

    let input = fs::File::open(input_file)
        .with_context(|| format!("Failed to open input file: {input_file}"))?;

    let output = fs::File::create(output_file)
        .with_context(|| format!("Failed to create output file: {output_file}"))?;

    crypto::decrypt_stream_simple(key, input, output)?;

    if verbose {
        eprintln!("Successfully decrypted to: {output_file}");
    }

    Ok(())
}

pub fn extract_encrypted_archive(
    input_file: &str,
    output_dir: &str,
    key: &[u8],
    verbose: bool,
) -> Result<()> {
    use tar::Archive;
    use zstd::stream::read::Decoder as ZstdDecoder;

    if verbose {
        eprintln!("Extracting encrypted archive: {input_file}");
    }

    let input = File::open(input_file)
        .with_context(|| format!("Failed to open input file: {input_file}"))?;

    // Use secure temporary file
    let temp_tar = NamedTempFile::new().context("Failed to create temporary decrypted file")?;
    let temp_tar_path = temp_tar.path().to_path_buf();

    crypto::decrypt_stream_simple(key, input, &temp_tar)?;

    let tar_zst = File::open(&temp_tar_path).context("Failed to open decrypted tar.zst file")?;
    let zstd_decoder = ZstdDecoder::new(tar_zst)?;
    let mut archive = Archive::new(zstd_decoder);

    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory: {output_dir}"))?;

    archive
        .unpack(output_dir)
        .with_context(|| format!("Failed to extract archive to {output_dir}"))?;

    // temp_tar is automatically deleted on drop

    if verbose {
        eprintln!("Successfully extracted to: {output_dir}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_validate_paths() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();

        let valid_paths = vec![file_path.clone()];
        assert!(validate_paths(&valid_paths).is_ok());

        let invalid_paths = vec![PathBuf::from("/nonexistent/path")];
        assert!(validate_paths(&invalid_paths).is_err());

        let empty_paths: Vec<PathBuf> = vec![];
        assert!(validate_paths(&empty_paths).is_err());
    }

    #[test]
    fn test_create_and_extract_archive() {
        let temp_dir = TempDir::new().unwrap();

        let test_dir = temp_dir.path().join("test_data");
        fs::create_dir(&test_dir).unwrap();
        fs::write(test_dir.join("file1.txt"), "Content 1").unwrap();
        fs::write(test_dir.join("file2.txt"), "Content 2").unwrap();

        let sub_dir = test_dir.join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        fs::write(sub_dir.join("file3.txt"), "Content 3").unwrap();

        let output_file = temp_dir.path().join("test.hecate");
        let output_filename = output_file.to_str().unwrap();

        let key = crate::crypto::generate_key().unwrap();

        create_encrypted_archive(&[test_dir.clone()], output_filename, &key, false).unwrap();

        assert!(output_file.exists());

        let mut encrypted_data = Vec::new();
        File::open(&output_file)
            .unwrap()
            .read_to_end(&mut encrypted_data)
            .unwrap();
        assert!(encrypted_data.len() > crate::crypto::HEADER_SIZE);

        let extract_dir = temp_dir.path().join("extracted");
        extract_encrypted_archive(output_filename, extract_dir.to_str().unwrap(), &key, false)
            .unwrap();

        assert!(extract_dir.join("file1.txt").exists());
        assert!(extract_dir.join("file2.txt").exists());
        assert!(extract_dir.join("subdir/file3.txt").exists());

        let content1 = fs::read_to_string(extract_dir.join("file1.txt")).unwrap();
        assert_eq!(content1, "Content 1");
    }

    #[test]
    fn test_archive_single_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("single.txt");
        fs::write(&test_file, "Single file content").unwrap();

        let output_file = temp_dir.path().join("single.hecate");
        let output_filename = output_file.to_str().unwrap();

        let key = crate::crypto::generate_key().unwrap();

        create_encrypted_archive(&[test_file], output_filename, &key, true).unwrap();

        assert!(output_file.exists());
        assert!(output_file.metadata().unwrap().len() > 0);
    }
}
