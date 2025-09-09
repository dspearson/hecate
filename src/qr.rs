use anyhow::{Context, Result};
use image::{DynamicImage, Luma};
use qrcode::QrCode;
use std::path::{Path, PathBuf};

use crate::shamir::{Share, deserialise_share, serialise_share};

pub fn generate_qr_codes(shares: &[Share], base_filename: &str) -> Result<Vec<PathBuf>> {
    let mut qr_paths = Vec::new();
    let base_path = Path::new(base_filename);
    let stem = base_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");

    for share in shares {
        let serialised = serialise_share(share);

        let code = QrCode::new(&serialised).context("Failed to generate QR code")?;

        let image = code
            .render::<Luma<u8>>()
            .dark_color(Luma([0u8]))
            .light_color(Luma([255u8]))
            .quiet_zone(true)
            .module_dimensions(8, 8)
            .build();

        let filename = format!("{}-key-{:02}.png", stem, share.index);
        let qr_path = base_path
            .parent()
            .map(|p| p.join(&filename))
            .unwrap_or_else(|| PathBuf::from(&filename));

        image
            .save(&qr_path)
            .with_context(|| format!("Failed to save QR code to {qr_path:?}"))?;

        qr_paths.push(qr_path);
    }

    Ok(qr_paths)
}

/// Decode QR code from an image file
pub fn decode_qr_from_image(img: DynamicImage) -> Result<String> {
    use rqrr::PreparedImage;

    // Convert to grayscale for QR detection
    let gray_img = img.to_luma8();

    // Prepare the image for QR detection
    let mut prepared = PreparedImage::prepare(gray_img);

    // Detect QR codes in the image
    let grids = prepared.detect_grids();

    if grids.is_empty() {
        anyhow::bail!("No QR code found in image");
    }

    // Decode the first QR code found
    let (_, content) = grids[0]
        .decode()
        .map_err(|e| anyhow::anyhow!("Failed to decode QR code: {:?}", e))?;

    Ok(content)
}

/// Read and parse a QR code share from an image file
pub fn parse_qr_share(file_path: &str) -> Result<Share> {
    // Read QR code from image file
    let img =
        image::open(file_path).with_context(|| format!("Failed to open image: {file_path}"))?;

    let qr_data = decode_qr_from_image(img)?;

    // Parse the decoded QR data
    deserialise_share(&qr_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_qr_codes() {
        let shares = vec![
            Share {
                index: 1,
                mnemonic: "test mnemonic one".to_string(),
            },
            Share {
                index: 2,
                mnemonic: "test mnemonic two".to_string(),
            },
            Share {
                index: 3,
                mnemonic: "test mnemonic three".to_string(),
            },
        ];

        let temp_dir = TempDir::new().unwrap();
        let base_filename = temp_dir.path().join("test.hecate");
        let base_filename_str = base_filename.to_str().unwrap();

        let paths = generate_qr_codes(&shares, base_filename_str).unwrap();

        assert_eq!(paths.len(), 3);

        for path in &paths {
            assert!(path.exists());
            assert!(path.is_file());
            assert_eq!(path.extension().and_then(|s| s.to_str()), Some("png"));
        }

        assert!(paths[0].to_str().unwrap().contains("key-01"));
        assert!(paths[1].to_str().unwrap().contains("key-02"));
        assert!(paths[2].to_str().unwrap().contains("key-03"));
    }
}
