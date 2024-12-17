use http::StatusCode;
use image::GenericImageView;
use mime::Mime;
use regex::Regex;
use once_cell::sync::Lazy;
use validator::{ValidateRegex};

static DISPLAY_NAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-ZÀ-ÖØ-öø-ÿ\s'-]{2,50}$").unwrap()
});

pub fn is_valid_display_name(display_name: &str) -> bool {
    display_name.validate_regex(DISPLAY_NAME_REGEX.clone())
}

/// Valide le fichier image
pub fn validate_image_file(content_type: &str, file_bytes: &[u8]) -> axum::response::Result<()> {
    // Check MIME type
    let mime: Mime = content_type.parse().map_err(|_|
        (StatusCode::BAD_REQUEST, "Invalid file type")
    )?;

    // Only allow jpg/jpeg
    if mime.type_() != mime::IMAGE ||
        (mime.subtype() != mime::JPEG) {
        return Err((StatusCode::BAD_REQUEST, "Only .jpg files are allowed").into());
    }

    // Validate image using image crate
    let img = image::load_from_memory(file_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid image file"))?;

    // Optional: Add size constraints
    let (width, height) = img.dimensions();
    if width > 500 || height > 500 || file_bytes.len() > 10 * 1024 * 1024 {
        return Err((StatusCode::BAD_REQUEST, "Image is too large. Max 500x500 pixels and 10MB").into());
    }

    Ok(())
}