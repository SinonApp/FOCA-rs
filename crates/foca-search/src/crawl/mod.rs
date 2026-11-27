//! Crawler building blocks: trap protection, adaptive pace and image selection.

pub mod images;
pub mod pace;
pub mod trap;

pub use images::{image_score, select_images, ImageCand};
pub use pace::{Pace, RateState};
pub use trap::{clean_url, risky_link, template_key, TrapGuard};
