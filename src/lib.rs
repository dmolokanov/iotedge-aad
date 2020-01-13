use std::error::Error;

mod auth;
mod context;
pub mod identity;

pub use auth::{Auth, TokenSource};
pub use context::Context;
pub use identity::Identity;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
