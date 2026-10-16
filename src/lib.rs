#![doc = include_str!("../README.md")]

pub mod crypto;
pub mod error;
pub mod fs;
pub mod header;
pub mod manifest;
pub mod object;
pub mod ops;
pub mod slot;
pub mod store;
pub mod vault;

#[cfg(test)]
mod tests;

pub use error::Error;
pub(crate) use error::Result;
