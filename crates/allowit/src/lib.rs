#![no_std]
//! Canonical AllowIt policy rules. One authored policy source compiles unchanged for the offchain
//! server, custom contracts and the standard contract preflight:
//!
//! ```ignore
//! use allowit::prelude::*;
//! pub fn execute(ctx: &AllowitEnv) -> allowit::Result {
//!     allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
//!     allowit::recipients(ctx, &ctx.grant.recipients)?;
//!     Ok(())
//! }
//! ```
//!
//! Rules are pure checks. Each returns its passing constraint or an `Error`. An unset Grant field
//! is `MissingGrant`. Only the standard contract preflight runner skips it.
//!
//! Types and rule logic are written once in `core.rs` and compiled per backend. Each backend binds
//! `Address`, `String` and `Vec`. Feature `soroban` uses host values and contract types. Feature
//! `std` uses heap strings and vectors. Both backends can be enabled together: `soroban` then backs
//! the crate root and `allowit::host` stays available.
#[cfg(feature = "std")]
extern crate alloc;

#[cfg(not(any(feature = "soroban", feature = "std")))]
compile_error!("Enable feature `soroban` or `std`");

/// Onchain backend. Owner-signed Grant and every rule input are Soroban contract types.
#[cfg(feature = "soroban")]
pub mod soroban {
    pub use soroban_sdk::Address;
    use soroban_sdk::{String, Vec};
    macro_rules! value {
        ($item:item) => {
            #[soroban_sdk::contracttype]
            $item
        };
    }
    macro_rules! error {
        ($item:item) => {
            #[soroban_sdk::contracterror]
            $item
        };
    }
    include!("core.rs");
}

/// Host backend for the offchain server and SDK evaluator. Addresses are StrKey strings.
#[cfg(feature = "std")]
pub mod host {
    /// Exact Stellar account or contract identity as its StrKey text.
    pub type Address = alloc::string::String;
    use alloc::{string::String, vec::Vec};
    macro_rules! value {
        ($item:item) => {
            $item
        };
    }
    macro_rules! error {
        ($item:item) => {
            $item
        };
    }
    include!("core.rs");
}

#[cfg(feature = "soroban")]
pub use soroban::*;

#[cfg(all(feature = "std", not(feature = "soroban")))]
pub use host::*;

#[cfg(all(test, feature = "soroban"))]
mod tests;
