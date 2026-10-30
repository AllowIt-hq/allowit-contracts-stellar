#![no_std]
//! Canonical AllowIt policy rules. The offchain server and CustomPolicy compile one authored
//! policy file verbatim:
//!
//! ```ignore
//! use allowit::prelude::*;
//! pub fn execute(ctx: &AllowitContext) -> allowit::Result {
//!     allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
//!     allowit::recipients(ctx, &ctx.grant.recipients)?;
//!     Ok(())
//! }
//! ```
//!
//! Rules are pure checks. Each returns its passing constraint or an `AllowitError`. An unset AllowitGrant field
//! is `MissingGrant`. The standard contract runs only the leading canonical calls, supplied by the
//! owner as `rules`, through `preflight`, which makes the same unguarded calls. Owner
//! configuration rejects a prefix rule whose Grant field is unset. `scripts/contract_admin.py`
//! derives `rules` from the source.
//!
//! Portable authored code uses rule calls, typed scalar fields and enum comparisons such as
//! `ctx.request.operation == AllowitOperation::sep56_deposit`. Backend list methods differ (for example
//! `len` returns `u32` onchain and `usize` on the host), so authored code reads lists only through
//! `recipients` and `tokens`.
//!
//! Types and rule logic are written once in `core.rs` and compiled per backend. Each backend binds
//! `Address` and `Vec`. Feature `soroban` (default) uses host values and contract types.
//! Feature `std` uses heap strings and vectors. The selected backend backs the crate root, which
//! authored policy names. The offchain server depends on
//! `allowit = { default-features = false, features = ["std"] }` and must not unify `soroban`:
//! enabling both is a compile error. Feature `dual` enables both for portability tests only;
//! `soroban` then backs the root and `allowit::host` stays available.
#[cfg(feature = "std")]
extern crate alloc;

#[cfg(not(any(feature = "soroban", feature = "std")))]
compile_error!("Enable feature `soroban` or `std`");

#[cfg(all(feature = "soroban", feature = "std", not(feature = "dual")))]
compile_error!(
    "Features `soroban` and `std` select different crate-root types; use `default-features = false`"
);

/// Onchain backend. Owner-signed AllowitGrant and every rule input are Soroban contract types.
#[cfg(feature = "soroban")]
pub mod soroban {
    pub use soroban_sdk::Address;
    use soroban_sdk::Vec;
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
    use alloc::vec::Vec;
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
