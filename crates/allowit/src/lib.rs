#![no_std]
//! Canonical AllowIt policy rules. The offchain server and `AllowitCustomPolicy` compile one authored
//! policy file verbatim:
//!
//! ```ignore
//! use allowit::prelude::*;
//! /// Let my agent pay our invoices. Cap its total spending and pay only vendors I approve.
//! pub fn execute(ctx: &AllowitContext) -> allowit::Result {
//!     // "Cap its total spending"
//!     allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
//!     // "pay only vendors I approve"
//!     allowit::recipients(ctx, &ctx.grant.recipients)?;
//!     Ok(())
//! }
//! ```
//!
//! Rules check only the facts they read. Each returns its passing constraint or an
//! `AllowitError`. An unset Grant field is `MissingGrant`. A failed rule also records its error in
//! `ctx.env`. `run` runs a complete policy: a failed rule ends the run with a denial, even if the
//! policy catches the error. The standard contract runs only the leading canonical calls, supplied
//! by the owner as `rules`, through `preflight`, which skips unset fields.
//! `scripts/contract_admin.py` derives `rules` from the source.
//!
//! `AllowitContext` is plain data: `env`, `grant`, `state` and `request`. Portable authored code
//! uses rule calls, typed scalar fields and enum comparisons such as
//! `ctx.request.operation == AllowitOperation::sep56_deposit`. Backend list methods differ (for
//! example `len` returns `u32` onchain and `usize` on the host), so authored code reads lists only
//! through `recipients` and `tokens`. Authored code does not call `ctx.env` methods, because the
//! two environments have none in common.
//!
//! Types and rule logic are written once in `core.rs` and compiled per backend. Each backend binds
//! `Address`, `AllowitEnv` and `Vec`. Feature `soroban` (default) uses host values, contract types
//! and the Soroban `Env`, and records rule failures in contract temporary storage. Feature `std`
//! uses heap strings and vectors, and records rule failures in a host `AllowitEnv`. The selected
//! backend backs the crate root, which authored policy names. The offchain server depends on
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

/// Onchain backend. Owner-signed Grant and every other rule input are Soroban contract types.
#[cfg(feature = "soroban")]
pub mod soroban {
    pub use soroban_sdk::Address;
    use soroban_sdk::{Env as AllowitEnv, Symbol, Vec, symbol_short};
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

    /// Temporary-storage key of the first rule failure of the running contract.
    const FAILURE: Symbol = symbol_short!("rule_fail");

    /// Record the first rule failure in the contract's temporary storage. A runner then denies,
    /// which rolls the write back with the rest of the invocation.
    fn record(env: &AllowitEnv, error: AllowitError) {
        let storage = env.storage().temporary();
        if !storage.has(&FAILURE) {
            storage.set(&FAILURE, &(error as u32));
        }
    }

    /// The first rule failure recorded in this contract, if any.
    fn recorded(env: &AllowitEnv) -> Option<AllowitError> {
        let code: u32 = env.storage().temporary().get(&FAILURE)?;
        Some(match code {
            1 => AllowitError::MissingGrant,
            2 => AllowitError::TransactionCapExceeded,
            3 => AllowitError::SpentCapExceeded,
            4 => AllowitError::DaySpentCapExceeded,
            5 => AllowitError::DayTotalCapExceeded,
            6 => AllowitError::CallCapExceeded,
            7 => AllowitError::RecipientNotAllowed,
            8 => AllowitError::TokenNotAllowed,
            9 => AllowitError::Expired,
            10 => AllowitError::Unpriced,
            11 => AllowitError::InvalidParameter,
            12 => AllowitError::InvalidState,
            // Only `record` writes this key. Deny an unknown value.
            _ => AllowitError::InvalidState,
        })
    }
}

/// Host backend for the offchain server and SDK evaluator. Addresses are StrKey strings.
#[cfg(feature = "std")]
pub mod host {
    /// Exact Stellar account or contract identity as its StrKey text.
    pub type Address = alloc::string::String;
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::Cell;

    /// Host environment of one policy evaluation. Clones share it. It records the first rule
    /// failure, so `run` denies even if the policy catches the error. Create a new one for every
    /// evaluation.
    #[derive(Clone, Debug, Default)]
    pub struct AllowitEnv {
        failure: Rc<Cell<Option<AllowitError>>>,
    }

    /// Record the first rule failure of this evaluation.
    fn record(env: &AllowitEnv, error: AllowitError) {
        if env.failure.get().is_none() {
            env.failure.set(Some(error));
        }
    }

    /// The first rule failure recorded in this evaluation, if any.
    fn recorded(env: &AllowitEnv) -> Option<AllowitError> {
        env.failure.get()
    }
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
