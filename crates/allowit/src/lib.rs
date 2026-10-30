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
//! `AllowitError`. An unset Grant field is `MissingGrant`. A failed rule also records its error
//! for the running evaluation: on the host in a thread-local of the evaluating thread, onchain in
//! the memory of the running contract instance. Neither lives in `ctx.env`, so policy code that
//! replaces or clones `ctx.env` cannot drop it. `run` runs a complete policy: a failed rule ends
//! the run with a denial, even if the policy catches the error. The standard contract runs only
//! the leading canonical calls, supplied by the owner as `rules`, through `preflight`, which skips
//! unset fields. `scripts/contract_admin.py` derives `rules` from the source.
//!
//! `AllowitContext` is plain data: `env`, `grant`, `state` and `request`. Portable authored code
//! uses rule calls, typed scalar fields and enum comparisons such as
//! `ctx.request.operation == AllowitOperation::sep56_deposit`. Backend list methods differ (for
//! example `len` returns `u32` onchain and `usize` on the host), so authored code reads lists only
//! through `recipients` and `tokens`. Authored code reads `ctx.env` only as a bare field and does
//! not call its methods, because the two environments have none in common.
//!
//! Types and rule logic are written once in `core.rs` and compiled per backend. Each backend binds
//! `Address`, `AllowitEnv` and `Vec`. Feature `soroban` (default) uses host values, contract types
//! and the Soroban `Env`, and records rule failures in the memory of the running contract
//! instance, not in ledger storage. Feature `std` uses unordered StrKey addresses, heap vectors
//! and a stateless host `AllowitEnv`, and records rule failures in a thread-local. The selected backend backs the crate
//! root, which authored policy names.
//!
//! The offchain server depends on `allowit = { default-features = false, features = ["std"] }`
//! and must not unify `soroban`: enabling both is a compile error. The server must also build
//! with `overflow-checks = true`, as the contract release profile does, so that integer overflow
//! in authored code panics and denies on both backends instead of wrapping on the host.
#[cfg(feature = "std")]
extern crate alloc;

// The host backend, and the Soroban backend in native builds, keep the rule-failure record in a
// thread-local.
#[cfg(any(feature = "std", all(feature = "soroban", not(target_family = "wasm"))))]
extern crate std;

#[cfg(not(any(feature = "soroban", feature = "std")))]
compile_error!("Enable feature `soroban` or `std`");

#[cfg(all(feature = "soroban", feature = "std"))]
compile_error!(
    "Features `soroban` and `std` select different crate-root types; use `default-features = false`"
);

/// Onchain backend. Owner-signed Grant and every other rule input are Soroban contract types.
#[cfg(feature = "soroban")]
pub mod soroban {
    pub use soroban_sdk::Address;
    use soroban_sdk::{Env as AllowitEnv, Vec};
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

    /// Code of the first rule failure in this contract instance, or zero. Soroban runs every
    /// contract invocation in a new VM instance, so the value starts at zero and dies with the
    /// invocation. It is not ledger state: recording a failure reads and writes no storage entry,
    /// so it adds nothing to the transaction footprint. Authored code cannot name it.
    #[cfg(target_family = "wasm")]
    static FAILURE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    #[cfg(target_family = "wasm")]
    fn exchange(code: u32) -> u32 {
        FAILURE.swap(code, core::sync::atomic::Ordering::Relaxed)
    }

    // Native tests run every contract frame of a test on one thread, and tests in parallel.
    #[cfg(not(target_family = "wasm"))]
    std::thread_local! {
        static FAILURE: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
    }

    #[cfg(not(target_family = "wasm"))]
    fn exchange(code: u32) -> u32 {
        FAILURE.with(|failure| failure.replace(code))
    }

    /// Record the first rule failure of the running contract instance.
    fn record(error: AllowitError) {
        let first = exchange(error as u32);
        if first != 0 {
            exchange(first);
        }
    }

    /// Replace the recorded rule failure of the running contract instance; return the old one.
    fn swap(failure: Option<AllowitError>) -> Option<AllowitError> {
        let code = exchange(failure.map_or(0, |error| error as u32));
        Some(match code {
            0 => return None,
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
            // `InvalidState` (12). Only `record` and `swap` write a code.
            _ => AllowitError::InvalidState,
        })
    }
}

/// Host backend for the offchain server and SDK evaluator. Addresses are StrKey strings.
#[cfg(feature = "std")]
pub mod host {
    use alloc::{string::String, vec::Vec};

    /// Exact Stellar account or contract identity, held as its StrKey text. It compares only for
    /// equality. Soroban orders addresses by `ScAddress`, so accounts sort before contracts, while
    /// text would sort by StrKey; `Address` therefore has no order on the host, and authored code
    /// that orders addresses fails the std-only compile.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Address(String);

    impl Address {
        /// The address with this StrKey text. The server supplies a validated StrKey.
        pub fn new(strkey: impl Into<String>) -> Self {
            Self(strkey.into())
        }

        /// The StrKey text of this address.
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }
    use core::cell::Cell;

    /// Host environment of one policy evaluation. It carries no state: the rule-failure record
    /// is a thread-local of the evaluating thread, as onchain it is memory of the running
    /// contract instance. So replacing `ctx.env`, cloning it or creating another `AllowitEnv`
    /// inside policy code cannot drop a recorded failure.
    #[derive(Clone, Debug)]
    pub struct AllowitEnv {
        _private: (),
    }

    impl AllowitEnv {
        /// The environment of a new evaluation.
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { _private: () }
        }
    }

    // `run` clears the record when it starts and restores the outer record when it returns, so
    // evaluations on one thread do not see each other's failures.
    std::thread_local! {
        static FAILURE: Cell<Option<AllowitError>> = const { Cell::new(None) };
    }

    /// Record the first rule failure of the evaluation running on this thread.
    fn record(error: AllowitError) {
        FAILURE.with(|failure| {
            if failure.get().is_none() {
                failure.set(Some(error));
            }
        });
    }

    /// Replace the recorded rule failure of this thread; return the old one.
    fn swap(failure: Option<AllowitError>) -> Option<AllowitError> {
        FAILURE.with(|cell| cell.replace(failure))
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

#[cfg(feature = "std")]
pub use host::*;

#[cfg(all(test, feature = "soroban"))]
mod tests;
