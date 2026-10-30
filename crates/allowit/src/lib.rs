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
//! `AllowitContext` is plain data: `env`, `grant`, `state` and `request`. `state` is the current
//! policy state, before this operation: one free-form map with standard keys (`spent`,
//! `day_spent`, `day_total`, `calls`, `day`, `unpriced`, `day_unpriced`) and policy-defined keys.
//! Rules add the request's own contribution to the current values, so each rule is written once
//! and reads current state. Each rule returns its passing constraint or an `AllowitError`; an
//! unset Grant field is `MissingGrant`. Only an error that the policy propagates with `?` ends the
//! run. A policy may catch a rule error, read it and continue.
//!
//! After approval, the wallet and the server run the same `post_flight`: it rolls the UTC day
//! over, counts the call, adds spent and gross amounts, marks unpriced operations, then applies
//! the policy's own `set_state` writes, and denies a result whose standard keys do not decode. The
//! server runs a policy through `evaluate`, which also discards the writes of a denied run. The
//! standard contract runs the leading canonical calls,
//! supplied by the owner as `rules`, through `preflight`, which skips unset fields.
//!
//! Portable authored code uses rule calls, `get_state` and `set_state`, typed scalar fields and
//! enum comparisons. `scripts/policy_source.py` admits only an allowlist of names, paths and
//! methods that give the same result on both backends.
//!
//! Types and rule logic are written once in `core.rs` and compiled per backend. Each backend binds
//! `Address`, `AllowitEnv`, `AllowitStateMap` and `Vec`. Feature `soroban` (default) uses host
//! values, contract types and the Soroban `Env`, and buffers policy writes in contract temporary
//! storage until `post_flight`. Feature `std` uses StrKey addresses, heap maps and vectors, and a
//! host `AllowitEnv` that buffers policy writes. The selected backend backs the crate root, which
//! authored policy names.
//!
//! The server-only enrichment functions (`price`, `fetch`, `internet_search`,
//! `marketplace_search`, `systemone`, `request_screening`, `clear_systemone_context`) exist only in
//! the host backend. A Custom policy that calls one does not compile onchain.
//!
//! The offchain server depends on `allowit = { default-features = false, features = ["std"] }`
//! and must not unify `soroban`: enabling both is a compile error. The server must also build
//! with `overflow-checks = true`, as the contract release profile does, so that integer overflow
//! in authored code panics and denies on both backends instead of wrapping on the host.
//!
//! Crate boundary: `core.rs` with the host backend becomes `sdk/core`; the Soroban backend with
//! the policy wallet crates becomes `stellar/core`.
//!
//! ```
//! use allowit::prelude::*;
//! /// Control for the test below: the same policy without the server-only call compiles onchain.
//! pub fn execute(ctx: &AllowitContext) -> allowit::Result {
//!     allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
//!     Ok(())
//! }
//! ```
//!
//! ```compile_fail,E0425
//! use allowit::prelude::*;
//! /// A Custom policy that calls a server-only function does not build onchain.
//! pub fn execute(ctx: &AllowitContext) -> allowit::Result {
//!     allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
//!     let _ = allowit::price(ctx, &ctx.request.asset, ctx.request.amount)?;
//!     Ok(())
//! }
//! ```
#[cfg(feature = "std")]
extern crate alloc;
#[cfg(feature = "std")]
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
    use soroban_sdk::{Env as AllowitEnv, IntoVal, Map, Symbol, TryFromVal, Val, Vec};
    /// Free-form policy state: standard and policy-defined keys.
    pub type AllowitStateMap = Map<Symbol, Val>;
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

    /// A state value: `i128`, `u64` or `bool`.
    pub trait AllowitValue: IntoVal<AllowitEnv, Val> + TryFromVal<AllowitEnv, Val> {}
    impl AllowitValue for i128 {}
    impl AllowitValue for u64 {}
    impl AllowitValue for bool {}

    /// Temporary-storage key of the running operation's policy writes. `post_flight` removes it,
    /// and a failed operation rolls it back, so it never outlives the transaction.
    const WRITES: Symbol = soroban_sdk::symbol_short!("allowit_w");

    /// The symbol of a valid state key.
    fn symbol(env: &AllowitEnv, key: &str) -> Result<Symbol> {
        if key_ok(key) {
            Ok(Symbol::new(env, key))
        } else {
            Err(AllowitError::InvalidParameter)
        }
    }

    /// The value of `key`, or `None`. A value of another type is `InvalidState`.
    pub(crate) fn read<V: AllowitValue>(
        env: &AllowitEnv,
        state: &AllowitStateMap,
        key: &str,
    ) -> Result<Option<V>> {
        match state.get(symbol(env, key)?) {
            None => Ok(None),
            Some(raw) => V::try_from_val(env, &raw)
                .map(Some)
                .map_err(|_| AllowitError::InvalidState),
        }
    }

    /// Set `key` to `value` in `state`.
    fn write<V: AllowitValue>(
        env: &AllowitEnv,
        state: &mut AllowitStateMap,
        key: &str,
        value: V,
    ) -> Result {
        state.set(symbol(env, key)?, value.into_val(env));
        Ok(())
    }

    /// Buffer one policy write for `post_flight`.
    fn record<V: AllowitValue>(env: &AllowitEnv, key: &str, value: V) -> Result {
        let store = env.storage().temporary();
        let mut writes = store.get(&WRITES).unwrap_or_else(|| Map::new(env));
        write(env, &mut writes, key, value)?;
        store.set(&WRITES, &writes);
        Ok(())
    }

    /// Remove and return the buffered policy writes.
    fn take_writes(env: &AllowitEnv) -> AllowitStateMap {
        let store = env.storage().temporary();
        let writes = store.get(&WRITES).unwrap_or_else(|| Map::new(env));
        if !writes.is_empty() {
            store.remove(&WRITES);
        }
        writes
    }

    /// Apply `writes` over `state`.
    fn merge(state: &mut AllowitStateMap, writes: AllowitStateMap) {
        for (key, value) in writes.iter() {
            state.set(key, value);
        }
    }
}

/// Host backend for the offchain server and SDK evaluator. Addresses are StrKey strings.
#[cfg(feature = "std")]
pub mod host {
    use alloc::{collections::BTreeMap, string::String, vec::Vec};
    use std::sync::{Arc, Mutex, MutexGuard};

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

    /// One state value, as the Soroban backend holds it in a `Val`.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AllowitVal {
        I128(i128),
        U64(u64),
        Bool(bool),
    }

    /// Free-form policy state: standard and policy-defined keys.
    pub type AllowitStateMap = BTreeMap<String, AllowitVal>;

    /// Host environment of policy evaluations. It buffers the policy's `set_state` writes for
    /// `post_flight`; clones share the buffer. `evaluate` clears it before a run and on denial.
    #[derive(Clone, Debug)]
    pub struct AllowitEnv {
        writes: Arc<Mutex<AllowitStateMap>>,
    }

    impl AllowitEnv {
        /// The environment of a new evaluation, with no buffered writes.
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self {
                writes: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }

        /// The write buffer. A panic while it was held leaves no partial write, so it stays usable.
        fn buffer(&self) -> MutexGuard<'_, AllowitStateMap> {
            self.writes
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
        }
    }

    /// A state value: `i128`, `u64` or `bool`.
    pub trait AllowitValue: Sized {
        /// This value as a state entry.
        fn to_val(self) -> AllowitVal;
        /// The value of a state entry of this type, or `None`.
        fn from_val(val: &AllowitVal) -> Option<Self>;
    }
    // One `AllowitValue` impl per state value type.
    macro_rules! values {
        ($($t:ty => $v:ident),*) => {$(
            impl AllowitValue for $t {
                fn to_val(self) -> AllowitVal {
                    AllowitVal::$v(self)
                }
                fn from_val(val: &AllowitVal) -> Option<Self> {
                    match val {
                        AllowitVal::$v(value) => Some(*value),
                        _ => None,
                    }
                }
            }
        )*};
    }
    values!(i128 => I128, u64 => U64, bool => Bool);

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

    /// The value of `key`, or `None`. A value of another type is `InvalidState`.
    pub(crate) fn read<V: AllowitValue>(
        _env: &AllowitEnv,
        state: &AllowitStateMap,
        key: &str,
    ) -> Result<Option<V>> {
        if !key_ok(key) {
            return Err(AllowitError::InvalidParameter);
        }
        state
            .get(key)
            .map(|val| V::from_val(val).ok_or(AllowitError::InvalidState))
            .transpose()
    }

    /// Set `key` to `value` in `state`.
    fn write<V: AllowitValue>(
        _env: &AllowitEnv,
        state: &mut AllowitStateMap,
        key: &str,
        value: V,
    ) -> Result {
        if !key_ok(key) {
            return Err(AllowitError::InvalidParameter);
        }
        state.insert(String::from(key), value.to_val());
        Ok(())
    }

    /// Buffer one policy write for `post_flight`.
    fn record<V: AllowitValue>(env: &AllowitEnv, key: &str, value: V) -> Result {
        write(env, &mut env.buffer(), key, value)
    }

    /// Remove and return the buffered policy writes.
    fn take_writes(env: &AllowitEnv) -> AllowitStateMap {
        core::mem::take(&mut *env.buffer())
    }

    /// Apply `writes` over `state`.
    fn merge(state: &mut AllowitStateMap, writes: AllowitStateMap) {
        state.extend(writes);
    }

    /// Server-only enrichment. Each function is an API stub that the offchain server fills; here
    /// it is `Unsupported`. The Soroban backend has none of them, so onchain policy cannot call one.
    pub mod server {
        use super::{Address, AllowitContext, AllowitError, Result};
        use alloc::string::String;

        /// Price `amount` of `asset` in the grant's accounting unit.
        pub fn price(_ctx: &AllowitContext, _asset: &Address, _amount: i128) -> Result<i128> {
            Err(AllowitError::Unsupported)
        }
        /// Fetch the text at `url`.
        pub fn fetch(_ctx: &AllowitContext, _url: &str) -> Result<String> {
            Err(AllowitError::Unsupported)
        }
        /// Search the internet for `query`.
        pub fn internet_search(_ctx: &AllowitContext, _query: &str) -> Result<String> {
            Err(AllowitError::Unsupported)
        }
        /// Search marketplaces for `query`.
        pub fn marketplace_search(_ctx: &AllowitContext, _query: &str) -> Result<String> {
            Err(AllowitError::Unsupported)
        }
        /// Ask SystemOne `prompt` within the evaluation's SystemOne context.
        pub fn systemone(_ctx: &AllowitContext, _prompt: &str) -> Result<String> {
            Err(AllowitError::Unsupported)
        }
        /// Screen the request; `true` passes.
        pub fn request_screening(_ctx: &AllowitContext) -> Result<bool> {
            Err(AllowitError::Unsupported)
        }
        /// Clear the evaluation's SystemOne context.
        pub fn clear_systemone_context(_ctx: &AllowitContext) -> Result {
            Err(AllowitError::Unsupported)
        }
    }
    pub use server::*;
}

#[cfg(feature = "soroban")]
pub use soroban::*;

#[cfg(feature = "std")]
pub use host::*;

#[cfg(all(test, feature = "soroban"))]
mod tests;
