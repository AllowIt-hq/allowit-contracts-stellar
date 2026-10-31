#![no_std]
//! Canonical AllowIt policy rules. The offchain server and `AllowitCustomPolicy` compile one authored
//! policy file verbatim:
//!
//! ```ignore
//! use allowit::prelude::*;
//! /// Let my agent pay our invoices. Cap its total spending and pay only vendors I approve.
//! pub fn execute(ctx: &AllowitContext) -> allowit::Result {
//!     // "Cap its total spending"
//!     allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;
//!     // "pay only vendors I approve"
//!     allowit::recipients(ctx, ctx.params.get(allowit::RECIPIENTS))?;
//!     Ok(())
//! }
//! ```
//!
//! `AllowitContext` is plain data: `env`, `params`, `state` and `request`. `params` holds the
//! owner's constructor params, key => `AllowitValue`; an absent key is unset. `state` is the
//! current policy state, before this operation: one free-form map with standard keys (`spent`,
//! `day_spent`, `day_total`, `calls`, `day`, `unpriced`, `day_unpriced`) and policy-defined keys.
//! `request.args` holds the agent's execution params for this call. Params, state and args share
//! the one value type `AllowitValue`.
//!
//! A rule takes the looked-up param value and decodes it: an unset param is `MissingParam` and a
//! value of the wrong type or range is `InvalidParam`. Rules add the request's own contribution to
//! the current values and return their passing constraint or an `AllowitError`. Only an error that
//! the policy propagates with `?` ends the run. A policy may catch a rule error, read it and
//! continue.
//!
//! After approval, the wallet and the server run the same `post_flight`: it rolls the UTC day
//! over, counts the call, adds spent and gross amounts, marks unpriced operations, then applies
//! the policy's own `set_state` writes, and denies a result whose standard keys do not decode.
//! Simple and Common run only the canonical prefix onchain and store only standard keys, so their
//! `post_flight` denies any policy write with `Unsupported`, on the host as onchain. The server
//! runs a policy through `evaluate`, which also discards the writes of a denied run. The standard
//! contract runs the leading canonical calls, supplied by the owner as `rules`, through
//! `preflight`, which skips absent params.
//!
//! Portable authored code uses rule calls, `param`, `get_state` and `set_state`, typed scalar
//! fields and enum comparisons. `scripts/policy_source.py` admits only an allowlist of names,
//! paths and methods that give the same result on both backends.
//!
//! Types and rule logic are written once in `core.rs` and compiled per backend. Each backend binds
//! `Address`, `AllowitEnv`, `Map`, `String`, `Symbol` and `Vec`. Feature `soroban` (default) uses
//! host values, contract types and the Soroban `Env`, and buffers policy writes in contract
//! temporary storage until `post_flight`. Feature `std` uses StrKey addresses, heap maps and
//! vectors, and a host `AllowitEnv` that buffers policy writes. The selected backend backs the
//! crate root, which authored policy names.
//!
//! The server-only enrichment functions (`price`, `fetch`, `internet_search`,
//! `marketplace_search`, `request_screening`, `systemone`, `clear_systemone_context`) exist only
//! in the host backend. A Custom policy that calls one does not compile onchain.
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
//!     allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;
//!     Ok(())
//! }
//! ```
//!
//! ```compile_fail,E0425
//! use allowit::prelude::*;
//! /// A Custom policy that calls a server-only function does not build onchain.
//! pub fn execute(ctx: &AllowitContext) -> allowit::Result {
//!     allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;
//!     allowit::clear_systemone_context(ctx)?;
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

/// Onchain backend. Params, state, request facts and errors are Soroban contract types.
#[cfg(feature = "soroban")]
pub mod soroban {
    pub use soroban_sdk::Address;
    use soroban_sdk::{Env as AllowitEnv, Map, String, Symbol, Vec};
    /// Make a `core.rs` value type a Soroban contract type.
    macro_rules! value {
        ($item:item) => {
            #[soroban_sdk::contracttype]
            $item
        };
    }
    /// Make the `core.rs` error enum a Soroban contract error.
    macro_rules! error {
        ($item:item) => {
            #[soroban_sdk::contracterror]
            $item
        };
    }
    include!("core.rs");

    /// Temporary-storage key of the running operation's policy writes. `post_flight` removes it,
    /// and a failed operation rolls it back, so it never outlives the transaction.
    const WRITES: Symbol = soroban_sdk::symbol_short!("allowit_w");

    /// The value of `key` in `map`, or `None` when it is absent or no map can hold the key.
    fn lookup(map: &AllowitMap, key: &str) -> Option<AllowitValue> {
        key_ok(key)
            .then(|| map.get(Symbol::new(map.env(), key)))
            .flatten()
    }

    /// Set `key` to `value` in `map`. An invalid key is `InvalidParam`.
    fn insert(map: &mut AllowitMap, key: &str, value: AllowitValue) -> Result {
        if !key_ok(key) {
            return Err(AllowitError::InvalidParam);
        }
        let key = Symbol::new(map.env(), key);
        map.set(key, value);
        Ok(())
    }

    /// The number of entries in `map`.
    fn count(map: &AllowitMap) -> u32 {
        map.len()
    }

    /// The byte length of a text value.
    fn text_len(text: &String) -> u32 {
        text.len()
    }

    /// Run `check` on each value of `map`. A value that does not decode is `InvalidParam`;
    /// every `Symbol` key is valid.
    fn each_value(map: &AllowitMap, mut check: impl FnMut(AllowitValue) -> Result) -> Result {
        for entry in map.try_iter() {
            check(entry.map_err(|_| AllowitError::InvalidParam)?.1)?;
        }
        Ok(())
    }

    /// Run `check` on each item of a list. An item that does not decode is `InvalidParam`.
    fn each_item(
        items: &Vec<AllowitValue>,
        mut check: impl FnMut(AllowitValue) -> Result,
    ) -> Result {
        for item in items.try_iter() {
            check(item.map_err(|_| AllowitError::InvalidParam)?)?;
        }
        Ok(())
    }

    /// Buffer one policy write for `post_flight`.
    fn record(env: &AllowitEnv, key: &str, value: AllowitValue) -> Result {
        let store = env.storage().temporary();
        let mut writes = store.get(&WRITES).unwrap_or_else(|| Map::new(env));
        insert(&mut writes, key, value)?;
        store.set(&WRITES, &writes);
        Ok(())
    }

    /// Remove and return the buffered policy writes.
    fn take_writes(env: &AllowitEnv) -> AllowitMap {
        let store = env.storage().temporary();
        let writes: AllowitMap = store.get(&WRITES).unwrap_or_else(|| Map::new(env));
        if !writes.is_empty() {
            store.remove(&WRITES);
        }
        writes
    }

    /// Apply `writes` over `state`.
    fn merge(state: &mut AllowitMap, writes: AllowitMap) {
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

    /// Host map: keys are text checked like Soroban `Symbol`s.
    type Map<K, V> = BTreeMap<K, V>;
    /// Host map key.
    type Symbol = String;

    /// Host environment of policy evaluations. It buffers the policy's `set_state` writes for
    /// `post_flight`; clones share the buffer. `evaluate` clears it before a run and on denial.
    #[derive(Clone, Debug)]
    pub struct AllowitEnv {
        writes: Arc<Mutex<AllowitMap>>,
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
        fn buffer(&self) -> MutexGuard<'_, AllowitMap> {
            self.writes
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
        }
    }

    /// Keep a `core.rs` value type a plain Rust type.
    macro_rules! value {
        ($item:item) => {
            $item
        };
    }
    /// Keep the `core.rs` error enum a plain Rust enum.
    macro_rules! error {
        ($item:item) => {
            $item
        };
    }
    include!("core.rs");

    /// The value of `key` in `map`, or `None` when it is absent or no map can hold the key.
    fn lookup(map: &AllowitMap, key: &str) -> Option<AllowitValue> {
        key_ok(key).then(|| map.get(key).cloned()).flatten()
    }

    /// Set `key` to `value` in `map`. An invalid key is `InvalidParam`.
    fn insert(map: &mut AllowitMap, key: &str, value: AllowitValue) -> Result {
        if !key_ok(key) {
            return Err(AllowitError::InvalidParam);
        }
        map.insert(String::from(key), value);
        Ok(())
    }

    /// The number of entries in `map`.
    fn count(map: &AllowitMap) -> u32 {
        u32::try_from(map.len()).unwrap_or(u32::MAX)
    }

    /// The byte length of a text value.
    fn text_len(text: &String) -> u32 {
        u32::try_from(text.len()).unwrap_or(u32::MAX)
    }

    /// Run `check` on each value of `map`. A key that no Soroban map could hold is `InvalidParam`.
    fn each_value(map: &AllowitMap, mut check: impl FnMut(AllowitValue) -> Result) -> Result {
        for (key, value) in map {
            if !key_ok(key) {
                return Err(AllowitError::InvalidParam);
            }
            check(value.clone())?;
        }
        Ok(())
    }

    /// Run `check` on each item of a list.
    fn each_item(
        items: &Vec<AllowitValue>,
        mut check: impl FnMut(AllowitValue) -> Result,
    ) -> Result {
        items.iter().try_for_each(|item| check(item.clone()))
    }

    /// Buffer one policy write for `post_flight`.
    fn record(env: &AllowitEnv, key: &str, value: AllowitValue) -> Result {
        insert(&mut env.buffer(), key, value)
    }

    /// Remove and return the buffered policy writes.
    fn take_writes(env: &AllowitEnv) -> AllowitMap {
        core::mem::take(&mut *env.buffer())
    }

    /// Apply `writes` over `state`.
    fn merge(state: &mut AllowitMap, writes: AllowitMap) {
        state.extend(writes);
    }

    /// Server-only enrichment. Each function takes its owner-written request, returns its passing
    /// constraint or an `AllowitError`, and is an API stub that the offchain server fills; here it
    /// is `Unsupported`. The Soroban backend has none of them, so onchain policy cannot call one.
    pub mod server {
        use super::{Address, AllowitContext, AllowitError, AllowitValue, Result};

        /// Price check: `amount` of `from` priced in `to` must stay within `slip` of `price`.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitPrice {
            /// Asset priced.
            pub from: Address,
            /// Quote asset.
            pub to: Address,
            /// Units of `from` priced.
            pub amount: i128,
            /// Expected price: units of `to` per unit of `from`, scaled by 10^7.
            pub price: i128,
            /// Largest accepted deviation from `price`, in basis points.
            pub slip: u32,
        }
        /// Fetch request: the response must verify under `pubkey`.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitFetch<'a> {
            /// HTTP method, such as `GET`.
            pub method: &'a str,
            /// Requested URL.
            pub url: &'a str,
            /// Request body; empty for none.
            pub data: &'a str,
            /// Key that signs the expected response.
            pub pubkey: &'a str,
        }
        /// Internet search request.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitInternetSearch<'a> {
            /// Search query.
            pub query: &'a str,
        }
        /// Marketplace search request.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitMarketplaceSearch<'a> {
            /// Search query.
            pub query: &'a str,
        }
        /// Request screening: the request must score at least `deny_below`.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitRequestScreening<'a> {
            /// What the screening checks the request for.
            pub query: &'a str,
            /// Lowest passing score, in basis points.
            pub deny_below: u32,
        }
        /// SystemOne question within the evaluation's SystemOne context `id`.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitSystemOne<'a> {
            /// SystemOne context identifier.
            pub id: &'a str,
            /// Question asked.
            pub query: &'a str,
            /// A confidence below this denies, in basis points.
            pub deny_below: u32,
            /// A confidence at or above this passes without review, in basis points.
            pub allow_above: u32,
        }

        /// Check a price; returns the observed price.
        pub fn price(_ctx: &AllowitContext, _request: &AllowitPrice) -> Result<i128> {
            Err(AllowitError::Unsupported)
        }
        /// Fetch a verified response; returns it as a value.
        pub fn fetch(_ctx: &AllowitContext, _request: &AllowitFetch) -> Result<AllowitValue> {
            Err(AllowitError::Unsupported)
        }
        /// Search the internet; returns the results as a value.
        pub fn internet_search(
            _ctx: &AllowitContext,
            _request: &AllowitInternetSearch,
        ) -> Result<AllowitValue> {
            Err(AllowitError::Unsupported)
        }
        /// Search marketplaces; returns the results as a value.
        pub fn marketplace_search(
            _ctx: &AllowitContext,
            _request: &AllowitMarketplaceSearch,
        ) -> Result<AllowitValue> {
            Err(AllowitError::Unsupported)
        }
        /// Screen the request; returns its passing score.
        pub fn request_screening(
            _ctx: &AllowitContext,
            _request: &AllowitRequestScreening,
        ) -> Result<u32> {
            Err(AllowitError::Unsupported)
        }
        /// Ask SystemOne; returns its passing confidence.
        pub fn systemone(_ctx: &AllowitContext, _request: &AllowitSystemOne) -> Result<u32> {
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
