#![no_std]
//! Shared engine ABI. Every rule delegates to the same canonical library used by bundled policy code.
use allowit_wallet_protocol::{EngineError, EngineRequest, EngineResult, EngineState};
use soroban_sdk::{Env, contract, contractimpl};
#[contract]
pub struct Engine;
/// First explicitly numbered engine executable release, independent of parent administration.
const ENGINE_VERSION: u32 = 1;
#[contractimpl]
impl Engine {
    /// Read the engine executable release without changing policy data or requiring authorization.
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// # Returns
    /// Returns ENGINE_VERSION; this value adds no execution ordering fence.
    pub fn engine_version(env: Env) -> u32 {
        let _ = env;
        ENGINE_VERSION
    }
    /// Run the explicitly selected spent_cap rule with authenticated request and owner Grant/current Spent.
    /// Returns only the decision and proposed spent map. See the canonical rule for exact units and state keys.
    pub fn spent_cap(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::spent_cap(env, request, state)
    }
    /// Run the explicitly selected day_spent_cap rule with authenticated request and owner Grant/current Spent.
    /// Returns only the decision and proposed spent map. See the canonical rule for exact units and state keys.
    pub fn day_spent_cap(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::day_spent_cap(env, request, state)
    }
    /// Run the explicitly selected day_total_cap rule with authenticated request and owner Grant/current Spent.
    /// Returns only the decision and proposed spent map. See the canonical rule for exact units and state keys.
    pub fn day_total_cap(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::day_total_cap(env, request, state)
    }
    /// Run the explicitly selected recipients rule with authenticated request and owner Grant/current Spent.
    /// Returns only the decision and proposed spent map. See the canonical rule for exact units and state keys.
    pub fn recipients(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::recipients(env, request, state)
    }
    /// Run the explicitly selected tokens rule with authenticated request and owner Grant/current Spent.
    /// Returns only the decision and proposed spent map. See the canonical rule for exact units and state keys.
    pub fn tokens(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::tokens(env, request, state)
    }

    /// Run the explicitly selected transaction_cap rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Grant per_transfer in native units. No usage fields change.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::transaction_cap] for required types, missing values, errors and usage updates.
    pub fn transaction_cap(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::transaction_cap(env, request, state)
    }

    /// Run the explicitly selected call_cap rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Grant max_calls U64; spent calls/call_operation. Repeated checks charge the same operation once.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::call_cap] for required types, missing values, errors and usage updates.
    pub fn call_cap(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::call_cap(env, request, state)
    }

    /// Run the explicitly selected expiry rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Grant expires_at U64 ledger seconds; no usage fields change.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::expiry] for required types, missing values, errors and usage updates.
    pub fn expiry(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::expiry(env, request, state)
    }
}
#[cfg(test)]
mod tests;
