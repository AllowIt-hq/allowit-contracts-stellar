#![no_std]
//! Shared engine ABI. Every rule delegates to the same canonical library used by bundled policy code.
use allowit_wallet_protocol::{EngineError, EngineRequest, EngineResult, EngineState};
use soroban_sdk::{Address, Env, String, Vec, contract, contractimpl};
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
    /// Run the explicitly selected daily_cap rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Grant daily_limit; spent day/daily/daily_operation. UTC rollover and operation deduplication follow the canonical rule.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::daily_cap] for required types, missing values, errors and usage updates.
    pub fn daily_cap(
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
        allowit_policy_rules::daily_cap(env, request, state)
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
    /// Run the explicitly selected total_cap rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Grant total_limit; spent total/total_operation. The same operation is charged once.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::total_cap] for required types, missing values, errors and usage updates.
    pub fn total_cap(
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
        allowit_policy_rules::total_cap(env, request, state)
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
    /// Run the explicitly selected recipient rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Grant recipients Vec<Address>; no usage fields change.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::recipient] for required types, missing values, errors and usage updates.
    pub fn recipient(
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
        allowit_policy_rules::recipient(env, request, state)
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
    /// Run the explicitly selected token rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Grant token String; compares the authenticated label and seven-decimal profile. No usage fields change.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::token] for required types, missing values, errors and usage updates.
    pub fn token(
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
        allowit_policy_rules::token(env, request, state)
    }
    /// Run the explicitly selected cap_per_transaction rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: No Grant keys or usage counters are read; the explicit source limit is used.
    /// - `limit`: Positive cap in native i128 asset base units.
    /// - `token`: Expected authenticated SAC label.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::cap_per_transaction] for required types, missing values, errors and usage updates.
    pub fn cap_per_transaction(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        limit: i128,
        token: String,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::cap_per_transaction(env, request, state, limit, token)
    }
    /// Run the explicitly selected cap_per_day rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: Explicit cap; spent day/daily/daily_operation, shared with daily_cap. See the canonical UTC/deduplication contract.
    /// - `limit`: Positive cap in native i128 asset base units.
    /// - `token`: Expected authenticated SAC label.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::cap_per_day] for required types, missing values, errors and usage updates.
    pub fn cap_per_day(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        limit: i128,
        token: String,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::cap_per_day(env, request, state, limit, token)
    }
    /// Run the explicitly selected recipient_is rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: No Grant keys or usage fields are read or changed.
    /// - `expected`: Exact expected native address or authenticated label.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::recipient_is] for required types, missing values, errors and usage updates.
    pub fn recipient_is(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        expected: Address,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::recipient_is(env, request, state, expected)
    }
    /// Run the explicitly selected asset_label rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: No Grant keys or usage fields change; compares authenticated label and decimals.
    /// - `expected`: Exact expected native address or authenticated label.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::asset_label] for required types, missing values, errors and usage updates.
    pub fn asset_label(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        expected: String,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::asset_label(env, request, state, expected)
    }
    /// Run the explicitly selected actions rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: No Grant keys or usage fields change; this profile admits stellar::sep41_transfer only.
    /// - `allowed`: Explicitly permitted action identifiers.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::actions] for required types, missing values, errors and usage updates.
    pub fn actions(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        allowed: Vec<String>,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::actions(env, request, state, allowed)
    }
    /// Run the explicitly selected amount_at_most rule.
    ///
    /// # Parameters
    /// - `env`: Host-provided environment, omitted from serialized arguments.
    /// - `request`: Exact custody-authenticated proposal and operation identity.
    /// - `state`: No Grant keys or usage fields change. A valid exceeded bound is false; invalid token/parameters are errors.
    /// - `limit`: Nonnegative bound in native i128 asset base units.
    /// - `token`: Expected authenticated SAC label.
    ///
    /// # Returns
    /// Returns data only. See [allowit_policy_rules::amount_at_most] for required types, missing values, errors and usage updates.
    pub fn amount_at_most(
        env: Env,
        request: EngineRequest,
        state: EngineState,
        limit: i128,
        token: String,
    ) -> core::result::Result<EngineResult, EngineError> {
        if cfg!(feature = "test-deny") {
            return Ok(EngineResult {
                approval: false,
                spent: state.spent,
            });
        }
        allowit_policy_rules::amount_at_most(env, request, state, limit, token)
    }
}
#[cfg(test)]
mod tests;
