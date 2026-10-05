#![no_std]
use soroban_sdk::{BytesN, Env, contract, contractimpl};
#[path = "../../../policy/policy.rs"]
pub mod policy;
#[path = "../../../policy/policy_api.rs"]
pub mod policy_api;
#[path = "../../../policy/source_hash.rs"]
mod source_hash;

#[contract]
pub struct NativePolicy;

#[contractimpl]
impl NativePolicy {
    pub fn evaluate(
        _env: Env,
        context: policy_api::Context,
    ) -> Result<u64, policy_api::PolicyError> {
        policy::evaluate(&context)
    }
    pub fn validate_daily_limit(_env: Env, value: u64) -> Result<(), policy_api::PolicyError> {
        policy::validate_daily_limit(value)
    }
    pub fn source_hash(env: Env) -> BytesN<32> {
        BytesN::from_array(&env, &source_hash::SOURCE_HASH)
    }
    pub fn max_daily_limit(_env: Env) -> u64 {
        policy::MAX_DAILY_LIMIT
    }
}

#[cfg(test)]
#[path = "../../../policy/tests.rs"]
mod tests;
