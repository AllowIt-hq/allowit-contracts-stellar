#![no_std]
//! Shared stateless checker. Each method runs the canonical rule on its same-named AllowitGrant field.
//! It holds no custody, AllowitGrant or accounting. No policy wallet or tool here calls it.
use allowit::{AllowitContext, AllowitError};
use soroban_sdk::{Address, Env, contract, contractimpl, panic_with_error};
#[contract]
pub struct Engine;
/// Engine executable release, independent of parent administration. Version 2 has the typed ABI.
const ENGINE_VERSION: u32 = 2;
/// Contract error code of the test fixture veto. It is outside `allowit::AllowitError`.
pub const TEST_DENY: u32 = 1000;
/// Test fixture veto: every rule aborts with `TEST_DENY`. Used only to prove reference upgrades
/// change behavior.
fn vetoed(env: &Env) {
    if cfg!(feature = "test-deny") {
        panic_with_error!(env, soroban_sdk::Error::from_contract_error(TEST_DENY));
    }
}
#[contractimpl]
impl Engine {
    /// Read the engine executable release without changing data or requiring authorization.
    pub fn engine_version(env: Env) -> u32 {
        let _ = env;
        ENGINE_VERSION
    }
    /// Run `allowit::transaction_cap(&ctx, &ctx.grant.transaction_cap)`; returns the headroom left for this operation.
    pub fn transaction_cap(env: Env, ctx: AllowitContext) -> Result<i128, AllowitError> {
        vetoed(&env);
        allowit::transaction_cap(&ctx, &ctx.grant.transaction_cap)
    }
    /// Run `allowit::spent_cap(&ctx, &ctx.grant.spent_cap)`; returns the cumulative expense headroom.
    pub fn spent_cap(env: Env, ctx: AllowitContext) -> Result<i128, AllowitError> {
        vetoed(&env);
        allowit::spent_cap(&ctx, &ctx.grant.spent_cap)
    }
    /// Run `allowit::day_spent_cap(&ctx, &ctx.grant.day_spent_cap)`; returns the UTC-day expense headroom.
    pub fn day_spent_cap(env: Env, ctx: AllowitContext) -> Result<i128, AllowitError> {
        vetoed(&env);
        allowit::day_spent_cap(&ctx, &ctx.grant.day_spent_cap)
    }
    /// Run `allowit::day_total_cap(&ctx, &ctx.grant.day_total_cap)`; returns the UTC-day gross headroom.
    pub fn day_total_cap(env: Env, ctx: AllowitContext) -> Result<i128, AllowitError> {
        vetoed(&env);
        allowit::day_total_cap(&ctx, &ctx.grant.day_total_cap)
    }
    /// Run `allowit::call_cap(&ctx, &ctx.grant.call_cap)`; returns the operations left.
    pub fn call_cap(env: Env, ctx: AllowitContext) -> Result<u64, AllowitError> {
        vetoed(&env);
        allowit::call_cap(&ctx, &ctx.grant.call_cap)
    }
    /// Run `allowit::recipients(&ctx, &ctx.grant.recipients)`; returns the matched recipient.
    pub fn recipients(env: Env, ctx: AllowitContext) -> Result<Address, AllowitError> {
        vetoed(&env);
        allowit::recipients(&ctx, &ctx.grant.recipients)
    }
    /// Run `allowit::tokens(&ctx, &ctx.grant.tokens)`; returns the matched asset.
    pub fn tokens(env: Env, ctx: AllowitContext) -> Result<Address, AllowitError> {
        vetoed(&env);
        allowit::tokens(&ctx, &ctx.grant.tokens)
    }
    /// Run `allowit::expiry(&ctx, &ctx.grant.expiry)`; returns the seconds left.
    pub fn expiry(env: Env, ctx: AllowitContext) -> Result<u64, AllowitError> {
        vetoed(&env);
        allowit::expiry(&ctx, &ctx.grant.expiry)
    }
}
#[cfg(test)]
mod tests;
