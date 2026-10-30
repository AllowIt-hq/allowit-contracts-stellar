#![no_std]
//! Shared stateless checker. Each method runs the canonical rule on its same-named Grant field.
//! It holds no custody, Grant or accounting. Policy wallets do not call it; it serves offchain simulation.
use allowit::{AllowitEnv, Error};
use soroban_sdk::{Address, Env, contract, contractimpl};
#[contract]
pub struct Engine;
/// Engine executable release, independent of parent administration. Version 2 has the typed ABI.
const ENGINE_VERSION: u32 = 2;
/// Test fixture veto: every rule denies. Used only to prove reference upgrades change behavior.
fn vetoed() -> Result<(), Error> {
    if cfg!(feature = "test-deny") {
        Err(Error::InvalidState)
    } else {
        Ok(())
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
    pub fn transaction_cap(_env: Env, ctx: AllowitEnv) -> Result<i128, Error> {
        vetoed()?;
        allowit::transaction_cap(&ctx, &ctx.grant.transaction_cap)
    }
    /// Run `allowit::spent_cap(&ctx, &ctx.grant.spent_cap)`; returns the cumulative expense headroom.
    pub fn spent_cap(_env: Env, ctx: AllowitEnv) -> Result<i128, Error> {
        vetoed()?;
        allowit::spent_cap(&ctx, &ctx.grant.spent_cap)
    }
    /// Run `allowit::day_spent_cap(&ctx, &ctx.grant.day_spent_cap)`; returns the UTC-day expense headroom.
    pub fn day_spent_cap(_env: Env, ctx: AllowitEnv) -> Result<i128, Error> {
        vetoed()?;
        allowit::day_spent_cap(&ctx, &ctx.grant.day_spent_cap)
    }
    /// Run `allowit::day_total_cap(&ctx, &ctx.grant.day_total_cap)`; returns the UTC-day gross headroom.
    pub fn day_total_cap(_env: Env, ctx: AllowitEnv) -> Result<i128, Error> {
        vetoed()?;
        allowit::day_total_cap(&ctx, &ctx.grant.day_total_cap)
    }
    /// Run `allowit::call_cap(&ctx, &ctx.grant.call_cap)`; returns the operations left.
    pub fn call_cap(_env: Env, ctx: AllowitEnv) -> Result<u64, Error> {
        vetoed()?;
        allowit::call_cap(&ctx, &ctx.grant.call_cap)
    }
    /// Run `allowit::recipients(&ctx, &ctx.grant.recipients)`; returns the matched recipient.
    pub fn recipients(_env: Env, ctx: AllowitEnv) -> Result<Address, Error> {
        vetoed()?;
        allowit::recipients(&ctx, &ctx.grant.recipients)
    }
    /// Run `allowit::tokens(&ctx, &ctx.grant.tokens)`; returns the matched asset.
    pub fn tokens(_env: Env, ctx: AllowitEnv) -> Result<Address, Error> {
        vetoed()?;
        allowit::tokens(&ctx, &ctx.grant.tokens)
    }
    /// Run `allowit::expiry(&ctx, &ctx.grant.expiry)`; returns the seconds left.
    pub fn expiry(_env: Env, ctx: AllowitEnv) -> Result<u64, Error> {
        vetoed()?;
        allowit::expiry(&ctx, &ctx.grant.expiry)
    }
}
#[cfg(test)]
mod tests;
