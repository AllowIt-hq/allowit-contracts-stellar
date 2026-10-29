#![no_std]
use allowit_wallet_protocol::{EngineContext, MAX_RECIPIENTS};
use soroban_sdk::{Env, contract, contractimpl};

#[contract]
pub struct Engine;

/// First explicitly numbered engine executable release; not a parent administration counter.
const ENGINE_VERSION: u32 = 1;

#[contractimpl]
impl Engine {
    /// Read this engine executable's declared release metadata.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    ///
    /// # Returns
    /// Returns ENGINE_VERSION without state reads, authorization or spending effects.
    pub fn engine_version(env: Env) -> u32 {
        let _ = env;
        ENGINE_VERSION
    }

    /// Evaluate an additional bounded veto from custody-supplied observations.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `context`: Exact transfer, local grant, protected counters and ledger time supplied by the wallet. The record alone grants no authority.
    ///
    /// # Returns
    /// Returns true only when these checks permit the proposal. The caller must independently enforce custody and actual effects.
    pub fn evaluate(env: Env, context: EngineContext) -> bool {
        let _ = env;
        // Compiled replacement fixture: an upgraded engine may veto everything.
        if cfg!(feature = "test-deny") {
            return false;
        }
        let g = &context.grant;
        let r = &context.request;
        if g.recipients.is_empty()
            || g.recipients.len() > MAX_RECIPIENTS
            || g.asset != context.asset
            || g.per_transfer <= 0
            || g.daily_limit <= 0
            || g.total_limit <= 0
            || g.max_calls == 0
            || context.now >= g.expires_at
            || context.now >= r.expires_at
            || r.expires_at > g.expires_at
            || r.amount <= 0
            || r.amount > g.per_transfer
            || r.recipient == context.wallet
            || !g.recipients.contains(&r.recipient)
            || context.spent_daily < 0
            || context.spent_total < context.spent_daily
            || context.calls >= g.max_calls
        {
            return false;
        }
        matches!(context.spent_daily.checked_add(r.amount), Some(next) if next <= g.daily_limit)
            && matches!(context.spent_total.checked_add(r.amount), Some(next) if next <= g.total_limit)
            && context.calls.checked_add(1).is_some()
    }
}

#[cfg(test)]
mod tests;
