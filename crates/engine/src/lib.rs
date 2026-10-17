#![no_std]
use allowit_wallet_protocol::{EngineContext, MAX_RECIPIENTS};
use soroban_sdk::{Env, contract, contractimpl};

#[contract]
pub struct Engine;

#[contractimpl]
impl Engine {
    /// Pure veto: callers must enforce custody and authenticate observations.
    pub fn evaluate(_env: Env, context: EngineContext) -> bool {
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
