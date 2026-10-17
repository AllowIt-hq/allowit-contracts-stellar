use super::*;
use allowit_wallet_protocol::{EngineContext, Grant, TransferRequest};
use soroban_sdk::{Address, testutils::Address as _, vec};

fn context(env: &Env) -> EngineContext {
    let asset = Address::generate(env);
    let recipient = Address::generate(env);
    EngineContext {
        wallet: Address::generate(env),
        agent: Address::generate(env),
        asset: asset.clone(),
        request: TransferRequest {
            recipient: recipient.clone(),
            amount: 10,
            nonce: 0,
            revision: 0,
            expires_at: 500,
        },
        grant: Grant {
            asset,
            recipients: vec![env, recipient],
            per_transfer: 10,
            daily_limit: 30,
            total_limit: 50,
            max_calls: 5,
            expires_at: 1_000,
        },
        spent_daily: 20,
        spent_total: 40,
        calls: 4,
        now: 100,
    }
}

#[test]
fn exact_limits_pass_and_each_exceeded_limit_denies() {
    let env = Env::default();
    let id = env.register(Engine, ());
    let client = allowit_wallet_protocol::EngineClient::new(&env, &id);
    let base = context(&env);
    assert!(client.evaluate(&base));
    let mut c = base.clone();
    c.request.amount = 11;
    assert!(!client.evaluate(&c));
    c = base.clone();
    c.spent_daily = 21;
    assert!(!client.evaluate(&c));
    c = base.clone();
    c.spent_total = 41;
    assert!(!client.evaluate(&c));
    c = base.clone();
    c.calls = 5;
    assert!(!client.evaluate(&c));
    assert!(env.auths().is_empty());
}

#[test]
fn malformed_or_expired_requests_deny() {
    let env = Env::default();
    let base = context(&env);
    let mut c = base.clone();
    c.request.amount = 0;
    assert!(!Engine::evaluate(env.clone(), c));
    c = base.clone();
    c.request.amount = -1;
    assert!(!Engine::evaluate(env.clone(), c));
    c = base.clone();
    c.asset = Address::generate(&env);
    assert!(!Engine::evaluate(env.clone(), c));
    c = base.clone();
    c.request.recipient = Address::generate(&env);
    assert!(!Engine::evaluate(env.clone(), c));
    c = base.clone();
    c.request.recipient = c.wallet.clone();
    assert!(!Engine::evaluate(env.clone(), c));
    c = base.clone();
    c.now = c.request.expires_at;
    assert!(!Engine::evaluate(env.clone(), c));
    c = base.clone();
    c.now = c.grant.expires_at;
    assert!(!Engine::evaluate(env.clone(), c));
    c = base.clone();
    c.request.expires_at = c.grant.expires_at + 1;
    assert!(!Engine::evaluate(env.clone(), c));
    c = base.clone();
    c.grant.recipients = vec![&env];
    assert!(!Engine::evaluate(env.clone(), c));
    c = base;
    for _ in 0..MAX_RECIPIENTS {
        c.grant.recipients.push_back(Address::generate(&env));
    }
    assert!(!Engine::evaluate(env, c));
}

#[test]
fn corrupt_accounting_and_arithmetic_overflow_deny() {
    let env = Env::default();
    let base = context(&env);
    let mut c = base.clone();
    c.spent_daily = -1;
    assert!(!Engine::evaluate(env.clone(), c));
    c = base.clone();
    c.spent_total = c.spent_daily - 1;
    assert!(!Engine::evaluate(env.clone(), c));
    c = base.clone();
    c.spent_daily = i128::MAX;
    c.spent_total = i128::MAX;
    c.grant.daily_limit = i128::MAX;
    c.grant.total_limit = i128::MAX;
    assert!(!Engine::evaluate(env.clone(), c));
    c = base;
    c.calls = u64::MAX;
    c.grant.max_calls = u64::MAX;
    assert!(!Engine::evaluate(env, c));
}
