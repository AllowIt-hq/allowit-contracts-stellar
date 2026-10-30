use super::*;
use allowit::{AllowitOperation, AllowitRule};
use soroban_sdk::{testutils::Address as _, vec};
fn fixture(env: &Env) -> AllowitContext {
    let asset = Address::generate(env);
    let recipient = Address::generate(env);
    AllowitContext {
        env: env.clone(),
        grant: AllowitGrant {
            transaction_cap: Some(100),
            spent_cap: Some(45),
            day_spent_cap: Some(50),
            day_total_cap: Some(100),
            call_cap: Some(3),
            recipients: Some(vec![env, recipient.clone()]),
            tokens: Some(vec![env, asset.clone()]),
            expiry: Some(1_000),
        },
        state: AllowitAccountingHistory {
            calls: 1,
            spent: 45,
            day_spent: 45,
            day_total: 43,
            ..Default::default()
        },
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset,
            recipient,
            amount: 40,
            now: 100,
            expires_at: 500,
        },
    }
}
const ALL: [AllowitRule; 8] = [
    AllowitRule::transaction_cap,
    AllowitRule::spent_cap,
    AllowitRule::day_spent_cap,
    AllowitRule::day_total_cap,
    AllowitRule::call_cap,
    AllowitRule::recipients,
    AllowitRule::tokens,
    AllowitRule::expiry,
];
#[test]
fn native_contract_wrapper_matches_the_bundled_rule() {
    let env = Env::default();
    let ctx = fixture(&env);
    let call = || {
        AllowitEngine::day_total_cap(
            env.clone(),
            ctx.grant.clone(),
            ctx.state.clone(),
            ctx.request.clone(),
        )
    };
    assert_eq!(
        call(),
        allowit::day_total_cap(&ctx, &ctx.grant.day_total_cap)
    );
    assert_eq!(call(), Ok(57));
}
#[test]
fn engine_metadata_is_pure_release_data() {
    let env = Env::default();
    assert_eq!(AllowitEngine::engine_version(env.clone()), 3);
    assert!(env.auths().is_empty());
}

#[test]
fn compiled_engine_returns_bundled_pass_values_and_rule_errors() {
    const WASM: &[u8] =
        include_bytes!("../../../target/wasm32v1-none/release/allowit_wallet_engine.wasm");
    let env = Env::default();
    let id = env.register(WASM, ());
    let client = AllowitEngineClient::new(&env, &id);
    let mut ctx = fixture(&env);
    let c = &ctx;
    let g = &c.grant;
    // The exhaustive match fails to compile when a rule lacks its engine method.
    for rule in ALL {
        match rule {
            AllowitRule::transaction_cap => {
                let v = allowit::transaction_cap(c, &g.transaction_cap);
                assert_eq!(
                    (client.transaction_cap(&c.grant, &c.state, &c.request), v),
                    (60, Ok(60))
                );
            }
            AllowitRule::spent_cap => {
                let v = allowit::spent_cap(c, &g.spent_cap);
                assert_eq!(
                    (client.spent_cap(&c.grant, &c.state, &c.request), v),
                    (0, Ok(0))
                );
            }
            AllowitRule::day_spent_cap => {
                let v = allowit::day_spent_cap(c, &g.day_spent_cap);
                assert_eq!(
                    (client.day_spent_cap(&c.grant, &c.state, &c.request), v),
                    (5, Ok(5))
                );
            }
            AllowitRule::day_total_cap => {
                let v = allowit::day_total_cap(c, &g.day_total_cap);
                assert_eq!(
                    (client.day_total_cap(&c.grant, &c.state, &c.request), v),
                    (57, Ok(57))
                );
            }
            AllowitRule::call_cap => {
                let v = allowit::call_cap(c, &g.call_cap);
                assert_eq!(
                    (client.call_cap(&c.grant, &c.state, &c.request), v),
                    (2, Ok(2))
                );
            }
            AllowitRule::recipients => {
                let v = allowit::recipients(c, &g.recipients);
                assert_eq!(Ok(client.recipients(&c.grant, &c.state, &c.request)), v);
                assert_eq!(v, Ok(c.request.recipient.clone()));
            }
            AllowitRule::tokens => {
                let v = allowit::tokens(c, &g.tokens);
                assert_eq!(Ok(client.tokens(&c.grant, &c.state, &c.request)), v);
                assert_eq!(v, Ok(c.request.asset.clone()));
            }
            AllowitRule::expiry => {
                let v = allowit::expiry(c, &g.expiry);
                assert_eq!(
                    (client.expiry(&c.grant, &c.state, &c.request), v),
                    (900, Ok(900))
                );
            }
        }
    }
    ctx.grant.day_total_cap = Some(42);
    assert_eq!(
        client.try_day_total_cap(&ctx.grant, &ctx.state, &ctx.request),
        Err(Ok(AllowitError::DayTotalCapExceeded))
    );
    ctx.grant.spent_cap = None;
    assert_eq!(
        client.try_spent_cap(&ctx.grant, &ctx.state, &ctx.request),
        Err(Ok(AllowitError::MissingGrant))
    );
    // A failed rule reads and writes no more ledger entries than a passing one, so a failure at
    // apply time that simulation did not see stays within the simulated footprint.
    let passing = fixture(&env);
    assert_eq!(
        client.try_expiry(&passing.grant, &passing.state, &passing.request),
        Ok(Ok(900))
    );
    let pass = env.cost_estimate().resources();
    assert_eq!(
        client.try_day_total_cap(&ctx.grant, &ctx.state, &ctx.request),
        Err(Ok(AllowitError::DayTotalCapExceeded))
    );
    let fail = env.cost_estimate().resources();
    assert_eq!(fail.write_entries, 0);
    assert_eq!(fail.memory_read_entries, pass.memory_read_entries);
    assert_eq!(fail.disk_read_entries, pass.disk_read_entries);
}
